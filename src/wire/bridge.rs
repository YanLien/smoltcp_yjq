use core::marker::PhantomData;
use std::{collections::HashMap, sync::{Arc, Mutex, RwLock, Weak}};
use crate::{iface::Interface, phy::{Device, DeviceCapabilities, RxToken, TunTapInterface, TxToken}, time::Instant};
use super::{bridge_device::BridgeDevice, bridge_fdb::{BridgeDfdb, BridgeifPortmask, BR_FLOOD, MAX_FDB_ENTRIES}, EthernetAddress, EthernetFrame};

const MAX_FRAME_SIZE: usize = 1522; // 略大于标准以太网帧的最大大小

// #[derive(Clone)]
pub struct BridgePort {
    pub bridge: Weak<Mutex<Bridge>>,                    // 指向所属网桥的指针
    pub port_iface: Interface,                      // 端口对应的 netif
    // pub port_device: Arc<RwLock<BridgeDevice>>,     // 端口对应的设备
    pub port_device: Arc<RwLock<TunTapInterface>>,
    // pub port_id: usize,
    pub port_num: u8,                                   // 端口号
}

pub struct Port<D: Device> {
    port_id: usize,
    _marker: PhantomData<D>,
}

impl BridgePort {
    pub fn send(&mut self, frame: &EthernetFrame<&mut [u8]>) -> Result<(), ()> {
        let time = Instant::now();

        if let Some(tx_token) = self.port_device.write().unwrap()
            .transmit(time) {
            tx_token.consume(frame.as_ref().len(), |buffer: &mut [u8]| {
                buffer[..frame.as_ref().len()].copy_from_slice(frame.as_ref());
            });
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn recv(&mut self) -> Option<[u8; MAX_FRAME_SIZE]> {
        let time = Instant::now();
        if let Some((rx_token, _)) = self.port_device.write().unwrap()
            .receive(time) {
            let mut frame_buffer = [0u8; MAX_FRAME_SIZE];
            let mut frame_len = 0;
            
            rx_token.consume(&mut |buffer: &mut [u8]| {
                if buffer.len() > MAX_FRAME_SIZE {
                    println!("Received frame too large, truncating");
                    frame_len = MAX_FRAME_SIZE;
                } else {
                    frame_len = buffer.len();
                }
                frame_buffer[..frame_len].copy_from_slice(&buffer[..frame_len]);
            });

            if frame_len > 0 {
                match EthernetFrame::new_checked(&frame_buffer[..frame_len]) {
                    Ok(_) => {
                        println!("Received valid frame on port {}", self.port_num);
                        Some(frame_buffer)
                    }
                    Err(_) => {
                        println!("Received invalid frame on port {}", self.port_num);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.port_device.read().unwrap()
            .capabilities()
    }

    pub fn get_port_num(&self) -> Option<u8> {
        Some(self.port_num)
    }

    pub fn get_port_device(&self) -> Arc<RwLock<TunTapInterface>> {
        self.port_device.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BridgeSfdbEntry {
    pub used: bool,             // 表示该项是否已使用
    pub dst_ports: usize,       // 目标端口的位掩码
}

#[derive(Debug, Clone)]
pub struct BridgeSfdb {
    pub max_fdb_entries: u16,               // 最大表项数
    pub fdb: Arc<Mutex<HashMap<EthernetAddress, BridgeSfdbEntry>>>,   // 指向表项数组的指针
}

impl BridgeSfdb {
    pub fn new(max_entries: u16) -> Self {
        BridgeSfdb {
            max_fdb_entries: max_entries,
            fdb: Arc::new(Mutex::new(HashMap::with_capacity(max_entries as usize))),
        }
    }

    pub fn add_entry(&self, addr: EthernetAddress, ports: usize) -> Result<(), &'static str> {
        let mut fdb = self.fdb.lock().unwrap();

        if fdb.len() >= self.max_fdb_entries as usize {
            return Err("FDB is full");
        }

        fdb.insert(addr, BridgeSfdbEntry {
            used: true,
            dst_ports: ports,
        });

        Ok(())
    }

    pub fn remove_entry(&self, addr: &EthernetAddress) -> Result<(), &'static str> {
        let mut fdb = self.fdb.lock().unwrap();

        if fdb.remove(addr).is_none() {
            return Err("Entry not found");
        }

        Ok(())
    }

    pub fn get_entry(&self, addr: &EthernetAddress) -> Option<BridgeSfdbEntry> {
        let fdb = self.fdb.lock().unwrap();
        println!("fdb {:?}", fdb);
        fdb.get(addr).cloned()
    }

    pub fn update_entry(&self, addr: EthernetAddress, new_ports: usize) -> Result<(), &'static str> {
        let mut fdb = self.fdb.lock().unwrap();

        if let Some(entry) = fdb.get_mut(&addr) {
            entry.dst_ports = new_ports;
            Ok(())
        } else {
            Err("Entry not found")
        }
    }

    pub fn clear(&self) {
        let mut fdb = self.fdb.lock().unwrap();
        fdb.clear();
    }

    pub fn len(&self) -> usize {
        let fdb = self.fdb.lock().unwrap();
        fdb.len()
    }

    pub fn is_full(&self) -> bool {
        self.len() >= self.max_fdb_entries as usize
    }

    pub fn sfdb_add(&self, addr: &EthernetAddress, ports: usize) -> Result<(), &'static str> {
        let mut fdb = self.fdb.lock().unwrap();

        if fdb.len() >= self.max_fdb_entries as usize {
            // 如果 FDB 已满，尝试找到一个未使用的条目并替换它
            if let Some(unused_key) = fdb.iter().find(|(_, v)| !v.used).map(|(k, _)| *k) {
                fdb.remove(&unused_key);
            } else {
                return Err("FDB is full");
            }
        }

        fdb.insert(*addr, BridgeSfdbEntry {
            used: true,
            dst_ports: ports,
        });

        Ok(())
    }

    pub fn sfdb_remove(&self, addr: &EthernetAddress) -> Result<(), &'static str> {
        let mut fdb = self.fdb.lock().unwrap();

        if let Some(unused_key) = fdb.iter().find(|(k, v)| !v.used && *k == addr).map(|(k, _)| *k) {
            fdb.remove(&unused_key);
        } else {
            return Err("FDB is full");
        }

        Ok(())
    }

    pub fn get(&self, addr: &EthernetAddress) -> Option<BridgeSfdbEntry> {
        let fdb = self.fdb.lock().unwrap();
        fdb.get(addr).cloned()
    }
}

pub struct Bridge {
    // pub iface: Interface,                       // 网桥自己的netif
    // pub ethaddr: EthernetAddress,               // 网桥的 MAC 地址
    pub max_ports: u8,                          // 端口的最大数量
    pub num_ports: u8,                          // 端口的当前数量
    pub ports: HashMap<u8, BridgePort>,         // 端口的指针
    pub fdb_static: BridgeSfdb,
    pub fdb_dynamic: BridgeDfdb,
}

#[derive(Clone)]
pub struct BridgeWrapper(Arc<Mutex<Bridge>>);

unsafe impl Send for BridgeWrapper {}
unsafe impl Sync for BridgeWrapper {}

impl std::fmt::Debug for BridgeWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeWrapper")
            .field("is_some", &true)
            .finish()
    }
}

impl BridgeWrapper {
    pub fn new(_iface: Interface, _ethaddr: EthernetAddress, max_ports: u8) -> Self {
        BridgeWrapper(Arc::new(Mutex::new(Bridge {
            // iface,
            // ethaddr,
            max_ports,
            num_ports: 0,
            ports: HashMap::new(),
            fdb_static: BridgeSfdb::new(MAX_FDB_ENTRIES as u16),
            fdb_dynamic: BridgeDfdb::new(MAX_FDB_ENTRIES as u16),
        })))
    }

    pub fn get_bridge(&self) -> Arc<Mutex<Bridge>> {
        self.0.clone()
    }

    pub fn num_ports(&self) -> u8 {
        let bridge = self.0.lock().unwrap();
        bridge.num_ports
    }

    pub fn add_port(&self, port_iface: Interface, port_device: Arc<RwLock<TunTapInterface>>, port_num: u8) -> Result<(), &'static str> {
        let mut bridge = self.0.lock().unwrap();
        if bridge.num_ports >= bridge.max_ports {
            return Err("Maximum number of ports reached");
        }
    
        let port = BridgePort {
            bridge: Arc::downgrade(&self.0),
            port_iface,
            port_device,
            port_num,
        };
    
        bridge.ports.insert(port_num, port);
        bridge.num_ports += 1;
        Ok(())
    }

    pub fn process_frame(&self, frame: &EthernetFrame<&[u8]>, in_port: u8) -> Result<(), &'static str> {
        let bridge = self.0.lock().unwrap();
        let src_addr = frame.src_addr();
        let dst_addr = frame.dst_addr();

        println!("src_addr {} dst_addr {}", src_addr, dst_addr);
        println!("Received frame from port {}", in_port);

        if bridge.fdb_dynamic.update_entry(src_addr, in_port).is_err() {
            println!("Failed to update dynamic FDB for source address");
            // 可以根据需求决定是否继续处理，还是返回错误
        }
    
        // 决定转发端口
        let out_ports = bridge.decide_forward_ports(&dst_addr, in_port);
        println!("transport port {:?}", out_ports);
    
        // 在转发帧之前，释放对网桥的锁
        drop(bridge);

        for &port_num in &out_ports {
            if let Some(port) = self.0.lock().unwrap().ports.get_mut(&(port_num)) {
                self.forward_frame(frame, port)?;
            } else {
                println!("PPort {} not found", port_num);
                continue; // 或者选择返回错误
            }
        }

        Ok(())
    }

    fn forward_frame(&self, frame: &EthernetFrame<&[u8]>, port: &mut BridgePort) -> Result<(), &'static str> {
        let mut binding = port.port_device.write().unwrap();
        let tx_token = binding.transmit(Instant::now()).ok_or("Failed to acquire transmit token")?;

        tx_token.consume(frame.as_ref().len(), |buffer: &mut [u8]| {
            buffer.copy_from_slice(frame.as_ref());
            println!("buffer {:?}", buffer);
        });

        Ok(())
    }

    pub fn age_fdb(&self) {
        let bridge = self.0.lock().unwrap();
        bridge.fdb_dynamic.age_entries();
    }

    pub fn receive_frame(&self) -> Option<(u8, Vec<u8>)> {
        let mut bridge = self.0.lock().unwrap();
        for (port_num, port) in bridge.ports.iter_mut() {
            let time = Instant::now();
            if let Some((rx_token, _)) = port.port_device.write().unwrap().receive(time) {
                let mut frame_data = None;
                rx_token.consume(&mut |buffer: &mut [u8]| {
                    let frame_buffer = buffer.to_vec();
                    match EthernetFrame::new_checked(&frame_buffer) {
                        Ok(_) => {
                            println!("Received valid frame on port {}", port_num);
                            frame_data = Some(frame_buffer);
                        }
                        Err(_) => {
                            println!("Received invalid frame on port {}", port_num);
                        }
                    }
                });
                if let Some(data) = frame_data {
                    return Some((*port_num, data));
                }
            }
        }
        None
    }

    pub fn fdb_add(&mut self, addr: &EthernetAddress, ports: usize) -> Result<(), &'static str> {
        let bridge = self.0.lock().unwrap();
        bridge.fdb_static.add_entry(*addr, ports)
    }

    pub fn fdb_remove(&mut self, addr: &EthernetAddress) -> Result<(), &'static str> {
        let bridge = self.0.lock().unwrap();
        bridge.fdb_static.remove_entry(addr)
    }

    pub fn find_dst_ports(&self, dst_addr: &EthernetAddress) -> BridgeifPortmask {
        let bridge = self.0.lock().unwrap();
        let mask  = (0..bridge.num_ports).fold(0, |acc, i| acc | (1 << i));
        println!("mask {:?}", mask);
        if let Some(entry) = bridge.fdb_static.get_entry(dst_addr) {
            return (entry.dst_ports & mask) as u8;
        }
        bridge.fdb_dynamic.get_dst_ports(dst_addr) & (mask as u8)
    }

    pub fn get_port(&mut self, netif: &Interface) -> Option<u8> {
        let bridge = self.0.lock().unwrap();
        bridge.ports.iter()
            .find(|(_, bridge_port)| &bridge_port.port_iface == netif)
            .map(|(port_num, _)| *port_num)
    }
}

impl Bridge {
    pub fn decide_forward_ports(&self, dst_addr: &EthernetAddress, in_port: u8) -> Vec<u8> {
        if let Some(entry) = self.fdb_static.get_entry(dst_addr) {
            println!("Static FDB {}", entry.dst_ports);
            return vec![entry.dst_ports as u8];
        }

        if let Some(port) = self.fdb_dynamic.get_entry(dst_addr) {
            println!("Dynamic FDB {}", port);
            return vec![port];
        }

        println!("Broadcasting frame");
        (0..self.num_ports).filter(|&p| p != in_port).collect()
    }

    pub fn fdb_add(&self, addr: &EthernetAddress, ports: usize) -> Result<(), &'static str> {
        self.fdb_static.sfdb_add(addr, ports)
    }

    pub fn fdb_remove(&self, addr: &EthernetAddress) -> Result<(), &'static str> {
        self.fdb_static.sfdb_remove(addr)
    }

    pub fn find_dst_ports(&self, dst_addr: &EthernetAddress) -> BridgeifPortmask {
        let fdb = self.fdb_static.fdb.lock().unwrap();

        for (k, v) in fdb.iter() {
            if v.used && k == dst_addr {
                return v.dst_ports as u8;
            }
        }

        if dst_addr.0[0] & 1 != 0 {
            return BR_FLOOD;
        }

        self.fdb_dynamic.get_dst_ports(dst_addr)
    }
}

