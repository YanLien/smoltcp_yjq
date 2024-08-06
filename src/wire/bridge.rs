use std::{collections::HashMap, sync::{Arc, Mutex, Weak}};
use crate::phy::RxToken;
use crate::{iface::Interface, phy::{Device, DeviceCapabilities, TxToken}, time::Instant};

use super::{bridge_fdb::{BridgeDfdb, BridgeifPortmask, BR_FLOOD, MAX_FDB_ENTRIES}, EthernetAddress, EthernetFrame};

pub struct BridgePort<D>
where
    D: for<'a> Device,
{
    pub bridge: Weak<Mutex<Bridge<D>>>,     // 指向所属网桥的指针
    pub port_iface: Interface,              // 端口对应的 netif
    pub port_device: D,                     // 端口对应的设备
    pub port_num: u32,                      // 端口号
}

impl<D> BridgePort<D>
where
    D: for<'a> Device,
{
    pub fn send(&mut self, frame: &EthernetFrame<&[u8]>) -> Result<(), ()> {
        let time = Instant::now();
        let tx_token = self.port_device.transmit(time).unwrap();
        tx_token.consume(frame.as_ref().len(), |buffer| {
            buffer[..frame.as_ref().len()].copy_from_slice(frame.as_ref());
        });

        Ok(())
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.port_device.capabilities()
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

pub struct Bridge<D> 
where
    D: for<'a> Device,
{
    pub iface: Interface,               // 网桥自己的netif
    pub ethaddr: EthernetAddress,       // 网桥的 MAC 地址
    pub max_ports: u8,                  // 端口的最大数量
    pub num_ports: u8,                  // 端口的当前数量
    pub ports: Vec<BridgePort<D>>,      // 端口的指针
    pub fdb_static: BridgeSfdb,
    pub fdb_dynamic: BridgeDfdb,
}

pub struct BridgeWrapper<D: for<'a> Device>(Arc<Mutex<Bridge<D>>>);

impl<D: for<'a> Device> BridgeWrapper<D> {
    pub fn new(iface: Interface, ethaddr: EthernetAddress, max_ports: u8) -> Self {
        BridgeWrapper(Arc::new(Mutex::new(Bridge {
            iface,
            ethaddr,
            max_ports,
            num_ports: 0,
            ports: Vec::new(),
            fdb_static: BridgeSfdb::new(MAX_FDB_ENTRIES as u16), // 假设最大静态表项为1024
            fdb_dynamic: BridgeDfdb::new(MAX_FDB_ENTRIES as u16), // 假设最大动态表项为1024
        })))
    }

    pub fn get_bridge(&self) -> Arc<Mutex<Bridge<D>>> {
        self.0.clone()
    }

    pub fn add_port(&self, port_iface: Interface, port_device: D) -> Result<(), &'static str> {
        let mut bridge = self.0.lock().unwrap();
        if bridge.num_ports >= bridge.max_ports {
            return Err("Maximum number of ports reached");
        }

        let port = BridgePort {
            bridge: Arc::downgrade(&self.0),
            port_iface,
            port_device,
            port_num: bridge.num_ports as u32,
        };

        bridge.ports.push(port);
        bridge.num_ports += 1;
        Ok(())
    }

    pub fn process_frame(&self, frame: &EthernetFrame<&mut Vec<u8>>, in_port: u8) -> Result<(), &'static str> {
        let mut bridge = self.0.lock().unwrap();
        let src_addr = frame.src_addr();
        let dst_addr = frame.dst_addr();

        println!("Received frame from port {}", in_port);

        // 更新动态FDB
        bridge.fdb_dynamic.update_entry(src_addr, in_port).unwrap_or_else(|_| {
            println!("Failed to update dynamic FDB for source address");
        });

        // 决定转发端口
        let out_ports = bridge.decide_forward_ports(&dst_addr, in_port);

        // 转发帧
        for &port_num in &out_ports {
            if let Some(port) = bridge.ports.get_mut(port_num as usize) {
                Self::forward_frame(&frame, port)?;
            }
        }

        Ok(())
    }

    fn forward_frame(frame: &EthernetFrame<&mut Vec<u8>>, port: &mut BridgePort<D>) -> Result<(), &'static str> {
        let tx_token = port.port_device.transmit(Instant::now()).expect("Failed to acquire transmit token");
        tx_token.consume(frame.as_ref().len(), |buffer| {
            buffer.copy_from_slice(frame.as_ref());
            println!("{:?}", buffer);
        });
        Ok(())
    }

    pub fn age_fdb(&self) {
        let bridge = self.0.lock().unwrap();
        bridge.fdb_dynamic.age_entries();
    }

    pub fn receive_frame(&self) -> Option<(u8, Vec<u8>)> {
        let mut bridge = self.0.lock().unwrap();
        
        // 遍历所有端口
        for (port_index, port) in bridge.ports.iter_mut().enumerate() {
            let time = Instant::now();
            
            // 尝试从端口接收数据
            if let Some((rx_token, _)) = port.port_device.receive(time) {
                let result = rx_token.consume(|buffer| {
                    // 创建一个新的缓冲区来存储接收到的数据
                    let frame_buffer = buffer.to_vec();

                    // 验证以太网帧
                    if let Ok(_) = EthernetFrame::new_checked(&frame_buffer) {
                        println!("Received valid frame on port {}", port_index);
                        Some(frame_buffer)
                    } else {
                        println!("Received invalid frame on port {}", port_index);
                        None
                    }
                });

                // 如果成功接收到帧，返回端口号和原始帧数据
                if let Some(frame_data) = result {
                    return Some((port_index as u8, frame_data));
                }
            }
        }

        // 如果所有端口都没有接收到帧，返回 None
        None
    }

    // pub fn get_port(&self, index: usize) -> Option<Cow<BridgePort<D>>> {
    //     let bridge = self.0.lock().unwrap();
    //     bridge.ports.get(index).map(|port| Cow::Borrowed(port))
    // }

    // pub fn get_port_mut(&mut self, index: usize) -> Option<&mut BridgePort<D>> {
    //     let mut bridge = self.0.lock().unwrap();
    //     bridge.ports.get_mut(index)
    // }
}

impl<D: for<'a> Device> Bridge<D> {
    fn decide_forward_ports(&self, dst_addr: &EthernetAddress, in_port: u8) -> Vec<u8> {
        // 检查静态 FDB
        if let Some(entry) = self.fdb_static.get_entry(dst_addr) {
            println!("Static FDB {}", entry.dst_ports);
            println!("{:?}", vec![entry.dst_ports as u8]);
            return vec![entry.dst_ports as u8];
        }

        // 检查动态 FDB
        if let Some(port) = self.fdb_dynamic.get_entry(dst_addr) {
            println!("Dynamic FDB{}", port);
            return vec![port];
        }

        // 如果没有找到匹配项，广播到所有端口（除了入口端口）
        println!("Broadcasting frame");
        (0..self.num_ports).filter(|&p| p != in_port).collect()
    }

    // 添加一个静态转发表项
    pub fn fdb_add(&self, addr: &EthernetAddress, ports: usize) -> Result<(), &'static str> {
        self.fdb_static.sfdb_add(addr, ports)
    }

    // 删除一个静态转发表项
    pub fn fdb_remove(&self, addr: &EthernetAddress) -> Result<(), &'static str> {
        self.fdb_static.sfdb_remove(addr)
    }

    // 根据目标 MAC 地址查找转发端口
    pub fn find_dst_ports(&self, dst_addr: &EthernetAddress) -> BridgeifPortmask {
        // 首先检查静态转发表项
        let fdb = self.fdb_static.fdb.lock().unwrap();  // 线程安全的获取 fdb 静态表

        for (k, v) in fdb.iter() {
            if v.used && k == dst_addr {
                return v.dst_ports;  // 找到匹配项，返回端口掩码
            }
        }

        // 如果没有匹配项且 MAC 地址是组播地址，则进行广播
        if dst_addr.0[0] & 1 != 0 {
            return BR_FLOOD;  // 返回广播标记
        }

        // 如果静态表中没有找到匹配项，则检查动态转发表
        self.fdb_dynamic.get_dst_ports(dst_addr)  // 调用动态转发表的方法
    }
}