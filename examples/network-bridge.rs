mod utils;
mod bridge_config;

use std::sync::Arc;
use std::sync::Mutex;
use bridge_config::get_bridge_mac;
use bridge_config::get_port1_mac;
use bridge_config::get_port2_mac;
use bridge_config::get_port3_mac;
use bridge_config::MAX_PORTS;
use log::{debug, error, info};
use smoltcp::phy::Loopback;
use smoltcp::wire::bridge_device::NetworkManager;
use smoltcp::wire::global_bridge::add_port;
use smoltcp::wire::global_bridge::initialize_bridge;
use smoltcp::wire::global_bridge::GLOBAL_BRIDGE;
use smoltcp::wire::HardwareAddress;
use std::io;
use std::thread;
use std::time::Duration;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{wait as phy_wait, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

fn main() -> io::Result<()> {
    utils::setup_logging("");

    println!("init bridge");
    let time = smoltcp::time::Instant::now();
    let mut network_manager = NetworkManager::new();
    // 获取或创建设备
    let device1 = network_manager.get_or_create_device("tap0", Medium::Ethernet).unwrap();
    let device2 = network_manager.get_or_create_device("tap1", Medium::Ethernet).unwrap();
    let device3 = network_manager.get_or_create_device("tap2", Medium::Ethernet).unwrap();

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));
    let config3 = Config::new(HardwareAddress::Ethernet(get_port3_mac()));

    // 创建接口
    let iface1 = Interface::new(config1, &mut *device1.write().unwrap(), time);
    let iface2 = Interface::new(config2, &mut *device2.write().unwrap(), time);
    let iface3 = Interface::new(config3, &mut *device3.write().unwrap(), time);

    let config = Config::new(HardwareAddress::Ethernet(get_bridge_mac()));

    // 初始化网桥
    initialize_bridge(
        Interface::new(config, &mut Loopback::new(Medium::Ethernet), time),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        MAX_PORTS // 最大端口数
    ).unwrap();

    // 添加端口到网桥
    add_port(iface1, Arc::clone(&device1), 0).expect("Failed to add port 1");
    add_port(iface2, Arc::clone(&device2), 1).expect("Failed to add port 2");
    add_port(iface3, Arc::clone(&device3), 2).expect("Failed to add port 3");

    let mut bridge_guard = GLOBAL_BRIDGE.lock().expect("Failed to get bridge");
    if let Some(bridge_lock) = bridge_guard.as_mut() {
        bridge_lock.fdb_add(&get_port1_mac(), 0)
            .expect("Failed to add static FDB entry 0");
        println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 1");

        bridge_lock.fdb_add(&get_port2_mac(), 1)
            .expect("Failed to add static FDB entry 1");
        println!("Added static FDB entry: 02:00:00:00:00:03 -> Port 2");
        
        bridge_lock.fdb_add(&get_port3_mac(), 2)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 3");
    }

    drop(bridge_guard);

    let network_manager = Arc::new(Mutex::new(network_manager));
    // let network_clone1 = Arc::clone(&network_manager);
    // let network_clone2 = Arc::clone(&network_manager);

    let tap1_ip = Ipv4Address::new(192, 168, 69, 8);
    let tap2_ip = Ipv4Address::new(192, 168, 69, 9);

    let handle = thread::spawn(move || {
        alternating_thread(Arc::clone(&network_manager), tap1_ip, tap2_ip)
    });

    handle.join().unwrap();

    Ok(())
}

fn alternating_thread(network_manager: Arc<Mutex<NetworkManager>>, tap1_ip: Ipv4Address, tap2_ip: Ipv4Address) {
    let mut network_manager = network_manager.lock().unwrap();

    let tap1 = network_manager.get_or_create_device("tap1", Medium::Ethernet).unwrap();
    let tap2 = network_manager.get_or_create_device("tap2", Medium::Ethernet).unwrap();

    let config1 = Config::new(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x03])));
    let config2 = Config::new(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x04])));

    let mut iface1 = Interface::new(config1, &mut *tap1.write().unwrap(), Instant::now());
    let mut iface2 = Interface::new(config2, &mut *tap2.write().unwrap(), Instant::now());

    iface1.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::from(tap1_ip), 24)).unwrap();
    });
    iface2.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::from(tap2_ip), 24)).unwrap();
    });

    let mut sockets1 = SocketSet::new(vec![]);
    let mut sockets2 = SocketSet::new(vec![]);

    let udp_rx_buffer1 = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_tx_buffer1 = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_rx_buffer2 = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_tx_buffer2 = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_socket1 = udp::Socket::new(udp_rx_buffer1, udp_tx_buffer1);
    let udp_socket2 = udp::Socket::new(udp_rx_buffer2, udp_tx_buffer2);

    let udp_handle1 = sockets1.add(udp_socket1);
    let udp_handle2 = sockets2.add(udp_socket2);

    let fd1 = network_manager.get_device_fd("tap1").unwrap();
    let fd2 = network_manager.get_device_fd("tap2").unwrap();

    loop {
        let timestamp1 = Instant::now();

        // 处理发送
        {
            let mut device1 = tap1.write().unwrap();
            iface1.poll(timestamp1, &mut *device1, &mut sockets1);

            let socket1 = sockets1.get_mut::<udp::Socket>(udp_handle1);
            if !socket1.is_open() {
                socket1.bind(7969).unwrap();
                info!("Sender socket bound to port 7969");
            }

            let data = b"Hello from sender!";
            match socket1.send_slice(data, (tap2_ip, 7979)) {
                Ok(_) => info!("Sent data to {}:{}", tap2_ip, 7979),
                Err(e) => error!("Failed to send data: {}", e),
            }
            
            if let Err(e) = phy_wait(fd1, iface1.poll_delay(timestamp1, &sockets1)) {
                error!("Sender wait error: {}", e);
            }
        }

        thread::sleep(Duration::from_millis(100));

        let timestamp2 = Instant::now();

        // 处理接收
        {
            let mut device2 = tap2.write().unwrap();
            iface2.poll(timestamp2, &mut *device2, &mut sockets2);

            let socket2 = sockets2.get_mut::<udp::Socket>(udp_handle2);
            if !socket2.is_open() {
                socket2.bind(7979).unwrap();
                info!("Receiver socket bound to port 7979");
            }

            let client = match socket2.recv() {
                Ok((data, endpoint)) => {
                    debug!("udp: recv data: {:?} from {}", data, endpoint);
                    let mut data = data.to_vec();
                    data.reverse();
                    Some((endpoint, data))
                }
                Err(_) => None,
            };

            if let Some((endpoint, data)) = client {
                debug!("udp: send data: {:?} to {}", data, endpoint,);
                socket2.send_slice(&data, endpoint).unwrap();
            }

            if let Err(e) = phy_wait(fd2, iface2.poll_delay(timestamp2, &sockets2)) {
                error!("Receiver wait error: {}", e);
            }
        }

        println!("tttt8");

        thread::sleep(Duration::from_millis(100));
    }
}