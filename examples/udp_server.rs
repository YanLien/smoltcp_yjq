mod utils;

use log::debug;
use std::sync::Arc;
use std::os::unix::io::AsRawFd;
use smoltcp::wire::bridge_device::{DeviceWrapper, NetworkManager};
use smoltcp::wire::global_bridge::{add_port, initialize_bridge, GLOBAL_BRIDGE};

use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{wait as phy_wait, Loopback, Medium, TunTapInterface};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

pub const BRIDGE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
// phy::TunTapInterface: tap0
pub const PORT1_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
// phy::TunTapInterface: tap1
pub const PORT2_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
// phy::TunTapInterface: tap2
pub const PORT3_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
// phy::Loopback
pub const PORT4_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x05];
// phy::Loopback
pub const PORT5_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x06];
// Bridge Max Ports
pub const MAX_PORTS: u8 = 8;


pub fn get_bridge_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&BRIDGE_MAC)
}

pub fn get_port1_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT1_MAC)
}

pub fn get_port2_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT2_MAC)
}

pub fn get_port3_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT3_MAC)
}

pub fn get_port4_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT4_MAC)
}

pub fn get_port5_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT5_MAC)
}

fn main() {
    utils::setup_logging("");
    
    println!("init bridge");
    let time = smoltcp::time::Instant::now();
    let mut network_manager = NetworkManager::new();
    // 获取或创建设备
    let tap0 = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let tap1 = TunTapInterface::new("tap1", Medium::Ethernet).unwrap();
    let tap2 = TunTapInterface::new("tap2", Medium::Ethernet).unwrap();

    let fd = tap0.as_raw_fd();

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));
    let config3 = Config::new(HardwareAddress::Ethernet(get_port3_mac()));

    let device1 = network_manager.get_or_create_device("tap0", tap0);
    let device2 = network_manager.get_or_create_device("tap1", tap1);
    let device3 = network_manager.get_or_create_device("tap2", tap2);
        
    // 创建 DeviceWrapper 实例和接口
    let (_tap0, iface1) = {
        let device = device1.lock().unwrap();
        let mut wrapper = DeviceWrapper::new(Arc::clone(&device.inner));
        let iface = Interface::new(config1, &mut wrapper, time);
        (wrapper, iface)
    };

    let (_tap1, iface2) = {
        let device = device2.lock().unwrap();
        let mut wrapper = DeviceWrapper::new(Arc::clone(&device.inner));
        let iface = Interface::new(config2, &mut wrapper, time);
        (wrapper, iface)
    };

    let (_tap2, iface3) = {
        let device = device3.lock().unwrap();
        let mut wrapper = DeviceWrapper::new(Arc::clone(&device.inner));
        let iface = Interface::new(config3, &mut wrapper, time);
        (wrapper, iface)
    };

    // 初始化网桥
    initialize_bridge(
        Interface::new(
            Config::new(HardwareAddress::Ethernet(get_bridge_mac())), 
            &mut Loopback::new(Medium::Ethernet), 
            time),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        MAX_PORTS // 最大端口数
    ).unwrap();

    add_port(iface1, Arc::clone(&device1), 0).expect("Failed to add port 1");
    add_port(iface2, Arc::clone(&device2), 1).expect("Failed to add port 2");
    add_port(iface3, Arc::clone(&device3), 2).expect("Failed to add port 3");

    let mut bridge_guard = GLOBAL_BRIDGE.lock().expect("Failed to get bridge");
    if let Some(bridge_lock) = bridge_guard.as_mut() {
        bridge_lock.fdb_add(&get_port1_mac(), 1)
            .expect("Failed to add static FDB entry 1");
        println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 1");

        bridge_lock.fdb_add(&get_port2_mac(), 2)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:03 -> Port 2");
        
        bridge_lock.fdb_add(&get_port3_mac(), 3)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 3");
    }
    drop(bridge_guard);

    // Create interface
    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).into());

    config.random_seed = rand::random();

    let mut tap0 = {
        let device = device1.lock().unwrap();
        DeviceWrapper::new(Arc::clone(&device.inner))
    };

    let mut iface = Interface::new(config, &mut tap0, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24))
            .unwrap();
        ip_addrs
            .push(IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64))
            .unwrap();
    });

    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 2))
        .unwrap();
    iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100))
        .unwrap();

    // Create sockets
    let udp_rx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
        vec![0; 65535],
    );
    let udp_tx_buffer = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY, udp::PacketMetadata::EMPTY],
        vec![0; 65535],
    );
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);

    loop {
        let timestamp = Instant::now();

        iface.poll(timestamp, &mut tap0, &mut sockets);

        // udp:6969: respond "hello"
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(6969).unwrap()
        }

        let client = match socket.recv() {
            Ok((data, endpoint)) => {
                debug!("udp:6969 recv data: {:?} from {}", data, endpoint);
                let mut data = data.to_vec();
                data.reverse();
                Some((endpoint, data))
            }
            Err(_) => None,
        };
        if let Some((endpoint, data)) = client {
            debug!("udp:6969 send data: {:?} to {}", data, endpoint,);
            socket.send_slice(&data, endpoint).unwrap();
        }

        phy_wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
}