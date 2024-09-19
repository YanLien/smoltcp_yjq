mod utils;
mod bridge_config;

use log::debug;
use std::os::unix::io::AsRawFd;
use smoltcp::wire::bridge_device::BridgeDevice;
use smoltcp::wire::global_bridge::{add_port, initialize_bridge, GLOBAL_BRIDGE};
use crate::bridge_config::{MAX_PORTS, get_bridge_mac, get_port3_mac, get_port2_mac, get_port1_mac};

use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::iface::{Config, SocketSet};
use smoltcp::phy::{wait as phy_wait, Loopback, Medium, TunTapInterface};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

fn main() {
    utils::setup_logging("");
    
    println!("init bridge");

    // 获取或创建设备
    let tap0 = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let fd = tap0.as_raw_fd();
    let device1 = BridgeDevice::new(tap0);

    let tap1 = TunTapInterface::new("tap1", Medium::Ethernet).unwrap();
    let device2 = BridgeDevice::new(tap1);

    let tap2 = TunTapInterface::new("tap2", Medium::Ethernet).unwrap();
    let device3 = BridgeDevice::new(tap2);

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));
    let config3 = Config::new(HardwareAddress::Ethernet(get_port3_mac()));

    // 初始化网桥
    initialize_bridge(
        Config::new(HardwareAddress::Ethernet(get_bridge_mac())),
        Loopback::new(Medium::Ethernet), 
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        MAX_PORTS, // 最大端口数
        Instant::now(),
    ).unwrap();

    add_port(config1, device1, 0, Instant::now()).expect("Failed to add port 0");
    add_port(config2, device2, 1, Instant::now()).expect("Failed to add port 1");
    add_port(config3, device3, 2, Instant::now()).expect("Failed to add port 2");

    let mut bridge_guard = GLOBAL_BRIDGE.lock();
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

    // Get interface
    let bridge_guard = GLOBAL_BRIDGE.lock();
    let bridge = bridge_guard.as_ref().expect("Failed to get bridge");

    let mut bridge = bridge.get_bridgeport(0).unwrap();

    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).into());
    config.random_seed = rand::random();

    bridge.add_config(config);

    let mut iface = bridge.create_interface(Instant::now());

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

    drop(bridge_guard);

    loop {
        let timestamp = Instant::now();

        let mut device = bridge.port_device.lock();
        let bridge_device = BridgeDevice::as_mut_bridge_device(&mut device.inner);
        
        iface.poll(timestamp, bridge_device, &mut sockets);

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