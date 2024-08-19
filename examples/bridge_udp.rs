use std::sync::{Arc, Mutex};
use std::thread;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::udp::{PacketMetadata, Socket, PacketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::global_bridge::{add_port, initialize_bridge, GlobalBridgeInner, GLOBAL_BRIDGE};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

pub const BRIDGE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const PORT1_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
pub const PORT2_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
pub const MAX_PORTS: u8 = 2;

// pub const SENDER_IP: Ipv4Address = Ipv4Address::new(192, 168, 0, 1);
// pub const RECEIVER_IP: Ipv4Address = Ipv4Address::new(192, 168, 0, 2);
// pub const SENDER_PORT: u16 = 12345;
// pub const RECEIVER_PORT: u16 = 54321;

pub fn get_bridge_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&BRIDGE_MAC)
}

pub fn get_port1_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT1_MAC)
}

pub fn get_port2_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT2_MAC)
}

fn buffer(packets: usize) -> PacketBuffer<'static> {
    PacketBuffer::new(
        (0..packets)
            .map(|_| PacketMetadata::EMPTY)
            .collect::<Vec<_>>(),
        vec![0; 16 * packets],
    )
}

// Global bridge variable
fn config() {
    let time = Instant::now();
    let mut device1 = Loopback::new(Medium::Ethernet);
    let mut device2 = Loopback::new(Medium::Ethernet);

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));

    let iface1 = Interface::new(config1, &mut device1, time);
    let iface2 = Interface::new(config2, &mut device2, time);

    let config = Config::new(HardwareAddress::Ethernet(get_bridge_mac()));

    // 初始化网桥
    initialize_bridge(
        Interface::new(config, &mut Loopback::new(Medium::Ethernet), time),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        2 // 最大端口数
    ).unwrap();

    // 添加端口到网桥
    add_port(iface1, device1, 1).expect("Failed to add port 1");
    add_port(iface2, device2, 2).expect("Failed to add port 2");

    let bridge_guard = GLOBAL_BRIDGE.write().expect("Failed to get bridge");
    if let Some(bridge) = bridge_guard.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let mut bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]), 1)
                .expect("Failed to add static FDB entry 1");
            println!("Added static FDB entry: 02:00:00:00:00:01 -> Port 1");

            bridge_lock.fdb_add(&EthernetAddress::from_bytes(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), 2)
                .expect("Failed to add static FDB entry 2");
            println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 2");
        }
    }
}

fn main() {
    config();

    let time = Instant::now();
    let mut device = Loopback::new(Medium::Ethernet);
    let config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
    let mut iface = Interface::new(config, &mut device, time);
    
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24))
            .unwrap();
        // ip_addrs
        //     .push(IpCidr::new(IpAddress::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64))
        //     .unwrap();
        // ip_addrs
        //     .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64))
        //     .unwrap();
    });
    // 为网络接口添加一条默认的 IPv4 路由。
    // 默认路由：默认路由用于处理那些没有明确匹配路由表中其他条目的流量。
    // 例如，如果数据包的目标 IP 地址不在本地网络上，网络堆栈会将数据包发送到默认路由指定的网关，这样网关可以将数据包转发到其他网络（通常是互联网）。
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(192, 168, 69, 100))
        .unwrap();
    iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100))
        .unwrap();

    iface.neighbor_cache_mut().fill(
        IpAddress::v4(192, 168, 69, 100),
        EthernetAddress([0x02, 0xbc, 0xea, 0x14, 0xc9, 0xbf]).into(),
        Instant::now()
    );

    let rx_buffer = buffer(64);
    let tx_buffer = buffer(64);   
    let udp_socket = Socket::new(rx_buffer, tx_buffer);

    let mut sockets = SocketSet::new(vec![]);
    let udp_handle = sockets.add(udp_socket);

    let socket = sockets.get_mut::<Socket>(udp_handle);
    socket.bind(24).expect("Failed to bind UDP socket");

    let iface = Arc::new(Mutex::new(iface));
    let device = Arc::new(Mutex::new(device));
    let sockets = Arc::new(Mutex::new(sockets));

    // 配置和监听线程
    let iface_clone = Arc::clone(&iface);
    let device_clone = Arc::clone(&device);
    let sockets_clone = Arc::clone(&sockets);
    let listen_thread = thread::spawn(move || {
        loop {
            let timestamp = Instant::now();
            let mut iface = iface_clone.lock().unwrap();
            let mut device = device_clone.lock().unwrap();
            let mut sockets = sockets_clone.lock().unwrap();
            
            let flags = iface.poll(timestamp, &mut *device, &mut *sockets);
            println!("Flags: {:?}", flags);

            let socket = sockets.get_mut::<Socket>(udp_handle);
            if socket.can_recv() {
                match socket.recv() {
                    Ok((data, endpoint)) => {
                        println!("Received data: {:?} from {}", data, endpoint);
                    }
                    Err(e) => {
                        println!("Error receiving data: {:?}", e);
                    }
                }
            }

            drop(iface);
            drop(device);
            drop(sockets);
            thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    // 发送数据线程
    let _iface_clone = Arc::clone(&iface);
    let sockets_clone = Arc::clone(&sockets);
    let send_thread = thread::spawn(move || {
        let mut send_timer = Instant::now();
        loop {
            let timestamp = Instant::now();
            if timestamp - send_timer >= smoltcp::time::Duration::from_secs(1) {
                send_timer = timestamp;
                let endpoint = (IpAddress::v4(192, 168, 1, 100), 1234);
                
                let mut sockets = sockets_clone.lock().unwrap();
                let socket = sockets.get_mut::<Socket>(udp_handle);
                
                if socket.can_send() {
                    match socket.send_slice(b"Hello, world!", endpoint) {
                        Ok(_) => println!("Sent data successfully"),
                        Err(e) => println!("Error sending data: {:?}", e),
                    }
                }
                drop(sockets);
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    listen_thread.join().unwrap();
    send_thread.join().unwrap();
}