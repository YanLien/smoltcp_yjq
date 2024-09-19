mod utils;
mod bridge_config;

use bridge_config::{get_bridge_mac, get_port5_mac};
use bridge_config::{get_port1_mac, get_port2_mac, get_port3_mac, get_port4_mac};
use bridge_config::MAX_PORTS;
use log::{debug, error, info};
use smoltcp::phy::Loopback;
use smoltcp::phy::TunTapInterface;
use smoltcp::wire::bridge_device::BridgeDevice;
use smoltcp::wire::global_bridge::add_port;
use smoltcp::wire::global_bridge::initialize_bridge;
use smoltcp::wire::global_bridge::GLOBAL_BRIDGE;
use smoltcp::wire::HardwareAddress;
use std::io;
use std::thread;
use std::time::Duration;
use std::os::unix::io::AsRawFd;
use smoltcp::iface::{Config, SocketSet};
use smoltcp::phy::{wait as phy_wait, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

fn main() -> io::Result<()> {
    utils::setup_logging("");
    println!("init bridge");

    let tap0 = TunTapInterface::new("tap0", Medium::Ethernet).unwrap();
    let device1 = BridgeDevice::new(tap0);
    let tap1 = TunTapInterface::new("tap1", Medium::Ethernet).unwrap();
    let fd1 = tap1.as_raw_fd();
    let device2 = BridgeDevice::new(tap1);
    let tap2 = TunTapInterface::new("tap2", Medium::Ethernet).unwrap();
    let fd2 = tap2.as_raw_fd();
    let device3 = BridgeDevice::new(tap2);
    let loop1 = Loopback::new(Medium::Ethernet);
    let device4 = BridgeDevice::new(loop1);
    let loop2 = Loopback::new(Medium::Ethernet);
    let device5 = BridgeDevice::new(loop2);

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));
    let config3 = Config::new(HardwareAddress::Ethernet(get_port3_mac()));
    let config4 = Config::new(HardwareAddress::Ethernet(get_port4_mac()));
    let config5 = Config::new(HardwareAddress::Ethernet(get_port5_mac()));
    
    let config = Config::new(HardwareAddress::Ethernet(get_bridge_mac()));

    // 初始化网桥
    initialize_bridge(
        config, 
        Loopback::new(Medium::Ethernet),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        MAX_PORTS, // 最大端口数
        Instant::now(),
    ).unwrap();

    // 添加端口到网桥
    add_port(config1, device1, 0, Instant::now()).expect("Failed to add port 0");
    add_port(config2, device2, 1, Instant::now()).expect("Failed to add port 1");
    add_port(config3, device3, 2, Instant::now()).expect("Failed to add port 2");
    add_port(config4, device4, 3, Instant::now()).expect("Failed to add port 3");
    add_port(config5, device5, 4, Instant::now()).expect("Failed to add port 4");

    let mut bridge_guard = GLOBAL_BRIDGE.lock();
    if let Some(bridge_lock) = bridge_guard.as_mut() {
        bridge_lock.fdb_add(&get_port1_mac(), 0)
            .expect("Failed to add static FDB entry 0");
        println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 0");

        bridge_lock.fdb_add(&get_port2_mac(), 1)
            .expect("Failed to add static FDB entry 1");
        println!("Added static FDB entry: 02:00:00:00:00:03 -> Port 1");
        
        bridge_lock.fdb_add(&get_port3_mac(), 2)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 2");

        bridge_lock.fdb_add(&get_port4_mac(), 3)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 2");

        bridge_lock.fdb_add(&get_port5_mac(), 4)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 2");
    }

    drop(bridge_guard);

    let tap1_ip = Ipv4Address::new(192, 168, 69, 8);
    let tap2_ip = Ipv4Address::new(192, 168, 69, 9);

    let handle = thread::spawn(move || {
        alternating_thread(tap1_ip, tap2_ip, fd1, fd2);
    });

    handle.join().unwrap();

    Ok(())
}

fn alternating_thread(tap1_ip: Ipv4Address, tap2_ip: Ipv4Address, fd1: i32, fd2: i32) {

    // Get interface
    let bridge_guard = GLOBAL_BRIDGE.lock();
    let bridge = bridge_guard.as_ref().expect("Failed to get bridge");
    
    let mut tap1 = bridge.get_bridgeport(1).unwrap();
    let mut tap2 = bridge.get_bridgeport(2).unwrap();

    drop(bridge_guard);

    let mut iface1 = tap1.create_interface(Instant::now());
    iface1.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::from(tap1_ip), 24)).unwrap();
    });

    let mut iface2 = tap2.create_interface(Instant::now());
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

    loop {
        let timestamp1 = Instant::now();
        // 处理发送
        {    
            let mut device1 = tap1.port_device.lock();
            let bridge_device1 = BridgeDevice::as_mut_bridge_device(&mut device1.inner);
            
            iface1.poll(timestamp1, bridge_device1, &mut sockets1);

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
            let mut device2 = tap2.port_device.lock();
            let bridge_device2 = BridgeDevice::as_mut_bridge_device(&mut device2.inner);
            
            iface2.poll(timestamp2, bridge_device2, &mut sockets2);

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

        thread::sleep(Duration::from_millis(100));
    }
}