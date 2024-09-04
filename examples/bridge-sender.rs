mod utils;
mod bridge_config;

use log::{error, info};
use bridge_config::NETWORK_MANAGER;
use std::{io, thread, time::Duration};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{wait as phy_wait, Medium};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

fn main() -> io::Result<()> {
    utils::setup_logging("");

    let tap1_ip = Ipv4Address::new(192, 168, 69, 8);
    let peer_ip = Ipv4Address::new(192, 168, 69, 9);

    let tap1 = NETWORK_MANAGER.lock().unwrap().get_or_create_device("tap1", Medium::Ethernet).unwrap();
    let fd = NETWORK_MANAGER.lock().unwrap().get_device_fd("tap1").unwrap();

    // Create interface
    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]).into());
    config.random_seed = rand::random();

    info!("Created {} interface", "tap1");

    let mut device_guard = tap1.lock().unwrap();
    let mut iface = Interface::new(config, &mut *device_guard, Instant::now());

    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::v4(tap1_ip.0[0], tap1_ip.0[1], tap1_ip.0[2], tap1_ip.0[3]), 24)).unwrap();
    });
    iface.neighbor_cache_mut().fill(IpAddress::v4(192, 168, 69, 9), EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x04]).into(), Instant::now());

    info!("Created interface with IP: {}", tap1_ip);

    let mut sockets = SocketSet::new(vec![]);
    
    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_handle = sockets.add(udp_socket);

    drop(device_guard);

    loop {
        let timestamp = Instant::now();

        let mut device_guard = tap1.lock().unwrap();
        iface.poll(timestamp, &mut *device_guard, &mut sockets);
        drop(device_guard);

        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(7969).unwrap();
            info!("Sender socket bound to port {}", 7969);
        }

        // Send data
        let data = b"Hello from sender!";
        match socket.send_slice(data, (peer_ip, 7979)) {
            Ok(_) => {
                info!("Sent data to {}:{}", peer_ip, 7979);
            }
            Err(e) => {
                error!("Failed to send data: {}", e);
            }
        }

        match phy_wait(fd, iface.poll_delay(timestamp, &sockets)) {
            Ok(_) => {}
            Err(e) => error!("Sender wait error: {}", e),
        }

        thread::sleep(Duration::from_secs(1));
    }
}