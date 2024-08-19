mod utils;
mod bridge_config;

use log::{debug, error, info};
use bridge_config::init_bridge;
use bridge_config::NETWORK_MANAGER;
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

    init_bridge();

    // let tap1_ip = Ipv4Address::new(192, 168, 69, 8);
    let tap2_ip = Ipv4Address::new(192, 168, 69, 9);

    let tap2 = NETWORK_MANAGER.lock().unwrap()
        .get_or_create_device("tap2", Medium::Ethernet).unwrap();
    let fd = NETWORK_MANAGER.lock().unwrap()
        .get_device_fd("tap2").unwrap();

    // Create interface
    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x04]).into());

    config.random_seed = rand::random();

    let mut device_guard = tap2.write().unwrap();
    let mut iface = Interface::new(config, &mut *device_guard, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::v4(tap2_ip.0[0], tap2_ip.0[1], tap2_ip.0[2], tap2_ip.0[3]), 24)).unwrap();
    });
    iface.neighbor_cache_mut().fill(IpAddress::v4(192, 168, 69, 8), EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]).into(), Instant::now());

    info!("Created interface with IP: {}", tap2_ip);

    let mut sockets = SocketSet::new(vec![]);
    
    let udp_rx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_tx_buffer = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65535]);
    let udp_socket = udp::Socket::new(udp_rx_buffer, udp_tx_buffer);
    let udp_handle = sockets.add(udp_socket);

    drop(device_guard);

    loop {
        let timestamp = Instant::now();

        let mut device_guard = tap2.write().unwrap();
        iface.poll(timestamp, &mut *device_guard, &mut sockets);
        drop(device_guard);

        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(7979).unwrap();
            info!("Receiver socket bound to port {}", 7979);
        }

        let client = match socket.recv() {
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
            socket.send_slice(&data, endpoint).unwrap();
        }

        match phy_wait(fd, iface.poll_delay(timestamp, &sockets)) {
            Ok(_) => {}
            Err(e) => error!("Receiver wait error: {}", e),
        }

        thread::sleep(Duration::from_millis(100));
    }
}