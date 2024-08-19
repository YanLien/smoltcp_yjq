use std::sync::Mutex;
use std::time::Duration;
use std::thread;

use smoltcp::iface::{Config, Interface};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::bridge::BridgeWrapper;
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Ipv4Address, Ipv4Packet, UdpPacket};

pub const BRIDGE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const PORT1_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
pub const PORT2_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
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

// Global bridge variable
lazy_static::lazy_static! {
    static ref BRIDGE: Mutex<BridgeWrapper> = {
        let time = Instant::now();
        let mut device1 = Loopback::new(Medium::Ethernet);
        let mut device2 = Loopback::new(Medium::Ethernet);

        let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
        let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));

        let iface1 = Interface::new(config1, &mut device1, time);
        let iface2 = Interface::new(config2, &mut device2, time);

        let bridge_config = Config::new(HardwareAddress::Ethernet(get_bridge_mac()));

        let bridge = BridgeWrapper::new(
            Interface::new(bridge_config, &mut Loopback::new(Medium::Ethernet), time),
            get_bridge_mac(),
            MAX_PORTS
        );

        bridge.add_port(iface1, device1, 1).expect("Failed to add port 1");
        bridge.add_port(iface2, device2, 2).expect("Failed to add port 2");

        let bridge_arc = bridge.get_bridge();
        let bridge_inner = bridge_arc.lock().unwrap();
        
        bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]), 1)
            .expect("Failed to add static FDB entry 1");
        bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]), 2)
            .expect("Failed to add static FDB entry 2");

        Mutex::new(bridge)
    };
}

fn sender_thread() {
    let messages = vec![
        "Hello from Device 1!",
        "More data from Device 1",
        "Final message from Device 1",
    ];

    for (i, message) in messages.iter().enumerate() {
        println!("\nTransmitting message {}: {}", i + 1, message);

        let src_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let dst_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

        let mut buffer_vec = vec![0u8; 64 + message.len()];
        let buffer = buffer_vec.as_mut_slice();
        let mut frame = EthernetFrame::new_unchecked(buffer);
        frame.set_src_addr(src_mac);
        frame.set_dst_addr(dst_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);

        let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip_packet.set_version(4);
        ip_packet.set_header_len(20);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_len((20 + 8 + message.len()) as u16);
        ip_packet.set_ident(0);
        ip_packet.set_src_addr(Ipv4Address::new(192, 168, 0, 1));
        ip_packet.set_dst_addr(Ipv4Address::new(192, 168, 0, 2));
        let checksum = ip_packet.checksum();
        ip_packet.set_checksum(checksum);

        let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
        udp_packet.set_src_port(12345);
        udp_packet.set_dst_port(54321);
        udp_packet.set_len((8 + message.len()) as u16);
        udp_packet.set_checksum(0);

        let udp_payload = udp_packet.payload_mut();
        udp_payload[..message.len()].copy_from_slice(message.as_bytes());

        let bridge = BRIDGE.lock().unwrap();
        let iframe = EthernetFrame::new_unchecked(frame.as_ref());
        match bridge.process_frame(&iframe, 0) {
            Ok(_) => println!("Frame processed successfully"),
            Err(e) => println!("Error processing frame: {}", e),
        }

        thread::sleep(Duration::from_millis(100));
    }

    println!("\nSender simulation completed");
}

fn receiver_thread() {
    loop {
        let bridge = BRIDGE.lock().unwrap();
        
        if let Some((port, frame_data)) = bridge.receive_frame() {
            println!("Received frame at Port {}", port + 1);
    
            if let Ok(eth_frame) = EthernetFrame::new_checked(&frame_data) {
                let ip_payload = eth_frame.payload();
                match Ipv4Packet::new_checked(ip_payload) {
                    Ok(ip_packet) => {
                        match UdpPacket::new_checked(ip_packet.payload()) {
                            Ok(udp_packet) => {
                                match std::str::from_utf8(udp_packet.payload()) {
                                    Ok(received_message) => {
                                        println!("Received message: {}", received_message);
                                    },
                                    Err(_) => {
                                        println!("Error: Unable to decode message as UTF-8");
                                    }
                                }
                            },
                            Err(_) => {
                                println!("Error: Invalid UDP packet");
                            }
                        }
                    },
                    Err(_) => {
                        println!("Error: Invalid IP packet");
                    }
                }
            } else {
                println!("Error: Invalid Ethernet frame");
            }
        }

        drop(bridge);  // Release the lock
        thread::sleep(Duration::from_millis(10));
    }
}

fn main() {
    println!("Bridge initialized with 2 ports");
    println!("Added static FDB entries");

    let sender = thread::spawn(sender_thread);
    let receiver = thread::spawn(receiver_thread);

    receiver.join().unwrap();
    sender.join().unwrap();
}