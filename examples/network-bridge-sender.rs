mod config;

use std::time::Duration;
use std::thread;

use smoltcp::wire::{EthernetFrame, EthernetProtocol, Ipv4Address, Ipv4Packet, UdpPacket};
use config::{BRIDGE, get_port1_mac, get_port2_mac};

fn sender() {
    println!("Sender initialized");

    let messages = vec![
        "Hello from Device 1!",
        "More data from Device 1",
        "Final message from Device 1",
    ];

    for (i, message) in messages.iter().enumerate() {
        println!("\nTransmitting message {}: {}", i + 1, message);

        let mut buffer_vec = vec![0u8; 64 + message.len()];
        let buffer = buffer_vec.as_mut_slice();
        let mut frame = EthernetFrame::new_unchecked(buffer);
        frame.set_src_addr(get_port1_mac());
        frame.set_dst_addr(get_port2_mac());
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
            Ok(_) => {
                println!("Frame processed successfully");
            },
            Err(e) => println!("Error processing frame: {}", e),
        }
        drop(bridge);

        thread::sleep(Duration::from_secs(1));
    }

    println!("\nSender simulation completed");
}

fn main() {
    thread::sleep(Duration::from_secs(5));  // Give time for receiver to start
    sender();
}