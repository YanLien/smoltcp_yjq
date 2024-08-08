mod config;

use std::time::Duration;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use smoltcp::wire::{EthernetFrame, Ipv4Packet, UdpPacket, Ipv4Address};
use config::BRIDGE;

fn receiver(running: Arc<AtomicBool>) {
    println!("Receiver initialized");

    while running.load(Ordering::Relaxed) {
        let bridge = BRIDGE.lock().unwrap();
        
        if let Some((port, frame_data)) = bridge.receive_frame() {
            println!("Received frame at Port {}", port + 1);
    
            if let Ok(eth_frame) = EthernetFrame::new_checked(&frame_data) {
                let ip_payload = eth_frame.payload();
                match Ipv4Packet::new_checked(ip_payload) {
                    Ok(ip_packet) => {
                        if ip_packet.dst_addr() == Ipv4Address::new(192, 168, 0, 2) {
                            match UdpPacket::new_checked(ip_packet.payload()) {
                                Ok(udp_packet) => {
                                    if udp_packet.dst_port() == 54321 {
                                        match std::str::from_utf8(udp_packet.payload()) {
                                            Ok(received_message) => {
                                                println!("Received message: {}", received_message);
                                            },
                                            Err(_) => {
                                                println!("Error: Unable to decode message as UTF-8");
                                            }
                                        }
                                    }
                                },
                                Err(_) => {
                                    println!("Error: Invalid UDP packet");
                                }
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
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let receiver_thread = thread::spawn(move || {
        receiver(running_clone);
    });

    // Run for 30 seconds
    thread::sleep(Duration::from_secs(30));

    // Stop the receiver
    running.store(false, Ordering::Relaxed);

    receiver_thread.join().unwrap();

    println!("Receiver simulation completed");
}