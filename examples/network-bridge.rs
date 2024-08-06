// use smoltcp::iface::{Config, Interface};
// use smoltcp::phy::{Loopback, Medium};
// use smoltcp::time::Instant;
// use smoltcp::wire::bridge::BridgeWrapper;
// use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Ipv4Address, Ipv4Packet, UdpPacket};
// use std::sync::{Arc, Mutex};
// use std::thread;
// use std::time::Duration;

// fn main() {
//     let time = Instant::now();
//     // 创建两个虚拟网络设备
//     let mut device1 = Loopback::new(Medium::Ethernet);
//     let mut device2 = Loopback::new(Medium::Ethernet);

//     let config1 = Config::new(HardwareAddress::Ethernet(
//         EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
//     ));

//     let config2 = Config::new(HardwareAddress::Ethernet(
//         EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
//     ));

//     // 创建对应的网络接口
//     let iface1 = Interface::new(config1, &mut device1, time);
//     let iface2 = Interface::new(config2, &mut device2, time);

//     let config = Config::new(HardwareAddress::Ethernet(
//         EthernetAddress::from_bytes(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])
//     ));

//     // 初始化网桥
//     let bridge = BridgeWrapper::new(
//         Interface::new(config, &mut Loopback::new(Medium::Ethernet), time),
//         EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
//         2 // 最大端口数
//     );

//     // 添加端口到网桥
//     bridge.add_port(iface1, device1).expect("Failed to add port 1");
//     bridge.add_port(iface2, device2).expect("Failed to add port 2");

//     println!("Bridge initialized with 2 ports");

//     // 添加静态转发表项
//     {
//         let bridge_arc = bridge.get_bridge();
//         let bridge_inner = bridge_arc.lock().unwrap();
        
//         bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]), 1)
//             .expect("Failed to add static FDB entry 1");
//         bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]), 2)
//             .expect("Failed to add static FDB entry 2");
//     }

//     // 创建一个克隆的Arc<BridgeWrapper>用于接收线程
//     let bridge_clone: Arc<BridgeWrapper<Loopback>> = Arc::clone(&bridge);

//     // 启动接收线程
//     let receiver_handle = thread::spawn(move || {
//         loop {
//             if let Some((port, frame_data)) = bridge_clone.receive_frame() {
//                 println!("Received frame on port {}", port);

//                 if let Ok(eth_frame) = EthernetFrame::new_checked(&frame_data) {
//                     let src_addr = eth_frame.src_addr();
//                     let dst_addr = eth_frame.dst_addr();
//                     println!("From: {:?}, To: {:?}", src_addr, dst_addr);

//                     if let Ok(ip_packet) = Ipv4Packet::new_checked(eth_frame.payload()) {
//                         if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
//                             let payload = udp_packet.payload();
//                             if let Ok(message) = std::str::from_utf8(payload) {
//                                 println!("Received message: {}", message);
//                             }
//                         }
//                     }
//                 }
//             } else {
//                 thread::sleep(Duration::from_millis(10));
//             }
//         }
//     });

//     // 模拟数据传输
//     let messages = vec![
//         "Hello from Device 1!",
//         "More data from Device 1",
//         "Final message from Device 1",
//     ];

//     for (i, message) in messages.iter().enumerate() {
//         println!("\nTransmitting message {}: {}", i + 1, message);

//         // 确定源和目的MAC地址
//         let (src_mac, dst_mac) = if i % 2 == 0 {
//             (EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
//             EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
//         } else {
//             (EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
//             EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
//         };

//         // 创建以太网帧
//         let mut buffer = vec![0u8; 64 + message.len()]; // 假设最大帧大小为64字节 + 消息长度
//         let mut frame = EthernetFrame::new_unchecked(&mut buffer);
//         frame.set_src_addr(src_mac);
//         frame.set_dst_addr(dst_mac);
//         frame.set_ethertype(EthernetProtocol::Ipv4);

//         // 构造 IPv4 数据包
//         let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
//         ip_packet.set_version(4);
//         ip_packet.set_header_len(20); // 5 * 4 = 20 bytes
//         ip_packet.set_dscp(0);
//         ip_packet.set_ecn(0);
//         ip_packet.set_total_len((20 + 8 + message.len()) as u16); // IP header + UDP header + message
//         ip_packet.set_ident(0);
//         ip_packet.set_src_addr(Ipv4Address::new(192, 168, 0, 1));
//         ip_packet.set_dst_addr(Ipv4Address::new(192, 168, 0, 2));
//         let checksum = ip_packet.checksum();
//         ip_packet.set_checksum(checksum);

//         // 构造 UDP 数据包
//         let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
//         udp_packet.set_src_port(12345);
//         udp_packet.set_dst_port(54321);
//         udp_packet.set_len((8 + message.len()) as u16);
//         udp_packet.set_checksum(0); // UDP校验和是可选的，这里设置为0

//         // 添加消息数据
//         let udp_payload = udp_packet.payload_mut();
//         udp_payload[..message.len()].copy_from_slice(message.as_bytes());

//         // 处理帧
//         match bridge.process_frame(&frame, 0) {
//             Ok(_) => println!("Frame processed successfully"),
//             Err(e) => println!("Error processing frame: {}", e),
//         }

//         // 模拟FDB老化
//         if i % 2 == 1 {
//             bridge.age_fdb();
//             println!("FDB aged");
//         }

//         // 模拟网络延迟
//         thread::sleep(Duration::from_millis(100));
//     }

//     println!("\nSender simulation completed");

//     // 等待接收线程一段时间后退出
//     thread::sleep(Duration::from_secs(2));
//     // 这里应该有一种方法来优雅地停止接收线程，比如使用 atomic flag
// }

use std::time::Duration;
use smoltcp::iface::{Config, Interface};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::bridge::BridgeWrapper;
use smoltcp::wire::{EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Ipv4Address, Ipv4Packet, UdpPacket};

fn main() {
    let time = Instant::now();
    // 创建两个虚拟网络设备
    let mut device1 = Loopback::new(Medium::Ethernet);
    let mut device2 = Loopback::new(Medium::Ethernet);

    let config1 = Config::new(HardwareAddress::Ethernet(
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    ));

    let config2 = Config::new(HardwareAddress::Ethernet(
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
    ));

    // 创建对应的网络接口
    let iface1 = Interface::new(config1, &mut device1, time);
    let iface2 = Interface::new(config2, &mut device2, time);

    let config = Config::new(HardwareAddress::Ethernet(
        EthernetAddress::from_bytes(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])
    ));

    // 初始化网桥
    let bridge = BridgeWrapper::new(
        Interface::new(config, &mut Loopback::new(Medium::Ethernet), time),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        2 // 最大端口数
    );

    // // 添加端口到网桥
    // bridge.add_port(iface1, device1).expect("Failed to add port 1");
    // bridge.add_port(iface2, device2).expect("Failed to add port 2");

    // 添加端口到网桥
    bridge.add_port(iface1, device1, 1).expect("Failed to add port 1");
    bridge.add_port(iface2, device2, 2).expect("Failed to add port 2");

    println!("Bridge initialized with 2 ports");

    // 添加静态转发表项
    {
        let bridge_arc = bridge.get_bridge();
        let bridge_inner = bridge_arc.lock().unwrap();
        
        bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]), 1)
            .expect("Failed to add static FDB entry 1");
        bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]), 2)
            .expect("Failed to add static FDB entry 2");
    }

    let messages = vec![
        "Hello from Device 1!",
        "More data from Device 1",
        "Final message from Device 1",
    ];

    for (i, message) in messages.iter().enumerate() {
        println!("\nTransmitting message {}: {}", i + 1, message);

        // 构造和发送帧
        let src_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let dst_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

        let mut buffer = vec![0u8; 64 + message.len()];
        let mut frame = EthernetFrame::new_unchecked(&mut buffer);
        frame.set_src_addr(src_mac);
        frame.set_dst_addr(dst_mac);
        frame.set_ethertype(EthernetProtocol::Ipv4);
    
        // 构造 IPv4 数据包
        let mut ip_packet = Ipv4Packet::new_unchecked(frame.payload_mut());
        ip_packet.set_version(4);
        ip_packet.set_header_len(20); // 5 * 4 = 20 bytes
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_len((20 + 8 + message.len()) as u16); // IP header + UDP header + message
        ip_packet.set_ident(0);
        ip_packet.set_src_addr(Ipv4Address::new(192, 168, 0, 1));
        ip_packet.set_dst_addr(Ipv4Address::new(192, 168, 0, 2));
        let checksum = ip_packet.checksum();
        ip_packet.set_checksum(checksum);
    
        // 构造 UDP 数据包
        let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
        udp_packet.set_src_port(12345);
        udp_packet.set_dst_port(54321);
        udp_packet.set_len((8 + message.len()) as u16);
        udp_packet.set_checksum(0); // UDP校验和是可选的，这里设置为0
    
        let udp_payload = udp_packet.payload_mut();
        udp_payload[..message.len()].copy_from_slice(message.as_bytes());
    

        match bridge.process_frame(&frame, 0) {
            Ok(_) => println!("Frame processed successfully"),
            Err(e) => println!("Error processing frame: {}", e),
        }

        // 模拟网络延迟
        std::thread::sleep(Duration::from_millis(100));

        // 尝试接收帧
        let max_attempts = 10;
        let mut attempts = 0;
        while attempts < max_attempts {
            if let Some((port, frame_data)) = bridge.receive_frame() {
                println!("Received frame on port {}", port);
                process_received_frame(&frame_data);
                break;
            } else {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if attempts == max_attempts {
            println!("No frame received after {} attempts", max_attempts);
        }

        // 模拟FDB老化
        if i % 2 == 1 {
            bridge.age_fdb();
            println!("FDB aged");
        }
    }

    println!("\nSimulation completed");
}

fn process_received_frame(frame_data: &[u8]) {
    if let Ok(eth_frame) = EthernetFrame::new_checked(frame_data) {
        let src_addr = eth_frame.src_addr();
        let dst_addr = eth_frame.dst_addr();
        println!("From: {:?}, To: {:?}", src_addr, dst_addr);

        if let Ok(ip_packet) = Ipv4Packet::new_checked(eth_frame.payload()) {
            if let Ok(udp_packet) = UdpPacket::new_checked(ip_packet.payload()) {
                let payload = udp_packet.payload();
                if let Ok(message) = std::str::from_utf8(payload) {
                    println!("Received message: {}", message);
                }
            }
        }
    }
}