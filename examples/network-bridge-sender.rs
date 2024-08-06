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
        println!("Added static FDB entry: 02:00:00:00:00:01 -> Port 1");

        bridge_inner.fdb_add(&EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]), 2)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 2");
    }

    // 模拟数据传输
    let messages = vec![
        "Hello from Device 1!",
        "More data from Device 1",
        "Final message from Device 1",
    ];

    for (i, message) in messages.iter().enumerate() {
        println!("\nTransmitting message {}: {}", i + 1, message);

        let src_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let dst_mac = EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

        // 创建以太网帧
        let mut buffer = vec![0u8; 64 + message.len()]; // 假设最大帧大小为64字节 + 消息长度
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

        // 添加消息数据
        let udp_payload = udp_packet.payload_mut();
        udp_payload[..message.len()].copy_from_slice(message.as_bytes());

        // 处理帧
        match bridge.process_frame(&frame, 0) {
            Ok(_) => println!("Frame processed successfully"),
            Err(e) => println!("Error processing frame: {}", e),
        }

        // 模拟FDB老化
        if i % 2 == 1 {
            bridge.age_fdb();
            println!("FDB aged");
        }

        // 模拟网络延迟
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!("\nSender simulation completed");
}