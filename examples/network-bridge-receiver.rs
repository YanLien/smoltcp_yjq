use std::time::Duration;
use smoltcp::iface::{Config, Interface};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::bridge::BridgeWrapper;
use smoltcp::wire::{EthernetAddress, EthernetFrame, HardwareAddress, Ipv4Packet, UdpPacket};
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

    // 模拟接收数据
    loop {
        // 从网桥接收数据
        if let Some((port, frame_data)) = bridge.receive_frame() {
            println!("Received frame at Port {}", port + 1);
    
            // 首先，解析以太网帧
            if let Ok(eth_frame) = EthernetFrame::new_checked(&frame_data) {
                // 提取 IP 包
                let ip_payload = eth_frame.payload();
                match Ipv4Packet::new_checked(ip_payload) {
                    Ok(ip_packet) => {
                        // 提取 UDP 包
                        match UdpPacket::new_checked(ip_packet.payload()) {
                            Ok(udp_packet) => {
                                // 尝试将 UDP 载荷解析为 UTF-8 字符串
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
        } else {
            // 如果没有接收到数据，短暂休眠以避免CPU占用过高
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}