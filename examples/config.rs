use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use smoltcp::iface::{Config, Interface};
use smoltcp::phy::Loopback;
use smoltcp::phy::Medium;
use smoltcp::time::Instant;
use smoltcp::wire::bridge::BridgeWrapper;
use smoltcp::wire::{EthernetAddress, HardwareAddress, Ipv4Address};

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

lazy_static! {
    pub static ref BRIDGE: Arc<Mutex<BridgeWrapper<Loopback>>> = {
        let time = Instant::now();
        let mut device1 = Loopback::new(Medium::Ethernet);
        let mut device2 = Loopback::new(Medium::Ethernet);

        let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
        let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));

        let mut iface1 = Interface::new(config1, &mut device1, time);
        let mut iface2 = Interface::new(config2, &mut device2, time);

        // iface1.update_ip_addrs(|addrs| {
        //     addrs.push(IpCidr::new(IpAddress::from(SENDER_IP), 24)).unwrap();
        // });
        
        // iface2.update_ip_addrs(|addrs| {
        //     addrs.push(IpCidr::new(IpAddress::from(RECEIVER_IP), 24)).unwrap();
        // });

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
        
        bridge_inner.fdb_add(&get_port1_mac(), 1).expect("Failed to add static FDB entry 1");
        bridge_inner.fdb_add(&get_port2_mac(), 2).expect("Failed to add static FDB entry 2");

        println!("Bridge initialized Successfully");

        Arc::new(Mutex::new(bridge))
    };
}


