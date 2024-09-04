use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;
use smoltcp::{iface::{Config, Interface}, phy::{Loopback, Medium}, wire::{bridge_device::NetworkManager, global_bridge::{add_port, initialize_bridge, GLOBAL_BRIDGE}, EthernetAddress, HardwareAddress}};

use smoltcp::time::Instant;

pub const BRIDGE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
// phy::TunTapInterface: tap0
pub const PORT1_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
// phy::TunTapInterface: tap1
pub const PORT2_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
// phy::TunTapInterface: tap2
pub const PORT3_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x04];
// phy::Loopback
pub const PORT4_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x05];
// phy::Loopback
pub const PORT5_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x06];
// Bridge Max Ports
pub const MAX_PORTS: u8 = 8;

pub fn get_bridge_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&BRIDGE_MAC)
}

pub fn get_port1_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT1_MAC)
}

pub fn get_port2_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT2_MAC)
}

pub fn get_port3_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT3_MAC)
}

pub fn get_port4_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT4_MAC)
}

pub fn get_port5_mac() -> EthernetAddress {
    EthernetAddress::from_bytes(&PORT5_MAC)
}

lazy_static! {
    pub static ref NETWORK_MANAGER: Mutex<NetworkManager> = {
        let network_manager = NetworkManager::new();
        Mutex::new(network_manager)
    };
}

pub fn init_bridge() {
    println!("init bridge");
    let time = Instant::now();

    // 获取或创建设备
    let device1 = NETWORK_MANAGER.lock().unwrap()
        .get_or_create_device("tap0", Medium::Ethernet).unwrap();
    let device2 = NETWORK_MANAGER.lock().unwrap()
        .get_or_create_device("tap1", Medium::Ethernet).unwrap();
    let device3 = NETWORK_MANAGER.lock().unwrap()
        .get_or_create_device("tap2", Medium::Ethernet).unwrap();

    let config1 = Config::new(HardwareAddress::Ethernet(get_port1_mac()));
    let config2 = Config::new(HardwareAddress::Ethernet(get_port2_mac()));
    let config3 = Config::new(HardwareAddress::Ethernet(get_port3_mac()));

    // 创建接口
    let iface1 = Interface::new(config1, &mut *device1.lock().unwrap(), time);
    let iface2 = Interface::new(config2, &mut *device2.lock().unwrap(), time);
    let iface3 = Interface::new(config3, &mut *device3.lock().unwrap(), time);

    let config = Config::new(HardwareAddress::Ethernet(get_bridge_mac()));

    // 初始化网桥
    initialize_bridge(
        Interface::new(config, &mut Loopback::new(Medium::Ethernet), time),
        EthernetAddress::from_bytes(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
        MAX_PORTS // 最大端口数
    ).unwrap();

    // 添加端口到网桥
    add_port(iface1, Arc::clone(&device1), 0).expect("Failed to add port 1");
    add_port(iface2, Arc::clone(&device2), 1).expect("Failed to add port 2");
    add_port(iface3, Arc::clone(&device3), 2).expect("Failed to add port 3");

    let mut bridge_guard = GLOBAL_BRIDGE.lock().expect("Failed to get bridge");
    if let Some(bridge_lock) = bridge_guard.as_mut() {
        bridge_lock.fdb_add(&get_port1_mac(), 1)
            .expect("Failed to add static FDB entry 1");
        println!("Added static FDB entry: 02:00:00:00:00:02 -> Port 0");

        bridge_lock.fdb_add(&get_port2_mac(), 2)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:03 -> Port 1");
        
        bridge_lock.fdb_add(&get_port3_mac(), 3)
            .expect("Failed to add static FDB entry 2");
        println!("Added static FDB entry: 02:00:00:00:00:04 -> Port 2");
    }

    drop(bridge_guard);
}

