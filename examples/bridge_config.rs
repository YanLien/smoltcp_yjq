use smoltcp::wire::EthernetAddress;

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