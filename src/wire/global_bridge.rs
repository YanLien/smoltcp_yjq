use spin::Mutex;
use alloc::{sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use crate::{iface::Config, phy::Device, time::Instant, wire::{EthernetAddress, EthernetFrame}};
use super::{bridge::BridgeWrapper, bridge_device::BridgeDevice, bridge_fdb::BridgeifPortmask};

lazy_static! {
    pub static ref GLOBAL_BRIDGE: Arc<Mutex<Option<BridgeWrapper>>> = Arc::new(Mutex::new(None));
}

pub fn initialize_bridge<D: Device + 'static>(
    config: Config,
    device: D,
    ethaddr: EthernetAddress,
    max_ports: u8,
    ts: Instant
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock();
    if global_bridge.is_some() {
        return Err("Bridge is already initialized");
    }

    let bridge_wrapper = BridgeWrapper::new(config, device, ethaddr, max_ports, ts);

    *global_bridge = Some(bridge_wrapper);
    Ok(())
}

pub fn add_port(
    port_config: Config,
    port_device: BridgeDevice,
    port_num: u8,
    port_now: Instant,
) -> Result<(), &'static str> {
    let mut bridge_guard = GLOBAL_BRIDGE.lock();
    if let Some(bridge) = bridge_guard.as_mut() {
        bridge.add_port(port_config, port_device, port_num, port_now)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn process_frame(
    frame: &EthernetFrame<&[u8]>,
    in_port: u8,
    time: Instant,
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock();
    if let Some(inner) = global_bridge.as_ref() {
        inner.process_frame(frame, in_port, time)
    } else {
        Err("Bridge is not initialized")
    }
}

// pub fn age_fdb(now: Instant) -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.lock();
//     if let Some(inner) = global_bridge.as_ref() {
//         inner.age_fdb(now);
//         Ok(())
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

pub fn receive_frame(time: Instant) -> Result<Option<(u8, Vec<u8>)>, &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock();
    if let Some(inner) = global_bridge.as_ref() {
        Ok(inner.receive_frame(time))
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn add_static_fdb_entry(
    addr: &EthernetAddress,
    ports: usize
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock();
    if let Some(inner) = global_bridge.as_mut() {
        // let mut bridge_lock = inner.bridge.lock();
        inner.fdb_add(addr, ports)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn remove_static_fdb_entry(
    addr: &EthernetAddress
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock();
    if let Some(inner) = global_bridge.as_mut() {
        inner.fdb_remove(addr)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn find_dst_ports(
    dst_addr: &EthernetAddress
) -> Result<BridgeifPortmask, &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock();
    if let Some(inner) = global_bridge.as_ref() {
        Ok(inner.find_dst_ports(dst_addr))
    } else {
        Err("Bridge is not initialized")
    }
}
