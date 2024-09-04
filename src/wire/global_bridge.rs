use std::sync::{Arc, Mutex, RwLock};
use lazy_static::lazy_static;
use crate::phy::TunTapInterface;
use crate::wire::{EthernetAddress, EthernetFrame};
use crate::iface::Interface;

use super::bridge::BridgeWrapper;

use super::bridge_device::BridgeDevice;
use super::bridge_fdb::BridgeifPortmask;

lazy_static! {
    pub static ref GLOBAL_BRIDGE: Arc<Mutex<Option<BridgeWrapper>>> = Arc::new(Mutex::new(None));
}

pub fn initialize_bridge(
    iface: Interface,
    ethaddr: EthernetAddress,
    max_ports: u8
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if global_bridge.is_some() {
        return Err("Bridge is already initialized");
    }

    let bridge_wrapper = BridgeWrapper::new(iface, ethaddr, max_ports);

    *global_bridge = Some(bridge_wrapper);
    Ok(())
}

pub fn add_port(
    port_iface: Interface,
    port_device: Arc<Mutex<BridgeDevice>>,
    port_num: u8
) -> Result<(), &'static str> {
    let mut bridge_guard = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(bridge) = bridge_guard.as_mut() {
        bridge.add_port(port_iface, port_device, port_num)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn process_frame(
    frame: &EthernetFrame<&[u8]>,
    in_port: u8
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_ref() {
        inner.process_frame(frame, in_port)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn age_fdb() -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_ref() {
        inner.age_fdb();
        Ok(())
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn receive_frame() -> Result<Option<(u8, Vec<u8>)>, &'static str> {
    let global_bridge: std::sync::MutexGuard<'_, Option<BridgeWrapper>> = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_ref() {
        Ok(inner.receive_frame())
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn add_static_fdb_entry(
    addr: &EthernetAddress,
    ports: usize
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_mut() {
        // let mut bridge_lock = inner.bridge.lock().unwrap();
        inner.fdb_add(addr, ports)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn remove_static_fdb_entry(
    addr: &EthernetAddress
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_mut() {
        inner.fdb_remove(addr)
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn find_dst_ports(
    dst_addr: &EthernetAddress
) -> Result<BridgeifPortmask, &'static str> {
    let global_bridge = GLOBAL_BRIDGE.lock().unwrap();
    if let Some(inner) = global_bridge.as_ref() {
        Ok(inner.find_dst_ports(dst_addr))
    } else {
        Err("Bridge is not initialized")
    }
}
