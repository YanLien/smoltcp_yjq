// use std::sync::{Arc, Mutex, RwLock};
// use std::any::Any;
// use lazy_static::lazy_static;
// use crate::phy::{Device, Loopback};
// use crate::wire::{EthernetAddress, EthernetFrame};
// use crate::iface::Interface;

// use super::bridge::BridgeWrapper;
// use super::bridge_fdb::BridgeifPortmask;

// pub struct GlobalBridgeInner {
//     pub bridge: Arc<Mutex<BridgeWrapper<Loopback>>>,
// }

// lazy_static! {
//     pub static ref GLOBAL_BRIDGE: Arc<RwLock<Option<Box<dyn Any + Send + Sync + 'static>>>> = Arc::new(RwLock::new(None));
// }

// pub fn initialize_bridge<D: Device + Send + Sync + 'static>(
//     iface: Interface,
//     ethaddr: EthernetAddress,
//     max_ports: u8
// ) -> Result<(), &'static str> {
//     let mut global_bridge = GLOBAL_BRIDGE.write().unwrap();
//     if global_bridge.is_some() {
//         return Err("Bridge is already initialized");
//     }

//     let bridge_wrapper: BridgeWrapper<D> = BridgeWrapper::new(iface, ethaddr, max_ports);
//     let inner = GlobalBridgeInner {
//         bridge: Arc::new(Mutex::new(bridge_wrapper)),
//     };
//     *global_bridge = Some(Box::new(inner));
//     Ok(())
// }

// pub fn add_port<D: Device + Send + Sync + 'static>(
//     port_iface: Interface,
//     port_device: D,
//     port_num: u32
// ) -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let bridge_lock = inner.bridge.lock().unwrap();
//             bridge_lock.add_port(port_iface, port_device, port_num)
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn process_frame<D: Device + Send + Sync + 'static>(
//     frame: &EthernetFrame<&[u8]>,
//     in_port: u8
// ) -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let bridge_lock = inner.bridge.lock().unwrap();
//             bridge_lock.process_frame(frame, in_port)
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn age_fdb<D: Device + Send + Sync + 'static>() -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let bridge_lock = inner.bridge.lock().unwrap();
//             bridge_lock.age_fdb();
//             Ok(())
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn receive_frame<D: Device + Send + Sync + 'static>() -> Result<Option<(u8, Vec<u8>)>, &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let bridge_lock = inner.bridge.lock().unwrap();
//             Ok(bridge_lock.receive_frame())
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn add_static_fdb_entry<D: Device + Send + Sync + 'static>(
//     addr: &EthernetAddress,
//     ports: usize
// ) -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let mut bridge_lock = inner.bridge.lock().unwrap();
//             bridge_lock.fdb_add(addr, ports)
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn remove_static_fdb_entry<D: Device + Send + Sync + 'static>(
//     addr: &EthernetAddress
// ) -> Result<(), &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let mut bridge_lock = inner.bridge.lock().unwrap();
//             bridge_lock.fdb_remove(addr)
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

// pub fn find_dst_ports<D: Device + Send + Sync + 'static>(
//     dst_addr: &EthernetAddress
// ) -> Result<BridgeifPortmask, &'static str> {
//     let global_bridge = GLOBAL_BRIDGE.read().unwrap();
//     if let Some(bridge) = global_bridge.as_ref() {
//         if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner<D>>() {
//             let bridge_lock = inner.bridge.lock().unwrap();
//             Ok(bridge_lock.find_dst_ports(dst_addr))
//         } else {
//             Err("Bridge is initialized with a different device type")
//         }
//     } else {
//         Err("Bridge is not initialized")
//     }
// }

use std::sync::{Arc, Mutex, RwLock};
use std::any::Any;
use lazy_static::lazy_static;
use crate::phy::Loopback;
use crate::wire::{EthernetAddress, EthernetFrame};
use crate::iface::Interface;

use super::bridge::BridgeWrapper;
use super::bridge_fdb::BridgeifPortmask;

pub struct GlobalBridgeInner {
    pub bridge: Arc<Mutex<BridgeWrapper<Loopback>>>,
}

lazy_static! {
    pub static ref GLOBAL_BRIDGE: Arc<RwLock<Option<Box<dyn Any + Send + Sync + 'static>>>> = Arc::new(RwLock::new(None));
}

pub fn initialize_bridge(
    iface: Interface,
    ethaddr: EthernetAddress,
    max_ports: u8
) -> Result<(), &'static str> {
    let mut global_bridge = GLOBAL_BRIDGE.write().unwrap();
    if global_bridge.is_some() {
        return Err("Bridge is already initialized");
    }

    let bridge_wrapper = BridgeWrapper::new(iface, ethaddr, max_ports);
    let inner = GlobalBridgeInner {
        bridge: Arc::new(Mutex::new(bridge_wrapper)),
    };
    *global_bridge = Some(Box::new(inner));
    Ok(())
}

pub fn add_port(
    port_iface: Interface,
    port_device: Loopback,
    port_num: u32
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.add_port(port_iface, port_device, port_num)
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn process_frame(
    frame: &EthernetFrame<&[u8]>,
    in_port: u8
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.process_frame(frame, in_port)
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn age_fdb() -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.age_fdb();
            Ok(())
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn receive_frame() -> Result<Option<(u8, Vec<u8>)>, &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let bridge_lock = inner.bridge.lock().unwrap();
            Ok(bridge_lock.receive_frame())
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn add_static_fdb_entry(
    addr: &EthernetAddress,
    ports: usize
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let mut bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.fdb_add(addr, ports)
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn remove_static_fdb_entry(
    addr: &EthernetAddress
) -> Result<(), &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let mut bridge_lock = inner.bridge.lock().unwrap();
            bridge_lock.fdb_remove(addr)
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}

pub fn find_dst_ports(
    dst_addr: &EthernetAddress
) -> Result<BridgeifPortmask, &'static str> {
    let global_bridge = GLOBAL_BRIDGE.read().unwrap();
    if let Some(bridge) = global_bridge.as_ref() {
        if let Some(inner) = bridge.downcast_ref::<GlobalBridgeInner>() {
            let bridge_lock = inner.bridge.lock().unwrap();
            Ok(bridge_lock.find_dst_ports(dst_addr))
        } else {
            Err("Unexpected error: Bridge inner type mismatch")
        }
    } else {
        Err("Bridge is not initialized")
    }
}
