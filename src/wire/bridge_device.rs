use std::collections::HashMap;
use std::error::Error;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, RwLock};
use crate::phy::{Device, DeviceCapabilities, Medium, RxToken, TunTapInterface, TxToken};
use crate::time::Instant;

pub trait ObjectSafeDeviceOps {
    fn capabilities(&self) -> DeviceCapabilities;
    fn receive<'a>(&'a mut self, timestamp: Instant) -> Option<(Box<dyn ObjectSafeRxTokenOps + 'a>, Box<dyn ObjectSafeTxTokenOps + 'a>)>;
    fn transmit<'a>(&'a mut self, timestamp: Instant) -> Option<Box<dyn ObjectSafeTxTokenOps + 'a>>;
}

pub trait ObjectSafeRxTokenOps {
    fn consume_with(&mut self, f: &mut dyn FnMut(&mut [u8]));
}

pub trait ObjectSafeTxTokenOps {
    fn consume_with(&mut self, len: usize, f: &mut dyn FnMut(&mut [u8]));
}

pub struct ObjectSafeDevice<D: Device> {
    inner: D,
}

impl<D: Device> ObjectSafeDevice<D> {
    pub fn new(device: D) -> Self {
        ObjectSafeDevice { 
            inner: device, 
        }
    }
}

impl<D: Device> Device for ObjectSafeDevice<D> {
    type RxToken<'a> = ObjectSafeRxToken<'a, D::RxToken<'a>> where Self: 'a;
    type TxToken<'a> = ObjectSafeTxToken<'a, D::TxToken<'a>> where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities() 
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // let mut inner = self.inner;
        self.inner.receive(timestamp).map(|(rx, tx)| {
            (ObjectSafeRxToken::new(rx), ObjectSafeTxToken::new(tx))
        })
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(timestamp).map(ObjectSafeTxToken::new)
    }
}

impl<D: Device> ObjectSafeDeviceOps for ObjectSafeDevice<D> {
    fn capabilities(&self) -> DeviceCapabilities {
        Device::capabilities(self)
    }

    fn receive<'a>(&'a mut self, timestamp: Instant) -> Option<(Box<dyn ObjectSafeRxTokenOps + 'a>, Box<dyn ObjectSafeTxTokenOps + 'a>)> {
        Device::receive(self, timestamp).map(|(rx, tx)| {
            (Box::new(rx) as Box<dyn ObjectSafeRxTokenOps + 'a>,
             Box::new(tx) as Box<dyn ObjectSafeTxTokenOps + 'a>)
        })
    }

    fn transmit<'a>(&'a mut self, timestamp: Instant) -> Option<Box<dyn ObjectSafeTxTokenOps + 'a>> {
        Device::transmit(self, timestamp).map(|tx| Box::new(tx) as Box<dyn ObjectSafeTxTokenOps + 'a>)
    }
}

pub struct ObjectSafeRxToken<'a, R: RxToken> {
    inner: Option<R>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, R: RxToken> ObjectSafeRxToken<'a, R> {
    fn new(token: R) -> Self {
        ObjectSafeRxToken {
            inner: Some(token),
            _phantom: PhantomData,
        }
    }
}

impl<'a, R: RxToken> RxToken for ObjectSafeRxToken<'a, R> {
    fn consume<T, F>(mut self, f: F) -> T
    where
        F: FnOnce(&mut [u8]) -> T,
    {
        self.inner.take().unwrap().consume(f)
    }
}

impl<'a, R: RxToken> ObjectSafeRxTokenOps for ObjectSafeRxToken<'a, R> {
    fn consume_with(&mut self, f: &mut dyn FnMut(&mut [u8])) {
        if let Some(token) = self.inner.take() {
            token.consume(|buffer| f(buffer));
        }
    }
}

pub struct ObjectSafeTxToken<'a, T: TxToken> {
    inner: Option<T>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, T: TxToken> ObjectSafeTxToken<'a, T> {
    fn new(token: T) -> Self {
        ObjectSafeTxToken {
            inner: Some(token),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: TxToken> TxToken for ObjectSafeTxToken<'a, T> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.inner.take().unwrap().consume(len, f)
    }
}

impl<'a, T: TxToken> ObjectSafeTxTokenOps for ObjectSafeTxToken<'a, T> {
    fn consume_with(&mut self, len: usize, f: &mut dyn FnMut(&mut [u8])) {
        if let Some(token) = self.inner.take() {
            token.consume(len, |buffer| f(buffer));
        }
    }
}

// 记录：TunTapInterface 未实现 Send 和 Sync

pub struct BridgeDevice {
    inner: Box<dyn ObjectSafeDeviceOps>,
}

impl BridgeDevice {
    pub fn new<D: Device + 'static>(device: D) -> Self {
        BridgeDevice { inner: Box::new(ObjectSafeDevice::new(device)) }
    }

    pub fn transmit<'a>(&'a mut self, timestamp: Instant) -> Option<Box<dyn ObjectSafeTxTokenOps + 'a>> {
        self.inner.transmit(timestamp)
    }

    pub fn receive<'a>(&'a mut self, timestamp: Instant) -> Option<(Box<dyn ObjectSafeRxTokenOps + 'a>, Box<dyn ObjectSafeTxTokenOps + 'a>)> {
        self.inner.receive(timestamp)
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub enum DeviceId {
    Named(String),
    Unnamed(usize),
}

pub struct DeviceManager {
    devices: HashMap<DeviceId, Arc<Mutex<BridgeDevice>>>,
    next_unnamed_id: usize,
}

impl DeviceManager {
    pub fn new() -> Self {
        DeviceManager {
            devices: HashMap::new(),
            next_unnamed_id: 0,
        }
    }

    pub fn get_or_create_device<F>(&mut self, id: Option<String>, create_fn: F) -> (DeviceId, Arc<Mutex<BridgeDevice>>)
    where
        F: FnOnce() -> BridgeDevice,
    {
        let device_id = match id {
            Some(name) => DeviceId::Named(name),
            None => {
                let id = self.next_unnamed_id;
                self.next_unnamed_id += 1;
                DeviceId::Unnamed(id)
            }
        };

        let device = self.devices.entry(device_id.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(create_fn()))
        }).clone();

        (device_id, device)
    }

    pub fn get_device(&self, id: &DeviceId) -> Option<Arc<Mutex<BridgeDevice>>> {
        self.devices.get(id).cloned()
    }
}

// Helper function to create a boxed ObjectSafeDeviceOps
pub fn boxed_object_safe_device<D: Device + 'static>(device: D) -> Box<dyn ObjectSafeDeviceOps> {
    Box::new(ObjectSafeDevice::new(device))
}

pub struct NetworkManager {
    devices: HashMap<String, Arc<RwLock<TunTapInterface>>>,
}

impl NetworkManager {
    pub fn new() -> Self {
        NetworkManager {
            devices: HashMap::new(),
        }
    }

    pub fn get_or_create_device(&mut self, name: &str, medium: Medium) -> Result<Arc<RwLock<TunTapInterface>>, Box<dyn Error>> {
        if let Some(device) = self.devices.get(name) {
            Ok(Arc::clone(device).into())
        } else {
            let device = TunTapInterface::new(name, medium)?;
            let device = Arc::new(RwLock::new(device));
            self.devices.insert(name.to_string(), Arc::clone(&device));
            Ok(device.into())
        }
    }

    pub fn get_device_fd(&self, name: &str) -> Result<i32, Box<dyn std::error::Error>> {
        if let Some(device) = self.devices.get(name) {
            let device = device.read().unwrap();
            Ok(device.as_raw_fd())
        } else {
            Err("Device not found".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::{Loopback, TunTapInterface, Medium};

    #[test]
    fn test_compatible_object_safe_devices() {
        println!("Testing compatible object-safe devices");

        // Create a Loopback device
        let loopback = Loopback::new(Medium::Ethernet);
        let mut object_safe_loopback = ObjectSafeDevice::new(loopback);

        // Test static dispatch (Device trait)
        let loopback_capabilities = Device::capabilities(&object_safe_loopback);
        assert_eq!(loopback_capabilities.medium, Medium::Ethernet);

        if let Some((rx, tx)) = Device::receive(&mut object_safe_loopback, Instant::now()) {
            rx.consume(|buffer| {
                println!("Received {} bytes (static dispatch)", buffer.len());
            });
            tx.consume(64, |buffer| {
                buffer.fill(0);
                println!("Transmitted {} bytes (static dispatch)", buffer.len());
            });
        }

        // Test dynamic dispatch (ObjectSafeDeviceOps trait)
        let mut boxed_loopback: Box<dyn ObjectSafeDeviceOps> = boxed_object_safe_device(Loopback::new(Medium::Ethernet));
        let boxed_loopback_capabilities = boxed_loopback.capabilities();
        assert_eq!(boxed_loopback_capabilities.medium, Medium::Ethernet);

        if let Some((mut rx, mut tx)) = boxed_loopback.receive(Instant::now()) {
            rx.consume_with(&mut |buffer| {
                println!("Received {} bytes (dynamic dispatch)", buffer.len());
            });
            tx.consume_with(64, &mut |buffer| {
                buffer.fill(0);
                println!("Transmitted {} bytes (dynamic dispatch)", buffer.len());
            });
        }

        // Create a TunTapInterface device (assuming it exists and can be created this way)
        // Note: This is a placeholder and may need to be adjusted based on your actual TunTapInterface implementation
        let tun = TunTapInterface::new("tun0", Medium::Ethernet).expect("Failed to create TUN device");
        let mut boxed_tun: &mut Box<dyn ObjectSafeDeviceOps> = &mut boxed_object_safe_device(tun);

        // Demonstrate usage with multiple device types
        let devices: Vec<&mut Box<dyn ObjectSafeDeviceOps>> = vec![&mut boxed_loopback, &mut boxed_tun];

        for device in devices {
            println!("Device capabilities: {:?}", device.capabilities());
            
            if let Some((mut rx, mut tx)) = device.receive(Instant::now()) {
                rx.consume_with(&mut |buffer| {
                    println!("Received {} bytes", buffer.len());
                });
                tx.consume_with(64, &mut |buffer| {
                    buffer.fill(0);
                    println!("Transmitted {} bytes", buffer.len());
                });
            }
        }

        println!("Compatible object-safe devices test completed successfully");
    }
}

