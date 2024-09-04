use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};


use crate::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use crate::time::Instant;

pub trait ObjectSafeDeviceOps {
    fn capabilities(&self) -> DeviceCapabilities;
    fn receive<'a>(&'a mut self, timestamp: Instant) -> Option<(Box<dyn ObjectSafeRxTokenOps + 'a>, Box<dyn ObjectSafeTxTokenOps + 'a>)>;
    fn transmit<'a>(&'a mut self, timestamp: Instant) -> Option<Box<dyn ObjectSafeTxTokenOps + 'a>>;
}

pub struct DeviceWrapper {
    inner: Arc<Box<dyn ObjectSafeDeviceOps>>,
}


impl Device for DeviceWrapper {
    type RxToken<'a> = RxTokenWrapper<'a> where Self: 'a;
    type TxToken<'a> = TxTokenWrapper<'a> where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 克隆 Arc 以获取新的引用
        // let inner = Arc::clone(&self.inner);

        if let Some(inner_mut) = Arc::get_mut(&mut self.inner) {
            inner_mut.receive(timestamp).map(|(rx, tx)| {
                (
                    RxTokenWrapper { rx },
                    TxTokenWrapper { tx }
                )
            })
        } else {
            // 如果无法获取可变引用，我们可以考虑返回 None 或使用其他策略
            None
        }
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // 类似于 receive 方法
        // let inner = Arc::clone(&self.inner);
        
        if let Some(inner_mut) = Arc::get_mut(&mut self.inner) {
            inner_mut.transmit(timestamp).map(|tx| 
                TxTokenWrapper { tx }
            )
        } else {
            None
        }
    }
}

impl DeviceWrapper {
    pub fn new(device: Arc<Box<dyn ObjectSafeDeviceOps>>) -> Self {
        DeviceWrapper { inner: device }
    }
}

pub trait ObjectSafeRxTokenOps<'a> {
    fn consume_with(&mut self, f: &mut dyn FnMut(&mut [u8]));
}

pub trait ObjectSafeTxTokenOps<'a> {
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

pub struct ObjectSafeRxToken<'a, R: RxToken + 'a> {
    inner: Option<R>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, R: RxToken + 'a> ObjectSafeRxToken<'a, R> {
    fn new(token: R) -> Self {
        ObjectSafeRxToken {
            inner: Some(token),
            _phantom: PhantomData,
        }
    }
}

impl<'a, R: RxToken + 'a> RxToken for ObjectSafeRxToken<'a, R> {
    fn consume<T, F>(mut self, f: F) -> T
    where
        F: FnOnce(&mut [u8]) -> T,
    {
        self.inner.take().unwrap().consume(f)
    }
}

impl<'a, R: RxToken + 'a> ObjectSafeRxTokenOps<'a> for ObjectSafeRxToken<'a, R> {
    fn consume_with(&mut self, f: &mut dyn FnMut(&mut [u8])) {
        if let Some(token) = self.inner.take() {
            token.consume(|buffer| f(buffer));
        }
    }
}

pub struct RxTokenWrapper<'a> {
    // inner: Arc<Box<dyn ObjectSafeDeviceOps>>,
    rx: Box<dyn ObjectSafeRxTokenOps<'a> + 'a>,
}

impl<'a> RxToken for RxTokenWrapper<'a> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut result = None;
        let mut f = Some(f);
        self.rx.consume_with(&mut |buffer| {
            if let Some(f) = f.take() {
                result = Some(f(buffer));
            }
        });
        result.unwrap()
    }
}

pub struct ObjectSafeTxToken<'a, T: TxToken + 'a> {
    inner: Option<T>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, T: TxToken + 'a> ObjectSafeTxToken<'a, T> {
    fn new(token: T) -> Self {
        ObjectSafeTxToken {
            inner: Some(token),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T: TxToken + 'a> TxToken for ObjectSafeTxToken<'a, T> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.inner.take().unwrap().consume(len, f)
    }
}

impl<'a, T: TxToken + 'a> ObjectSafeTxTokenOps<'a> for ObjectSafeTxToken<'a, T> {
    fn consume_with(&mut self, len: usize, f: &mut dyn FnMut(&mut [u8])) {
        if let Some(token) = self.inner.take() {
            token.consume(len, |buffer| f(buffer));
        }
    }
}

// pub struct TxTokenWrapper<'a>(Box<dyn ObjectSafeTxTokenOps<'a> + 'a>);

pub struct TxTokenWrapper<'a> {
    // inner: Arc<Box<dyn ObjectSafeDeviceOps>>,
    tx: Box<dyn ObjectSafeTxTokenOps<'a> + 'a>,
}

impl<'a> TxTokenWrapper<'a> {
    pub fn new(token: Box<dyn ObjectSafeTxTokenOps<'a> + 'a>) -> Self {
        TxTokenWrapper { 
            tx: token
        }
    }
}

impl<'a> TxToken for TxTokenWrapper<'a> {
    fn consume<R, F>(mut self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut result = None;
        let mut f = Some(f);
        self.tx.consume_with(len, &mut |buffer| {
            if let Some(f) = f.take() {
                result = Some(f(buffer));
            }
        });
        result.expect("consume_with should have called the closure")
    }
}

pub struct BridgeDevice {
    pub inner: Arc<Box<dyn ObjectSafeDeviceOps>>,
}

impl BridgeDevice {
    pub fn new<D: Device + 'static>(device: D) -> Self {
        BridgeDevice {
            inner: Arc::new(Box::new(ObjectSafeDevice::new(device)))
        }
    }

    pub fn transmit(&mut self, timestamp: Instant) -> Option<Box<dyn ObjectSafeTxTokenOps + '_>> {
        Arc::get_mut(&mut self.inner)
            .expect("Cannot get mutable reference to Arc")
            .transmit(timestamp)
    }

    pub fn receive(&mut self, timestamp: Instant) -> Option<(Box<dyn ObjectSafeRxTokenOps + '_>, Box<dyn ObjectSafeTxTokenOps + '_>)> {
        Arc::get_mut(&mut self.inner)
            .expect("Cannot get mutable reference to Arc")
            .receive(timestamp)
    }

    pub fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    pub fn get_inner(&self) -> Arc<Box<dyn ObjectSafeDeviceOps>> {
        Arc::clone(&self.inner)
    }
}

// Helper function to create a boxed ObjectSafeDeviceOps
pub fn boxed_object_safe_device<D: Device + 'static>(device: D) -> Box<dyn ObjectSafeDeviceOps> {
    Box::new(ObjectSafeDevice::new(device))
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

pub struct NetworkManager {
    devices: HashMap<String, Arc<Mutex<BridgeDevice>>>,
}

impl NetworkManager {
    pub fn new() -> Self {
        NetworkManager {
            devices: HashMap::new(),
        }
    }

    pub fn get_or_create_device<D: Device + 'static>(&mut self, name: &str, device: D) -> Arc<Mutex<BridgeDevice>> {
        self.devices.entry(name.to_string()).or_insert_with(|| {
            Arc::new(Mutex::new(BridgeDevice::new(device)))
        }).clone()
    }
}
