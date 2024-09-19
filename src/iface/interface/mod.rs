// Heads up! Before working on this file you should read the parts
// of RFC 1122 that discuss Ethernet, ARP and IP for any IPv4 work
// and RFCs 8200 and 4861 for any IPv6 and NDISC work.

#[cfg(test)]
mod tests;

#[cfg(feature = "medium-ethernet")]
mod ethernet;
#[cfg(feature = "medium-ieee802154")]
mod ieee802154;

#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-sixlowpan")]
mod sixlowpan;

#[cfg(feature = "proto-igmp")]
mod igmp;
#[cfg(feature = "socket-tcp")]
mod tcp;
#[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
mod udp;

use bridge_device::TxTokenWrapper;
#[cfg(feature = "proto-igmp")]
pub use igmp::MulticastError;
use log::{debug, error};

use super::packet::*;

use core::result::Result;
use core::sync::atomic::{AtomicUsize, Ordering};
use heapless::{LinearMap, Vec};

#[cfg(feature = "_proto-fragmentation")]
use super::fragmentation::FragKey;
#[cfg(any(feature = "proto-ipv4", feature = "proto-sixlowpan"))]
use super::fragmentation::PacketAssemblerSet;
use super::fragmentation::{Fragmenter, FragmentsBuffer};

#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use super::neighbor::{Answer as NeighborAnswer, Cache as NeighborCache};
use super::socket_set::SocketSet;
use crate::config::{
    IFACE_MAX_ADDR_COUNT, IFACE_MAX_MULTICAST_GROUP_COUNT,
    IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT,
};
use crate::iface::Routes;
use crate::phy::PacketMeta;
use crate::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::*;
use crate::time::{Duration, Instant};

use bridge_fdb::BridgeifPortmask;
use global_bridge::GLOBAL_BRIDGE;

static INTERFACE_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

use crate::wire::*;

macro_rules! check {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(_) => {
                // concat!/stringify! doesn't work with defmt macros
                #[cfg(not(feature = "defmt"))]
                net_trace!(concat!("iface: malformed ", stringify!($e)));
                #[cfg(feature = "defmt")]
                net_trace!("iface: malformed");
                return Default::default();
            }
        }
    };
}
use check;

/// A  network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface {
    ifid: usize, // Unique ID for the interface
    pub(crate) inner: InterfaceInner,
    fragments: FragmentsBuffer,
    fragmenter: Fragmenter,
}

/// The device independent part of an Ethernet network interface.
///
/// Separating the device from the data required for processing and dispatching makes
/// it possible to borrow them independently. For example, the tx and rx tokens borrow
/// the `device` mutably until they're used, which makes it impossible to call other
/// methods on the `Interface` in this time (since its `device` field is borrowed
/// exclusively). However, it is still possible to call methods on its `inner` field.
pub struct InterfaceInner {
    caps: DeviceCapabilities,
    now: Instant,
    rand: Rand,

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    neighbor_cache: NeighborCache,
    hardware_addr: HardwareAddress,
    #[cfg(feature = "medium-ieee802154")]
    sequence_no: u8,
    #[cfg(feature = "medium-ieee802154")]
    pan_id: Option<Ieee802154Pan>,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_id: u16,
    #[cfg(feature = "proto-sixlowpan")]
    sixlowpan_address_context:
        Vec<SixlowpanAddressContext, IFACE_MAX_SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    tag: u16,
    ip_addrs: Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    #[cfg(feature = "proto-ipv4")]
    any_ip: bool,
    routes: Routes,
    #[cfg(feature = "proto-igmp")]
    ipv4_multicast_groups: LinearMap<Ipv4Address, (), IFACE_MAX_MULTICAST_GROUP_COUNT>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "proto-igmp")]
    igmp_report_state: IgmpReportState,
}

/// Configuration structure used for creating a network interface.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct Config {
    /// Random seed.
    ///
    /// It is strongly recommended that the random seed is different on each boot,
    /// to avoid problems with TCP port/sequence collisions.
    ///
    /// The seed doesn't have to be cryptographically secure.
    pub random_seed: u64,

    /// Set the Hardware address the interface will use.
    ///
    /// # Panics
    /// Creating the interface panics if the address is not unicast.
    pub hardware_addr: HardwareAddress,

    /// Set the IEEE802.15.4 PAN ID the interface will use.
    ///
    /// **NOTE**: we use the same PAN ID for destination and source.
    #[cfg(feature = "medium-ieee802154")]
    pub pan_id: Option<Ieee802154Pan>,
}

impl Config {
    pub fn new(hardware_addr: HardwareAddress) -> Self {
        Config {
            random_seed: 0,
            hardware_addr,
            #[cfg(feature = "medium-ieee802154")]
            pan_id: None,
        }
    }
}

impl Interface {
    /// Create a network interface using the previously provided configuration.
    ///
    /// # Panics
    /// This function panics if the [`Config::hardware_address`] does not match
    /// the medium of the device.
    pub fn new<D>(config: Config, device: &mut D, now: Instant) -> Self
    where
        D: Device + ?Sized,
    {
        let caps = device.capabilities();
        assert_eq!(
            config.hardware_addr.medium(),
            caps.medium,
            "The hardware address does not match the medium of the interface."
        );

        let mut rand = Rand::new(config.random_seed);

        #[cfg(feature = "medium-ieee802154")]
        let mut sequence_no;
        #[cfg(feature = "medium-ieee802154")]
        loop {
            sequence_no = (rand.rand_u32() & 0xff) as u8;
            if sequence_no != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-sixlowpan")]
        let mut tag;

        #[cfg(feature = "proto-sixlowpan")]
        loop {
            tag = rand.rand_u16();
            if tag != 0 {
                break;
            }
        }

        #[cfg(feature = "proto-ipv4")]
        let mut ipv4_id;

        #[cfg(feature = "proto-ipv4")]
        loop {
            ipv4_id = rand.rand_u16();
            if ipv4_id != 0 {
                break;
            }
        }

        Interface {
            ifid: INTERFACE_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
            fragments: FragmentsBuffer {
                #[cfg(feature = "proto-sixlowpan")]
                decompress_buf: [0u8; sixlowpan::MAX_DECOMPRESSED_LEN],

                #[cfg(feature = "_proto-fragmentation")]
                assembler: PacketAssemblerSet::new(),
                #[cfg(feature = "_proto-fragmentation")]
                reassembly_timeout: Duration::from_secs(60),
            },
            fragmenter: Fragmenter::new(),
            inner: InterfaceInner {
                now,
                caps,
                hardware_addr: config.hardware_addr,
                ip_addrs: Vec::new(),
                #[cfg(feature = "proto-ipv4")]
                any_ip: false,
                routes: Routes::new(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: NeighborCache::new(),
                #[cfg(feature = "proto-igmp")]
                ipv4_multicast_groups: LinearMap::new(),
                #[cfg(feature = "proto-igmp")]
                igmp_report_state: IgmpReportState::Inactive,
                #[cfg(feature = "medium-ieee802154")]
                sequence_no,
                #[cfg(feature = "medium-ieee802154")]
                pan_id: config.pan_id,
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                tag,
                #[cfg(feature = "proto-ipv4-fragmentation")]
                ipv4_id,
                #[cfg(feature = "proto-sixlowpan")]
                sixlowpan_address_context: Vec::new(),
                rand,
            },
        }
    }

    /// Get the socket context.
    ///
    /// The context is needed for some socket methods.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Get the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the medium is not Ethernet or Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn hardware_addr(&self) -> HardwareAddress {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        self.inner.hardware_addr
    }

    /// Set the HardwareAddress address of the interface.
    ///
    /// # Panics
    /// This function panics if the address is not unicast, and if the medium is not Ethernet or
    /// Ieee802154.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        #[cfg(all(feature = "medium-ethernet", not(feature = "medium-ieee802154")))]
        assert!(self.inner.caps.medium == Medium::Ethernet);
        #[cfg(all(feature = "medium-ieee802154", not(feature = "medium-ethernet")))]
        assert!(self.inner.caps.medium == Medium::Ieee802154);

        #[cfg(all(feature = "medium-ieee802154", feature = "medium-ethernet"))]
        assert!(
            self.inner.caps.medium == Medium::Ethernet
                || self.inner.caps.medium == Medium::Ieee802154
        );

        InterfaceInner::check_hardware_addr(&addr);
        self.inner.hardware_addr = addr;
    }

    /// Get the IP addresses of the interface.
    pub fn ip_addrs(&self) -> &[IpCidr] {
        self.inner.ip_addrs.as_ref()
    }

    /// Get the first IPv4 address if present.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.inner.ipv4_addr()
    }

    /// Get the first IPv6 address if present.
    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr(&self) -> Option<Ipv6Address> {
        self.inner.ipv6_addr()
    }

    /// Get an address from the interface that could be used as source address. For IPv4, this is
    /// the first IPv4 address from the list of addresses. For IPv6, the address is based on the
    /// destination address and uses RFC6724 for selecting the source address.
    pub fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.inner.get_source_address(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. This is the first
    /// IPv4 address from the list of addresses in the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        self.inner.get_source_address_ipv4(dst_addr)
    }

    /// Get an address from the interface that could be used as source address. The selection is
    /// based on RFC6724.
    #[cfg(feature = "proto-ipv6")]
    pub fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address) -> Ipv6Address {
        self.inner.get_source_address_ipv6(dst_addr)
    }

    /// Update the IP addresses of the interface.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_ip_addrs<F: FnOnce(&mut Vec<IpCidr, IFACE_MAX_ADDR_COUNT>)>(&mut self, f: F) {
        f(&mut self.inner.ip_addrs);
        InterfaceInner::flush_neighbor_cache(&mut self.inner);
        InterfaceInner::check_ip_addrs(&self.inner.ip_addrs)
    }

    /// Check whether the interface has the given IP address assigned.
    pub fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.inner.has_ip_addr(addr)
    }

    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    pub fn neighbor_cache(&self) -> &NeighborCache {
        &self.inner.neighbor_cache
    }

    pub fn neighbor_cache_mut(&mut self) -> &mut NeighborCache {
        &mut self.inner.neighbor_cache
    }

    /// Enable or disable the AnyIP capability.
    ///
    /// AnyIP allowins packets to be received
    /// locally on IPv4 addresses other than the interface's configured [ip_addrs].
    /// When AnyIP is enabled and a route prefix in [`routes`](Self::routes) specifies one of
    /// the interface's [`ip_addrs`](Self::ip_addrs) as its gateway, the interface will accept
    /// packets addressed to that prefix.
    ///
    /// # IPv6
    ///
    /// This option is not available or required for IPv6 as packets sent to
    /// the interface are not filtered by IPv6 address.
    #[cfg(feature = "proto-ipv4")]
    pub fn set_any_ip(&mut self, any_ip: bool) {
        self.inner.any_ip = any_ip;
    }

    /// Get whether AnyIP is enabled.
    ///
    /// See [`set_any_ip`](Self::set_any_ip) for details on AnyIP
    #[cfg(feature = "proto-ipv4")]
    pub fn any_ip(&self) -> bool {
        self.inner.any_ip
    }

    /// Get the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.reassembly_timeout
    }

    /// Set the packet reassembly timeout.
    #[cfg(feature = "_proto-fragmentation")]
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        if timeout > Duration::from_secs(60) {
            net_debug!("RFC 4944 specifies that the reassembly timeout MUST be set to a maximum of 60 seconds");
        }
        self.fragments.reassembly_timeout = timeout;
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    pub fn poll<D>(
        &mut self,
        timestamp: Instant,
        device: &mut D,
        sockets: &mut SocketSet<'_>,
    ) -> bool
    where
        D: Device + ?Sized,
    {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        self.fragments.assembler.remove_expired(timestamp);

        match self.inner.caps.medium {
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 =>
            {
                #[cfg(feature = "proto-sixlowpan-fragmentation")]
                if self.sixlowpan_egress(device) {
                    return true;
                }
            }
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ip"))]
            _ =>
            {
                #[cfg(feature = "proto-ipv4-fragmentation")]
                if self.ipv4_egress(device) {
                    return true;
                }
            }
        }

        let mut readiness_may_have_changed = false;

        loop {
            let mut did_something = false;
            
            did_something |= self.socket_ingress(device, sockets);
            did_something |= self.socket_egress(device, sockets);


            // println!("poll: did_something_socket_egress: {}", did_something);
            
            
            // println!("poll: did_something_socket_egress: {}", did_something);
            
            #[cfg(feature = "proto-igmp")]
            {
                did_something |= self.igmp_egress(device);
            }

            if did_something {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }

        readiness_may_have_changed
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;

        #[cfg(feature = "_proto-fragmentation")]
        if !self.fragmenter.is_empty() {
            return Some(Instant::from_millis(0));
        }

        let inner = &mut self.inner;

        sockets
            .items()
            .filter_map(move |item| {
                let socket_poll_at = item.socket.poll_at(inner);
                match item
                    .meta
                    .poll_at(socket_poll_at, |ip_addr| inner.has_neighbor(&ip_addr))
                {
                    PollAt::Ingress => None,
                    PollAt::Time(instant) => Some(instant),
                    PollAt::Now => Some(Instant::from_millis(0)),
                }
            })
            .min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Duration> {
        match self.poll_at(timestamp, sockets) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        let mut processed_any = false;
        // debug!("socket_ingress: rx_token, test");
        let Some((rx_token, tx_token)) = device.receive(self.inner.now) else {
            // debug!("socket_ingress: no rx_token, return false");
            return processed_any;
        };

        let rx_meta = rx_token.meta();
        rx_token.consume(|frame| {
            if frame.is_empty() {
                return;
            }

            debug!("socket_ingress: frame: {:02x?}", frame);

            match self.inner.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => {
                    let ethernet_frame = EthernetFrame::new_checked(frame);
                    if let Ok(eth_frame) = ethernet_frame {
                        let src_mac = eth_frame.src_addr();
                        let dst_mac = eth_frame.dst_addr();
                
                        net_debug!("socket_ingress:: src_mac: {:02x?}", src_mac);
                        net_debug!("socket_ingress:: dst_mac: {:02x?}", dst_mac);

                        // 检查是否需要桥接此数据帧
                        let bridge_ports = self.check_bridge_ports(&src_mac, &dst_mac);

                        net_debug!("socket_ingress: bridge_ports: {:?}", bridge_ports);
                
                        // 如果数据帧需要通过网桥转发
                        if let Some(ports) = bridge_ports {
                            // 执行网桥转发
                            let ethernet_frame = match EthernetFrame::new_checked(eth_frame.as_ref()) {
                                Ok(frame) => frame,
                                Err(e) => {
                                    net_debug!("Failed to parse Ethernet frame: {:?}", e);
                                    return;
                                }
                            };
                        
                            let src_addr = ethernet_frame.src_addr();
                            let dst_addr = ethernet_frame.dst_addr();
                            
                            let bridge_guard = GLOBAL_BRIDGE.lock();
                            let bridge_lock = bridge_guard.as_ref().unwrap();
                        
                            let bindings = bridge_lock.get_bridge();
                            let mut bridge = bindings.lock();
                    
                            let num_ports = bridge.num_ports;
                            drop(bridge_guard);
                    
                            for port in 0..num_ports {  // Assuming max 8 ports, adjust as needed
                                if ports & (1 << port) != 0 {
                                    net_debug!("src_addr {} dst_addr {}, received from port {}", src_addr, dst_addr, port);
                        
                                    // if let Err(e) = bridge.fdb_dynamic.update_entry(src_addr, port) {
                                    //     net_debug!("Failed to update dynamic FDB for source address: {:?}", e);
                                    // }
                                    
                                    debug!("forward_to_bridge: forwarding to port {}", port);
                                    if let Some(port) = bridge.ports.get_mut(&port) {
                                        let mut port_iface = port.create_interface(port.get_instant());

                                        let port_device = port.get_port_device();
                                        let mut binding = port_device.lock();

                                        let inner_device = binding.get_inner_mut();
                                        let Some((_, tx_tokenx)) = inner_device.receive(self.inner.now) else {
                                            continue;
                                        };

                                        if let Some(packet) = port_iface.inner.process_ethernet(
                                            sockets,
                                            rx_meta,
                                            eth_frame.as_ref(),
                                            &mut self.fragments,
                                        ) {
                                            let tx_token_wrapper = TxTokenWrapper::new(tx_tokenx);
                                            if let Err(err) = port_iface.inner.dispatch(tx_token_wrapper, packet, &mut self.fragmenter) {
                                                net_debug!("Failed to send response: {:?}", err);
                                            }
                                        };
                                    } else {
                                        net_debug!("Port {} not found", port);
                                    }
                                }
                            }
                        }
                
                        // 如果数据帧是针对传入的 Device，继续处理。
                        if let Some(packet) = self.inner.process_ethernet(
                            sockets,
                            rx_meta,
                            eth_frame.as_ref(),
                            &mut self.fragments,
                        ) {
                            if let Err(err) = self.inner.dispatch(tx_token, packet, &mut self.fragmenter) {
                                net_debug!("Failed to send response: {:?}", err);
                            }
                        };
                    }
                }
                #[cfg(feature = "medium-ip")]
                Medium::Ip => {
                    if let Some(packet) =
                        self.inner
                            .process_ip(sockets, rx_meta, frame, &mut self.fragments)
                    {
                        if let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        ) {
                            net_debug!("Failed to send response: {:?}", err);
                        }
                    }
                }
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => {
                    if let Some(packet) =
                        self.inner
                            .process_ieee802154(sockets, rx_meta, frame, &mut self.fragments)
                    {
                        if let Err(err) = self.inner.dispatch_ip(
                            tx_token,
                            PacketMeta::default(),
                            packet,
                            &mut self.fragmenter,
                        ) {
                            net_debug!("Failed to send response: {:?}", err);
                        }
                    }
                }
            }
            processed_any = true;
        });

        processed_any
    }

    fn check_bridge_ports(&self, _src_mac: &EthernetAddress, dst_mac: &EthernetAddress) -> Option<BridgeifPortmask> {
        let mut bridge_result = GLOBAL_BRIDGE.lock();

        if let Some(bridge_lock) = bridge_result.as_mut() {
            // 获取源端口，如果获取失败则返回错误

            let port_num = match bridge_lock.get_port(self) {
                Some(port) => port,
                None => {
                    // 处理获取端口失败的情况，比如返回默认的错误端口号或者提前退出
                    let max_ports = bridge_lock.num_ports();
                    if max_ports >= 8 {
                        error!("Port number exceeds maximum limit");
                        return None;
                    }
                    max_ports + 1  // 添加边界限制，确保端口号不会超出范围
                }
            };

            // 源端口(掩码)
            debug!("port_num {}", port_num);
    
            // // 学习源 MAC 地址，将其添加到转发表（FDB）
            // if let Err(err) = bridge_lock.fdb_add(src_mac, port_num as usize) {
            //     eprintln!("Failed to add MAC address to FDB: {:?}", err);
            //     return None;  // 失败时提前返回，避免后续处理
            // }
    
            // 查找目标 MAC 地址对应的端口
            let dst_ports = bridge_lock.find_dst_ports(dst_mac) & !port_num;

            debug!("check_bridge_ports: dst_ports {}", dst_ports);
    
            // 决定是否需要转发帧
            if dst_ports & (1 << port_num) == 0 {
                // 释放锁后进行转发操作
                drop(bridge_result);
                return Some(dst_ports);
            }
        }
    
        // 如果未找到对应的转发端口，返回 None
        drop(bridge_result);
        None
    }

    fn socket_egress<D>(&mut self, device: &mut D, sockets: &mut SocketSet<'_>) -> bool
    where
        D: Device + ?Sized,
    {
        // let _caps = device.capabilities();
        enum EgressError {
            Exhausted,
            Dispatch(DispatchError),
        }

        // Check if we have a global bridge
        let bridge_result = GLOBAL_BRIDGE.lock();

        // Get the MAC address for the IP
        let port_num = match bridge_result.as_ref() {
            Some(bridge_lock) => {
                bridge_lock.get_port(&self)
            },
            None => None,
        };

        drop(bridge_result);

        let mut emitted_any = false;
        // add 
        let now = self.inner.now;
        let neighbor_cache = self.inner.neighbor_cache.clone();

        for item in sockets.items_mut() {
            if !item
                .meta
                .egress_permitted(now, |ip_addr| self.inner.has_neighbor(&ip_addr))
            {
                continue;
            }

            let mut neighbor_addr = None;
            let mut respond = |inner: &mut InterfaceInner, meta: PacketMeta, response: Packet| {
                neighbor_addr = Some(response.ip_repr().dst_addr());
                let t = device.transmit(inner.now).ok_or_else(|| {
                    net_debug!("failed to transmit IP: device exhausted");
                    EgressError::Exhausted
                })?;

                debug!("socket_egress: response {:?}", response);

                if let Some(port_num) = port_num {
                    debug!("socket_egress: port_num {}", port_num);
                    // Check if we have a global bridge
                    let bridge_result = GLOBAL_BRIDGE.lock();

                    if let Some(bridge_lock) = bridge_result.as_ref() {
                        // Get the MAC address for the IP

                        if let Some(ip_addr) = neighbor_addr {
                            let dst_mac = neighbor_cache.lookup(&ip_addr, now);
                            debug!("socket_egress: dst_mac {:02x?}", dst_mac);
                            debug!("socket_egress: neighbor_addr {:?}", neighbor_addr);
                            match dst_mac {
                                NeighborAnswer::Found(hw_addr) => {
                                    // Get the destination ports from the bridge using the HardwareAddress
                                    let dst_ports = match hw_addr {
                                        #[cfg(feature = "medium-ethernet")]
                                        HardwareAddress::Ethernet(eth_addr) => {
                                            debug!("socket_egress: eth_addr {:02x?}", eth_addr);
                                            bridge_lock.find_dst_ports(&eth_addr)
                                        },
                                        #[cfg(feature = "medium-ieee802154")]
                                        HardwareAddress::Ieee802154(_) => {
                                            net_debug!("Ieee802154 hardware address not supported for bridge lookup");
                                            0 // or handle this case as appropriate
                                        },
                                        #[cfg(feature = "medium-ip")]
                                        HardwareAddress::Ip => {
                                            net_debug!("IP hardware address not supported for bridge lookup");
                                            0 // or handle this case as appropriate
                                        }
                                    };

                                    debug!("socket_egress: dst_ports {}", dst_ports); // 掩码

                                    let binding = bridge_lock.get_bridge();
                                    let bridge_lock = binding.lock();
                                    let mut bridge = bridge_lock;

                                    // If we have destination ports, use the bridge to forward the packet
                                    if dst_ports != 0 {
                                        if let HardwareAddress::Ethernet(dst_mac) = hw_addr {
                                            debug!("socket_egress: dst_mac {:02x?}", dst_mac);
                                            for port in 0..bridge.num_ports {
                                                debug!("  {} {}", port, port_num);
                                                if dst_ports & (1 << port) != 0 && port != port_num {
                                                    net_debug!("socket_egress: Port {} was successfully found and is now being processed", port);
                                                    if let Some(port) = bridge.ports.get_mut(&port) {
                                                        let port_device = port.get_port_device();
                                                        let process_result = {
                                                            let mut port_iface = port.create_interface(port.get_instant());
                                                            let mut port_lock = port_device.lock();
                                                            
                                                            let inner_device = port_lock.get_inner_mut();
                                                            let tx = match inner_device.transmit(now) {
                                                                Some(tx) => tx,
                                                                None => {
                                                                    net_debug!("failed to transmit IP: device exhausted");
                                                                    continue;
                                                                }
                                                            };
                                                            
                                                            let tx_token_wrapper = TxTokenWrapper::new(tx);
                                                            port_iface.inner.dispatch_ip(tx_token_wrapper, meta, response.clone(), &mut self.fragmenter)
                                                        };
                                                        if let Err(err) = process_result {
                                                            net_debug!("Failed to dispatch IP: {:?}", err);
                                                        }
                                                    }
                                                } else {
                                                    net_debug!("Port {} is not a target device!", port);
                                                }
                                            }
                                        } else {
                                            net_debug!("Non-Ethernet hardware address, cannot create Ethernet frame");
                                        }
                                    }
                                },
                                NeighborAnswer::NotFound => {
                                    // Initiate neighbor discovery if necessary
                                    // This might involve sending an ARP request for IPv4 or Neighbor Solicitation for IPv6
                                    // The exact implementation depends on your network stack
                                    net_debug!("Neighbor not found for IP: {:?}", ip_addr);
                                },
                                NeighborAnswer::RateLimited => {
                                    net_debug!("Neighbor lookup rate limited for IP: {:?}", ip_addr);
                                },
                            }
                        }
                    }
                    drop(bridge_result);
                }

                // 发送逻辑
                inner
                    .dispatch_ip(t, meta, response, &mut self.fragmenter)
                    .map_err(EgressError::Dispatch)?;

                debug!("------------------------------------------------------------------------------------");

                emitted_any = true;
                Ok(())
            };

            let result = match &mut item.socket {
                #[cfg(feature = "socket-raw")]
                Socket::Raw(socket) => socket.dispatch(&mut self.inner, |inner, (ip, raw)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Raw(raw)),
                    )
                }),
                #[cfg(feature = "socket-icmp")]
                Socket::Icmp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, response| match response {
                        #[cfg(feature = "proto-ipv4")]
                        (IpRepr::Ipv4(ipv4_repr), IcmpRepr::Ipv4(icmpv4_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ipv4_repr, IpPayload::Icmpv4(icmpv4_repr)),
                        ),
                        #[cfg(feature = "proto-ipv6")]
                        (IpRepr::Ipv6(ipv6_repr), IcmpRepr::Ipv6(icmpv6_repr)) => respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv6(ipv6_repr, IpPayload::Icmpv6(icmpv6_repr)),
                        ),
                        #[allow(unreachable_patterns)]
                        _ => unreachable!(),
                    })
                }
                #[cfg(feature = "socket-udp")]
                Socket::Udp(socket) => {
                    socket.dispatch(&mut self.inner, |inner, meta, (ip, udp, payload)| {
                        respond(inner, meta, Packet::new(ip, IpPayload::Udp(udp, payload)))
                    })
                }
                #[cfg(feature = "socket-tcp")]
                Socket::Tcp(socket) => socket.dispatch(&mut self.inner, |inner, (ip, tcp)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Tcp(tcp)),
                    )
                }),
                #[cfg(feature = "socket-dhcpv4")]
                Socket::Dhcpv4(socket) => {
                    socket.dispatch(&mut self.inner, |inner, (ip, udp, dhcp)| {
                        respond(
                            inner,
                            PacketMeta::default(),
                            Packet::new_ipv4(ip, IpPayload::Dhcpv4(udp, dhcp)),
                        )
                    })
                }
                #[cfg(feature = "socket-dns")]
                Socket::Dns(socket) => socket.dispatch(&mut self.inner, |inner, (ip, udp, dns)| {
                    respond(
                        inner,
                        PacketMeta::default(),
                        Packet::new(ip, IpPayload::Udp(udp, dns)),
                    )
                }),
            };
            match result {
                Err(EgressError::Exhausted) => break, // Device buffer full.
                Err(EgressError::Dispatch(_)) => {
                    // `NeighborCache` already takes care of rate limiting the neighbor discovery
                    // requests from the socket. However, without an additional rate limiting
                    // mechanism, we would spin on every socket that has yet to discover its
                    // neighbor.
                    item.meta.neighbor_missing(
                        self.inner.now,
                        neighbor_addr.expect("non-IP response packet"),
                    );
                }
                Ok(()) => {}
            }
        }
        emitted_any
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.ifid == other.ifid
    }
}

impl InterfaceInner {
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn hardware_addr(&self) -> HardwareAddress {
        self.hardware_addr
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum.clone()
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn ip_mtu(&self) -> usize {
        self.caps.ip_mtu()
    }

    #[allow(unused)] // unused depending on which sockets are enabled, and in tests
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(|a| a.into()),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => Some(self.get_source_address_ipv6(addr).into()),
        }
    }

    #[cfg(test)]
    #[allow(unused)] // unused depending on which sockets are enabled
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn check_hardware_addr(addr: &HardwareAddress) {
        if !addr.is_unicast() {
            panic!("Hardware address {addr} is not unicast")
        }
    }

    fn check_ip_addrs(addrs: &[IpCidr]) {
        for cidr in addrs {
            if !cidr.address().is_unicast() && !cidr.address().is_unspecified() {
                panic!("IP address {} is not unicast", cidr.address())
            }
        }
    }

    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Check whether the interface listens to given destination multicast IP address.
    ///
    /// If built without feature `proto-igmp` this function will
    /// always return `false` when using IPv4.
    fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        match addr.into() {
            #[cfg(feature = "proto-igmp")]
            IpAddress::Ipv4(key) => {
                key == Ipv4Address::MULTICAST_ALL_SYSTEMS
                    || self.ipv4_multicast_groups.get(&key).is_some()
            }
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_NODES) => true,
            #[cfg(feature = "proto-rpl")]
            IpAddress::Ipv6(Ipv6Address::LINK_LOCAL_ALL_RPL_NODES) => true,
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(addr) => self.has_solicited_node(addr),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        ip_payload: &'frame [u8],
        frag: &'frame mut FragmentsBuffer,
    ) -> Option<Packet<'frame>> {
        match IpVersion::of_packet(ip_payload) {
            #[cfg(feature = "proto-ipv4")]
            Ok(IpVersion::Ipv4) => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(ip_payload));

                self.process_ipv4(sockets, meta, &ipv4_packet, frag)
            }
            #[cfg(feature = "proto-ipv6")]
            Ok(IpVersion::Ipv6) => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(ip_payload));
                self.process_ipv6(sockets, meta, &ipv6_packet)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    #[cfg(feature = "socket-raw")]
    fn raw_socket_filter(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: &IpRepr,
        ip_payload: &[u8],
    ) -> bool {
        let mut handled_by_raw_socket = false;

        // Pass every IP packet to all raw sockets we have registered.
        for raw_socket in sockets
            .items_mut()
            .filter_map(|i| raw::Socket::downcast_mut(&mut i.socket))
        {
            if raw_socket.accepts(ip_repr) {
                raw_socket.process(self, ip_repr, ip_payload);
                handled_by_raw_socket = true;
            }
        }
        handled_by_raw_socket
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn dispatch<Tx>(
        &mut self,
        tx_token: Tx,
        packet: EthernetPacket,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
    {
        match packet {
            #[cfg(feature = "proto-ipv4")]
            EthernetPacket::Arp(arp_repr) => {
                let dst_hardware_addr = match arp_repr {
                    ArpRepr::EthernetIpv4 {
                        target_hardware_addr,
                        ..
                    } => target_hardware_addr,
                };

                self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                    frame.set_dst_addr(dst_hardware_addr);
                    frame.set_ethertype(EthernetProtocol::Arp);

                    let mut packet = ArpPacket::new_unchecked(frame.payload_mut());
                    arp_repr.emit(&mut packet);
                })
            }
            EthernetPacket::Ip(packet) => {
                self.dispatch_ip(tx_token, PacketMeta::default(), packet, frag)
            }
        }
    }

    fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.ip_addrs.iter().any(|cidr| cidr.contains_addr(addr))
    }

    fn route(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        debug!("addr {}, timestamp {}", addr, timestamp);
        // Send directly.
        // note: no need to use `self.is_broadcast()` to check for subnet-local broadcast addrs
        //       here because `in_same_network` will already return true.
        if self.in_same_network(addr) || addr.is_broadcast() {
            return Some(*addr);
        }

        debug!("addr {}, timestamp {}", addr, timestamp);

        // Route via a router.
        self.routes.lookup(addr, timestamp)
    }

    fn has_neighbor(&self, addr: &IpAddress) -> bool {
        match self.route(addr, self.now) {
            Some(_routed_addr) => match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => self.neighbor_cache.lookup(&_routed_addr, self.now).found(),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => true,
            },
            None => false,
        }
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr<Tx>(
        &mut self,
        tx_token: Tx,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        fragmenter: &mut Fragmenter,
    ) -> Result<(HardwareAddress, Tx), DispatchError>
    where
        Tx: TxToken,
    {
        if self.is_broadcast(dst_addr) {
            let hardware_addr = match self.caps.medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return Ok((hardware_addr, tx_token));
        }

        if dst_addr.is_multicast() {
            let b = dst_addr.as_bytes();
            let hardware_addr = match *dst_addr {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x01,
                        0x00,
                        0x5e,
                        b[1] & 0x7F,
                        b[2],
                        b[3],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => unreachable!(),
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_addr) => match self.caps.medium {
                    #[cfg(feature = "medium-ethernet")]
                    Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::from_bytes(&[
                        0x33, 0x33, b[12], b[13], b[14], b[15],
                    ])),
                    #[cfg(feature = "medium-ieee802154")]
                    Medium::Ieee802154 => {
                        // Not sure if this is correct
                        HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST)
                    }
                    #[cfg(feature = "medium-ip")]
                    Medium::Ip => unreachable!(),
                },
            };

            return Ok((hardware_addr, tx_token));
        }

        let dst_addr = self
            .route(dst_addr, self.now)
            .ok_or(DispatchError::NoRoute)?;

        match self.neighbor_cache.lookup(&dst_addr, self.now) {
            NeighborAnswer::Found(hardware_addr) => return Ok((hardware_addr, tx_token)),
            NeighborAnswer::RateLimited => return Err(DispatchError::NeighborPending),
            _ => (), // XXX
        }

        match (src_addr, dst_addr) {
            #[cfg(all(feature = "medium-ethernet", feature = "proto-ipv4"))]
            (&IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr))
                if matches!(self.caps.medium, Medium::Ethernet) =>
            {
                net_debug!(
                    "address {} not in neighbor cache, sending ARP request",
                    dst_addr
                );
                let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: src_hardware_addr,
                    source_protocol_addr: src_addr,
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: dst_addr,
                };

                if let Err(e) =
                    self.dispatch_ethernet(tx_token, arp_repr.buffer_len(), |mut frame| {
                        frame.set_dst_addr(EthernetAddress::BROADCAST);
                        frame.set_ethertype(EthernetProtocol::Arp);

                        arp_repr.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()))
                    })
                {
                    net_debug!("Failed to dispatch ARP request: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[cfg(feature = "proto-ipv6")]
            (&IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                net_debug!(
                    "address {} not in neighbor cache, sending Neighbor Solicitation",
                    dst_addr
                );

                let solicit = Icmpv6Repr::Ndisc(NdiscRepr::NeighborSolicit {
                    target_addr: dst_addr,
                    lladdr: Some(self.hardware_addr.into()),
                });

                let packet = Packet::new_ipv6(
                    Ipv6Repr {
                        src_addr,
                        dst_addr: dst_addr.solicited_node(),
                        next_header: IpProtocol::Icmpv6,
                        payload_len: solicit.buffer_len(),
                        hop_limit: 0xff,
                    },
                    IpPayload::Icmpv6(solicit),
                );

                if let Err(e) =
                    self.dispatch_ip(tx_token, PacketMeta::default(), packet, fragmenter)
                {
                    net_debug!("Failed to dispatch NDISC solicit: {:?}", e);
                    return Err(DispatchError::NeighborPending);
                }
            }

            #[allow(unreachable_patterns)]
            _ => (),
        }

        // The request got dispatched, limit the rate on the cache.
        self.neighbor_cache.limit_rate(self.now);
        Err(DispatchError::NeighborPending)
    }

    fn flush_neighbor_cache(&mut self) {
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        self.neighbor_cache.flush()
    }

    fn dispatch_ip<Tx: TxToken>(
        &mut self,
        // NOTE(unused_mut): tx_token isn't always mutated, depending on
        // the feature set that is used.
        #[allow(unused_mut)] mut tx_token: Tx,
        meta: PacketMeta,
        packet: Packet,
        frag: &mut Fragmenter,
    ) -> Result<(), DispatchError> {
        let mut ip_repr = packet.ip_repr();
        assert!(!ip_repr.dst_addr().is_unspecified());

        // Dispatch IEEE802.15.4:

        #[cfg(feature = "medium-ieee802154")]
        if matches!(self.caps.medium, Medium::Ieee802154) {
            let (addr, tx_token) = self.lookup_hardware_addr(
                tx_token,
                &ip_repr.src_addr(),
                &ip_repr.dst_addr(),
                frag,
            )?;
            let addr = addr.ieee802154_or_panic();

            self.dispatch_ieee802154(addr, tx_token, meta, packet, frag);
            return Ok(());
        }

        // Dispatch IP/Ethernet:

        let caps = self.caps.clone();

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let ipv4_id = self.next_ipv4_frag_ident();

        // First we calculate the total length that we will have to emit.
        let mut total_len = ip_repr.buffer_len();

        // Add the size of the Ethernet header if the medium is Ethernet.
        #[cfg(feature = "medium-ethernet")]
        if matches!(self.caps.medium, Medium::Ethernet) {
            total_len = EthernetFrame::<&[u8]>::buffer_len(total_len);
        }

        // If the medium is Ethernet, then we need to retrieve the destination hardware address.
        #[cfg(feature = "medium-ethernet")]
        let (dst_hardware_addr, mut tx_token) = match self.caps.medium {
            Medium::Ethernet => {
                match self.lookup_hardware_addr(
                    tx_token,
                    &ip_repr.src_addr(),
                    &ip_repr.dst_addr(),
                    frag,
                )? {
                    (HardwareAddress::Ethernet(addr), tx_token) => (addr, tx_token),
                    (_, _) => unreachable!(),
                }
            }
            _ => (EthernetAddress([0; 6]), tx_token),
        };

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }

            Ok(())
        };

        // Emit function for the IP header and payload.
        let emit_ip = |repr: &IpRepr, mut tx_buffer: &mut [u8]| {
            repr.emit(&mut tx_buffer, &self.caps.checksum);

            let payload = &mut tx_buffer[repr.header_len()..];
            packet.emit_payload(repr, payload, &caps)
        };

        let total_ip_len = ip_repr.buffer_len();

        match &mut ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(repr) => {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                if total_ip_len > self.caps.max_transmission_unit {
                    #[cfg(feature = "proto-ipv4-fragmentation")]
                    {
                        net_debug!("start fragmentation");

                        // Calculate how much we will send now (including the Ethernet header).
                        let tx_len = self.caps.max_transmission_unit;

                        let ip_header_len = repr.buffer_len();
                        let first_frag_ip_len = self.caps.ip_mtu();

                        if frag.buffer.len() < total_ip_len {
                            net_debug!(
                                "Fragmentation buffer is too small, at least {} needed. Dropping",
                                total_ip_len
                            );
                            return Ok(());
                        }

                        #[cfg(feature = "medium-ethernet")]
                        {
                            frag.ipv4.dst_hardware_addr = dst_hardware_addr;
                        }

                        // Save the total packet len (without the Ethernet header, but with the first
                        // IP header).
                        frag.packet_len = total_ip_len;

                        // Save the IP header for other fragments.
                        frag.ipv4.repr = *repr;

                        // Save how much bytes we will send now.
                        frag.sent_bytes = first_frag_ip_len;

                        // Modify the IP header
                        repr.payload_len = first_frag_ip_len - repr.buffer_len();

                        // Emit the IP header to the buffer.
                        emit_ip(&ip_repr, &mut frag.buffer);

                        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut frag.buffer[..]);
                        frag.ipv4.ident = ipv4_id;
                        ipv4_packet.set_ident(ipv4_id);
                        ipv4_packet.set_more_frags(true);
                        ipv4_packet.set_dont_frag(false);
                        ipv4_packet.set_frag_offset(0);

                        if caps.checksum.ipv4.tx() {
                            ipv4_packet.fill_checksum();
                        }

                        // Transmit the first packet.
                        tx_token.consume(tx_len, |mut tx_buffer| {
                            #[cfg(feature = "medium-ethernet")]
                            if matches!(self.caps.medium, Medium::Ethernet) {
                                emit_ethernet(&ip_repr, tx_buffer)?;
                                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                            }

                            // Change the offset for the next packet.
                            frag.ipv4.frag_offset = (first_frag_ip_len - ip_header_len) as u16;

                            // Copy the IP header and the payload.
                            tx_buffer[..first_frag_ip_len]
                                .copy_from_slice(&frag.buffer[..first_frag_ip_len]);

                            Ok(())
                        })
                    }

                    #[cfg(not(feature = "proto-ipv4-fragmentation"))]
                    {
                        net_debug!("Enable the `proto-ipv4-fragmentation` feature for fragmentation support.");
                        Ok(())
                    }
                } else {
                    tx_token.set_meta(meta);

                    // No fragmentation is required.
                    tx_token.consume(total_len, |mut tx_buffer| {
                        #[cfg(feature = "medium-ethernet")]
                        if matches!(self.caps.medium, Medium::Ethernet) {
                            emit_ethernet(&ip_repr, tx_buffer)?;
                            tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                        }

                        emit_ip(&ip_repr, tx_buffer);
                        Ok(())
                    })
                }
            }
            // We don't support IPv6 fragmentation yet.
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) => tx_token.consume(total_len, |mut tx_buffer| {
                #[cfg(feature = "medium-ethernet")]
                if matches!(self.caps.medium, Medium::Ethernet) {
                    emit_ethernet(&ip_repr, tx_buffer)?;
                    tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
                }

                emit_ip(&ip_repr, tx_buffer);
                Ok(())
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum DispatchError {
    /// No route to dispatch this packet. Retrying won't help unless
    /// configuration is changed.
    NoRoute,
    /// We do have a route to dispatch this packet, but we haven't discovered
    /// the neighbor for it yet. Discovery has been initiated, dispatch
    /// should be retried later.
    NeighborPending,
}
