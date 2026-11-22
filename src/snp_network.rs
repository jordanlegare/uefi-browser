//! SNP-backed Ethernet device and smoltcp IPv4/DHCP/UDP/TCP runtime.
use alloc::vec;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::time::Duration;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Cidr};
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::network::snp::{NetworkState, ReceiveFlags, SimpleNetwork};
use crate::dns::{DnsIoError, UdpDnsTransport};
use crate::entropy::SecureRandom;

const FRAME_BUFFER_SIZE: usize = 2048;
const DHCP_TIMEOUT_MS: u64 = 60_000;
const TCP_RX_BUFFER: usize = 16 * 1024;
const TCP_TX_BUFFER: usize = 16 * 1024;
const UDP_BUFFER_SIZE: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnpNetworkError {
    NoSimpleNetwork, NicStartFailed, NicInitializeFailed, InvalidMacAddress,
    EntropyUnavailable, DhcpTimeout, NoDnsServer, DnsTimeout, DnsNetwork,
    DnsInvalidDatagram, TcpConnectTimeout, TcpNetwork,
}

struct SnpRxToken(Vec<u8>);
impl RxToken for SnpRxToken {
    fn consume<R, F>(self, f: F) -> R where F: FnOnce(&[u8]) -> R { f(&self.0) }
}

struct SnpTxToken<'a>(&'a mut SnpDevice);
impl TxToken for SnpTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R where F: FnOnce(&mut [u8]) -> R {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if frame.len() < 60 { frame.resize(60, 0); }
        let _ = self.0.snp.transmit(0, &mut frame, None, None, None);
        result
    }
}

struct SnpDevice { snp: ScopedProtocol<SimpleNetwork>, mtu: usize }
impl SnpDevice {
    fn open() -> Result<(Self, EthernetAddress), SnpNetworkError> {
        let handles = boot::find_handles::<SimpleNetwork>().map_err(|_| SnpNetworkError::NoSimpleNetwork)?;
        for handle in handles {
            let params = OpenProtocolParams { handle, agent: boot::image_handle(), controller: None };
            // SAFETY: Handle was located by the SNP protocol GUID.
            let mut snp = match unsafe { boot::open_protocol::<SimpleNetwork>(params, OpenProtocolAttributes::GetProtocol) } {
                Ok(p) => p, Err(_) => continue,
            };
            if snp.mode().state == NetworkState::STOPPED && snp.start().is_err() { continue; }
            if snp.mode().state != NetworkState::INITIALIZED && snp.initialize(0, 0).is_err() { continue; }
            if snp.receive_filters(ReceiveFlags::UNICAST | ReceiveFlags::BROADCAST | ReceiveFlags::MULTICAST,
                ReceiveFlags::empty(), false, None).is_err() { continue; }
            let mac = EthernetAddress::from_bytes(&snp.mode().current_address.0[..6]);
            if !mac.is_unicast() || mac.0.iter().all(|b| *b == 0) { continue; }
            let mtu = core::cmp::max(576, snp.mode().max_packet_size as usize);
            return Ok((Self { snp, mtu }, mac));
        }
        Err(SnpNetworkError::NoSimpleNetwork)
    }
}
impl Device for SnpDevice {
    type RxToken<'a> = SnpRxToken where Self: 'a;
    type TxToken<'a> = SnpTxToken<'a> where Self: 'a;
    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut frame = vec![0u8; core::cmp::max(FRAME_BUFFER_SIZE, self.mtu + 64)];
        let mut header_size = 0usize;
        match self.snp.receive(&mut frame, Some(&mut header_size), None, None, None) {
            Ok(n) if n >= 14 && n <= frame.len() => { frame.truncate(n); Some((SnpRxToken(frame), SnpTxToken(self))) }
            _ => None,
        }
    }
    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> { Some(SnpTxToken(self)) }
    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities { medium: Medium::Ethernet, max_transmission_unit: self.mtu, ..DeviceCapabilities::default() }
    }
}

pub struct SnpNetwork {
    device: SnpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp_handle: SocketHandle,
    dns_server: Option<Ipv4Addr>,
    now_ms: i64,
    next_local_port: u16,
}
impl SnpNetwork {
    pub fn new<R: SecureRandom>(random: &mut R) -> Result<Self, SnpNetworkError> {
        let (device, mac) = SnpDevice::open()?;
        let mut seed = [0u8; 8];
        let mut port = [0u8; 2];
        random.fill_bytes(&mut seed).map_err(|_| SnpNetworkError::EntropyUnavailable)?;
        random.fill_bytes(&mut port).map_err(|_| SnpNetworkError::EntropyUnavailable)?;
        let mut config = Config::new(HardwareAddress::Ethernet(mac));
        config.random_seed = u64::from_le_bytes(seed);
        let mut device = device;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        let mut sockets = SocketSet::new(Vec::new());
        let dhcp_handle = sockets.add(dhcpv4::Socket::new());
        iface.update_ip_addrs(|addrs| addrs.clear());
        Ok(Self { device, iface, sockets, dhcp_handle, dns_server: None, now_ms: 0,
            next_local_port: 49_152 + (u16::from_be_bytes(port) % 16_384) })
    }

    fn poll_once(&mut self) {
        let _ = self.iface.poll(Instant::from_millis(self.now_ms), &mut self.device, &mut self.sockets);
        self.now_ms = self.now_ms.saturating_add(1);
        self.process_dhcp_event();
    }
    fn wait_step(&mut self) { self.poll_once(); boot::stall(Duration::from_millis(1)); }

    fn process_dhcp_event(&mut self) {
        enum Update { Configured(Ipv4Cidr, Option<Ipv4Addr>, Option<Ipv4Addr>), Deconfigured }
        let update = {
            let dhcp = self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp_handle);
            match dhcp.poll() {
                Some(dhcpv4::Event::Configured(c)) => Some(Update::Configured(c.address, c.router, c.dns_servers.first().copied())),
                Some(dhcpv4::Event::Deconfigured) => Some(Update::Deconfigured),
                None => None,
            }
        };
        match update {
            Some(Update::Configured(addr, router, dns)) => {
                self.iface.update_ip_addrs(|addrs| { addrs.clear(); let _ = addrs.push(IpCidr::Ipv4(addr)); });
                if let Some(gateway) = router { let _ = self.iface.routes_mut().add_default_ipv4_route(gateway); }
                else { self.iface.routes_mut().remove_default_ipv4_route(); }
                self.dns_server = dns;
            }
            Some(Update::Deconfigured) => {
                self.iface.update_ip_addrs(|addrs| addrs.clear());
                self.iface.routes_mut().remove_default_ipv4_route();
                self.dns_server = None;
            }
            None => {}
        }
    }

    pub fn acquire_dhcp(&mut self, timeout_ms: u64) -> Result<Ipv4Addr, SnpNetworkError> {
        let timeout = if timeout_ms == 0 { DHCP_TIMEOUT_MS } else { timeout_ms };
        for _ in 0..timeout {
            self.wait_step();
            if let Some(dns) = self.dns_server { if self.iface.ipv4_addr().is_some() { return Ok(dns); } }
        }
        Err(if self.iface.ipv4_addr().is_some() { SnpNetworkError::NoDnsServer } else { SnpNetworkError::DhcpTimeout })
    }

    fn allocate_local_port(&mut self) -> u16 {
        let p = self.next_local_port;
        self.next_local_port = if p >= 65_535 { 49_152 } else { p + 1 };
        p
    }

    pub fn connect_tcp(&mut self, destination: Ipv4Addr, port: u16, timeout_ms: u64) -> Result<SocketHandle, SnpNetworkError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        let local_port = self.allocate_local_port();
        let result = {
            let context = self.iface.context();
            self.sockets.get_mut::<tcp::Socket>(handle).connect(context, (destination, port), local_port)
        };
        if result.is_err() { let _ = self.sockets.remove(handle); return Err(SnpNetworkError::TcpNetwork); }
        let timeout = if timeout_ms == 0 { 15_000 } else { timeout_ms };
        for _ in 0..timeout {
            self.wait_step();
            let socket = self.sockets.get::<tcp::Socket>(handle);
            if socket.may_send() { return Ok(handle); }
            if !socket.is_active() { let _ = self.sockets.remove(handle); return Err(SnpNetworkError::TcpNetwork); }
        }
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        let _ = self.sockets.remove(handle);
        Err(SnpNetworkError::TcpConnectTimeout)
    }
}

impl UdpDnsTransport for SnpNetwork {
    fn exchange(&mut self, resolver: Ipv4Addr, port: u16, query: &[u8], output: &mut [u8], timeout_ms: u64) -> Result<usize, DnsIoError> {
        if query.is_empty() || query.len() > UDP_BUFFER_SIZE || output.is_empty() || port == 0 { return Err(DnsIoError::InvalidDatagram); }
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_BUFFER_SIZE]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_BUFFER_SIZE]);
        let mut socket = udp::Socket::new(rx, tx);
        let local_port = self.allocate_local_port();
        socket.bind(local_port).map_err(|_| DnsIoError::Network)?;
        let handle = self.sockets.add(socket);
        if self.sockets.get_mut::<udp::Socket>(handle).send_slice(query, IpEndpoint::new(IpAddress::Ipv4(resolver), port)).is_err() {
            let _ = self.sockets.remove(handle); return Err(DnsIoError::Network);
        }
        let timeout = if timeout_ms == 0 { 3_000 } else { timeout_ms };
        let mut answer = Err(DnsIoError::Timeout);
        for _ in 0..timeout {
            self.wait_step();
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                match socket.recv_slice(output) {
                    Ok((n, meta)) if meta.endpoint.addr == IpAddress::Ipv4(resolver) && meta.endpoint.port == port => { answer = Ok(n); break; }
                    Ok(_) => {}
                    Err(udp::RecvError::Truncated) => { answer = Err(DnsIoError::InvalidDatagram); break; }
                    Err(udp::RecvError::Exhausted) => {}
                }
            }
        }
        let _ = self.sockets.remove(handle);
        answer
    }
}

pub struct SnpTcpStream { network: SnpNetwork, socket: SocketHandle, timeout_ms: u64, closed: bool }
impl SnpTcpStream {
    pub fn new(network: SnpNetwork, socket: SocketHandle, timeout_ms: u64) -> Self {
        Self { network, socket, timeout_ms: if timeout_ms == 0 { 15_000 } else { timeout_ms }, closed: false }
    }
}
impl crate::tls::TlsStreamIo for SnpTcpStream {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if self.closed { return Err(()); }
        if bytes.is_empty() { return Ok(0); }
        for _ in 0..self.timeout_ms {
            let n = {
                let socket = self.network.sockets.get_mut::<tcp::Socket>(self.socket);
                if !socket.may_send() { return Err(()); }
                if socket.can_send() { socket.send_slice(bytes).unwrap_or(0) } else { 0 }
            };
            if n > 0 { return Ok(n); }
            self.network.wait_step();
        }
        Err(())
    }
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if self.closed || output.is_empty() { return Ok(0); }
        for _ in 0..self.timeout_ms {
            let (n, done) = {
                let socket = self.network.sockets.get_mut::<tcp::Socket>(self.socket);
                if socket.can_recv() { (socket.recv_slice(output).unwrap_or(0), false) }
                else { (0, !socket.may_recv()) }
            };
            if n > 0 { return Ok(n); }
            if done { return Ok(0); }
            self.network.wait_step();
        }
        Err(())
    }
}
impl Drop for SnpTcpStream {
    fn drop(&mut self) {
        if self.closed { return; }
        self.network.sockets.get_mut::<tcp::Socket>(self.socket).close();
        for _ in 0..1_000 {
            self.network.wait_step();
            if self.network.sockets.get::<tcp::Socket>(self.socket).state() == tcp::State::Closed { break; }
        }
        let _ = self.network.sockets.remove(self.socket);
        self.closed = true;
    }
}
