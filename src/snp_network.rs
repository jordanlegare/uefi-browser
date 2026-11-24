//! SNP-backed Ethernet device and smoltcp IPv4/DHCP/UDP/TCP runtime.
use crate::dns::{DnsIoError, UdpDnsTransport};
use crate::entropy::SecureRandom;
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

const FRAME_BUFFER_SIZE: usize = 2048;
const DHCP_TIMEOUT_MS: u64 = 60_000;
const TCP_RX_BUFFER: usize = 16 * 1024;
const TCP_TX_BUFFER: usize = 16 * 1024;
const UDP_BUFFER_SIZE: usize = 2048;
const MAX_PENDING_TX_BUFFERS: usize = 16;
const TX_SUBMIT_RETRIES: usize = 100;

/// Counters collected from the SNP and smoltcp request path. The EFI status
/// fields contain the raw UEFI status value from the last non-retryable error.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SnpNetworkDiagnostics {
    pub tx_queued: u64,
    pub tx_recycled: u64,
    pub tx_failures: u64,
    pub tx_queue_full: u64,
    pub tx_recycle_errors: u64,
    pub tx_last_status: usize,
    pub rx_frames: u64,
    pub rx_errors: u64,
    pub rx_last_status: usize,
    pub udp_datagrams_sent: u64,
    pub udp_datagrams_received: u64,
    pub udp_timeouts: u64,
    pub tcp_connect_attempts: u64,
    pub tcp_connect_failures: u64,
    pub tcp_connect_timeouts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnpNetworkError {
    NoSimpleNetwork,
    NicStartFailed,
    NicInitializeFailed,
    InvalidMacAddress,
    NoEthernetLink,
    UnsupportedMtu,
    ReceiveFilterFailed,
    EntropyUnavailable,
    DhcpTimeout,
    NoDnsServer,
    DnsTimeout,
    DnsNetwork,
    DnsInvalidDatagram,
    TcpConnectTimeout,
    TcpNetwork,
}

struct SnpRxToken(Vec<u8>);
impl RxToken for SnpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct SnpTxToken<'a>(&'a mut SnpDevice);
impl TxToken for SnpTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        if frame.len() < 60 {
            frame.resize(60, 0);
        }
        self.0.queue_transmit(frame);
        result
    }
}

struct SnpDevice {
    snp: ScopedProtocol<SimpleNetwork>,
    mtu: usize,
    // UEFI SNP Transmit is asynchronous. Every queued buffer must remain
    // allocated and unchanged until GetStatus returns that exact pointer.
    pending_tx: Vec<Vec<u8>>,
    diagnostics: SnpNetworkDiagnostics,
}

impl SnpDevice {
    fn reclaim_transmit_buffers(&mut self) {
        loop {
            match self.snp.get_recycled_transmit_buffer_status() {
                Ok(Some(recycled)) => {
                    let pointer = recycled.as_ptr();
                    if let Some(index) = self
                        .pending_tx
                        .iter()
                        .position(|frame| frame.as_ptr() == pointer as *const u8)
                    {
                        self.pending_tx.swap_remove(index);
                        self.diagnostics.tx_recycled =
                            self.diagnostics.tx_recycled.saturating_add(1);
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let status = error.status();
                    if status != uefi::Status::NOT_READY {
                        self.diagnostics.tx_recycle_errors =
                            self.diagnostics.tx_recycle_errors.saturating_add(1);
                        self.diagnostics.tx_last_status = status.0;
                    }
                    break;
                }
            }
        }
    }

    fn queue_transmit(&mut self, mut frame: Vec<u8>) {
        self.reclaim_transmit_buffers();
        if self.pending_tx.len() >= MAX_PENDING_TX_BUFFERS {
            self.diagnostics.tx_queue_full = self.diagnostics.tx_queue_full.saturating_add(1);
            return;
        }

        // EFI_NOT_READY means the driver's asynchronous transmit queue is
        // temporarily full. Reap completed buffers and retry while retaining
        // ownership of this frame. Other EFI errors mean the frame was not
        // accepted and can be safely dropped.
        for attempt in 0..TX_SUBMIT_RETRIES {
            match self.snp.transmit(0, &mut frame, None, None, None) {
                Ok(()) => {
                    self.pending_tx.push(frame);
                    self.diagnostics.tx_queued = self.diagnostics.tx_queued.saturating_add(1);
                    return;
                }
                Err(error) => {
                    let status = error.status();
                    self.diagnostics.tx_failures = self.diagnostics.tx_failures.saturating_add(1);
                    self.diagnostics.tx_last_status = status.0;
                    if status != uefi::Status::NOT_READY || attempt + 1 == TX_SUBMIT_RETRIES {
                        return;
                    }
                    self.reclaim_transmit_buffers();
                    boot::stall(Duration::from_millis(1));
                }
            }
        }

        self.diagnostics.tx_queue_full = self.diagnostics.tx_queue_full.saturating_add(1);
    }
}

impl Drop for SnpDevice {
    fn drop(&mut self) {
        // Do not free packet memory while firmware may still be reading it.
        // Wait briefly for normal completion; if a broken driver never
        // recycles a buffer, intentionally leak only those few buffers rather
        // than hand firmware a dangling pointer during application teardown.
        for _ in 0..250 {
            self.reclaim_transmit_buffers();
            if self.pending_tx.is_empty() {
                break;
            }
            boot::stall(Duration::from_millis(1));
        }
        for frame in self.pending_tx.drain(..) {
            core::mem::forget(frame);
        }
    }
}
impl SnpDevice {
    fn open() -> Result<(Self, EthernetAddress), SnpNetworkError> {
        let handles =
            boot::find_handles::<SimpleNetwork>().map_err(|_| SnpNetworkError::NoSimpleNetwork)?;
        let mut last_error = SnpNetworkError::NoSimpleNetwork;

        for handle in handles {
            let params = OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            };
            // SAFETY: Handle was located by the SNP protocol GUID.
            let mut snp = match unsafe {
                boot::open_protocol::<SimpleNetwork>(params, OpenProtocolAttributes::GetProtocol)
            } {
                Ok(p) => p,
                Err(_) => continue,
            };

            if snp.mode().state == NetworkState::STOPPED && snp.start().is_err() {
                last_error = SnpNetworkError::NicStartFailed;
                continue;
            }
            if snp.mode().state != NetworkState::INITIALIZED && snp.initialize(0, 0).is_err() {
                last_error = SnpNetworkError::NicInitializeFailed;
                continue;
            }

            let (hw_address_size, mac, mtu, media_present_supported, media_present) = {
                let mode = snp.mode();
                (
                    mode.hw_address_size,
                    EthernetAddress::from_bytes(&mode.current_address.0[..6]),
                    mode.max_packet_size as usize,
                    mode.media_present_supported == uefi_raw::Boolean::TRUE,
                    mode.media_present == uefi_raw::Boolean::TRUE,
                )
            };

            if hw_address_size != 6 || !mac.is_unicast() || mac.0.iter().all(|b| *b == 0) {
                last_error = SnpNetworkError::InvalidMacAddress;
                continue;
            }
            if media_present_supported && !media_present {
                last_error = SnpNetworkError::NoEthernetLink;
                continue;
            }
            if mtu < 576 {
                last_error = SnpNetworkError::UnsupportedMtu;
                continue;
            }

            // DHCP discovery and ARP require broadcast and unicast reception.
            // Do not require multicast filter support from a NIC that does
            // not implement that optional SNP receive filter.
            if snp
                .receive_filters(
                    ReceiveFlags::UNICAST | ReceiveFlags::BROADCAST,
                    ReceiveFlags::empty(),
                    false,
                    None,
                )
                .is_err()
            {
                last_error = SnpNetworkError::ReceiveFilterFailed;
                continue;
            }

            return Ok((
                Self {
                    snp,
                    mtu,
                    pending_tx: Vec::new(),
                    diagnostics: SnpNetworkDiagnostics::default(),
                },
                mac,
            ));
        }
        Err(last_error)
    }
}
impl Device for SnpDevice {
    type RxToken<'a>
        = SnpRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = SnpTxToken<'a>
    where
        Self: 'a;
    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.reclaim_transmit_buffers();
        if self.pending_tx.len() >= MAX_PENDING_TX_BUFFERS {
            return None;
        }

        let mut frame = vec![0u8; core::cmp::max(FRAME_BUFFER_SIZE, self.mtu + 64)];
        let mut header_size = 0usize;
        match self
            .snp
            .receive(&mut frame, Some(&mut header_size), None, None, None)
        {
            Ok(n) if n >= 14 && n <= frame.len() => {
                frame.truncate(n);
                self.diagnostics.rx_frames = self.diagnostics.rx_frames.saturating_add(1);
                Some((SnpRxToken(frame), SnpTxToken(self)))
            }
            Ok(_) => {
                self.diagnostics.rx_errors = self.diagnostics.rx_errors.saturating_add(1);
                None
            }
            Err(error) => {
                let status = error.status();
                if status != uefi::Status::NOT_READY {
                    self.diagnostics.rx_errors = self.diagnostics.rx_errors.saturating_add(1);
                    self.diagnostics.rx_last_status = status.0;
                }
                None
            }
        }
    }
    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        self.reclaim_transmit_buffers();
        if self.pending_tx.len() >= MAX_PENDING_TX_BUFFERS {
            self.diagnostics.tx_queue_full = self.diagnostics.tx_queue_full.saturating_add(1);
            return None;
        }
        Some(SnpTxToken(self))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
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
        random
            .fill_bytes(&mut seed)
            .map_err(|_| SnpNetworkError::EntropyUnavailable)?;
        random
            .fill_bytes(&mut port)
            .map_err(|_| SnpNetworkError::EntropyUnavailable)?;
        let mut config = Config::new(HardwareAddress::Ethernet(mac));
        config.random_seed = u64::from_le_bytes(seed);
        let mut device = device;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        let mut sockets = SocketSet::new(Vec::new());
        let dhcp_handle = sockets.add(dhcpv4::Socket::new());
        iface.update_ip_addrs(|addrs| addrs.clear());
        Ok(Self {
            device,
            iface,
            sockets,
            dhcp_handle,
            dns_server: None,
            now_ms: 0,
            next_local_port: 49_152 + (u16::from_be_bytes(port) % 16_384),
        })
    }

    fn poll_once(&mut self) {
        let _ = self.iface.poll(
            Instant::from_millis(self.now_ms),
            &mut self.device,
            &mut self.sockets,
        );
        self.now_ms = self.now_ms.saturating_add(1);
        self.process_dhcp_event();
    }
    /// Poll the Ethernet/IP stack once. Call this periodically while the
    /// application is waiting for user input so DHCP leases can renew.
    pub fn poll(&mut self) {
        self.poll_once();
    }

    fn wait_step(&mut self) {
        self.poll_once();
        boot::stall(Duration::from_millis(1));
    }

    fn process_dhcp_event(&mut self) {
        enum Update {
            Configured(Ipv4Cidr, Option<Ipv4Addr>, Option<Ipv4Addr>),
            Deconfigured,
        }
        let update = {
            let dhcp = self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp_handle);
            match dhcp.poll() {
                Some(dhcpv4::Event::Configured(c)) => Some(Update::Configured(
                    c.address,
                    c.router,
                    c.dns_servers.first().copied(),
                )),
                Some(dhcpv4::Event::Deconfigured) => Some(Update::Deconfigured),
                None => None,
            }
        };
        match update {
            Some(Update::Configured(addr, router, dns)) => {
                self.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    let _ = addrs.push(IpCidr::Ipv4(addr));
                });
                if let Some(gateway) = router {
                    let _ = self.iface.routes_mut().add_default_ipv4_route(gateway);
                } else {
                    self.iface.routes_mut().remove_default_ipv4_route();
                }
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

    pub fn dns_server(&self) -> Option<Ipv4Addr> {
        self.dns_server
    }

    /// Snapshot packet and request counters for on-screen diagnostics.
    pub fn diagnostics(&self) -> SnpNetworkDiagnostics {
        self.device.diagnostics
    }

    pub fn acquire_dhcp(&mut self, timeout_ms: u64) -> Result<Ipv4Addr, SnpNetworkError> {
        let timeout = if timeout_ms == 0 {
            DHCP_TIMEOUT_MS
        } else {
            timeout_ms
        };
        for _ in 0..timeout {
            self.wait_step();
            if let Some(dns) = self.dns_server {
                if self.iface.ipv4_addr().is_some() {
                    return Ok(dns);
                }
            }
        }
        Err(if self.iface.ipv4_addr().is_some() {
            SnpNetworkError::NoDnsServer
        } else {
            SnpNetworkError::DhcpTimeout
        })
    }

    fn allocate_local_port(&mut self) -> u16 {
        let p = self.next_local_port;
        self.next_local_port = if p >= 65_535 { 49_152 } else { p + 1 };
        p
    }

    pub fn connect_tcp(
        &mut self,
        destination: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> Result<SocketHandle, SnpNetworkError> {
        self.device.diagnostics.tcp_connect_attempts = self
            .device
            .diagnostics
            .tcp_connect_attempts
            .saturating_add(1);
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        let local_port = self.allocate_local_port();
        let result = {
            let context = self.iface.context();
            self.sockets.get_mut::<tcp::Socket>(handle).connect(
                context,
                (destination, port),
                local_port,
            )
        };
        if result.is_err() {
            let _ = self.sockets.remove(handle);
            self.device.diagnostics.tcp_connect_failures = self
                .device
                .diagnostics
                .tcp_connect_failures
                .saturating_add(1);
            return Err(SnpNetworkError::TcpNetwork);
        }
        let timeout = if timeout_ms == 0 { 15_000 } else { timeout_ms };
        for _ in 0..timeout {
            self.wait_step();
            let socket = self.sockets.get::<tcp::Socket>(handle);
            if socket.may_send() {
                return Ok(handle);
            }
            if !socket.is_active() {
                let _ = self.sockets.remove(handle);
                self.device.diagnostics.tcp_connect_failures = self
                    .device
                    .diagnostics
                    .tcp_connect_failures
                    .saturating_add(1);
                return Err(SnpNetworkError::TcpNetwork);
            }
        }
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        let _ = self.sockets.remove(handle);
        self.device.diagnostics.tcp_connect_timeouts = self
            .device
            .diagnostics
            .tcp_connect_timeouts
            .saturating_add(1);
        Err(SnpNetworkError::TcpConnectTimeout)
    }
}

impl UdpDnsTransport for SnpNetwork {
    fn exchange(
        &mut self,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError> {
        if query.is_empty() || query.len() > UDP_BUFFER_SIZE || output.is_empty() || port == 0 {
            return Err(DnsIoError::InvalidDatagram);
        }
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 4],
            vec![0u8; UDP_BUFFER_SIZE],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 4],
            vec![0u8; UDP_BUFFER_SIZE],
        );
        let mut socket = udp::Socket::new(rx, tx);
        let local_port = self.allocate_local_port();
        socket.bind(local_port).map_err(|_| DnsIoError::Network)?;
        let handle = self.sockets.add(socket);
        if self
            .sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(query, IpEndpoint::new(IpAddress::Ipv4(resolver), port))
            .is_err()
        {
            let _ = self.sockets.remove(handle);
            return Err(DnsIoError::Network);
        }
        self.device.diagnostics.udp_datagrams_sent =
            self.device.diagnostics.udp_datagrams_sent.saturating_add(1);
        let timeout = if timeout_ms == 0 { 3_000 } else { timeout_ms };
        let mut answer = Err(DnsIoError::Timeout);
        for _ in 0..timeout {
            self.wait_step();
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                match socket.recv_slice(output) {
                    Ok((n, meta))
                        if meta.endpoint.addr == IpAddress::Ipv4(resolver)
                            && meta.endpoint.port == port =>
                    {
                        answer = Ok(n);
                        break;
                    }
                    Ok(_) => {}
                    Err(udp::RecvError::Truncated) => {
                        answer = Err(DnsIoError::InvalidDatagram);
                        break;
                    }
                    Err(udp::RecvError::Exhausted) => {}
                }
            }
        }
        let _ = self.sockets.remove(handle);
        match answer {
            Ok(_) => {
                self.device.diagnostics.udp_datagrams_received = self
                    .device
                    .diagnostics
                    .udp_datagrams_received
                    .saturating_add(1);
            }
            Err(DnsIoError::Timeout) => {
                self.device.diagnostics.udp_timeouts =
                    self.device.diagnostics.udp_timeouts.saturating_add(1);
            }
            Err(_) => {}
        }
        answer
    }
}

impl UdpDnsTransport for SnpNetwork {
    fn exchange(
        &mut self,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError> {
        if query.is_empty() || query.len() > UDP_BUFFER_SIZE || output.is_empty() || port == 0 {
            return Err(DnsIoError::InvalidDatagram);
        }
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 4],
            vec![0u8; UDP_BUFFER_SIZE],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 4],
            vec![0u8; UDP_BUFFER_SIZE],
        );
        let mut socket = udp::Socket::new(rx, tx);
        let local_port = self.allocate_local_port();
        socket.bind(local_port).map_err(|_| DnsIoError::Network)?;
        let handle = self.sockets.add(socket);
        if self
            .sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(query, IpEndpoint::new(IpAddress::Ipv4(resolver), port))
            .is_err()
        {
            let _ = self.sockets.remove(handle);
            return Err(DnsIoError::Network);
        }
        self.device.diagnostics.udp_datagrams_sent =
            self.device.diagnostics.udp_datagrams_sent.saturating_add(1);
        let timeout = if timeout_ms == 0 { 3_000 } else { timeout_ms };
        let mut answer = Err(DnsIoError::Timeout);
        for _ in 0..timeout {
            self.wait_step();
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                match socket.recv_slice(output) {
                    Ok((n, meta))
                        if meta.endpoint.addr == IpAddress::Ipv4(resolver)
                            && meta.endpoint.port == port =>
                    {
                        answer = Ok(n);
                        break;
                    }
                    Ok(_) => {}
                    Err(udp::RecvError::Truncated) => {
                        answer = Err(DnsIoError::InvalidDatagram);
                        break;
                    }
                    Err(udp::RecvError::Exhausted) => {}
                }
            }
        }
        let _ = self.sockets.remove(handle);
        match answer {
            Ok(_) => {
                self.device.diagnostics.udp_datagrams_received = self
                    .device
                    .diagnostics
                    .udp_datagrams_received
                    .saturating_add(1);
            }
            Err(DnsIoError::Timeout) => {
                self.device.diagnostics.udp_timeouts =
                    self.device.diagnostics.udp_timeouts.saturating_add(1);
            }
            Err(_) => {}
        }
        answer
    }

    fn exchange_tcp(
        &mut self,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError> {
        if query.is_empty() || query.len() > u16::MAX as usize || output.is_empty() || port == 0 {
            return Err(DnsIoError::InvalidDatagram);
        }
        let handle = self
            .connect_tcp(resolver, port, timeout_ms)
            .map_err(|error| match error {
                SnpNetworkError::TcpConnectTimeout => DnsIoError::Timeout,
                _ => DnsIoError::Network,
            })?;
        let mut stream = SnpTcpStream::new(self, handle, timeout_ms);
        let length_prefix = (query.len() as u16).to_be_bytes();
        let mut frame_offset = 0usize;
        let frame_parts = [&length_prefix[..], query];
        for part in frame_parts {
            let mut sent = 0usize;
            while sent < part.len() {
                let count = crate::tls::TlsStreamIo::send(&mut stream, &part[sent..])
                    .map_err(|_| DnsIoError::Timeout)?;
                if count == 0 || count > part.len() - sent {
                    return Err(DnsIoError::Network);
                }
                sent += count;
                frame_offset = frame_offset.saturating_add(count);
            }
        }
        let expected_frame = query.len().saturating_add(length_prefix.len());
        if frame_offset != expected_frame {
            return Err(DnsIoError::Network);
        }

        let mut response_prefix = [0u8; 2];
        let mut prefix_read = 0usize;
        while prefix_read < response_prefix.len() {
            let count = crate::tls::TlsStreamIo::receive(
                &mut stream,
                &mut response_prefix[prefix_read..],
            )
            .map_err(|_| DnsIoError::Timeout)?;
            if count == 0 || count > response_prefix.len() - prefix_read {
                return Err(DnsIoError::InvalidDatagram);
            }
            prefix_read += count;
        }
        let message_length = usize::from(u16::from_be_bytes(response_prefix));
        if message_length < 12 || message_length > output.len() {
            return Err(DnsIoError::InvalidDatagram);
        }

        let mut received = 0usize;
        while received < message_length {
            let count = crate::tls::TlsStreamIo::receive(
                &mut stream,
                &mut output[received..message_length],
            )
            .map_err(|_| DnsIoError::Timeout)?;
            if count == 0 || count > message_length - received {
                return Err(DnsIoError::InvalidDatagram);
            }
            received += count;
        }
        Ok(message_length)
    }
}

pub struct SnpTcpStream<'a> {
    network: &'a mut SnpNetwork,
    socket: SocketHandle,
    timeout_ms: u64,
    closed: bool,
}
impl<'a> SnpTcpStream<'a> {
    pub fn new(network: &'a mut SnpNetwork, socket: SocketHandle, timeout_ms: u64) -> Self {
        Self {
            network,
            socket,
            timeout_ms: if timeout_ms == 0 { 15_000 } else { timeout_ms },
            closed: false,
        }
    }

    /// Set the maximum wait for an individual blocking stream operation.
    /// TLS uses a shorter value so an unresponsive peer cannot pin the
    /// firmware console indefinitely during its handshake.
    pub fn set_io_timeout_ms(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms.max(1);
    }
}
impl crate::tls::TlsStreamIo for SnpTcpStream<'_> {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if self.closed {
            return Err(());
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        for _ in 0..self.timeout_ms {
            let n = {
                let socket = self.network.sockets.get_mut::<tcp::Socket>(self.socket);
                if !socket.may_send() {
                    return Err(());
                }
                if socket.can_send() {
                    socket.send_slice(bytes).unwrap_or(0)
                } else {
                    0
                }
            };
            if n > 0 {
                return Ok(n);
            }
            self.network.wait_step();
        }
        Err(())
    }
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if self.closed || output.is_empty() {
            return Ok(0);
        }
        for _ in 0..self.timeout_ms {
            let (n, done) = {
                let socket = self.network.sockets.get_mut::<tcp::Socket>(self.socket);
                if socket.can_recv() {
                    (socket.recv_slice(output).unwrap_or(0), false)
                } else {
                    (0, !socket.may_recv())
                }
            };
            if n > 0 {
                return Ok(n);
            }
            if done {
                return Ok(0);
            }
            self.network.wait_step();
        }
        // This timeout occurs beneath the Mbed TLS BIO callback. Defer
        // diagnostics until the handshake unwinds to the Rust caller.
        Err(())
    }
}
impl Drop for SnpTcpStream<'_> {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.network
            .sockets
            .get_mut::<tcp::Socket>(self.socket)
            .close();
        for _ in 0..1_000 {
            self.network.wait_step();
            if self.network.sockets.get::<tcp::Socket>(self.socket).state() == tcp::State::Closed {
                break;
            }
        }
        let _ = self.network.sockets.remove(self.socket);
        self.closed = true;
    }
}
