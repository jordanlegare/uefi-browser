//! Name-to-TCP-to-TLS integration for UEFI network adapters.
//!
//! DNS is a UDP datagram protocol, not a TLS byte stream. Hickory creates and
//! validates DNS packets; a UEFI UDP4 adapter transports those packets. The
//! resulting IPv4 address is passed to UEFI TCP4. Mbed TLS wraps that TCP byte
//! stream while retaining the original hostname for SNI and X.509 checks.

use alloc::string::String;
use core::net::Ipv4Addr;

use crate::dns::{self, DnsError, UdpDnsTransport};
use crate::entropy::SecureRandom;
use crate::tls::{TlsConnection, TlsError, TlsStreamIo};
use crate::url::{Scheme, Url};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tcp4Error {
    Timeout,
    Network,
    ConnectionRefused,
    NoServiceBinding,
    Firmware(usize),
    ConnectionClosed,
    Unsupported,
}

pub trait Tcp4Connector {
    type Stream: TlsStreamIo;

    /// Connect to the resolved IPv4 endpoint using EFI_TCP4_PROTOCOL.
    /// The implementation must bound connect/read/write waits and close the
    /// TCP child on failure.
    fn connect_tcp4(
        &mut self,
        destination: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> Result<Self::Stream, Tcp4Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectError {
    Dns(DnsError),
    Tcp(Tcp4Error),
    NoDnsServer,
    FirmwareRandomUnavailable,
}

pub struct ConnectedPeer<S> {
    /// Original DNS hostname, retained for TLS SNI and certificate checks.
    pub server_name: String,
    /// Resolved IPv4 address used only for the TCP connection.
    pub address: Ipv4Addr,
    pub port: u16,
    pub scheme: Scheme,
    pub stream: S,
}

impl<S: TlsStreamIo> ConnectedPeer<S> {
    /// Start Mbed TLS over this resolved TCP4 connection.
    ///
    /// The original URL hostname, not the numeric address, is passed to
    /// Mbed TLS. This is essential for SNI and certificate hostname checks.
    pub fn start_tls<'a>(
        &'a mut self,
        ca_bundle_pem: &[u8],
    ) -> Result<TlsConnection<'a, S>, TlsError> {
        if self.scheme != Scheme::Https {
            return Err(TlsError::NotHttps);
        }
        TlsConnection::new(&self.server_name, ca_bundle_pem, &mut self.stream)
    }
}

/// Resolve the URL host with Hickory, connect TCP4 to the numeric address,
/// and preserve the hostname for the subsequent Mbed TLS session.
pub fn connect_url<T, C, R>(
    dns_transport: &mut T,
    tcp4: &mut C,
    random: &mut R,
    dns_server: Ipv4Addr,
    url: &Url,
    timeout_ms: u64,
) -> Result<ConnectedPeer<C::Stream>, ConnectError>
where
    T: UdpDnsTransport,
    C: Tcp4Connector,
    R: SecureRandom,
{
    let address = dns::resolve_a(dns_transport, random, dns_server, &url.host, timeout_ms)
        .map_err(ConnectError::Dns)?;

    let stream = tcp4
        .connect_tcp4(address, url.port, timeout_ms)
        .map_err(ConnectError::Tcp)?;

    Ok(ConnectedPeer {
        server_name: url.host.clone(),
        address,
        port: url.port,
        scheme: url.scheme,
        stream,
    })
}

/// A firmware connection retains its TCP4 stream and original server name.
/// TLS randomness is obtained independently through the TF-PSA EFI_RNG hook.
#[cfg(target_os = "uefi")]
pub struct FirmwareConnection {
    pub peer: ConnectedPeer<crate::uefi_tcp4::Tcp4Stream>,
}

#[cfg(target_os = "uefi")]
impl FirmwareConnection {
    /// Start Mbed TLS over the retained TCP4 stream. TF-PSA obtains entropy
    /// from EFI_RNG_PROTOCOL through mbedtls_platform_get_entropy().
    pub fn start_tls(
        &mut self,
        ca_bundle_pem: &[u8],
    ) -> Result<TlsConnection<'_, crate::uefi_tcp4::Tcp4Stream>, TlsError> {
        self.peer.start_tls(ca_bundle_pem)
    }
}

/// Complete the firmware DNS-to-TCP connection setup.
///
/// DNS server addresses are discovered from EFI IPv4 Config2 (normally
/// provisioned by DHCP). Hickory creates/validates DNS packets, UEFI UDP4
/// transports them, and UEFI TCP4 connects to the resolved A record. The
/// original URL hostname remains on FirmwareConnection for TLS SNI and
/// certificate hostname verification.
#[cfg(target_os = "uefi")]
pub fn connect_firmware_url(
    url: &Url,
    timeout_ms: u64,
) -> Result<FirmwareConnection, ConnectError> {
    let dns_server = crate::uefi_udp4::first_dns_server().ok_or(ConnectError::NoDnsServer)?;
    let mut random = crate::firmware_rng::UefiRandom::open()
        .map_err(|_| ConnectError::FirmwareRandomUnavailable)?;
    let mut dns_transport = crate::uefi_udp4::UefiUdp4Transport;
    let mut tcp4 = crate::uefi_tcp4::UefiTcp4Connector::new();

    let peer = connect_url(
        &mut dns_transport,
        &mut tcp4,
        &mut random,
        dns_server,
        url,
        timeout_ms,
    )?;

    Ok(FirmwareConnection { peer })
}
