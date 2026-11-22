//! Bring up DHCP/IPv4 through EFI IPv4 Config2 before opening UDP4/TCP4 children.

use core::net::Ipv4Addr;
use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkInitError {
    NoIp4Config2,
    DhcpFailed,
    NoDnsServer,
    NoUdp4Binding,
    NoTcp4Binding,
}

/// Ask each firmware IPv4 Config2 interface to acquire DHCP configuration,
/// then verify that both transport service bindings and a DNS resolver exist.
pub fn initialize() -> Result<Ipv4Addr, NetworkInitError> {
    let handles = boot::find_handles::<Ip4Config2>()
        .map_err(|_| NetworkInitError::NoIp4Config2)?;
    if handles.is_empty() {
        return Err(NetworkInitError::NoIp4Config2);
    }

    let mut configured = false;
    for handle in handles.iter().copied() {
        let Ok(mut config) = Ip4Config2::new(handle) else {
            continue;
        };
        if config.ifup().is_ok() {
            configured = true;
        }
    }
    if !configured {
        return Err(NetworkInitError::DhcpFailed);
    }

    if !crate::uefi_udp4::service_binding_available() {
        return Err(NetworkInitError::NoUdp4Binding);
    }
    if !crate::uefi_tcp4::service_binding_available() {
        return Err(NetworkInitError::NoTcp4Binding);
    }

    crate::uefi_udp4::first_dns_server().ok_or(NetworkInitError::NoDnsServer)
}
