//! Bring up DHCP/IPv4 through the UEFI network stack before opening UDP4/TCP4 children.
//!
//! Some firmware leaves the NIC's driver stack disconnected until an application
//! asks Boot Services to connect the network controller. Discovering
//! EFI_IP4_CONFIG2_PROTOCOL before that step can therefore produce a false
//! "missing protocol" result even when a usable NIC driver is present.

use alloc::vec::Vec;
use core::net::Ipv4Addr;
use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::Handle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkInitError {
    NoSimpleNetwork,
    NoIp4Config2,
    DhcpFailed,
    NoDnsServer,
    NoUdp4Binding,
    NoTcp4Binding,
}

/// Discover IPv4 Config2 interfaces, connecting available NIC driver stacks
/// first when firmware has not exposed IPv4 Config2 yet.
fn discover_ip4_config2() -> Result<Vec<Handle>, NetworkInitError> {
    let mut handles = boot::find_handles::<Ip4Config2>().unwrap_or_default();
    if !handles.is_empty() {
        return Ok(handles);
    }

    // EFI_SIMPLE_NETWORK_PROTOCOL is the packet-level NIC interface. Ask UEFI
    // to connect the drivers layered above each NIC; recursive connection lets
    // the firmware bind its managed-network, IP4, DHCP and transport drivers.
    // A failed connect on one adapter must not prevent trying the others.
    let nic_handles =
        boot::find_handles::<SimpleNetwork>().map_err(|_| NetworkInitError::NoSimpleNetwork)?;
    if nic_handles.is_empty() {
        return Err(NetworkInitError::NoSimpleNetwork);
    }

    for controller in nic_handles {
        let _ = boot::connect_controller(controller, &[], None, true);
    }

    handles = boot::find_handles::<Ip4Config2>().unwrap_or_default();
    if handles.is_empty() {
        return Err(NetworkInitError::NoIp4Config2);
    }
    Ok(handles)
}

/// Ask each firmware IPv4 Config2 interface to acquire DHCP configuration,
/// then verify that both transport service bindings and a DNS resolver exist.
pub fn initialize() -> Result<Ipv4Addr, NetworkInitError> {
    let handles = discover_ip4_config2()?;

    let mut configured = false;
    for handle in handles {
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
