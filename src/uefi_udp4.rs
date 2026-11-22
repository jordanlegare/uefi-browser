//! EFI_UDP4_PROTOCOL transport for the Hickory DNS client.
//!
//! The pinned uefi-raw release does not currently expose UDP4 bindings, so this
//! module defines the small UEFI 2.11 ABI surface needed by the DNS transport.
//! Hickory remains responsible for DNS encoding and parsing; this module only
//! sends/receives UDP datagrams through the firmware network stack.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::net::Ipv4Addr;
use core::ptr;
use core::ptr::NonNull;
use core::time::Duration;

use uefi::boot::{self, EventType, ScopedProtocol, Tpl};
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::unsafe_protocol;
use uefi::{
    Event, Handle, Status,
    boot::{OpenProtocolAttributes, OpenProtocolParams},
};
use uefi_raw::Boolean;
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::protocol::network::ip4_config2::Ip4Config2DataType;
use uefi_raw::time::Time;
use uefi_raw::{Guid, Ipv4Address};

use crate::dns::{DNS_PORT, DnsIoError, UdpDnsTransport};
use crate::entropy::SecureRandom;
use crate::firmware_rng::UefiRandom;

const UDP4_SERVICE_BINDING_GUID: Guid = uefi::guid!("83f01464-99bd-45e5-b383-af6305d8e9e6");
const UDP4_PROTOCOL_GUID: Guid = uefi::guid!("3ad9df29-4501-478d-b1f8-7f7fe70e50f3");
const MAX_DNS_FRAGMENTS: usize = 16;
const DEFAULT_TIMEOUT_MS: u64 = 2500;

/// Firmware service binding wrapper for UDP4 child creation.
#[derive(Debug)]
#[repr(transparent)]
#[unsafe_protocol(UDP4_SERVICE_BINDING_GUID)]
struct Udp4Binding(ServiceBindingProtocol);

/// Minimal UEFI UDP4 protocol ABI used by this driver.
#[derive(Debug)]
#[repr(C)]
struct Udp4Protocol {
    get_mode_data: unsafe extern "efiapi" fn(
        this: *mut Self,
        config: *mut Udp4ConfigData,
        ip4_mode: *mut c_void,
        mnp_mode: *mut c_void,
        snp_mode: *mut c_void,
    ) -> Status,
    configure: unsafe extern "efiapi" fn(this: *mut Self, config: *const Udp4ConfigData) -> Status,
    groups: unsafe extern "efiapi" fn(
        this: *mut Self,
        join: Boolean,
        group: *const Ipv4Address,
    ) -> Status,
    routes: unsafe extern "efiapi" fn(
        this: *mut Self,
        delete_route: Boolean,
        subnet: *const Ipv4Address,
        mask: *const Ipv4Address,
        gateway: *const Ipv4Address,
    ) -> Status,
    transmit: unsafe extern "efiapi" fn(this: *mut Self, token: *mut Udp4CompletionToken) -> Status,
    receive: unsafe extern "efiapi" fn(this: *mut Self, token: *mut Udp4CompletionToken) -> Status,
    cancel: unsafe extern "efiapi" fn(this: *mut Self, token: *mut Udp4CompletionToken) -> Status,
    poll: unsafe extern "efiapi" fn(this: *mut Self) -> Status,
}

#[derive(Debug)]
#[repr(transparent)]
#[unsafe_protocol(UDP4_PROTOCOL_GUID)]
struct Udp4(Udp4Protocol);

#[derive(Debug)]
#[repr(C)]
struct Udp4ConfigData {
    accept_broadcast: Boolean,
    accept_promiscuous: Boolean,
    accept_any_port: Boolean,
    allow_duplicate_port: Boolean,
    type_of_service: u8,
    time_to_live: u8,
    do_not_fragment: Boolean,
    receive_timeout: u32,
    transmit_timeout: u32,
    use_default_address: Boolean,
    station_address: Ipv4Address,
    subnet_mask: Ipv4Address,
    station_port: u16,
    remote_address: Ipv4Address,
    remote_port: u16,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct Udp4SessionData {
    source_address: Ipv4Address,
    source_port: u16,
    destination_address: Ipv4Address,
    destination_port: u16,
}

#[derive(Debug)]
#[repr(C)]
struct Udp4FragmentData {
    fragment_length: u32,
    fragment_buffer: *mut u8,
}

#[derive(Debug)]
#[repr(C)]
struct Udp4TransmitData {
    session: *mut Udp4SessionData,
    gateway_address: *mut Ipv4Address,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [Udp4FragmentData; 0],
}

#[derive(Debug)]
#[repr(C)]
struct Udp4ReceiveData {
    timestamp: Time,
    recycle_signal: uefi_raw::Event,
    session: Udp4SessionData,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [Udp4FragmentData; 1],
}

#[repr(C)]
union Udp4Packet {
    rx_data: *mut Udp4ReceiveData,
    tx_data: *mut Udp4TransmitData,
}

#[repr(C)]
struct Udp4CompletionToken {
    event: uefi_raw::Event,
    status: Status,
    packet: Udp4Packet,
}

#[repr(C)]
struct Udp4TxPacket {
    header: Udp4TransmitData,
    fragment: Udp4FragmentData,
}

/// DNS-over-UDP4 implementation using a firmware UDP4 child instance.
#[derive(Debug, Default)]
pub struct UefiUdp4Transport;

impl UdpDnsTransport for UefiUdp4Transport {
    fn exchange(
        &mut self,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError> {
        if query.is_empty() || query.len() > 512 || port == 0 || output.is_empty() {
            return Err(DnsIoError::InvalidDatagram);
        }

        let handles = boot::find_handles::<Udp4Binding>().map_err(|_| DnsIoError::Network)?;
        let mut last_error = DnsIoError::Network;

        for controller in handles.iter().copied() {
            match self.exchange_on_controller(
                controller,
                resolver,
                port,
                query,
                output,
                if timeout_ms == 0 {
                    DEFAULT_TIMEOUT_MS
                } else {
                    timeout_ms
                },
            ) {
                Ok(length) => return Ok(length),
                Err(error) => last_error = error,
            }
        }

        Err(last_error)
    }
}

impl UefiUdp4Transport {
    fn exchange_on_controller(
        &mut self,
        controller: Handle,
        resolver: Ipv4Addr,
        port: u16,
        query: &[u8],
        output: &mut [u8],
        timeout_ms: u64,
    ) -> Result<usize, DnsIoError> {
        // SAFETY: GetProtocol opens the controller's UDP4 service binding.
        let mut binding = unsafe {
            boot::open_protocol::<Udp4Binding>(
                OpenProtocolParams {
                    handle: controller,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|_| DnsIoError::Network)?;

        let mut child_ptr = ptr::null_mut();
        // SAFETY: The service-binding pointer is valid and child_ptr is an out pointer.
        let status = unsafe { (binding.0.create_child)(&mut binding.0, &mut child_ptr) };
        if status != Status::SUCCESS {
            return Err(map_status(status));
        }
        // SAFETY: successful CreateChild returns a non-null handle.
        let child = unsafe { Handle::from_ptr(child_ptr) }.ok_or(DnsIoError::Network)?;

        // SAFETY: child was created by this service-binding instance.
        let protocol_result = unsafe {
            boot::open_protocol::<Udp4>(
                OpenProtocolParams {
                    handle: child,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let mut protocol = match protocol_result {
            Ok(protocol) => protocol,
            Err(_) => {
                // SAFETY: Destroy the just-created child after OpenProtocol failed.
                let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
                return Err(DnsIoError::Network);
            }
        };

        let mut rng = UefiRandom::open().map_err(|_| DnsIoError::Network)?;
        let mut random_port_bytes = [0u8; 2];
        rng.fill_bytes(&mut random_port_bytes)
            .map_err(|_| DnsIoError::Network)?;
        let station_port = 49_152u16 + (u16::from_be_bytes(random_port_bytes) % 16_384);

        let remote = Ipv4Address(resolver.octets());
        let config = Udp4ConfigData {
            accept_broadcast: Boolean::FALSE,
            accept_promiscuous: Boolean::FALSE,
            accept_any_port: Boolean::FALSE,
            allow_duplicate_port: Boolean::FALSE,
            type_of_service: 0,
            time_to_live: 64,
            do_not_fragment: Boolean::TRUE,
            receive_timeout: 0,
            transmit_timeout: 0,
            use_default_address: Boolean::TRUE,
            station_address: Ipv4Address([0; 4]),
            subnet_mask: Ipv4Address([0; 4]),
            station_port,
            remote_address: remote,
            remote_port: port,
        };

        // SAFETY: config remains live for Configure.
        let status = unsafe { (protocol.0.configure)(&mut protocol.0, &config) };
        if status != Status::SUCCESS {
            drop(protocol);
            // SAFETY: the child remains owned by this binding.
            let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
            return Err(map_status(status));
        }

        let receive_events = create_completion_events()?;
        let transmit_events = create_completion_events()?;

        let mut receive_token = Udp4CompletionToken {
            event: receive_events.notify_ptr(),
            status: Status::NOT_READY,
            packet: Udp4Packet {
                rx_data: ptr::null_mut(),
            },
        };
        let receive_status = unsafe { (protocol.0.receive)(&mut protocol.0, &mut receive_token) };
        if receive_status != Status::SUCCESS {
            drop(protocol);
            let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
            return Err(map_status(receive_status));
        }

        let mut session = Udp4SessionData {
            source_address: Ipv4Address([0; 4]),
            source_port: 0,
            destination_address: remote,
            destination_port: port,
        };
        let mut tx_packet = Udp4TxPacket {
            header: Udp4TransmitData {
                session: &mut session,
                gateway_address: ptr::null_mut(),
                data_length: query.len() as u32,
                fragment_count: 1,
                fragment_table: [],
            },
            fragment: Udp4FragmentData {
                fragment_length: query.len() as u32,
                fragment_buffer: query.as_ptr().cast_mut(),
            },
        };
        let mut transmit_token = Udp4CompletionToken {
            event: transmit_events.notify_ptr(),
            status: Status::NOT_READY,
            packet: Udp4Packet {
                tx_data: ptr::addr_of_mut!(tx_packet.header),
            },
        };

        // SAFETY: tx packet, session, and input query remain live until the
        // transmit completion event has been signaled.
        let transmit_status =
            unsafe { (protocol.0.transmit)(&mut protocol.0, &mut transmit_token) };
        if transmit_status != Status::SUCCESS {
            cancel_receive_and_drain(
                &mut protocol,
                &mut receive_token,
                receive_events.wait_event(),
            );
            drop(protocol);
            let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
            return Err(map_status(transmit_status));
        }

        let mut elapsed_us = 0u64;
        let timeout_us = timeout_ms.max(1).saturating_mul(1000);
        let mut rx_complete = false;
        let mut tx_complete = false;

        while elapsed_us < timeout_us {
            // SAFETY: protocol remains open for the operation lifetime.
            let _ = unsafe { (protocol.0.poll)(&mut protocol.0) };

            if !tx_complete {
                tx_complete = boot::check_event(transmit_events.wait_event()).unwrap_or(false);
                if tx_complete && transmit_token.status != Status::SUCCESS {
                    cancel_receive_and_drain(
                        &mut protocol,
                        &mut receive_token,
                        receive_events.wait_event(),
                    );
                    drop(protocol);
                    let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
                    return Err(map_status(transmit_token.status));
                }
            }

            if !rx_complete {
                rx_complete = boot::check_event(receive_events.wait_event()).unwrap_or(false);
                if rx_complete && receive_token.status != Status::SUCCESS {
                    drop(protocol);
                    let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
                    return Err(map_status(receive_token.status));
                }
            }

            if rx_complete && tx_complete {
                break;
            }

            let step = core::cmp::min(1000, timeout_us - elapsed_us);
            let _ = boot::stall(Duration::from_micros(step));
            elapsed_us += step;
        }

        if !rx_complete || !tx_complete {
            if !rx_complete {
                cancel_receive_and_drain(
                    &mut protocol,
                    &mut receive_token,
                    receive_events.wait_event(),
                );
            }
            if !tx_complete {
                cancel_transmit_and_drain(
                    &mut protocol,
                    &mut transmit_token,
                    transmit_events.wait_event(),
                );
            }
            drop(protocol);
            let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
            return Err(DnsIoError::Timeout);
        }

        // SAFETY: a successful receive token provides the driver-owned RxData.
        let rx_data = unsafe { receive_token.packet.rx_data };
        if rx_data.is_null() {
            drop(protocol);
            let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };
            return Err(DnsIoError::InvalidDatagram);
        }

        // Copy data while the receive buffer is owned by the UDP driver, then
        // signal its recycle event exactly once.
        let received = unsafe { copy_and_recycle(rx_data, resolver, port, output) };

        drop(protocol);
        let _ = unsafe { (binding.0.destroy_child)(&mut binding.0, child.as_ptr()) };

        received
    }
}

unsafe fn copy_and_recycle(
    rx: *mut Udp4ReceiveData,
    expected_address: Ipv4Addr,
    expected_port: u16,
    output: &mut [u8],
) -> Result<usize, DnsIoError> {
    // SAFETY: rx comes from a successful EFI_UDP4_PROTOCOL receive token.
    let packet = unsafe { &*rx };
    let source = Ipv4Addr::from(packet.session.source_address.0);
    let source_port = packet.session.source_port;
    let mut result = Err(DnsIoError::InvalidDatagram);

    if source == expected_address
        && source_port == expected_port
        && packet.data_length as usize <= output.len()
        && packet.fragment_count > 0
        && (packet.fragment_count as usize) <= MAX_DNS_FRAGMENTS
    {
        // SAFETY: The driver-provided packet contains fragment_count descriptors.
        let fragments = unsafe {
            core::slice::from_raw_parts(
                packet.fragment_table.as_ptr(),
                packet.fragment_count as usize,
            )
        };

        let mut offset = 0usize;
        let mut valid = true;
        for fragment in fragments {
            let length = fragment.fragment_length as usize;
            if fragment.fragment_buffer.is_null()
                || offset.checked_add(length).is_none()
                || offset + length > output.len()
            {
                valid = false;
                break;
            }
            // SAFETY: The fragment pointer and length are supplied by the live
            // driver-owned RxData object and are consumed before recycle.
            let bytes = unsafe { core::slice::from_raw_parts(fragment.fragment_buffer, length) };
            output[offset..offset + length].copy_from_slice(bytes);
            offset += length;
        }

        if valid && offset == packet.data_length as usize {
            result = Ok(offset);
        }
    }

    // Signal recycling even for rejected packets. This releases the driver's
    // receive buffers and prevents exhausting firmware network memory.
    if let Some(recycle) = unsafe { Event::from_ptr(packet.recycle_signal) } {
        let _ = boot::signal_event(&recycle);
    }

    result
}

/// UEFI requires UDP4 completion tokens to reference EVT_NOTIFY_SIGNAL
/// events. A paired plain event is signalled by the notification callback so
/// the application can poll it with CheckEvent.
struct CompletionEvents {
    notify: Option<Event>,
    wait: Option<Event>,
}

impl CompletionEvents {
    fn notify_ptr(&self) -> uefi_raw::Event {
        self.notify.as_ref().expect("notify event is live").as_ptr()
    }

    fn wait_event(&self) -> &Event {
        self.wait.as_ref().expect("wait event is live")
    }
}

impl Drop for CompletionEvents {
    fn drop(&mut self) {
        if let Some(event) = self.notify.take() {
            let _ = boot::close_event(event);
        }
        if let Some(event) = self.wait.take() {
            let _ = boot::close_event(event);
        }
    }
}

fn create_completion_events() -> Result<CompletionEvents, DnsIoError> {
    let wait = unsafe { boot::create_event(EventType::empty(), Tpl::APPLICATION, None, None) }
        .map_err(|_| DnsIoError::Network)?;
    let context = NonNull::new(wait.as_ptr()).ok_or(DnsIoError::Network)?;
    let notify = match unsafe {
        boot::create_event(
            EventType::NOTIFY_SIGNAL,
            Tpl::CALLBACK,
            Some(signal_completion_event),
            Some(context),
        )
    } {
        Ok(event) => event,
        Err(_) => {
            let _ = boot::close_event(wait);
            return Err(DnsIoError::Network);
        }
    };

    Ok(CompletionEvents {
        notify: Some(notify),
        wait: Some(wait),
    })
}

unsafe extern "efiapi" fn signal_completion_event(_event: Event, context: Option<NonNull<c_void>>) {
    let Some(context) = context else {
        return;
    };
    // SAFETY: context points to the paired plain wait event. CompletionEvents
    // closes the notify event before it closes the wait event.
    if let Some(event) = unsafe { Event::from_ptr(context.as_ptr()) } {
        let _ = boot::signal_event(&event);
    }
}

fn wait_for_event(
    udp: &mut ScopedProtocol<Udp4>,
    event: &Event,
    timeout_ms: u64,
) -> Result<(), DnsIoError> {
    let timeout_us = timeout_ms.max(1).saturating_mul(1000);
    let mut elapsed = 0u64;
    loop {
        if boot::check_event(event).map_err(|_| DnsIoError::Network)? {
            return Ok(());
        }
        // SAFETY: protocol remains open and the pending token is live.
        let _ = unsafe { (udp.0.poll)(&mut udp.0) };
        if elapsed >= timeout_us {
            return Err(DnsIoError::Timeout);
        }
        let step = core::cmp::min(1000, timeout_us - elapsed);
        let _ = boot::stall(Duration::from_micros(step));
        elapsed += step;
    }
}

fn cancel_receive_and_drain(
    udp: &mut ScopedProtocol<Udp4>,
    token: &mut Udp4CompletionToken,
    wait_event: &Event,
) {
    // SAFETY: token is still live and was submitted to this protocol.
    let _ = unsafe { (udp.0.cancel)(&mut udp.0, token) };
    drain_token(udp, wait_event);
}

fn cancel_transmit_and_drain(
    udp: &mut ScopedProtocol<Udp4>,
    token: &mut Udp4CompletionToken,
    wait_event: &Event,
) {
    // SAFETY: token is still live and was submitted to this protocol.
    let _ = unsafe { (udp.0.cancel)(&mut udp.0, token) };
    drain_token(udp, wait_event);
}

fn drain_token(udp: &mut ScopedProtocol<Udp4>, event: &Event) {
    loop {
        if boot::check_event(event).unwrap_or(false) {
            return;
        }
        // SAFETY: protocol remains open until token completion.
        let _ = unsafe { (udp.0.poll)(&mut udp.0) };
        let _ = boot::stall(Duration::from_micros(1_000));
    }
}

fn map_status(status: Status) -> DnsIoError {
    if status == Status::TIMEOUT {
        DnsIoError::Timeout
    } else {
        DnsIoError::Network
    }
}

/// Discover recursive DNS servers recorded by EFI IPv4 Config2 (normally
/// populated by DHCP). The returned addresses are ordered as firmware reports.
pub fn discover_dns_servers() -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    let Ok(handles) = boot::find_handles::<Ip4Config2>() else {
        return servers;
    };

    for handle in handles.iter().copied() {
        let Ok(mut config) = Ip4Config2::new(handle) else {
            continue;
        };
        let Ok(bytes) = config.get_data(Ip4Config2DataType::DNS_SERVER) else {
            continue;
        };

        for octets in bytes.chunks_exact(4) {
            let address = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
            if !address.is_unspecified()
                && !address.is_broadcast()
                && !address.is_multicast()
                && !servers.contains(&address)
            {
                servers.push(address);
            }
        }
    }

    servers
}

pub fn first_dns_server() -> Option<Ipv4Addr> {
    discover_dns_servers().into_iter().next()
}
