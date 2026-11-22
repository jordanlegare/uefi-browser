//! Concrete EFI_TCP4_PROTOCOL connector and byte-stream implementation.
//!
//! Each connection owns a TCP4 service-binding child. UEFI asynchronous
//! completion tokens are drained before their backing buffers/events are
//! released. TCP send/receive operations are bounded and actively poll the
//! firmware stack while waiting.

use core::ffi::c_void;
use core::net::Ipv4Addr;
use core::ptr;
use core::ptr::NonNull;
use core::time::Duration;

use uefi::boot::{self, EventType, ScopedProtocol, Tpl};
use uefi::proto::unsafe_protocol;
use uefi::{
    Handle, Status,
    boot::{OpenProtocolAttributes, OpenProtocolParams},
};
use uefi_raw::Boolean;
use uefi_raw::Ipv4Address;
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::protocol::network::tcp4::{
    Tcp4AccessPoint, Tcp4CloseToken, Tcp4CompletionToken, Tcp4ConfigData, Tcp4ConnectionToken,
    Tcp4FragmentData, Tcp4IoToken, Tcp4Option, Tcp4Packet, Tcp4Protocol, Tcp4ReceiveData,
    Tcp4TransmitData,
};

use crate::network::{Tcp4Connector, Tcp4Error};
use crate::tls::TlsStreamIo;

const DEFAULT_IO_TIMEOUT_MS: u64 = 15_000;
const MAX_TCP_SEGMENT: usize = 16 * 1024;
const RX_BUFFER_SIZE: usize = 16 * 1024;

/// TCP4 service-binding protocol used to create per-connection child handles.
#[derive(Debug)]
#[repr(transparent)]
#[unsafe_protocol(Tcp4Protocol::SERVICE_BINDING_GUID)]
struct Tcp4Binding(ServiceBindingProtocol);

/// TCP4 data protocol installed on a service-binding child.
#[derive(Debug)]
#[repr(transparent)]
#[unsafe_protocol(Tcp4Protocol::GUID)]
struct Tcp4(Tcp4Protocol);

impl Tcp4Binding {
    fn create_child(&mut self) -> Result<Handle, Tcp4Error> {
        let mut child = ptr::null_mut();
        // SAFETY: The service-binding interface is live and child is a valid out pointer.
        let status = unsafe { (self.0.create_child)(&mut self.0, &mut child) };
        if status != Status::SUCCESS {
            return Err(firmware_error(status));
        }
        // SAFETY: Successful CreateChild must return a valid non-null handle.
        unsafe { Handle::from_ptr(child) }.ok_or(Tcp4Error::Firmware(0))
    }

    fn destroy_child(&mut self, child: Handle) {
        // SAFETY: child was created by this exact service-binding instance.
        let _ = unsafe { (self.0.destroy_child)(&mut self.0, child.as_ptr()) };
    }
}

/// Connector that discovers TCP4 service bindings exposed by firmware.
#[derive(Debug)]
pub struct UefiTcp4Connector {
    io_timeout_ms: u64,
}

impl Default for UefiTcp4Connector {
    fn default() -> Self {
        Self::new()
    }
}

impl UefiTcp4Connector {
    pub const fn new() -> Self {
        Self {
            io_timeout_ms: DEFAULT_IO_TIMEOUT_MS,
        }
    }

    pub const fn with_io_timeout_ms(timeout_ms: u64) -> Self {
        Self {
            io_timeout_ms: timeout_ms,
        }
    }

    fn connect_on_handle(
        &mut self,
        controller: Handle,
        destination: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> Result<Tcp4Stream, Tcp4Error> {
        // SAFETY: GetProtocol is used to access the service-binding interface.
        let mut binding = unsafe {
            boot::open_protocol::<Tcp4Binding>(
                OpenProtocolParams {
                    handle: controller,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|_| Tcp4Error::NoServiceBinding)?;

        let child = binding.create_child()?;
        // SAFETY: The child handle was just created by this binding.
        let tcp_result = unsafe {
            boot::open_protocol::<Tcp4>(
                OpenProtocolParams {
                    handle: child,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        };
        let mut tcp = match tcp_result {
            Ok(protocol) => protocol,
            Err(_) => {
                binding.destroy_child(child);
                return Err(Tcp4Error::NoServiceBinding);
            }
        };

        let config = Tcp4ConfigData {
            type_of_service: 0,
            time_to_live: 64,
            access_point: Tcp4AccessPoint {
                use_default_address: Boolean::TRUE,
                station_address: Ipv4Address([0; 4]),
                subnet_mask: Ipv4Address([0; 4]),
                station_port: 0,
                remote_address: Ipv4Address(destination.octets()),
                remote_port: port,
                active_flag: Boolean::TRUE,
            },
            control_option: ptr::null_mut::<Tcp4Option>(),
        };

        // SAFETY: config stays live for the duration of Configure.
        let status = unsafe { (tcp.0.configure)(&mut tcp.0, &config) };
        if status != Status::SUCCESS {
            drop(tcp);
            binding.destroy_child(child);
            return Err(firmware_error(status));
        }

        let events = match create_completion_events() {
            Ok(events) => events,
            Err(error) => {
                drop(tcp);
                binding.destroy_child(child);
                return Err(error);
            }
        };
        let mut token = Tcp4ConnectionToken {
            completion_token: Tcp4CompletionToken {
                event: events.notify_ptr(),
                status: Status::NOT_READY,
            },
        };

        // SAFETY: token and both completion events remain alive until completion/cancellation drains.
        let status = unsafe { (tcp.0.connect)(&mut tcp.0, &mut token) };
        if status != Status::SUCCESS {
            drop(tcp);
            binding.destroy_child(child);
            return Err(firmware_error(status));
        }

        if let Err(error) = wait_for_token(&mut tcp, events.wait_event(), timeout_ms) {
            cancel_connect_and_drain(&mut tcp, &mut token, events.wait_event());
            drop(tcp);
            binding.destroy_child(child);
            return Err(error);
        }

        let completion_status = token.completion_token.status;
        if completion_status != Status::SUCCESS {
            drop(tcp);
            binding.destroy_child(child);
            return Err(firmware_error(completion_status));
        }

        Ok(Tcp4Stream {
            child,
            binding: Some(binding),
            tcp: Some(tcp),
            io_timeout_ms: if timeout_ms == 0 {
                self.io_timeout_ms
            } else {
                timeout_ms
            },
            peer_eof: false,
            closed: false,
        })
    }
}

impl Tcp4Connector for UefiTcp4Connector {
    type Stream = Tcp4Stream;

    fn connect_tcp4(
        &mut self,
        destination: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> Result<Self::Stream, Tcp4Error> {
        if port == 0 {
            return Err(Tcp4Error::Unsupported);
        }

        let handles =
            boot::find_handles::<Tcp4Binding>().map_err(|_| Tcp4Error::NoServiceBinding)?;
        let timeout = if timeout_ms == 0 {
            self.io_timeout_ms
        } else {
            timeout_ms
        };

        let mut last_error = Tcp4Error::NoServiceBinding;
        for handle in handles.iter().copied() {
            match self.connect_on_handle(handle, destination, port, timeout) {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

/// Established TCP4 connection. Dropping it aborts the connection and destroys
/// its service-binding child after protocol operations have been drained.
#[derive(Debug)]
pub struct Tcp4Stream {
    child: Handle,
    binding: Option<ScopedProtocol<Tcp4Binding>>,
    tcp: Option<ScopedProtocol<Tcp4>>,
    io_timeout_ms: u64,
    peer_eof: bool,
    closed: bool,
}

impl Tcp4Stream {
    fn protocol(&mut self) -> Result<&mut ScopedProtocol<Tcp4>, ()> {
        self.tcp.as_mut().ok_or(())
    }

    fn transmit_chunk(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.len() > MAX_TCP_SEGMENT || bytes.len() > u32::MAX as usize {
            return Err(());
        }

        let events = create_completion_events().map_err(|_| ())?;
        let mut packet = TxPacket {
            header: Tcp4TransmitData {
                push: Boolean::TRUE,
                urgent: Boolean::FALSE,
                data_length: bytes.len() as u32,
                fragment_count: 1,
                fragment_table: [],
            },
            fragment: Tcp4FragmentData {
                fragment_length: bytes.len() as u32,
                fragment_buf: bytes.as_ptr().cast_mut(),
            },
        };

        let mut token = Tcp4IoToken {
            completion_token: Tcp4CompletionToken {
                event: events.notify_ptr(),
                status: Status::NOT_READY,
            },
            packet: Tcp4Packet {
                tx_data: ptr::addr_of_mut!(packet.header),
            },
        };

        let call_status = {
            let tcp = self.protocol()?;
            // SAFETY: token, fragment descriptor, and byte slice stay live until completion.
            unsafe { (tcp.0.transmit)(&mut tcp.0, &mut token) }
        };

        if call_status != Status::SUCCESS {
            return Err(());
        }

        let wait = {
            let timeout = self.io_timeout_ms;
            let tcp = self.protocol()?;
            wait_for_token(tcp, events.wait_event(), timeout)
        };

        if wait.is_err() {
            let tcp = self.protocol()?;
            cancel_io_and_drain(tcp, &mut token, events.wait_event());
            return Err(());
        }

        let completion = token.completion_token.status;
        if completion == Status::SUCCESS {
            Ok(())
        } else {
            Err(())
        }
    }

    fn receive_chunk(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if output.is_empty() || self.peer_eof {
            return Ok(0);
        }
        let capacity = core::cmp::min(output.len(), RX_BUFFER_SIZE);
        if capacity > u32::MAX as usize {
            return Err(());
        }

        let events = create_completion_events().map_err(|_| ())?;
        let mut packet = RxPacket {
            header: Tcp4ReceiveData {
                urgent: Boolean::FALSE,
                data_length: capacity as u32,
                fragment_count: 1,
                fragment_table: [],
            },
            fragment: Tcp4FragmentData {
                fragment_length: capacity as u32,
                fragment_buf: output.as_mut_ptr(),
            },
        };

        let mut token = Tcp4IoToken {
            completion_token: Tcp4CompletionToken {
                event: events.notify_ptr(),
                status: Status::NOT_READY,
            },
            packet: Tcp4Packet {
                rx_data: ptr::addr_of_mut!(packet.header),
            },
        };

        let call_status = {
            let tcp = self.protocol()?;
            // SAFETY: output and packet storage stay live until completion or drained cancellation.
            unsafe { (tcp.0.receive)(&mut tcp.0, &mut token) }
        };

        if call_status != Status::SUCCESS {
            return Err(());
        }

        let wait = {
            let timeout = self.io_timeout_ms;
            let tcp = self.protocol()?;
            wait_for_token(tcp, events.wait_event(), timeout)
        };
        if wait.is_err() {
            let tcp = self.protocol()?;
            cancel_io_and_drain(tcp, &mut token, events.wait_event());
            return Err(());
        }

        let completion = token.completion_token.status;
        let received = packet.header.data_length as usize;
        if completion != Status::SUCCESS || received > capacity {
            return Err(());
        }
        if received == 0 {
            self.peer_eof = true;
            return Ok(0);
        }
        Ok(received)
    }

    fn abort(&mut self) {
        if self.closed {
            return;
        }

        if let Some(tcp) = self.tcp.as_mut() {
            if let Ok(events) = create_completion_events() {
                let mut close = Tcp4CloseToken {
                    completion_token: Tcp4CompletionToken {
                        event: events.notify_ptr(),
                        status: Status::NOT_READY,
                    },
                    abort_on_close: Boolean::FALSE,
                };
                // SAFETY: close token and completion events remain live through completion.
                let status = unsafe { (tcp.0.close)(&mut tcp.0, &mut close) };
                if status != Status::SUCCESS {
                    // SAFETY: null configuration resets the open TCP instance.
                    let _ = unsafe { (tcp.0.configure)(&mut tcp.0, ptr::null()) };
                } else if close.completion_token.status == Status::NOT_READY
                    && wait_for_token(tcp, events.wait_event(), 1000).is_err()
                {
                    // Configure(NULL) forcibly resets TCP state and completes
                    // the outstanding close request with EFI_ABORTED.
                    // SAFETY: null configuration resets the open TCP instance.
                    let _ = unsafe { (tcp.0.configure)(&mut tcp.0, ptr::null()) };
                    while close.completion_token.status == Status::NOT_READY
                        && !boot::check_event(events.wait_event()).unwrap_or(false)
                    {
                        // SAFETY: protocol remains open while the close token drains.
                        let _ = unsafe { (tcp.0.poll)(&mut tcp.0) };
                        let _ = boot::stall(Duration::from_micros(1_000));
                    }
                }
            } else {
                // SAFETY: null configuration brutally resets the TCP instance.
                let _ = unsafe { (tcp.0.configure)(&mut tcp.0, ptr::null()) };
            }
        }
        self.closed = true;
    }
}

impl TlsStreamIo for Tcp4Stream {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        if self.closed {
            return Err(());
        }
        let length = core::cmp::min(bytes.len(), MAX_TCP_SEGMENT);
        self.transmit_chunk(&bytes[..length])?;
        Ok(length)
    }

    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if self.closed {
            return Ok(0);
        }
        self.receive_chunk(output)
    }
}

impl Drop for Tcp4Stream {
    fn drop(&mut self) {
        self.abort();
        self.tcp.take();
        if let Some(mut binding) = self.binding.take() {
            binding.destroy_child(self.child);
        }
    }
}

#[repr(C)]
struct TxPacket {
    header: Tcp4TransmitData,
    fragment: Tcp4FragmentData,
}

#[repr(C)]
struct RxPacket {
    header: Tcp4ReceiveData,
    fragment: Tcp4FragmentData,
}

/// A protocol-compliant notify event plus a separate plain wait event.
/// UEFI CheckEvent rejects EVT_NOTIFY_SIGNAL events, so the callback signals
/// the plain event that this application polls.
struct CompletionEvents {
    notify: Option<uefi::Event>,
    wait: Option<uefi::Event>,
}

impl CompletionEvents {
    fn notify_ptr(&self) -> uefi_raw::Event {
        self.notify.as_ref().expect("notify event is live").as_ptr()
    }

    fn wait_event(&self) -> &uefi::Event {
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

fn create_completion_events() -> Result<CompletionEvents, Tcp4Error> {
    let wait = unsafe { boot::create_event(EventType::empty(), Tpl::APPLICATION, None, None) }
        .map_err(|_| Tcp4Error::Firmware(0))?;
    let context = NonNull::new(wait.as_ptr()).ok_or(Tcp4Error::Firmware(0))?;
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
            return Err(Tcp4Error::Firmware(0));
        }
    };

    Ok(CompletionEvents {
        notify: Some(notify),
        wait: Some(wait),
    })
}

unsafe extern "efiapi" fn signal_completion_event(
    _event: uefi::Event,
    context: Option<NonNull<c_void>>,
) {
    let Some(context) = context else {
        return;
    };
    // SAFETY: The context is the live plain event allocated with the notify event.
    if let Some(event) = unsafe { uefi::Event::from_ptr(context.as_ptr()) } {
        let _ = boot::signal_event(&event);
    }
}

fn wait_for_token(
    tcp: &mut ScopedProtocol<Tcp4>,
    event: &uefi::Event,
    timeout_ms: u64,
) -> Result<(), Tcp4Error> {
    let timeout_us = timeout_ms.max(1).saturating_mul(1000);
    let mut elapsed_us = 0u64;

    loop {
        if boot::check_event(event).map_err(|_| Tcp4Error::Network)? {
            return Ok(());
        }
        // SAFETY: tcp is open and no other async operation is active.
        let poll_status = unsafe { (tcp.0.poll)(&mut tcp.0) };
        if poll_status != Status::SUCCESS && poll_status != Status::NOT_READY {
            return Err(firmware_error(poll_status));
        }
        if elapsed_us >= timeout_us {
            return Err(Tcp4Error::Timeout);
        }
        let step = core::cmp::min(1000, timeout_us - elapsed_us);
        boot::stall(Duration::from_micros(step));
        elapsed_us += step;
    }
}

fn cancel_connect_and_drain(
    tcp: &mut ScopedProtocol<Tcp4>,
    token: &mut Tcp4ConnectionToken,
    wait_event: &uefi::Event,
) {
    // SAFETY: token is live and was submitted to this protocol.
    let _ = unsafe { (tcp.0.cancel)(&mut tcp.0, &mut token.completion_token) };
    drain_event(tcp, wait_event);
}

fn cancel_io_and_drain(
    tcp: &mut ScopedProtocol<Tcp4>,
    token: &mut Tcp4IoToken,
    wait_event: &uefi::Event,
) {
    // SAFETY: token is live and was submitted to this protocol.
    let _ = unsafe { (tcp.0.cancel)(&mut tcp.0, &mut token.completion_token) };
    drain_event(tcp, wait_event);
}

fn drain_event(tcp: &mut ScopedProtocol<Tcp4>, event: &uefi::Event) {
    loop {
        if boot::check_event(event).unwrap_or(false) {
            return;
        }
        // SAFETY: TCP protocol remains open until the token drains.
        let _ = unsafe { (tcp.0.poll)(&mut tcp.0) };
        let _ = boot::stall(Duration::from_micros(1_000));
    }
}

fn firmware_error(status: Status) -> Tcp4Error {
    if status == Status::TIMEOUT {
        Tcp4Error::Timeout
    } else {
        Tcp4Error::Firmware(status.0)
    }
}


/// Whether firmware exposes at least one TCP4 service-binding controller.
pub fn service_binding_available() -> bool {
    boot::find_handles::<Tcp4Binding>()
        .map(|handles| !handles.is_empty())
        .unwrap_or(false)
}
