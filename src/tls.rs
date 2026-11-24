//! wolfSSL TLS 1.3 client over the browser's existing TCP stream.
//!
//! wolfSSL owns the TLS handshake, record protection, and X.509 peer
//! verification. Rust retains ownership of the SNP/smoltcp TCP stream.

use alloc::ffi::CString;
use core::ffi::{c_int, c_void};
use core::marker::PhantomData;

pub trait TlsStreamIo {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()>;
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()>;
}

#[repr(C)]
struct RawTlsSession {
    _private: [u8; 0],
}

type SendCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type ReceiveCallback = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;

unsafe extern "C" {
    fn uefi_wolfssl_client_new(
        hostname: *const u8, hostname_len: usize,
        ca_pem: *const u8, ca_pem_len: usize,
        io_context: *mut c_void,
        send_callback: Option<SendCallback>,
        receive_callback: Option<ReceiveCallback>,
        output: *mut *mut RawTlsSession,
    ) -> c_int;
    fn uefi_wolfssl_client_free(session: *mut RawTlsSession);
    fn uefi_wolfssl_handshake(session: *mut RawTlsSession) -> c_int;
    fn uefi_wolfssl_read(session: *mut RawTlsSession, output: *mut u8, capacity: usize) -> c_int;
    fn uefi_wolfssl_write(session: *mut RawTlsSession, input: *const u8, length: usize) -> c_int;
    fn uefi_wolfssl_verify_result(session: *mut RawTlsSession) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    NotHttps,
    InvalidHostname,
    InvalidCaBundle,
    Initialization(c_int),
    Handshake(c_int),
    CertificateVerification(u32),
    Read(c_int),
    Write(c_int),
}

/// A TLS session borrowing the underlying TCP stream.
///
/// Entropy comes exclusively from EFI_RNG_PROTOCOL and certificate time comes
/// from the validated UEFI Runtime Services clock.
pub struct TlsConnection<'a, S: TlsStreamIo> {
    raw: *mut RawTlsSession,
    _borrow: PhantomData<&'a mut S>,
}

impl<'a, S: TlsStreamIo> TlsConnection<'a, S> {
    /// Create a TLS 1.3 client. hostname is used for SNI and identity checks;
    /// ca_pem must be a trusted PEM bundle with a trailing NUL byte.
    pub fn new(hostname: &str, ca_pem: &[u8], stream: &'a mut S) -> Result<Self, TlsError> {
        let hostname = CString::new(hostname).map_err(|_| TlsError::InvalidHostname)?;
        if ca_pem.last() != Some(&0) {
            return Err(TlsError::InvalidCaBundle);
        }

        let mut raw = core::ptr::null_mut();
        let result = unsafe {
            uefi_wolfssl_client_new(
                hostname.as_ptr() as *const u8,
                hostname.as_bytes().len(),
                ca_pem.as_ptr(),
                ca_pem.len(),
                stream as *mut S as *mut c_void,
                Some(send_callback::<S>),
                Some(receive_callback::<S>),
                &mut raw,
            )
        };
        if result != 0 {
            return Err(TlsError::Initialization(result));
        }
        if raw.is_null() {
            return Err(TlsError::Initialization(-1));
        }
        Ok(Self { raw, _borrow: PhantomData })
    }

    /// wolfSSL verifies the peer during connect; the explicit result check is
    /// retained as a second fail-closed guard.
    pub fn handshake(&mut self) -> Result<(), TlsError> {
        let result = unsafe { uefi_wolfssl_handshake(self.raw) };
        if result != 0 {
            return Err(TlsError::Handshake(result));
        }
        let verification = unsafe { uefi_wolfssl_verify_result(self.raw) };
        if verification != 0 {
            return Err(TlsError::CertificateVerification(verification));
        }
        Ok(())
    }

    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        let result = unsafe { uefi_wolfssl_read(self.raw, output.as_mut_ptr(), output.len()) };
        if result < 0 { Err(TlsError::Read(result)) } else { Ok(result as usize) }
    }

    pub fn write(&mut self, input: &[u8]) -> Result<usize, TlsError> {
        if input.len() > c_int::MAX as usize {
            return Err(TlsError::Write(-1));
        }
        let result = unsafe { uefi_wolfssl_write(self.raw, input.as_ptr(), input.len()) };
        if result < 0 { Err(TlsError::Write(result)) } else { Ok(result as usize) }
    }
}

impl<S: TlsStreamIo> TlsStreamIo for TlsConnection<'_, S> {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> { self.write(bytes).map_err(|_| ()) }
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> { self.read(output).map_err(|_| ()) }
}

impl<S: TlsStreamIo> Drop for TlsConnection<'_, S> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { uefi_wolfssl_client_free(self.raw) };
            self.raw = core::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn send_callback<S: TlsStreamIo>(
    context: *mut c_void, data: *const u8, length: usize,
) -> c_int {
    if context.is_null() || (data.is_null() && length != 0) || length > c_int::MAX as usize {
        return -1;
    }
    if length == 0 { return 0; }
    let Some(stream) = (unsafe { (context as *mut S).as_mut() }) else { return -1; };
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    match stream.send(bytes) {
        Ok(written) if written <= c_int::MAX as usize => written as c_int,
        _ => -1,
    }
}

unsafe extern "C" fn receive_callback<S: TlsStreamIo>(
    context: *mut c_void, output: *mut u8, capacity: usize,
) -> c_int {
    if context.is_null() || (output.is_null() && capacity != 0) || capacity > c_int::MAX as usize {
        return -1;
    }
    if capacity == 0 { return 0; }
    let Some(stream) = (unsafe { (context as *mut S).as_mut() }) else { return -1; };
    let buffer = unsafe { core::slice::from_raw_parts_mut(output, capacity) };
    match stream.receive(buffer) {
        Ok(read) if read <= c_int::MAX as usize => read as c_int,
        _ => -1,
    }
}
