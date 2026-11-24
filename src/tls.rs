//! wolfSSL TLS 1.3 client over the browser's existing TCP stream.
//!
//! wolfSSL owns the TLS handshake, record protection, and X.509 peer
//! verification. Rust retains ownership of the SNP/smoltcp TCP stream.

use alloc::ffi::CString;
use alloc::vec::Vec;
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
type ProgressCallback = unsafe extern "C" fn(c_int, c_int, c_int);

unsafe extern "C" {
    fn uefi_wolfssl_client_new(
        hostname: *const u8,
        hostname_len: usize,
        ca_pem: *const u8,
        ca_pem_len: usize,
        io_context: *mut c_void,
        send_callback: Option<SendCallback>,
        receive_callback: Option<ReceiveCallback>,
        progress_callback: Option<ProgressCallback>,
        output: *mut *mut RawTlsSession,
    ) -> c_int;
    fn uefi_wolfssl_client_free(session: *mut RawTlsSession);
    fn uefi_wolfssl_last_ca_cert_index() -> c_int;
    fn uefi_wolfssl_last_time_unix() -> i64;
    fn uefi_wolfssl_last_verify_error() -> c_int;
    fn uefi_wolfssl_last_verify_depth() -> c_int;
    fn uefi_wolfssl_peer_chain_count() -> c_int;
    fn uefi_wolfssl_copy_peer_chain_sha1(depth: c_int, output: *mut u8, capacity: usize) -> c_int;
    fn uefi_wolfssl_copy_bad_cert_sha256(output: *mut u8, capacity: usize) -> c_int;
    fn uefi_wolfssl_bad_cert_der_length() -> c_int;
    fn uefi_wolfssl_copy_bad_cert_der(output: *mut u8, capacity: usize) -> c_int;
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
    Initialization {
        code: c_int,
        ca_cert_index: c_int,
        wolfssl_time_unix: i64,
    },
    Handshake {
        code: c_int,
        verify_error: c_int,
        verify_depth: c_int,
        failing_certificate_sha256: [u8; 32],
    },
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
                Some(verification_progress_callback),
                &mut raw,
            )
        };
        if result != 0 {
            return Err(TlsError::Initialization {
                code: result,
                ca_cert_index: unsafe { uefi_wolfssl_last_ca_cert_index() },
                wolfssl_time_unix: unsafe { uefi_wolfssl_last_time_unix() },
            });
        }
        if raw.is_null() {
            return Err(TlsError::Initialization {
                code: -1,
                ca_cert_index: 0,
                wolfssl_time_unix: -1,
            });
        }
        Ok(Self {
            raw,
            _borrow: PhantomData,
        })
    }

    /// wolfSSL verifies the peer during connect; the explicit result check is
    /// retained as a second fail-closed guard.
    pub fn handshake(&mut self) -> Result<(), TlsError> {
        let result = unsafe { uefi_wolfssl_handshake(self.raw) };
        if result != 0 {
            return Err(TlsError::Handshake {
                code: result,
                verify_error: unsafe { uefi_wolfssl_last_verify_error() },
                verify_depth: unsafe { uefi_wolfssl_last_verify_depth() },
                failing_certificate_sha256: {
                    let mut fingerprint = [0u8; 32];
                    let copied = unsafe {
                        uefi_wolfssl_copy_bad_cert_sha256(
                            fingerprint.as_mut_ptr(),
                            fingerprint.len(),
                        )
                    };
                    if copied == 32 { fingerprint } else { [0u8; 32] }
                },
            });
        }
        let verification = unsafe { uefi_wolfssl_verify_result(self.raw) };
        if verification != 0 {
            return Err(TlsError::CertificateVerification(verification));
        }
        Ok(())
    }

    /// Return the exact DER bytes for the certificate rejected by wolfSSL.
    /// The bridge caps this diagnostic copy at 16 KiB; an oversized certificate
    /// remains rejected but its parsed field report is unavailable.
    pub fn failing_certificate_der(&self) -> Option<Vec<u8>> {
        let length = unsafe { uefi_wolfssl_bad_cert_der_length() };
        if length <= 0 || length as usize > 16 * 1024 {
            return None;
        }
        let mut der = Vec::new();
        der.resize(length as usize, 0);
        let copied = unsafe {
            uefi_wolfssl_copy_bad_cert_der(der.as_mut_ptr(), der.len())
        };
        if copied == length { Some(der) } else { None }
    }

    /// Return SHA-1 fingerprints for the peer chain captured by wolfSSL's
    /// verification callback, in verifier depth order (leaf first).
    ///
    /// SHA-1 is used only for compatibility with external fingerprint
    /// references; it is not used for TLS certificate verification.
    pub fn peer_chain_sha1(&self) -> Vec<[u8; 20]> {
        let count = unsafe { uefi_wolfssl_peer_chain_count() };
        if count <= 0 {
            return Vec::new();
        }

        let mut fingerprints = Vec::new();
        for depth in 0..count {
            let mut fingerprint = [0u8; 20];
            let copied = unsafe {
                uefi_wolfssl_copy_peer_chain_sha1(
                    depth,
                    fingerprint.as_mut_ptr(),
                    fingerprint.len(),
                )
            };
            if copied == 20 {
                fingerprints.push(fingerprint);
            }
        }
        fingerprints
    }

    pub fn read(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        let result = unsafe { uefi_wolfssl_read(self.raw, output.as_mut_ptr(), output.len()) };
        if result < 0 {
            Err(TlsError::Read(result))
        } else {
            Ok(result as usize)
        }
    }

    pub fn write(&mut self, input: &[u8]) -> Result<usize, TlsError> {
        if input.len() > c_int::MAX as usize {
            return Err(TlsError::Write(-1));
        }
        let result = unsafe { uefi_wolfssl_write(self.raw, input.as_ptr(), input.len()) };
        if result < 0 {
            Err(TlsError::Write(result))
        } else {
            Ok(result as usize)
        }
    }
}

impl<S: TlsStreamIo> TlsStreamIo for TlsConnection<'_, S> {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        self.write(bytes).map_err(|_| ())
    }

    fn receive(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        self.read(output).map_err(|_| ())
    }
}

impl<S: TlsStreamIo> Drop for TlsConnection<'_, S> {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                uefi_wolfssl_client_free(self.raw);
            }
            self.raw = core::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn verification_progress_callback(event: c_int, depth: c_int, error: c_int) {
    #[cfg(target_os = "uefi")]
    match event {
        1 => uefi::println!(
            "[TLS VERIFY] Certificate at depth {} passed its current X.509 check; wolfSSL is continuing path validation.",
            depth
        ),
        2 => uefi::println!(
            "[TLS VERIFY] CERTIFICATE REJECTED at depth {} (0 = leaf); wolfSSL X.509 error {}. Capturing the exact rejected certificate.",
            depth, error
        ),
        _ => {}
    }
    #[cfg(not(target_os = "uefi"))]
    let _ = (event, depth, error);
}

unsafe extern "C" fn send_callback<S: TlsStreamIo>(
    context: *mut c_void,
    data: *const u8,
    length: usize,
) -> c_int {
    if context.is_null() || (data.is_null() && length != 0) || length > c_int::MAX as usize {
        return -1;
    }
    if length == 0 {
        return 0;
    }
    let Some(stream) = (unsafe { (context as *mut S).as_mut() }) else {
        return -1;
    };
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    match stream.send(bytes) {
        Ok(written) if written <= c_int::MAX as usize => written as c_int,
        _ => -1,
    }
}

unsafe extern "C" fn receive_callback<S: TlsStreamIo>(
    context: *mut c_void,
    output: *mut u8,
    capacity: usize,
) -> c_int {
    if context.is_null() || (output.is_null() && capacity != 0) || capacity > c_int::MAX as usize {
        return -1;
    }
    if capacity == 0 {
        return 0;
    }
    let Some(stream) = (unsafe { (context as *mut S).as_mut() }) else {
        return -1;
    };
    let buffer = unsafe { core::slice::from_raw_parts_mut(output, capacity) };
    match stream.receive(buffer) {
        Ok(read) if read <= c_int::MAX as usize => read as c_int,
        _ => -1,
    }
}
