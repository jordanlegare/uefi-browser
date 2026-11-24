//! EFI_RNG_PROTOCOL-backed cryptographically secure random source.

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol};
use uefi::proto::rng::Rng;

use crate::entropy::SecureRandom;

/// Firmware random source using the default EFI RNG algorithm.
///
/// The default algorithm lets firmware select its configured cryptographic
/// generator. There is no pseudo-random fallback: missing/failed EFI RNG is an
/// error and callers must fail closed.
#[derive(Debug)]
pub struct UefiRandom {
    protocol: ScopedProtocol<Rng>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomInitError {
    NoRngProtocol,
    CannotOpenProtocol,
}

impl UefiRandom {
    pub fn open() -> Result<Self, RandomInitError> {
        let handles = boot::find_handles::<Rng>().map_err(|_| RandomInitError::NoRngProtocol)?;
        let mut last_error = RandomInitError::NoRngProtocol;

        for handle in handles.iter().copied() {
            // SAFETY: GetProtocol opens the firmware RNG interface for this
            // handle; the ScopedProtocol closes the reference on Drop.
            match unsafe {
                boot::open_protocol::<Rng>(
                    OpenProtocolParams {
                        handle,
                        agent: boot::image_handle(),
                        controller: None,
                    },
                    OpenProtocolAttributes::GetProtocol,
                )
            } {
                Ok(protocol) => return Ok(Self { protocol }),
                Err(_) => last_error = RandomInitError::CannotOpenProtocol,
            }
        }

        Err(last_error)
    }

    pub fn fill(&mut self, output: &mut [u8]) -> Result<(), RandomInitError> {
        if output.is_empty() {
            return Ok(());
        }
        self.protocol
            .get_rng(None, output)
            .map_err(|_| RandomInitError::CannotOpenProtocol)
    }
}

impl SecureRandom for UefiRandom {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), ()> {
        self.fill(output).map_err(|_| ())
    }
}

/// C ABI entropy callback used by TF-PSA-Crypto's Mbed TLS 4.x RNG.
///
/// Each request opens EFI_RNG_PROTOCOL for the duration of the read. This
/// keeps protocol lifetime scoped to the call and ensures that missing or
/// failing firmware RNG access propagates as an error (there is no fallback).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uefi_browser_fill_random(output: *mut u8, output_size: usize) -> i32 {
    if output_size == 0 {
        return 0;
    }
    if output.is_null() {
        return -1;
    }

    // SAFETY: The C caller supplies a writable buffer of output_size bytes.
    let buffer = unsafe { core::slice::from_raw_parts_mut(output, output_size) };
    let mut random = match UefiRandom::open() {
        Ok(random) => random,
        Err(_) => {
            return -1;
        }
    };

    let result = match random.fill(buffer) {
        Ok(()) => 0,
        Err(_) => -1,
    };
    result
}
