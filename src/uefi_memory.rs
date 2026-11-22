//! UEFI Boot Services allocation hooks for the embedded Mbed TLS library.
//!
//! Mbed TLS is configured to use these callbacks instead of libc calloc/free.
//! Pool allocations are zero-initialized and remain valid during Boot Services.
//! The browser must not invoke these hooks after ExitBootServices.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use uefi::boot::{self, MemoryType};

/// Mbed TLS platform calloc hook. Returns null on overflow or allocation failure.
#[unsafe(no_mangle)]
pub extern "C" fn uefi_mbedtls_calloc(count: usize, size: usize) -> *mut c_void {
    let requested = match count.checked_mul(size) {
        Some(bytes) => bytes.max(1),
        None => return ptr::null_mut(),
    };

    let allocation = match boot::allocate_pool(MemoryType::LOADER_DATA, requested) {
        Ok(allocation) => allocation,
        Err(_) => return ptr::null_mut(),
    };

    // SAFETY: allocation is a valid writable UEFI pool of requested bytes.
    unsafe { ptr::write_bytes(allocation.as_ptr(), 0, requested) };
    allocation.as_ptr().cast()
}

/// Mbed TLS platform free hook. Null pointers are accepted.
#[unsafe(no_mangle)]
pub extern "C" fn uefi_mbedtls_free(pointer: *mut c_void) {
    let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
        return;
    };

    // SAFETY: Every non-null pointer passed here came from uefi_mbedtls_calloc.
    let _ = unsafe { boot::free_pool(pointer) };
}
