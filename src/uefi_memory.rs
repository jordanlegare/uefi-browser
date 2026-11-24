//! UEFI Boot Services allocation hooks for wolfSSL/wolfCrypt.
//!
//! wolfSSL's custom allocator callbacks use these functions instead of libc.
//! Pool allocations are zero-initialized and remain valid during Boot Services.
//! The browser must not invoke these hooks after ExitBootServices.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use uefi::boot::{self, MemoryType};

/// Allocate at least one byte from UEFI Boot Services. Returns null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_alloc(size: usize) -> *mut c_void {
    let requested = size.max(1);
    let allocation = match boot::allocate_pool(MemoryType::LOADER_DATA, requested) {
        Ok(allocation) => allocation,
        Err(_) => return ptr::null_mut(),
    };

    // Zero initialization avoids exposing stale pool contents to cryptographic code.
    unsafe { ptr::write_bytes(allocation.as_ptr(), 0, requested) };
    allocation.as_ptr().cast()
}

/// Free a pointer returned by uefi_browser_alloc. Null pointers are accepted.
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_free(pointer: *mut c_void) {
    let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
        return;
    };
    let _ = unsafe { boot::free_pool(pointer) };
}
