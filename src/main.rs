#![no_main]
#![no_std]

use uefi::{Status, helpers, system};

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
unsafe extern "C" {
    fn uefi_mbedtls_link_anchor() -> i32;
}

#[uefi::entry]
fn main() -> Status {
    helpers::init().unwrap();

    let _ = system::with_stdout(|out| out.clear());
    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("|                         UEFI BROWSER                         |");
    uefi::println!("|               standalone x86_64 pre-OS browser               |");
    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("");
    uefi::println!("Core: URL, HTML and HTTP/1.1 codecs initialized.");
    uefi::println!("DNS: Hickory over firmware UDP4; resolver from IPv4 Config2.");
    uefi::println!("TCP: firmware TCP4 adapter; bounded async I/O and cleanup.");
    uefi::println!("RNG: EFI_RNG_PROTOCOL; clock: UEFI Runtime Services.");

    #[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
    {
        // Touch the allocator and clock exports so their Rust definitions are
        // retained for the C bridge's EFI link references.
        let allocation = uefi_browser::uefi_memory::uefi_mbedtls_calloc(1, 16);
        if !allocation.is_null() {
            uefi_browser::uefi_memory::uefi_mbedtls_free(allocation);
        }
        let clock_valid = uefi_browser::firmware_time::uefi_browser_time_unix() >= 0;
        // SAFETY: This no-op function exists to retain the linked Mbed TLS bridge.
        let bridge_linked = unsafe { uefi_mbedtls_link_anchor() } == 0;
        uefi::println!("Mbed TLS 4.3 static bridge linked: {}", bridge_linked);
        uefi::println!("Firmware UTC clock valid for X.509: {}", clock_valid);
    }

    #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked)))]
    uefi::println!("Mbed TLS static bridge not linked (run scripts/build-uefi.sh).");

    #[cfg(all(target_os = "uefi", uefi_ca_bundle))]
    uefi::println!("Embedded CA trust bundle: present.");

    #[cfg(not(all(target_os = "uefi", uefi_ca_bundle)))]
    uefi::println!("Embedded CA trust bundle: missing; HTTPS must remain disabled.");

    uefi::println!("");
    uefi::println!("BROWSER FETCH LOOP NOT YET AVAILABLE");
    uefi::println!("HTTP transport and terminal navigation still need integration.");
    uefi::println!("");
    uefi::println!("Returning to firmware.");
    Status::SUCCESS
}
