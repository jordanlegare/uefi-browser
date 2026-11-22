#![no_main]
#![no_std]

use uefi::{Status, helpers, system};

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
    uefi::println!("");
    uefi::println!("BROWSER FETCH LOOP NOT YET AVAILABLE");
    uefi::println!("Mbed TLS static link, embedded CA bundle and terminal");
    uefi::println!("navigation renderer still need integration.");
    uefi::println!("");
    uefi::println!("Returning to firmware.");
    Status::SUCCESS
}
