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
    uefi::println!("Browser core: URL and HTML text model initialized.");
    uefi::println!("TLS boundary: Mbed TLS static-link integration source added.");
    uefi::println!("");
    uefi::println!("NETWORK TRANSPORT NOT READY");
    uefi::println!("The UDP4/TCP4 adapters and Mbed TLS firmware callbacks are");
    uefi::println!("not connected to the navigation loop in this milestone.");
    uefi::println!("");
    uefi::println!("Returning to firmware.");
    Status::SUCCESS
}
