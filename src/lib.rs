#![no_std]

extern crate alloc;

pub mod dns;
pub mod document;
pub mod entropy;
pub mod http;
pub mod network;
pub mod tls;
pub mod url;

#[cfg(target_os = "uefi")]
pub mod ca_bundle;

#[cfg(target_os = "uefi")]
pub mod firmware_rng;
#[cfg(target_os = "uefi")]
pub mod firmware_time;
#[cfg(target_os = "uefi")]
pub mod uefi_memory;
#[cfg(target_os = "uefi")]
pub mod uefi_tcp4;
#[cfg(target_os = "uefi")]
pub mod uefi_udp4;

#[cfg(test)]
extern crate std;
