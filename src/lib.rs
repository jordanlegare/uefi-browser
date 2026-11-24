#![no_std]

extern crate alloc;

pub mod dns;
pub mod document;
pub mod entropy;
pub mod grc_chain;
pub mod http;
pub mod network;
pub mod tls;
pub mod x509_summary;
pub mod url;

#[cfg(target_os = "uefi")]
pub mod ca_bundle;
#[cfg(target_os = "uefi")]
pub mod firmware_ntp;
#[cfg(target_os = "uefi")]
pub mod firmware_rng;
#[cfg(target_os = "uefi")]
pub mod firmware_time;
#[cfg(target_os = "uefi")]
pub mod snp_network;
#[cfg(target_os = "uefi")]
pub mod uefi_memory;

#[cfg(test)]
extern crate std;
