#![no_std]

extern crate alloc;

pub mod dns;
pub mod document;
pub mod entropy;
pub mod network;
pub mod tls;
pub mod url;

#[cfg(test)]
extern crate std;
