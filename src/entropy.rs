//! Entropy provider contract shared by DNS and Mbed TLS.
//!
//! The firmware implementation must use EFI_RNG_PROTOCOL and return an error
//! when no cryptographically secure source is available.

pub trait SecureRandom {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), ()>;
}
