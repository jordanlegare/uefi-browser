//! Build-time embedded CA trust bundle.
//!
//! Run scripts/update-ca-bundle.sh, review the resulting Mozilla-derived roots,
//! then build with UEFI_CA_BUNDLE_PATH pointing at assets/cacert.pem.

#[cfg(all(target_os = "uefi", uefi_ca_bundle))]
pub fn pem() -> Option<&'static [u8]> {
    Some(include_bytes!(env!("UEFI_CA_BUNDLE_FILE")))
}

#[cfg(not(all(target_os = "uefi", uefi_ca_bundle)))]
pub fn pem() -> Option<&'static [u8]> {
    None
}

pub fn is_available() -> bool {
    pem().is_some()
}
