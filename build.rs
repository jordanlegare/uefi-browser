use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(uefi_wolfssl_linked)");
    println!("cargo:rustc-check-cfg=cfg(uefi_ca_bundle)");
    println!("cargo:rerun-if-env-changed=UEFI_WOLFSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_WOLFSSL_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_PATH");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_SOURCE_DATE");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_SHA256");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_CERT_COUNT");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "uefi" {
        return;
    }

    if let (Ok(lib_dir), Ok(bridge_dir)) = (
        env::var("UEFI_WOLFSSL_LIB_DIR"),
        env::var("UEFI_WOLFSSL_BRIDGE_DIR"),
    ) {
        let lib_dir = PathBuf::from(lib_dir);
        let bridge_dir = PathBuf::from(bridge_dir);
        let bridge_archive = bridge_dir.join("libuefi_wolfssl_bridge.a");
        let wolfssl_archive = lib_dir.join("libwolfssl.a");

        for required in [&bridge_archive, &wolfssl_archive] {
            if !required.is_file() {
                panic!("wolfSSL link input is missing: {}", required.display());
            }
        }

        println!("cargo:rustc-link-search=native={}", bridge_dir.display());
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=uefi_wolfssl_bridge");
        println!("cargo:rustc-link-lib=static=wolfssl");
        println!("cargo:rustc-cfg=uefi_wolfssl_linked");
    }

    if let Ok(ca_path) = env::var("UEFI_CA_BUNDLE_PATH") {
        let ca_path = PathBuf::from(ca_path);
        let bytes = fs::read(&ca_path)
            .unwrap_or_else(|error| panic!("cannot read CA bundle {}: {error}", ca_path.display()));
        const MAX_CA_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
        const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

        if bytes.len() > MAX_CA_BUNDLE_BYTES {
            panic!(
                "CA bundle is too large ({} bytes; maximum is {} bytes)",
                bytes.len(),
                MAX_CA_BUNDLE_BYTES
            );
        }
        if bytes.contains(&0) {
            panic!("CA bundle contains an embedded NUL byte");
        }

        let first_certificate = bytes
            .windows(PEM_BEGIN.len())
            .position(|window| window == PEM_BEGIN)
            .unwrap_or_else(|| panic!("CA bundle contains no PEM certificate"));
        let pem = &bytes[first_certificate..];
        if !pem.windows(PEM_END.len()).any(|window| window == PEM_END) {
            panic!("CA bundle has a PEM begin marker but no certificate end marker");
        }

        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
        let embedded = out_dir.join("uefi-ca-bundle.pem");
        let mut nul_terminated = pem.to_vec();
        if nul_terminated.last() != Some(&0) {
            nul_terminated.push(0);
        }
        fs::write(&embedded, nul_terminated).expect("failed to stage the NUL-terminated CA bundle");

        println!("cargo:rustc-env=UEFI_CA_BUNDLE_FILE={}", embedded.display());
        for (key, variable) in [
            ("UEFI_CA_BUNDLE_SOURCE_DATE", "UEFI_CA_BUNDLE_SOURCE_DATE"),
            ("UEFI_CA_BUNDLE_SHA256", "UEFI_CA_BUNDLE_SHA256"),
            ("UEFI_CA_BUNDLE_CERT_COUNT", "UEFI_CA_BUNDLE_CERT_COUNT"),
        ] {
            if let Ok(value) = env::var(variable) {
                println!("cargo:rustc-env={key}={value}");
            }
        }
        println!("cargo:rustc-cfg=uefi_ca_bundle");
        println!("cargo:rerun-if-changed={}", ca_path.display());
    }
}
