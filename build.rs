use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(uefi_mbedtls_linked)");
    println!("cargo:rustc-check-cfg=cfg(uefi_ca_bundle)");
    println!("cargo:rerun-if-env-changed=UEFI_MBEDTLS_LIB_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_MBEDTLS_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_PATH");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "uefi" {
        return;
    }

    if let (Ok(lib_dir), Ok(bridge_dir)) = (
        env::var("UEFI_MBEDTLS_LIB_DIR"),
        env::var("UEFI_MBEDTLS_BRIDGE_DIR"),
    ) {
        let lib_dir = PathBuf::from(lib_dir);
        let bridge_dir = PathBuf::from(bridge_dir);
        let bridge_archive = bridge_dir.join("libuefi_mbedtls_bridge.a");

        for required in [
            bridge_archive,
            lib_dir.join("libmbedtls.a"),
            lib_dir.join("libmbedx509.a"),
            lib_dir.join("libmbedcrypto.a"),
        ] {
            if !required.is_file() {
                panic!("Mbed TLS link input is missing: {}", required.display());
            }
        }

        println!("cargo:rustc-link-search=native={}", bridge_dir.display());
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=uefi_mbedtls_bridge");
        println!("cargo:rustc-link-lib=static=mbedtls");
        println!("cargo:rustc-link-lib=static=mbedx509");
        println!("cargo:rustc-link-lib=static=mbedcrypto");
        println!("cargo:rustc-cfg=uefi_mbedtls_linked");
    }

    if let Ok(ca_path) = env::var("UEFI_CA_BUNDLE_PATH") {
        let ca_path = PathBuf::from(ca_path);
        let bytes = fs::read(&ca_path).unwrap_or_else(|error| {
            panic!("cannot read CA bundle {}: {error}", ca_path.display())
        });
        if !bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
            panic!("CA bundle does not begin with a PEM certificate");
        }

        let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
        let embedded = out_dir.join("uefi-ca-bundle.pem");
        let mut nul_terminated = bytes;
        if nul_terminated.last() != Some(&0) {
            nul_terminated.push(0);
        }
        fs::write(&embedded, nul_terminated)
            .expect("failed to stage the NUL-terminated CA bundle");

        println!("cargo:rustc-env=UEFI_CA_BUNDLE_FILE={}", embedded.display());
        println!("cargo:rustc-cfg=uefi_ca_bundle");
        println!("cargo:rerun-if-changed={}", ca_path.display());
    }
}
