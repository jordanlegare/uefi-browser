use std::{env, fs, path::PathBuf};


fn generate_elinks_entity_decoder() {
    use std::collections::BTreeMap;

    const SOURCE: &str = "assets/elinks-entities.txt";
    println!("cargo:rerun-if-changed={SOURCE}");

    let source = fs::read_to_string(SOURCE)
        .unwrap_or_else(|error| panic!("cannot read ELinks entity table {SOURCE}: {error}"));
    let mut entities = BTreeMap::<String, u32>::new();

    for line in source.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut columns = line.split('\t');
        let Some(name) = columns.next() else {
            continue;
        };
        let _public_set = columns.next();
        let Some(codepoint) = columns.next() else {
            continue;
        };
        let Some(hex) = codepoint.strip_prefix("0x") else {
            // ELinks marks legacy multi-character entities without a single
            // Unicode scalar as 0x????. Leave those undecoded rather than guess.
            continue;
        };
        let Ok(value) = u32::from_str_radix(hex, 16) else {
            continue;
        };
        if char::from_u32(value).is_none() {
            continue;
        }

        // The upstream table contains one duplicate name ("loz") with two
        // values. Keep the first canonical mapping (U+25CA LOZENGE).
        entities.entry(name.to_string()).or_insert(value);
    }

    if entities.is_empty() {
        panic!("the ELinks public-domain entity table contains no usable entries");
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let generated = out_dir.join("elinks_entities.rs");
    let mut code = String::from(
        "// Generated from assets/elinks-entities.txt. Do not edit by hand.\n\
         pub fn decode_named_entity(name: &str) -> Option<char> {\n\
             match name {\n",
    );
    for (name, value) in &entities {
        code.push_str(&format!(
            "        {name:?} => char::from_u32(0x{value:X}),\n"
        ));
    }
    code.push_str("        _ => None,\n    }\n}\n");
    fs::write(&generated, code)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", generated.display()));

    println!(
        "cargo:warning=generated {} public-domain ELinks named HTML entity mappings",
        entities.len()
    );
}

fn main() {
    generate_elinks_entity_decoder();
    println!("cargo:rustc-check-cfg=cfg(uefi_wolfssl_linked)");
    println!("cargo:rustc-check-cfg=cfg(uefi_ca_bundle)");
    println!("cargo:rerun-if-env-changed=UEFI_WOLFSSL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_WOLFSSL_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_PATH");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_SOURCE_DATE");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_SHA256");
    println!("cargo:rerun-if-env-changed=UEFI_CA_BUNDLE_CERT_COUNT");
    println!("cargo:rerun-if-changed=scripts/build-uefi.sh");
    println!("cargo:rerun-if-changed=vendor/wolfssl-bridge/include/user_settings.h");
    println!("cargo:rerun-if-changed=vendor/wolfssl-bridge/uefi_tls.c");
    println!("cargo:rerun-if-changed=vendor/wolfssl-bridge/uefi_platform.c");
    println!("cargo:rerun-if-changed=vendor/wolfssl-bridge/uefi_date.c");
    println!("cargo:rerun-if-changed=vendor/wolfssl-bridge/uefi_crt.c");

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
            println!("cargo:rerun-if-changed={}", required.display());
        }

        println!("cargo:rustc-link-search=native={}", bridge_dir.display());
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=static=uefi_wolfssl_bridge");
        println!("cargo:rustc-link-lib=static=wolfssl");
        // Re-scan the bridge archive for freestanding CRT symbols referenced by wolfSSL.
        println!("cargo:rustc-link-lib=static=uefi_wolfssl_bridge");
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
