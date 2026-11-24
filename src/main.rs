#![no_main]
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::proto::console::text::Key;
use uefi::{Status, helpers, system};

use uefi_browser::document::{Document, Link, parse_html};
use uefi_browser::http::{self, HttpResponse};
use uefi_browser::network::connect_firmware_url;
use uefi_browser::url::{Scheme, Url};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_REDIRECTS: usize = 5;
const MAX_INPUT_BYTES: usize = 2048;

struct BrowserPage {
    url: Url,
    status: u16,
    title: String,
    text: String,
    links: Vec<Link>,
}

#[uefi::entry]
fn main() -> Status {
    helpers::init().unwrap();

    clear_screen();

    // UEFI arms a five-minute watchdog before launching a boot option.
    // This interactive browser intentionally remains in Boot Services.
    match uefi::boot::set_watchdog_timer(0, 0x1_0000, None) {
        Ok(()) => uefi::println!("UEFI boot watchdog disabled for interactive session."),
        Err(error) => uefi::println!("Warning: unable to disable UEFI boot watchdog: {:?}", error),
    }

    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("|                         UEFI BROWSER                         |");
    uefi::println!("|               standalone x86_64 pre-OS browser               |");
    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("Rust DNS: Hickory | IP stack: smoltcp over UEFI SNP");
    uefi::println!("TLS: embedded wolfSSL | Rendering: UEFI text console");
    uefi::println!("");
    uefi::println!("Initializing SNP Ethernet and smoltcp IPv4/DHCP...");
    let mut network = match uefi_browser::firmware_rng::UefiRandom::open() {
        Ok(mut random) => match uefi_browser::snp_network::SnpNetwork::new(&mut random) {
            Ok(mut network) => match network.acquire_dhcp(60_000) {
                Ok(dns_server) => {
                    uefi::println!("smoltcp DHCP configured; DNS resolver: {}", dns_server);
                    uefi::println!("Synchronizing UTC clock from NTP...");
                    match uefi_browser::firmware_ntp::synchronize(&mut network, dns_server) {
                        Ok(unix) => uefi::println!("NTP synchronized; UTC Unix time: {}", unix),
                        Err(error) => uefi::println!("NTP synchronization failed: {}", error),
                    }
                    Some(network)
                }
                Err(error) => {
                    uefi::println!("smoltcp DHCP initialization failed: {:?}", error);
                    None
                }
            },
            Err(error) => {
                uefi::println!("SNP network initialization failed: {:?}", error);
                None
            }
        },
        Err(_) => {
            uefi::println!("Network unavailable: EFI_RNG_PROTOCOL could not seed smoltcp.");
            None
        }
    };
    uefi::println!("");

    #[cfg(all(target_os = "uefi", uefi_wolfssl_linked))]
    {
        // Touch the allocator and clock exports so their definitions remain
        // reachable for the statically linked C bridge.
        // Touch the UEFI allocator exports used by wolfSSL's custom heap hooks.
        let allocation = uefi_browser::uefi_memory::uefi_browser_alloc(16);
        let allocator_linked = !allocation.is_null();
        if allocator_linked {
            uefi_browser::uefi_memory::uefi_browser_free(allocation);
        }
        let bridge_linked = cfg!(uefi_wolfssl_linked) && allocator_linked;
        uefi::println!("wolfSSL 5.9.4 static bridge: {}", bridge_linked);
        uefi::println!(
            "UEFI clock suitable for X.509: {}",
            uefi_browser::firmware_time::uefi_browser_time_unix() >= 0
        );
    }

    #[cfg(not(all(target_os = "uefi", uefi_wolfssl_linked)))]
    uefi::println!("wolfSSL bridge: unavailable (build with scripts/build-uefi.sh)");

    if !uefi_browser::ca_bundle::is_available() {
        uefi::println!("CA roots: not embedded; HTTPS is disabled.");
    } else {
        uefi::println!("CA roots: embedded.");
    }

    let Some(network) = network.as_mut() else {
        uefi::println!("No usable DHCP configuration; returning to firmware.");
        return Status::SUCCESS;
    };

    uefi::println!("");
    uefi::println!("Enter a hostname or URL. Bare hostnames default to HTTPS.");
    uefi::println!("Type 'help' for commands, or Ctrl+C to return to firmware.");
    uefi::println!("");

    let mut first_url = loop {
        let Some(address) = read_line("Open address: ", network) else {
            return Status::SUCCESS;
        };
        match Url::parse(&address) {
            Ok(url) => break url,
            Err(error) => uefi::println!("Invalid address: {error}. Enter another URL."),
        }
    };

    let mut history = Vec::new();
    let (mut page, mut history_index) = loop {
        match fetch_document(&first_url, network) {
            Ok(page) => {
                history.push(first_url.clone());
                break (page, 0usize);
            }
            Err(error) => {
                uefi::println!("");
                uefi::println!("NAVIGATION FAILED: {error}");
                uefi::println!("The browser is staying open. Press ENTER to retry,");
                uefi::println!("enter another URL, or type 'quit' to return to firmware.");
                let Some(retry) = read_line("Retry URL: ", network) else {
                    return Status::SUCCESS;
                };
                match retry.trim() {
                    "" | "retry" => {}
                    "q" | "quit" | "exit" => return Status::SUCCESS,
                    value => match Url::parse(value) {
                        Ok(url) => first_url = url,
                        Err(error) => uefi::println!("Invalid address: {error}"),
                    },
                }
            }
        }
    };
    let mut navigation_error: Option<String> = None;

    loop {
        render_page(&page, navigation_error.as_deref());
        let prompt = format!("\n{} > ", page.url.as_string());
        let Some(command) = read_line(&prompt, network) else {
            break;
        };
        let command = command.trim();

        if command.is_empty() {
            continue;
        }
        if matches!(command, "q" | "quit" | "exit") {
            break;
        }
        if matches!(command, "help" | "?") {
            print_help();
            continue;
        }
        if command == "links" {
            render_links(&page.links);
            continue;
        }
        if command == "clear" {
            continue;
        }
        if let Some(query) = command.strip_prefix("search ") {
            search_page(&page, query);
            continue;
        }

        let mut target_index = None;
        let target_url;
        let mut add_history = false;

        match command {
            "back" => {
                if history_index == 0 {
                    uefi::println!("No previous page.");
                    continue;
                }
                target_index = Some(history_index - 1);
                target_url = Some(history[history_index - 1].clone());
            }
            "forward" => {
                if history_index + 1 >= history.len() {
                    uefi::println!("No forward page.");
                    continue;
                }
                target_index = Some(history_index + 1);
                target_url = Some(history[history_index + 1].clone());
            }
            "reload" => {
                target_url = Some(page.url.clone());
            }
            other => {
                let argument = other.strip_prefix("open ").unwrap_or(other).trim();
                if let Ok(number) = argument.parse::<usize>() {
                    if number == 0 || number > page.links.len() {
                        uefi::println!("No link with that number.");
                        continue;
                    }
                    target_url = match Url::parse(&page.links[number - 1].target) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            uefi::println!("Invalid link target: {error}");
                            continue;
                        }
                    };
                } else {
                    target_url = match Url::parse(argument) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            uefi::println!("Invalid address: {error}");
                            continue;
                        }
                    };
                }
                add_history = true;
            }
        }

        let Some(target) = target_url else {
            continue;
        };

        match fetch_document(&target, network) {
            Ok(next_page) => {
                if let Some(index) = target_index {
                    history_index = index;
                } else if add_history {
                    history.truncate(history_index + 1);
                    history.push(next_page.url.clone());
                    history_index = history.len() - 1;
                }
                page = next_page;
                navigation_error = None;
            }
            Err(error) => {
                navigation_error = Some(error);
            }
        }
    }

    uefi::println!("\nLeaving UEFI Browser and returning to firmware.");
    Status::SUCCESS
}

fn fetch_document(
    initial_url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<BrowserPage, String> {
    let mut current = initial_url.clone();

    for redirect_index in 0..=MAX_REDIRECTS {
        let response = fetch_response(&current, network)?;
        if response.is_redirect() {
            if redirect_index == MAX_REDIRECTS {
                return Err(String::from("redirect limit exceeded"));
            }

            let location = response
                .location()
                .ok_or_else(|| String::from("redirect response has no Location header"))?
                .to_string();
            let next = current
                .resolve(&location)
                .map_err(|error| format!("invalid redirect target: {error}"))?;

            if current.scheme == Scheme::Https && next.scheme == Scheme::Http {
                return Err(String::from("refusing HTTPS-to-HTTP redirect downgrade"));
            }

            current = next;
            continue;
        }

        let content_type = response.content_type().unwrap_or("text/plain");
        let body = String::from_utf8_lossy(&response.body).into_owned();

        let document = if content_type.to_ascii_lowercase().starts_with("text/html") {
            parse_html(&body, &current)
        } else if content_type.to_ascii_lowercase().starts_with("text/plain") {
            Document {
                title: current.host.clone(),
                text: body,
                links: Vec::new(),
            }
        } else {
            Document {
                title: current.host.clone(),
                text: format!(
                    "This text browser does not render Content-Type: {content_type}\n{} bytes received.",
                    response.body.len()
                ),
                links: Vec::new(),
            }
        };

        return Ok(BrowserPage {
            url: current,
            status: response.status,
            title: document.title,
            text: document.text,
            links: document.links,
        });
    }

    Err(String::from("redirect limit exceeded"))
}

fn fetch_response(
    url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<HttpResponse, String> {
    #[cfg(not(all(target_os = "uefi", uefi_wolfssl_linked, uefi_ca_bundle)))]
    if url.scheme == Scheme::Https {
        return Err(String::from(
            "HTTPS unavailable: this EFI image needs the linked wolfSSL bridge and embedded CA bundle",
        ));
    }

    uefi::println!(
        "Resolving {} and opening TCP port {}...",
        url.host,
        url.port
    );
    let mut connection = match connect_firmware_url(network, url, 15_000) {
        Ok(connection) => connection,
        Err(failure) => {
            let d = failure.diagnostics;
            return Err(format!(
                "DNS/TCP connection failed: {:?}\nSNP TX: queued={} recycled={} failures={} queue-full={} last-status=0x{:x}\nSNP RX: frames={} errors={} last-status=0x{:x}\nUDP: sent={} received={} timeouts={}; TCP: attempts={} failures={} timeouts={}",
                failure.error,
                d.tx_queued,
                d.tx_recycled,
                d.tx_failures,
                d.tx_queue_full,
                d.tx_last_status,
                d.rx_frames,
                d.rx_errors,
                d.rx_last_status,
                d.udp_datagrams_sent,
                d.udp_datagrams_received,
                d.udp_timeouts,
                d.tcp_connect_attempts,
                d.tcp_connect_failures,
                d.tcp_connect_timeouts,
            ));
        }
    };
    uefi::println!(
        "TCP connected: {}:{}",
        connection.peer.address,
        connection.peer.port
    );

    match url.scheme {
        Scheme::Http => {
            uefi::println!("Sending HTTP request...");
            let response = http::exchange_get(&mut connection.peer.stream, url, MAX_BODY_BYTES)
                .map_err(|error| format!("HTTP transaction failed: {error:?}"))?;
            uefi::println!("HTTP response received ({} bytes).", response.body.len());
            Ok(response)
        }
        Scheme::Https => {
            #[cfg(all(target_os = "uefi", uefi_wolfssl_linked, uefi_ca_bundle))]
            {
                let ca_bundle = uefi_browser::ca_bundle::pem()
                    .ok_or_else(|| String::from("no embedded CA trust bundle"))?;
                // Keep TLS I/O bounded so an unresponsive peer cannot freeze the firmware UI.
                connection.peer.stream.set_io_timeout_ms(5_000);
                uefi::println!(
                    "[TLS 1/6] Loading the embedded CA trust bundle and creating a TLS 1.3 client."
                );
                uefi::println!(
                    "[TLS 2/6] wolfSSL peer verification is mandatory; no certificate-override mode is enabled."
                );
                uefi::println!(
                    "[TLS 3/6] Binding SNI and certificate identity checks to requested host: {}",
                    url.host
                );
                // CA parsing and trust-store loading occur during TLS session construction.
                let mut tls = connection
                    .start_tls(ca_bundle)
                    .map_err(|error| format!("TLS initialization failed: {error:?}"))?;
                uefi::println!(
                    "[TLS 4/6] TLS context ready. Starting handshake and certificate-path validation."
                );
                if let Err(error) = tls.handshake() {
                    uefi::println!(
                        "[TLS 5/6] Handshake did not complete. The site is not trusted and no HTTP request will be sent."
                    );
                    let observed_chain = tls.peer_chain_sha1();
                    let failing_certificate_der = tls.failing_certificate_der();
                    let der_status = failing_certificate_der
                        .as_ref()
                        .map(|der| format!("{} bytes captured", der.len()))
                        .unwrap_or_else(|| {
                            String::from("unavailable or above the 16 KiB diagnostic cap")
                        });
                    uefi::println!(
                        "[TLS 6/6] Rejected certificate DER: {}. Closing the original TLS/TCP connection.",
                        der_status
                    );
                    // Print the key evidence before the independent GRC request.
                    // GRC has its own TLS handshake and may fail or stall; that must
                    // never hide diagnostics already captured from the original peer.
                    print_tls_rejection_diagnostics(
                        &error,
                        failing_certificate_der.as_deref(),
                        &observed_chain,
                    );
                    let report = if is_certificate_verification_failure(&error) {
                        drop(tls);
                        drop(connection);
                        describe_tls_failure_with_grc(
                            &error,
                            &url.host,
                            &observed_chain,
                            failing_certificate_der.as_deref(),
                            network,
                        )
                    } else {
                        describe_tls_failure(&error)
                    };
                    return Err(report);
                }
                uefi::println!(
                    "[TLS] Certificate path, validity, and hostname checks passed. HTTPS data may now flow."
                );
                let response = http::exchange_get(&mut tls, url, MAX_BODY_BYTES)
                    .map_err(|error| format!("HTTPS transaction failed: {error:?}"))?;
                uefi::println!("HTTPS response received ({} bytes).", response.body.len());
                Ok(response)
            }

            #[cfg(not(all(target_os = "uefi", uefi_wolfssl_linked, uefi_ca_bundle)))]
            {
                let _ = connection;
                Err(String::from(
                    "HTTPS unavailable: this EFI image has no linked wolfSSL bridge and embedded CA bundle",
                ))
            }
        }
    }
}

fn is_certificate_verification_failure(error: &uefi_browser::tls::TlsError) -> bool {
    matches!(
        error,
        uefi_browser::tls::TlsError::Handshake {
            verify_error,
            ..
        } if *verify_error != 0
    )
}

fn print_tls_rejection_diagnostics(
    error: &uefi_browser::tls::TlsError,
    failing_certificate_der: Option<&[u8]>,
    observed_chain: &[[u8; 20]],
) {
    use uefi_browser::tls::TlsError;

    let TlsError::Handshake {
        verify_error,
        verify_depth,
        failing_certificate_sha256,
        ..
    } = error
    else {
        return;
    };

    uefi::println!(
        "[TLS VERIFY] Original peer rejected: X.509 error {}, chain depth {} (0 = leaf).",
        verify_error,
        verify_depth
    );

    if failing_certificate_sha256.iter().any(|byte| *byte != 0) {
        let mut fingerprint = String::new();
        for (index, byte) in failing_certificate_sha256.iter().enumerate() {
            if index != 0 {
                fingerprint.push(':');
            }
            fingerprint.push_str(&format!("{:02X}", byte));
        }
        uefi::println!("[TLS VERIFY] Rejected certificate SHA-256: {}", fingerprint);
    } else {
        uefi::println!(
            "[TLS VERIFY] Rejected certificate SHA-256: unavailable (wolfSSL did not return a digest)."
        );
    }

    if *verify_depth >= 0 {
        if let Some(fingerprint) = observed_chain.get(*verify_depth as usize) {
            uefi::println!(
                "[TLS VERIFY] Rejected-depth SHA-1 (GRC comparison format): {}",
                uefi_browser::grc_chain::format_sha1(fingerprint)
            );
        } else {
            uefi::println!(
                "[TLS VERIFY] No peer-chain SHA-1 fingerprint was captured at depth {}.",
                verify_depth
            );
        }
    }

    match failing_certificate_der {
        Some(der) => match uefi_browser::x509_summary::summarize_certificate(der) {
            Ok(summary) => {
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate Subject: {}",
                    summary.subject
                );
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate Issuer: {}",
                    summary.issuer
                );
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate Serial: {}",
                    summary.serial_number
                );
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate SKI: {}",
                    summary.subject_key_identifier
                );
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate AKI: {}",
                    summary.authority_key_identifier
                );
                uefi::println!(
                    "[TLS VERIFY] Rejected certificate Basic Constraints: {}",
                    summary.basic_constraints
                );
                uefi::println!(
                    "[TLS VERIFY] Exact rejected DER length: {} bytes.",
                    summary.der_bytes
                );
            }
            Err(reason) => uefi::println!(
                "[TLS VERIFY] Captured rejected DER, but its diagnostic parser could not decode it: {}",
                reason
            ),
        },
        None => uefi::println!(
            "[TLS VERIFY] Rejected certificate DER unavailable; subject/issuer fields cannot be reported."
        ),
    }
}

fn describe_tls_failure_with_grc(
    error: &uefi_browser::tls::TlsError,
    hostname: &str,
    observed_chain: &[[u8; 20]],
    failing_certificate_der: Option<&[u8]>,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> String {
    use uefi_browser::grc_chain::{compare_chains, format_sha1};

    let mut report = describe_tls_failure(error);
    report.push_str("\n\nVERIFICATION TRACE (the original connection remains fail-closed):");
    report.push_str("\n1. The TLS 1.3 client was configured with the embedded CA trust store and the requested hostname as the identity to verify.");
    report.push_str("\n2. wolfSSL processed the peer certificate path. The live console trace identifies each callback depth that passed an individual check; a later failure can still invalidate the path.");
    if let uefi_browser::tls::TlsError::Handshake {
        verify_error,
        verify_depth,
        ..
    } = error
    {
        report.push_str(&format!(
            "\n3. wolfSSL reported X.509 error {} at chain depth {} (depth 0 is the leaf). This is the first failure recorded by the verification callback.",
            verify_error, verify_depth
        ));
    }
    match failing_certificate_der {
        Some(der) => {
            report.push_str(&format!(
                "\n4. The exact rejected certificate was copied from wolfSSL's callback ({} DER bytes) and parsed locally for field reporting.",
                der.len()
            ));
            match uefi_browser::x509_summary::summarize_certificate(der) {
                Ok(summary) => {
                    report.push_str(&format!(
                        "\nCULPRIT IDENTIFICATION: wolfSSL rejected the certificate at the reported depth. Subject: {}; Issuer: {}; Serial: {}.",
                        summary.subject, summary.issuer, summary.serial_number
                    ));
                    uefi::println!(
                        "[CHAIN] Rejected certificate identified from its captured DER. Subject: {}; Issuer: {}.",
                        summary.subject, summary.issuer
                    );
                    report.push_str("\n\nREJECTED CERTIFICATE — FIELD-BY-FIELD SUMMARY\n");
                    report.push_str(&summary.render());
                }
                Err(reason) => report.push_str(&format!(
                    "\n4. The rejected certificate DER was captured but its fields could not be parsed safely: {reason}."
                )),
            }
        }
        None => report.push_str("\n4. The rejected certificate DER was not available (the callback did not expose it or it exceeded the 16 KiB diagnostic cap); certificate fields are not guessed."),
    }
    report.push_str("\n5. The browser closed the failed TLS session and TCP connection before making any reference request. No HTTP request was sent to the rejected site.");
    report.push_str("\n6. For an ASCII DNS hostname, the browser may retrieve a GRC reference using a separate HTTPS session with the same embedded trust anchors and normal mandatory certificate verification.");
    report.push_str("\n7. The reference is corroborating evidence only. It cannot make the rejected certificate trusted or reopen the blocked connection.");
    uefi::println!("[CHAIN] Original site connection is closed and remains blocked.");
    report.push_str("\n\nIndependent chain reference: GRC HTTPS fingerprint service");
    report.push_str(&format!(
        "\nQuery: https://www.grc.com/fingerprints.htm?chain={hostname}"
    ));

    uefi::println!(
        "[CHAIN] Original failed session is gone; retrieving an independent reference before comparing fingerprints."
    );
    if let uefi_browser::tls::TlsError::Handshake { verify_depth, .. } = error {
        if *verify_depth >= 0 {
            if let Some(fingerprint) = observed_chain.get(*verify_depth as usize) {
                report.push_str(&format!(
                    "\nRejected certificate SHA-1 (GRC comparison format): {}",
                    format_sha1(fingerprint)
                ));
            }
        }
    }

    match fetch_grc_reference_chain(hostname, network) {
        Ok(reference) => {
            let comparison = compare_chains(&reference, observed_chain);
            uefi::println!(
                "[CHAIN] GRC reference parsed; comparing leaf and non-root peer-chain fingerprints."
            );
            if let uefi_browser::tls::TlsError::Handshake { verify_depth, .. } = error {
                if *verify_depth >= 0 {
                    if let Some(fingerprint) = observed_chain.get(*verify_depth as usize) {
                        if let Some(certificate) = reference
                            .certificates
                            .iter()
                            .find(|certificate| &certificate.sha1 == fingerprint)
                        {
                            uefi::println!(
                                "[CHAIN] Culprit identified at depth {}: {} {}.",
                                verify_depth,
                                certificate.role.label(),
                                certificate.name
                            );
                            report.push_str(&format!(
                                "\nProblematic certificate identified at wolfSSL depth {}: {} {} [{}].",
                                verify_depth,
                                certificate.role.label(),
                                certificate.name,
                                format_sha1(fingerprint)
                            ));
                        } else {
                            uefi::println!(
                                "[CHAIN] Culprit fingerprint at depth {} is not present in GRC's reference.",
                                verify_depth
                            );
                            report.push_str(&format!(
                                "\nProblematic certificate fingerprint at wolfSSL depth {}: {} (not listed in the GRC reference).",
                                verify_depth,
                                format_sha1(fingerprint)
                            ));
                        }
                    }
                }
            }
            report.push_str(&format!(
                "\nGRC returned {} certificate fingerprints for {}.",
                reference.certificates.len(),
                reference.hostname
            ));
            report.push_str(&format!(
                "\nLocal verifier captured {} certificate fingerprint(s), ordered by chain depth (leaf first).",
                observed_chain.len()
            ));

            if comparison.local_chain_empty {
                report.push_str(
                    "\nCOMPARISON: unavailable. wolfSSL did not expose a certificate path to the diagnostic callback.",
                );
            } else if comparison.is_consistent() {
                report.push_str(
                    "\nCOMPARISON: MATCH. The observed server/intermediate fingerprints agree with the GRC reference. The root may be omitted from the peer-sent chain.",
                );
            } else {
                report.push_str(
                    "\nCOMPARISON: CHAIN DIVERGENCE. The locally observed path differs from GRC's independently retrieved reference.",
                );
                if !comparison.server_leaf_matches {
                    report.push_str(
                        "\nThe server leaf fingerprint does not match the GRC server certificate fingerprint.",
                    );
                }
                for certificate in &comparison.missing {
                    report.push_str(&format!(
                        "\nMissing from local path: {} {} — {}",
                        certificate.role.label(),
                        certificate.name,
                        format_sha1(&certificate.sha1)
                    ));
                }
                for fingerprint in &comparison.unexpected_local {
                    report.push_str(&format!(
                        "\nNot present in GRC reference: {}",
                        format_sha1(fingerprint)
                    ));
                }
                report.push_str(
                    "\nInterpretation: possible TLS interception or a different certificate path/edge. CDN routing, certificate rotation, cross-signing, and timing can also cause legitimate differences; this comparison alone does not prove MITM.",
                );
            }

            report.push_str("\nGRC reference chain:");
            for certificate in &reference.certificates {
                report.push_str(&format!(
                    "\n  {}: {} [{}]",
                    certificate.role.label(),
                    certificate.name,
                    format_sha1(&certificate.sha1)
                ));
            }
        }
        Err(reason) => {
            report.push_str(&format!(
                "\nCOMPARISON: unavailable. Could not retrieve or parse the GRC reference: {reason}"
            ));
            report.push_str("\nThe browser did not relax TLS verification for the GRC connection.");
        }
    }

    report
}

fn fetch_grc_reference_chain(
    hostname: &str,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<uefi_browser::grc_chain::ReferenceChain, String> {
    use uefi_browser::grc_chain::parse_grc_chain_html;

    if !is_dns_hostname(hostname) {
        return Err(String::from(
            "GRC comparison requires an ASCII DNS hostname; IP literals and malformed names are not queried.",
        ));
    }

    uefi::println!("[GRC 1/4] Validating the DNS hostname before constructing the reference URL.");
    let reference_url = Url::parse(&format!(
        "https://www.grc.com/fingerprints.htm?chain={hostname}"
    ))
    .map_err(|error| format!("invalid GRC reference URL: {error}"))?;

    let ca_bundle = uefi_browser::ca_bundle::pem()
        .ok_or_else(|| String::from("embedded CA trust bundle unavailable"))?;
    uefi::println!("[GRC 2/4] Opening a separate DNS/TCP connection to www.grc.com.");
    let mut connection = connect_firmware_url(network, &reference_url, 15_000)
        .map_err(|failure| format!("GRC DNS/TCP connection failed: {:?}", failure.error))?;
    connection.peer.stream.set_io_timeout_ms(5_000);

    uefi::println!(
        "[GRC 3/4] Starting independent TLS verification for www.grc.com (5-second network I/O timeout)."
    );
    uefi::println!("[GRC 3a/4] Creating wolfSSL context and loading the embedded CA trust bundle.");
    let mut tls = connection
        .start_tls(ca_bundle)
        .map_err(|error| format!("GRC TLS initialization failed: {error:?}"))?;
    uefi::println!(
        "[GRC 3b/4] TLS context ready. Sending ClientHello and waiting for the verified server handshake."
    );
    tls.handshake()
        .map_err(|error| format!("GRC TLS certificate verification failed: {error:?}"))?;
    uefi::println!(
        "[GRC 4/4] GRC TLS certificate and hostname verification passed. Fetching the bounded fingerprint response."
    );

    let response = http::exchange_get(&mut tls, &reference_url, 128 * 1024)
        .map_err(|error| format!("GRC HTTPS request failed: {error:?}"))?;
    if response.status != 200 {
        return Err(format!("GRC returned HTTP status {}", response.status));
    }

    let html = String::from_utf8_lossy(&response.body);
    parse_grc_chain_html(&html, hostname)
        .map_err(|error| format!("GRC chain page parse failed: {error:?}"))
}

fn is_dns_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
        return false;
    }
    if !hostname.bytes().any(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }

    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn describe_tls_failure(error: &uefi_browser::tls::TlsError) -> String {
    use uefi_browser::tls::TlsError;

    match error {
        TlsError::Handshake {
            code,
            verify_error,
            verify_depth,
            failing_certificate_sha256,
        } => {
            let mut fingerprint = String::new();
            for byte in failing_certificate_sha256 {
                fingerprint.push_str(&format!("{:02X}", byte));
            }
            let has_fingerprint = failing_certificate_sha256.iter().any(|byte| *byte != 0);
            let certificate = if has_fingerprint {
                format!("Failing certificate SHA-256: {}", fingerprint)
            } else {
                String::from("Failing certificate fingerprint: unavailable")
            };
            let depth = if *verify_depth >= 0 {
                format!("Failing chain depth: {} (0 = leaf)", verify_depth)
            } else {
                String::from("Failing chain depth: unavailable")
            };
            let reason = match *code {
                188 => "No trusted issuer could be found for a certificate in the presented chain.",
                _ => {
                    "wolfSSL rejected the peer certificate chain; see the raw verifier code below."
                }
            };
            let suspicion = if *code == 188 {
                "SECURITY ASSESSMENT: Possible TLS interception, but MITM is NOT proven. An intercepting proxy can present a certificate signed by an untrusted local CA; a missing intermediate or incomplete trust bundle can produce the same failure."
            } else {
                "SECURITY ASSESSMENT: Certificate validation failed. This alone does not establish a man-in-the-middle attack."
            };
            format!(
                "TLS CERTIFICATE VERIFICATION FAILED\n{reason}\nVerifier code: {code}; X.509 error: {verify_error}\n{depth}\n{certificate}\n{suspicion}\nThe connection was blocked. Do not enter credentials or sensitive data.\nChecks performed by wolfSSL include chain signatures/path building, CA constraints, certificate validity times, and hostname identity where applicable. Revocation status (CRL/OCSP) is not currently checked."
            )
        }
        _ => format!(
            "TLS handshake failed: {error:?}\nThe connection was blocked; certificate verification was not bypassed."
        ),
    }
}

fn render_page(page: &BrowserPage, navigation_error: Option<&str>) {
    clear_screen();
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("| UEFI BROWSER                                                             |");
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("Title:  {}", page.title);
    uefi::println!("URL:    {}", page.url.as_string());
    uefi::println!("HTTP:   {}", page.status);
    uefi::println!("--------------------------------------------------------------------------");
    if let Some(error) = navigation_error {
        uefi::println!("NAVIGATION ERROR: {error}");
        uefi::println!("Previous page remains available. Enter a new URL or 'reload'.");
        uefi::println!(
            "--------------------------------------------------------------------------"
        );
    }
    uefi::println!("{}", page.text);
    if !page.links.is_empty() {
        uefi::println!("");
        render_links(&page.links);
    }
    uefi::println!("");
    uefi::println!(
        "Commands: open N | URL | back | forward | reload | links | search WORD | help | quit"
    );
}

fn render_links(links: &[Link]) {
    if links.is_empty() {
        uefi::println!("No HTTP/HTTPS links on this page.");
        return;
    }
    uefi::println!("Links:");
    for (index, link) in links.iter().enumerate() {
        uefi::println!("  [{}] {} -> {}", index + 1, link.label, link.target);
    }
}

fn search_page(page: &BrowserPage, query: &str) {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        uefi::println!("Usage: search WORD");
        return;
    }

    let mut matches = 0usize;
    for line in page.text.lines() {
        if line.to_ascii_lowercase().contains(&query) {
            uefi::println!("{line}");
            matches += 1;
        }
    }

    if matches == 0 {
        uefi::println!("No match for: {query}");
    }
}

fn print_help() {
    uefi::println!("");
    uefi::println!("UEFI Browser commands");
    uefi::println!("  HOST or URL     Navigate to a hostname or HTTP/HTTPS URL");
    uefi::println!("  open URL        Navigate to an explicit URL");
    uefi::println!("  open N / N      Follow numbered link N");
    uefi::println!("  links           List links on the current page");
    uefi::println!("  back            Visit the previous page");
    uefi::println!("  forward         Visit the next page");
    uefi::println!("  reload          Fetch the current page again");
    uefi::println!("  search WORD     Find matching text lines on the current page");
    uefi::println!("  clear           Redraw the current page");
    uefi::println!("  help            Show this help");
    uefi::println!("  quit            Return to firmware");
    uefi::println!("");
}

fn clear_screen() {
    let _ = system::with_stdout(|output| output.clear());
}

fn read_line(prompt: &str, network: &mut uefi_browser::snp_network::SnpNetwork) -> Option<String> {
    uefi::print!("{prompt}");
    let mut line = String::new();

    loop {
        network.poll();
        let key = system::with_stdin(|input| input.read_key().ok().flatten());
        match key {
            Some(Key::Printable(unit)) => {
                let character: char = unit.into();
                match character {
                    '\r' | '\n' => {
                        uefi::println!("");
                        return Some(line);
                    }
                    '\u{8}' | '\u{7f}' => {
                        if line.pop().is_some() {
                            uefi::print!("\u{8} \u{8}");
                        }
                    }
                    '\u{3}' => {
                        uefi::println!("");
                        return None;
                    }
                    value if !value.is_control() => {
                        if line.len() < MAX_INPUT_BYTES {
                            line.push(value);
                            uefi::print!("{value}");
                        }
                    }
                    _ => {}
                }
            }
            Some(Key::Special(_)) => {}
            None => {
                uefi::boot::stall(core::time::Duration::from_micros(1_000));
            }
        }
    }
}
