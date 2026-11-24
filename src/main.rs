#![no_main]
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::fmt::Write as _;
use uefi::proto::console::text::{Color, Key, ScanCode};
use uefi::{Status, helpers, system};

use uefi_browser::document::{
    BlockKind, Document, Form, FormControlKind, FormMethod, Link, TermColor,
    external_stylesheet_urls, parse_html, parse_html_with_styles,
};
use uefi_browser::http::{self, HttpResponse};
use uefi_browser::network::connect_firmware_url;
use uefi_browser::persistence::{CachedPage, PersistentStore};
use uefi_browser::renderer::{self, RenderLine};
use uefi_browser::uefi_storage::UefiFileStore;
use uefi_browser::url::{Scheme, Url};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_STYLESHEET_BYTES: usize = 32 * 1024;
const MAX_REDIRECTS: usize = 5;
const MAX_INPUT_BYTES: usize = 2048;
const MAX_FORM_BODY_BYTES: usize = 8 * 1024;

type BrowserStore = Option<PersistentStore<UefiFileStore>>;

struct BrowserPage {
    url: Url,
    status: u16,
    document: Document,
    from_cache: bool,
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

    let mut storage: BrowserStore = match UefiFileStore::open(uefi::boot::image_handle()) {
        Ok(file_store) => {
            uefi::println!("Persistent bookmarks and page cache: boot volume\\UEFI_BROWSER");
            Some(PersistentStore::new(file_store))
        }
        Err(error) => {
            uefi::println!("Persistent storage unavailable: {error}");
            None
        }
    };

    let mut history = Vec::new();
    let (mut page, mut history_index) = loop {
        match fetch_document(&first_url, network, &mut storage) {
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
    run_browser_ui(
        &mut page,
        &mut history,
        &mut history_index,
        &mut storage,
        network,
    );

    uefi::println!("\nLeaving UEFI Browser and returning to firmware.");
    Status::SUCCESS
}

fn cache_key(url: &Url) -> String {
    format!("{}{}", url.origin(), url.path_and_query)
}

fn cache_clock() -> i64 {
    uefi_browser::firmware_time::unix_time_utc().unwrap_or(0)
}

fn build_browser_page(
    url: Url,
    status: u16,
    content_type: &str,
    body: &[u8],
    external_css: &[String],
    from_cache: bool,
) -> BrowserPage {
    let text = String::from_utf8_lossy(body).into_owned();
    let document = if content_type.to_ascii_lowercase().starts_with("text/html") {
        if external_css.is_empty() {
            parse_html(&text, &url)
        } else {
            parse_html_with_styles(&text, &url, external_css)
        }
    } else if content_type.to_ascii_lowercase().starts_with("text/plain") {
        Document::from_plain(&url.host, &text)
    } else {
        Document::from_plain(
            &url.host,
            &format!(
                "This text browser does not render Content-Type: {content_type}\n{} bytes received.",
                body.len()
            ),
        )
    };

    BrowserPage {
        url,
        status,
        document,
        from_cache,
    }
}

fn fetch_document(
    initial_url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
    storage: &mut BrowserStore,
) -> Result<BrowserPage, String> {
    let key = cache_key(initial_url);
    let now = cache_clock();
    if now > 0 {
        if let Some(store) = storage.as_mut() {
            if let Some(cached) = store.cached_page(&key, now) {
                let css = fetch_stylesheets(&cached.body, initial_url, network);
                return Ok(build_browser_page(
                    initial_url.clone(),
                    200,
                    &cached.content_type,
                    &cached.body,
                    &css,
                    true,
                ));
            }
        }
    }

    let mut current = initial_url.clone();
    for redirect_index in 0..=MAX_REDIRECTS {
        let response = fetch_response_with_method(&current, network, "GET", &[], MAX_BODY_BYTES)?;
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

        let content_type = response.content_type().unwrap_or("text/plain").to_string();
        let cache_control = response
            .header("cache-control")
            .unwrap_or("")
            .to_ascii_lowercase();
        let content_type_lower = content_type.to_ascii_lowercase();
        let cacheable = response.status == 200
            && (content_type_lower.starts_with("text/html")
                || content_type_lower.starts_with("text/plain"))
            && !cache_control.contains("no-store")
            && !cache_control.contains("no-cache")
            && !cache_control.contains("private")
            && response.header("set-cookie").is_none()
            && response.body.len() <= MAX_BODY_BYTES;

        let css = if content_type_lower.starts_with("text/html") {
            fetch_stylesheets(&response.body, &current, network)
        } else {
            Vec::new()
        };

        if cacheable && now > 0 {
            if let Some(store) = storage.as_mut() {
                let cached = CachedPage {
                    url: cache_key(&current),
                    content_type: content_type.clone(),
                    stored_at: now,
                    body: response.body.clone(),
                };
                let _ = store.cache_page(&cached);
            }
        }

        return Ok(build_browser_page(
            current,
            response.status,
            &content_type,
            &response.body,
            &css,
            false,
        ));
    }

    Err(String::from("redirect limit exceeded"))
}

fn fetch_stylesheets(
    html: &[u8],
    page_url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Vec<String> {
    let source = String::from_utf8_lossy(html);
    let urls = external_stylesheet_urls(&source, page_url);
    let mut sheets = Vec::new();

    for initial in urls {
        let mut current = initial;
        for redirect_index in 0..=3 {
            let response = match fetch_response_with_method(
                &current,
                network,
                "GET",
                &[],
                MAX_STYLESHEET_BYTES,
            ) {
                Ok(response) => response,
                Err(_) => break,
            };
            if response.is_redirect() {
                if redirect_index == 3 {
                    break;
                }
                let Some(location) = response.location() else {
                    break;
                };
                let Ok(next) = current.resolve(location) else {
                    break;
                };
                if current.scheme == Scheme::Https && next.scheme == Scheme::Http {
                    break;
                }
                current = next;
                continue;
            }
            if response.status == 200
                && response
                    .content_type()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .starts_with("text/css")
                && response.body.len() <= MAX_STYLESHEET_BYTES
            {
                sheets.push(String::from_utf8_lossy(&response.body).into_owned());
            }
            break;
        }
    }
    sheets
}

fn fetch_form_document(
    initial_url: &Url,
    method: &str,
    body: &[u8],
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<BrowserPage, String> {
    let mut current = initial_url.clone();
    let mut current_method = method;
    let mut current_body = body;

    for redirect_index in 0..=MAX_REDIRECTS {
        let response = fetch_response_with_method(
            &current,
            network,
            current_method,
            current_body,
            MAX_BODY_BYTES,
        )?;
        if response.is_redirect() {
            if redirect_index == MAX_REDIRECTS {
                return Err(String::from("form redirect limit exceeded"));
            }
            let location = response
                .location()
                .ok_or_else(|| String::from("form redirect has no Location header"))?
                .to_string();
            let next = current
                .resolve(&location)
                .map_err(|error| format!("invalid form redirect target: {error}"))?;
            if current.scheme == Scheme::Https && next.scheme == Scheme::Http {
                return Err(String::from(
                    "refusing HTTPS-to-HTTP form redirect downgrade",
                ));
            }
            if matches!(response.status, 301 | 302 | 303) && current_method == "POST" {
                current_method = "GET";
                current_body = &[];
            }
            current = next;
            continue;
        }

        let content_type = response.content_type().unwrap_or("text/plain").to_string();
        let css = if content_type.to_ascii_lowercase().starts_with("text/html") {
            fetch_stylesheets(&response.body, &current, network)
        } else {
            Vec::new()
        };
        return Ok(build_browser_page(
            current,
            response.status,
            &content_type,
            &response.body,
            &css,
            false,
        ));
    }

    Err(String::from("form redirect limit exceeded"))
}

fn fetch_response_with_method(
    url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
    method: &str,
    body: &[u8],
    max_body: usize,
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
            let response =
                http::exchange_request(&mut connection.peer.stream, url, method, body, max_body)
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
                let response = http::exchange_request(&mut tls, url, method, body, max_body)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserAction {
    Quit,
    Back,
    Forward,
    Reload,
    Goto,
    Search,
    Command,
    Help,
    Links,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    Top,
    Bottom,
    NextLink,
    PreviousLink,
    MoveFocusUp,
    MoveFocusDown,
    ActivateLink,
    FindNext,
    Bookmark,
    Bookmarks,
    Text(char),
    Backspace,
    ToggleControl,
    ClearFocus,
}

fn same_resource(left: &Url, right: &Url) -> bool {
    left.origin() == right.origin() && left.path_and_query == right.path_and_query
}

fn url_encode_component(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else if byte == b' ' {
            output.push('+');
        } else {
            output.push('%');
            output.push_str(&format!("{:02X}", byte));
        }
    }
    output
}

fn form_query_string(fields: &[(String, String)]) -> Result<String, String> {
    let mut query = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        if index > 0 {
            query.push('&');
        }
        query.push_str(&url_encode_component(name));
        query.push('=');
        query.push_str(&url_encode_component(value));
        if query.len() > MAX_FORM_BODY_BYTES {
            return Err(String::from("form data exceeds the 8 KiB submission limit"));
        }
    }
    Ok(query)
}

fn submit_form(
    form: &Form,
    submitter_control: Option<usize>,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<(Url, &'static str, Vec<u8>), String> {
    let effective_submitter = submitter_control.or_else(|| {
        form.controls
            .iter()
            .position(|control| !control.disabled && control.kind == FormControlKind::Submit)
    });
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut selected_radio_names: Vec<String> = Vec::new();

    for (index, control) in form.controls.iter().enumerate() {
        if control.disabled || control.name.is_empty() {
            continue;
        }

        let value = match control.kind {
            FormControlKind::Hidden
            | FormControlKind::Text
            | FormControlKind::Password
            | FormControlKind::Email
            | FormControlKind::Search
            | FormControlKind::Number
            | FormControlKind::TextArea => Some(control.value.clone()),
            FormControlKind::Checkbox => {
                if control.checked {
                    Some(if control.value.is_empty() {
                        String::from("on")
                    } else {
                        control.value.clone()
                    })
                } else {
                    if control.required {
                        return Err(format!("{} must be checked", control.label));
                    }
                    None
                }
            }
            FormControlKind::Radio => {
                if control.checked {
                    if selected_radio_names
                        .iter()
                        .any(|name| name == &control.name)
                    {
                        None
                    } else {
                        selected_radio_names.push(control.name.clone());
                        Some(control.value.clone())
                    }
                } else {
                    None
                }
            }
            FormControlKind::Select => Some(control.value.clone()),
            FormControlKind::Submit => {
                if effective_submitter == Some(index) {
                    Some(control.value.clone())
                } else {
                    None
                }
            }
            FormControlKind::File => {
                if !control.value.is_empty() {
                    return Err(String::from(
                        "file uploads are not supported by this firmware browser",
                    ));
                }
                None
            }
            FormControlKind::Reset | FormControlKind::Button => None,
        };

        if control.required && value.as_ref().is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{} is required", control.label));
        }
        if control.required && value.is_none() && control.kind != FormControlKind::Radio {
            return Err(format!("{} is required", control.label));
        }
        if let Some(value) = value {
            if control.kind == FormControlKind::Email
                && !value.is_empty()
                && (!value.contains('@') || value.ends_with('@'))
            {
                return Err(format!("{} is not a valid email address", control.label));
            }
            if control.kind == FormControlKind::Number
                && !value.is_empty()
                && value.parse::<f64>().is_err()
            {
                return Err(format!("{} must be a number", control.label));
            }
            fields.push((control.name.clone(), value));
        }
    }

    for control in form
        .controls
        .iter()
        .filter(|control| control.required && control.kind == FormControlKind::Radio)
    {
        if !form.controls.iter().any(|candidate| {
            candidate.name == control.name && candidate.checked && !candidate.disabled
        }) {
            return Err(format!("{} requires one selected option", control.label));
        }
    }

    let mut query = String::new();
    for (name, value) in &fields {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&url_encode_component(name));
        query.push('=');
        query.push_str(&url_encode_component(value));
        if query.len() > MAX_FORM_BODY_BYTES {
            return Err(String::from("form data exceeds the 8 KiB submission limit"));
        }
    }

    let action =
        Url::parse(&form.action).map_err(|error| format!("invalid form action: {error}"))?;
    match form.method {
        FormMethod::Get => {
            let target = if query.is_empty() {
                action
            } else {
                action
                    .resolve(&format!("?{query}"))
                    .map_err(|error| format!("invalid GET form URL: {error}"))?
            };
            Ok((target, "GET", Vec::new()))
        }
        FormMethod::Post => {
            uefi::println!("POST sends entered form data to:");
            uefi::println!("{}", action.as_string());
            let Some(confirm) = read_line("Confirm POST? Type 'yes' to send: ", network) else {
                return Err(String::from("form cancelled"));
            };
            if !confirm.trim().eq_ignore_ascii_case("yes") {
                return Err(String::from("POST cancelled; form data was not sent"));
            }
            Ok((action, "POST", query.into_bytes()))
        }
    }
}

fn display_bookmarks(store: &mut BrowserStore) {
    let Some(store) = store.as_mut() else {
        uefi::println!("Persistent storage is unavailable.");
        return;
    };
    let entries = store.bookmarks();
    if entries.is_empty() {
        uefi::println!("No saved bookmarks.");
        return;
    }
    uefi::println!("Saved bookmarks:");
    for (index, entry) in entries.iter().enumerate() {
        uefi::println!("  {}. {} — {}", index + 1, entry.title, entry.url);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FocusTarget {
    Link(usize),
    Control(usize, usize),
}

fn control_accepts_text(kind: FormControlKind) -> bool {
    matches!(
        kind,
        FormControlKind::Text
            | FormControlKind::Password
            | FormControlKind::Email
            | FormControlKind::Search
            | FormControlKind::Number
            | FormControlKind::TextArea
    )
}

fn focus_targets(page: &BrowserPage, lines: &[RenderLine]) -> Vec<(usize, FocusTarget)> {
    let mut targets = Vec::new();
    for (index, _) in page.document.links.iter().enumerate() {
        if let Some(line) = renderer::line_for_link(lines, index) {
            targets.push((line, FocusTarget::Link(index)));
        }
    }
    for (block_index, block) in page.document.blocks.iter().enumerate() {
        let BlockKind::FormControl {
            form_index,
            control_index,
        } = &block.kind
        else {
            continue;
        };
        let form_index = *form_index;
        let control_index = *control_index;
        let Some(control) = page
            .document
            .forms
            .get(form_index)
            .and_then(|form| form.controls.get(control_index))
        else {
            continue;
        };
        if control.disabled || control.kind == FormControlKind::Hidden {
            continue;
        }
        if let Some(line) = lines
            .iter()
            .position(|line| line.block_index == Some(block_index))
        {
            targets.push((line, FocusTarget::Control(form_index, control_index)));
        }
    }
    targets.sort_by_key(|(line, target)| {
        let order = match target {
            FocusTarget::Link(index) => *index,
            FocusTarget::Control(form, control) => {
                usize::MAX / 2 + form.saturating_mul(128) + control
            }
        };
        (*line, order)
    });
    targets
}

fn apply_focus_target(
    target: FocusTarget,
    line: usize,
    selected_link: &mut Option<usize>,
    selected_control: &mut Option<(usize, usize)>,
    first_line: &mut usize,
    content_height: usize,
) {
    match target {
        FocusTarget::Link(index) => {
            *selected_link = Some(index);
            *selected_control = None;
        }
        FocusTarget::Control(form, control) => {
            *selected_link = None;
            *selected_control = Some((form, control));
        }
    }
    reveal_focus_line(line, first_line, content_height);
}

fn reveal_focus_line(line: usize, first_line: &mut usize, content_height: usize) {
    if line < *first_line {
        *first_line = line;
    } else if line >= first_line.saturating_add(content_height) {
        *first_line = line.saturating_sub(content_height.saturating_sub(1));
    }
}

fn move_focus(
    page: &BrowserPage,
    lines: &[RenderLine],
    direction: i8,
    selected_link: &mut Option<usize>,
    selected_control: &mut Option<(usize, usize)>,
    first_line: &mut usize,
    content_height: usize,
) -> bool {
    let targets = focus_targets(page, lines);
    if targets.is_empty() {
        return false;
    }
    let current = selected_control
        .map(|(form, control)| FocusTarget::Control(form, control))
        .or_else(|| selected_link.map(FocusTarget::Link));
    let current_index = current.and_then(|target| {
        targets
            .iter()
            .position(|(_, candidate)| *candidate == target)
    });
    let next = if direction >= 0 {
        current_index.map_or(0, |index| (index + 1) % targets.len())
    } else {
        current_index.map_or(targets.len() - 1, |index| {
            if index == 0 {
                targets.len() - 1
            } else {
                index - 1
            }
        })
    };
    let (line, target) = targets[next];
    apply_focus_target(
        target,
        line,
        selected_link,
        selected_control,
        first_line,
        content_height,
    );
    true
}

fn move_focus_vertical(
    page: &BrowserPage,
    lines: &[RenderLine],
    direction: i8,
    selected_link: &mut Option<usize>,
    selected_control: &mut Option<(usize, usize)>,
    first_line: &mut usize,
    content_height: usize,
) -> bool {
    let targets = focus_targets(page, lines);
    if targets.is_empty() {
        return false;
    }
    let current_line = if let Some((form, control)) = *selected_control {
        targets
            .iter()
            .find(|(_, target)| *target == FocusTarget::Control(form, control))
            .map(|(line, _)| *line)
    } else if let Some(link) = *selected_link {
        targets
            .iter()
            .find(|(_, target)| *target == FocusTarget::Link(link))
            .map(|(line, _)| *line)
    } else {
        None
    };
    let reference = current_line.unwrap_or(*first_line);
    let candidate = if direction >= 0 {
        targets
            .iter()
            .filter(|(line, _)| *line > reference || (current_line.is_none() && *line >= reference))
            .min_by_key(|(line, _)| *line)
    } else {
        targets
            .iter()
            .filter(|(line, _)| *line < reference)
            .max_by_key(|(line, _)| *line)
    };
    if let Some((line, target)) = candidate {
        apply_focus_target(
            *target,
            *line,
            selected_link,
            selected_control,
            first_line,
            content_height,
        );
        true
    } else {
        false
    }
}

fn cycle_select_option(
    page: &mut BrowserPage,
    selected_control: Option<(usize, usize)>,
    direction: i8,
) -> bool {
    let Some((form_index, control_index)) = selected_control else {
        return false;
    };
    let Some(control) = page
        .document
        .forms
        .get_mut(form_index)
        .and_then(|form| form.controls.get_mut(control_index))
    else {
        return false;
    };
    if control.kind != FormControlKind::Select || control.options.is_empty() {
        return false;
    }
    let current = control
        .options
        .iter()
        .position(|option| option.value == control.value)
        .unwrap_or(0);
    let next = if direction >= 0 {
        (current + 1) % control.options.len()
    } else if current == 0 {
        control.options.len() - 1
    } else {
        current - 1
    };
    control.value = control.options[next].value.clone();
    true
}

fn toggle_form_control(page: &mut BrowserPage, selected_control: Option<(usize, usize)>) -> bool {
    let Some((form_index, control_index)) = selected_control else {
        return false;
    };
    let Some(form) = page.document.forms.get_mut(form_index) else {
        return false;
    };
    let Some(control) = form.controls.get_mut(control_index) else {
        return false;
    };
    match control.kind {
        FormControlKind::Checkbox => {
            control.checked = !control.checked;
            true
        }
        FormControlKind::Radio => {
            let name = control.name.clone();
            for (index, sibling) in form.controls.iter_mut().enumerate() {
                if sibling.kind == FormControlKind::Radio && sibling.name == name {
                    sibling.checked = index == control_index;
                }
            }
            true
        }
        _ => false,
    }
}

fn run_browser_ui(
    page: &mut BrowserPage,
    history: &mut Vec<Url>,
    history_index: &mut usize,
    storage: &mut BrowserStore,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) {
    let mut first_line = 0usize;
    let mut selected_link: Option<usize> = None;
    let mut selected_control: Option<(usize, usize)> = None;
    let mut navigation_error: Option<String> = None;
    let mut status = String::from("Ready");
    let mut last_search = String::new();
    let mut anchor_pending = true;

    loop {
        let (columns, rows) = terminal_dimensions();
        let content_width = columns.saturating_sub(2).max(8);
        let content_height = rows.saturating_sub(5).max(1);
        let lines = renderer::layout_document(&page.document, content_width);
        if anchor_pending {
            if let Some(fragment) = page.url.fragment.as_deref() {
                first_line =
                    renderer::line_for_anchor(&page.document, &lines, fragment).unwrap_or(0);
            }
            anchor_pending = false;
        }
        let max_first = lines.len().saturating_sub(content_height);
        first_line = first_line.min(max_first);

        if selected_link.is_some_and(|index| index >= page.document.links.len()) {
            selected_link = None;
        }

        render_terminal_page(
            page,
            &lines,
            first_line,
            content_height,
            selected_link,
            selected_control,
            navigation_error.as_deref(),
            &status,
        );

        let text_entry = selected_control
            .and_then(|(form, control)| page.document.forms.get(form)?.controls.get(control))
            .is_some_and(|control| control_accepts_text(control.kind));
        let Some(action) = read_browser_action(network, selected_control.is_some(), text_entry)
        else {
            break;
        };

        let command = match action {
            BrowserAction::Quit => break,
            BrowserAction::ScrollUp => {
                first_line = first_line.saturating_sub(1);
                status = String::from("Scrolled up");
                continue;
            }
            BrowserAction::ScrollDown => {
                first_line = first_line.saturating_add(1).min(max_first);
                status = String::from("Scrolled down");
                continue;
            }
            BrowserAction::Text(character) => {
                if let Some((form, control)) = selected_control {
                    if let Some(field) = page
                        .document
                        .forms
                        .get_mut(form)
                        .and_then(|form| form.controls.get_mut(control))
                    {
                        if control_accepts_text(field.kind)
                            && !field.read_only
                            && !character.is_control()
                            && field.value.len().saturating_add(character.len_utf8())
                                <= MAX_INPUT_BYTES
                        {
                            field.value.push(character);
                            status = format!("Editing {}", field.label);
                        } else if control_accepts_text(field.kind) {
                            status = String::from("Input field reached its 2 KiB limit");
                        }
                    }
                }
                continue;
            }
            BrowserAction::Backspace => {
                if let Some((form, control)) = selected_control {
                    if let Some(field) = page
                        .document
                        .forms
                        .get_mut(form)
                        .and_then(|form| form.controls.get_mut(control))
                    {
                        if control_accepts_text(field.kind) && !field.read_only {
                            field.value.pop();
                            status = format!("Editing {}", field.label);
                        }
                    }
                }
                continue;
            }
            BrowserAction::ToggleControl => {
                if toggle_form_control(page, selected_control) {
                    status = String::from("Form control changed");
                }
                continue;
            }
            BrowserAction::ClearFocus => {
                selected_link = None;
                selected_control = None;
                status = String::from("Focus cleared");
                continue;
            }
            BrowserAction::PageUp => {
                first_line = first_line.saturating_sub(content_height.saturating_sub(1).max(1));
                status = String::from("Previous screen");
                continue;
            }
            BrowserAction::PageDown => {
                first_line = first_line
                    .saturating_add(content_height.saturating_sub(1).max(1))
                    .min(max_first);
                status = String::from("Next screen");
                continue;
            }
            BrowserAction::Top => {
                first_line = 0;
                status = String::from("Top of document");
                continue;
            }
            BrowserAction::Bottom => {
                first_line = max_first;
                status = String::from("End of document");
                continue;
            }
            BrowserAction::NextLink => {
                if cycle_select_option(page, selected_control, 1) {
                    status = String::from("Selection changed");
                } else if move_focus(
                    page,
                    &lines,
                    1,
                    &mut selected_link,
                    &mut selected_control,
                    &mut first_line,
                    content_height,
                ) {
                    status = String::from("Moved focus forward");
                } else {
                    status = String::from("No links or form controls on this page");
                }
                continue;
            }
            BrowserAction::PreviousLink => {
                if cycle_select_option(page, selected_control, -1) {
                    status = String::from("Selection changed");
                } else if move_focus(
                    page,
                    &lines,
                    -1,
                    &mut selected_link,
                    &mut selected_control,
                    &mut first_line,
                    content_height,
                ) {
                    status = String::from("Moved focus backward");
                } else {
                    status = String::from("No links or form controls on this page");
                }
                continue;
            }
            BrowserAction::MoveFocusDown => {
                if move_focus_vertical(
                    page,
                    &lines,
                    1,
                    &mut selected_link,
                    &mut selected_control,
                    &mut first_line,
                    content_height,
                ) {
                    status = String::from("Moved to next link or control");
                } else {
                    first_line = first_line.saturating_add(1).min(max_first);
                    status = String::from("Scrolled down");
                }
                continue;
            }
            BrowserAction::MoveFocusUp => {
                if move_focus_vertical(
                    page,
                    &lines,
                    -1,
                    &mut selected_link,
                    &mut selected_control,
                    &mut first_line,
                    content_height,
                ) {
                    status = String::from("Moved to previous link or control");
                } else {
                    first_line = first_line.saturating_sub(1);
                    status = String::from("Scrolled up");
                }
                continue;
            }
            BrowserAction::ActivateLink => {
                if let Some((form, control)) = selected_control {
                    format!("form-submit {} {}", form + 1, control + 1)
                } else if let Some(index) = selected_link {
                    format!("open {}", index + 1)
                } else {
                    status =
                        String::from("Press TAB or an arrow key to focus a link or form field");
                    continue;
                }
            }
            BrowserAction::Goto => {
                let Some(value) = read_line("Go to URL: ", network) else {
                    continue;
                };
                if value.trim().is_empty() {
                    continue;
                }
                format!("open {}", value.trim())
            }
            BrowserAction::Search => {
                let Some(query) = read_line("Find text: ", network) else {
                    continue;
                };
                if query.trim().is_empty() {
                    continue;
                }
                last_search = query.trim().to_string();
                let found = renderer::find_line(&lines, &last_search, first_line.saturating_add(1))
                    .or_else(|| renderer::find_line(&lines, &last_search, 0));
                if let Some(line) = found {
                    first_line = line.min(max_first);
                    status = format!("Found: {}", last_search);
                } else {
                    status = format!("Not found: {}", last_search);
                }
                continue;
            }
            BrowserAction::FindNext => {
                if last_search.is_empty() {
                    status = String::from("Use / to search the page first");
                } else {
                    let found =
                        renderer::find_line(&lines, &last_search, first_line.saturating_add(1))
                            .or_else(|| renderer::find_line(&lines, &last_search, 0));
                    if let Some(line) = found {
                        first_line = line.min(max_first);
                        status = format!("Next match: {}", last_search);
                    } else {
                        status = format!("No match: {}", last_search);
                    }
                }
                continue;
            }
            BrowserAction::Command => {
                let Some(value) = read_line(": ", network) else {
                    continue;
                };
                value
            }
            BrowserAction::Back => String::from("back"),
            BrowserAction::Forward => String::from("forward"),
            BrowserAction::Reload => String::from("reload"),
            BrowserAction::Bookmark => String::from("bookmark"),
            BrowserAction::Bookmarks => String::from("bookmarks"),
            BrowserAction::Help => {
                print_help();
                let _ = read_line("Press ENTER to return: ", network);
                status = String::from("Help closed");
                continue;
            }
            BrowserAction::Links => {
                render_links(&page.document.links);
                let _ = read_line("Press ENTER to return: ", network);
                status = String::from("Link list closed");
                continue;
            }
        };

        let mut command = command.trim().to_string();
        if let Some(number) = command.strip_prefix("open-bookmark ") {
            let index = number
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|value| value.checked_sub(1));
            let bookmark = storage
                .as_mut()
                .and_then(|store| index.and_then(|i| store.bookmarks().get(i).cloned()));
            if let Some(bookmark) = bookmark {
                command = format!("open {}", bookmark.url);
            } else {
                status = String::from("Bookmark not found, or persistent storage is unavailable");
                continue;
            }
        }
        let command = command.as_str();
        if command.is_empty() {
            continue;
        }
        if matches!(command, "q" | "quit" | "exit") {
            break;
        }
        if matches!(command, "help" | "?") {
            print_help();
            let _ = read_line("Press ENTER to return: ", network);
            continue;
        }
        if command == "links" {
            render_links(&page.document.links);
            let _ = read_line("Press ENTER to return: ", network);
            continue;
        }
        if command == "clear" {
            continue;
        }
        if command == "bookmark" {
            if let Some(store) = storage.as_mut() {
                match store.add_bookmark(&page.url.as_string(), &page.document.title) {
                    Ok(true) => status = String::from("Bookmark saved to the UEFI boot volume"),
                    Ok(false) => status = String::from("Bookmark updated"),
                    Err(_) => status = String::from("Unable to save bookmark"),
                }
            } else {
                status = String::from("Persistent storage is unavailable");
            }
            continue;
        }
        if command == "bookmarks" {
            display_bookmarks(storage);
            let _ = read_line("Press ENTER to return: ", network);
            continue;
        }
        if let Some(number) = command.strip_prefix("delete-bookmark ") {
            let removed = number
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|value| value.checked_sub(1))
                .and_then(|index| {
                    storage
                        .as_mut()
                        .and_then(|store| store.remove_bookmark(index).ok())
                })
                .unwrap_or(false);
            status = if removed {
                String::from("Bookmark deleted")
            } else {
                String::from("Bookmark not found or storage unavailable")
            };
            continue;
        }
        if command == "clear-cache" {
            if let Some(store) = storage.as_mut() {
                store.clear_cache();
                status = String::from("Persistent page cache cleared");
            } else {
                status = String::from("Persistent storage is unavailable");
            }
            continue;
        }
        if command == "cache-stats" {
            if let Some(store) = storage.as_mut() {
                let stats = store.cache_stats();
                status = format!("Disk cache: {} pages, {} bytes", stats.entries, stats.bytes);
            } else {
                status = String::from("Persistent storage is unavailable");
            }
            continue;
        }
        if let Some(arguments) = command.strip_prefix("form-submit ") {
            let mut parts = arguments.split_whitespace();
            let form_index = parts
                .next()
                .and_then(|part| part.parse::<usize>().ok())
                .and_then(|value| value.checked_sub(1));
            let control_index = parts
                .next()
                .and_then(|part| part.parse::<usize>().ok())
                .and_then(|value| value.checked_sub(1));
            let Some(form_index) = form_index else {
                status = String::from("Usage: form-submit FORM [SUBMIT_CONTROL]");
                continue;
            };
            let Some(form) = page.document.forms.get(form_index).cloned() else {
                status = String::from("Form not found on this page");
                continue;
            };
            let submitter = control_index.filter(|index| {
                form.controls.get(*index).is_some_and(|control| {
                    control.kind == FormControlKind::Submit && !control.disabled
                })
            });
            match submit_form(&form, submitter, network) {
                Ok((target, method, body)) => {
                    status = format!("Submitting {} form to {}", method, target.as_string());
                    match fetch_form_document(&target, method, &body, network) {
                        Ok(next_page) => {
                            history.truncate(*history_index + 1);
                            history.push(next_page.url.clone());
                            *history_index = history.len() - 1;
                            *page = next_page;
                            first_line = 0;
                            anchor_pending = true;
                            selected_link = None;
                            selected_control = None;
                            navigation_error = None;
                            last_search.clear();
                            status = format!("Form response: HTTP {}", page.status);
                        }
                        Err(error) => {
                            navigation_error = Some(error);
                            status = String::from("Form submission failed");
                        }
                    }
                }
                Err(error) => status = error,
            }
            continue;
        }

        if let Some(number) = command.strip_prefix("form ") {
            let index = number
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|value| value.checked_sub(1));
            let Some(form_index) = index.filter(|index| *index < page.document.forms.len()) else {
                status = String::from("Form not found on this page");
                continue;
            };
            let Some((control_index, _)) = page.document.forms[form_index]
                .controls
                .iter()
                .enumerate()
                .find(|(_, control)| !control.disabled && control.kind != FormControlKind::Hidden)
            else {
                status = String::from("This form has no visible editable controls");
                continue;
            };
            let target = FocusTarget::Control(form_index, control_index);
            let targets = focus_targets(page, &lines);
            if let Some((line, _)) = targets.iter().find(|(_, candidate)| *candidate == target) {
                apply_focus_target(
                    target,
                    *line,
                    &mut selected_link,
                    &mut selected_control,
                    &mut first_line,
                    content_height,
                );
                status = format!(
                    "Focused form {}. Type into the field; ENTER submits.",
                    form_index + 1
                );
            } else {
                status = String::from("Form control is not visible in the rendered page");
            }
            continue;
        }

        if let Some(query) = command.strip_prefix("search ") {
            let found = renderer::find_line(&lines, query, first_line.saturating_add(1))
                .or_else(|| renderer::find_line(&lines, query, 0));
            if let Some(line) = found {
                first_line = line.min(max_first);
                status = format!("Found: {}", query.trim());
            } else {
                status = format!("Not found: {}", query.trim());
            }
            last_search = query.trim().to_string();
            continue;
        }

        let mut target_index = None;
        let target_url;
        let mut add_history = false;

        match command {
            "back" => {
                if *history_index == 0 {
                    status = String::from("No previous page");
                    continue;
                }
                target_index = Some(*history_index - 1);
                target_url = Some(history[*history_index - 1].clone());
            }
            "forward" => {
                if *history_index + 1 >= history.len() {
                    status = String::from("No forward page");
                    continue;
                }
                target_index = Some(*history_index + 1);
                target_url = Some(history[*history_index + 1].clone());
            }
            "reload" => {
                target_url = Some(page.url.clone());
            }
            other => {
                let argument = other.strip_prefix("open ").unwrap_or(other).trim();
                if let Ok(number) = argument.parse::<usize>() {
                    if number == 0 || number > page.document.links.len() {
                        status = String::from("No link with that number");
                        continue;
                    }
                    target_url = match Url::parse(&page.document.links[number - 1].target) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            status = format!("Invalid link target: {error}");
                            continue;
                        }
                    };
                } else {
                    target_url = match Url::parse(argument) {
                        Ok(url) => Some(url),
                        Err(error) => {
                            status = format!("Invalid address: {error}");
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

        if same_resource(&page.url, &target)
            && (target_index.is_some() || (add_history && target.fragment.is_some()))
        {
            let anchor_line = match target.fragment.as_deref() {
                Some(fragment) => renderer::line_for_anchor(&page.document, &lines, fragment),
                None => Some(0),
            };
            if let Some(line) = anchor_line {
                if let Some(index) = target_index {
                    *history_index = index;
                } else if add_history {
                    history.truncate(*history_index + 1);
                    history.push(target.clone());
                    *history_index = history.len() - 1;
                }
                page.url = target;
                first_line = line.min(max_first);
                navigation_error = None;
                status = String::from("Moved to page fragment");
            } else {
                status = String::from("Fragment target not found on this page");
            }
            continue;
        }

        status = format!("Loading {}", target.as_string());
        render_terminal_page(
            page,
            &lines,
            first_line,
            content_height,
            selected_link,
            selected_control,
            None,
            &status,
        );
        match fetch_document(&target, network, storage) {
            Ok(next_page) => {
                if let Some(index) = target_index {
                    *history_index = index;
                } else if add_history {
                    history.truncate(*history_index + 1);
                    history.push(next_page.url.clone());
                    *history_index = history.len() - 1;
                }
                *page = next_page;
                navigation_error = None;
                first_line = 0;
                anchor_pending = true;
                selected_link = None;
                selected_control = None;
                last_search.clear();
                status = format!("Loaded HTTP {}", page.status);
            }
            Err(error) => {
                navigation_error = Some(error);
                status = String::from("Navigation failed; previous page retained");
            }
        }
    }
}

fn reveal_link(lines: &[RenderLine], link: usize, first_line: &mut usize, height: usize) {
    if let Some(line) = renderer::line_for_link(lines, link) {
        if line < *first_line {
            *first_line = line;
        } else if line >= (*first_line).saturating_add(height) {
            *first_line = line.saturating_sub(height.saturating_sub(1));
        }
    }
}

fn read_browser_action(
    network: &mut uefi_browser::snp_network::SnpNetwork,
    focused_control: bool,
    text_entry: bool,
) -> Option<BrowserAction> {
    loop {
        network.poll();
        let key = system::with_stdin(|input| input.read_key().ok().flatten());
        match key {
            Some(Key::Printable(unit)) => {
                let character: char = unit.into();
                if character == '\r' || character == '\n' {
                    return Some(BrowserAction::ActivateLink);
                }
                if character == '\u{8}' {
                    return Some(BrowserAction::Backspace);
                }
                if focused_control {
                    if text_entry && !character.is_control() {
                        return Some(BrowserAction::Text(character));
                    }
                    if character == ' ' {
                        return Some(BrowserAction::ToggleControl);
                    }
                    continue;
                }
                match character {
                    'q' | '\u{3}' => return Some(BrowserAction::Quit),
                    'g' | 'o' => return Some(BrowserAction::Goto),
                    '/' => return Some(BrowserAction::Search),
                    ':' => return Some(BrowserAction::Command),
                    'b' => return Some(BrowserAction::Back),
                    'f' => return Some(BrowserAction::Forward),
                    'r' => return Some(BrowserAction::Reload),
                    'h' | '?' => return Some(BrowserAction::Help),
                    'l' => return Some(BrowserAction::Links),
                    'm' => return Some(BrowserAction::Bookmark),
                    'v' => return Some(BrowserAction::Bookmarks),
                    'n' => return Some(BrowserAction::FindNext),
                    'j' => return Some(BrowserAction::ScrollDown),
                    'k' => return Some(BrowserAction::ScrollUp),
                    ' ' => return Some(BrowserAction::PageDown),
                    '\t' => return Some(BrowserAction::NextLink),
                    '[' => return Some(BrowserAction::PreviousLink),
                    _ => {}
                }
            }
            Some(Key::Special(code)) => match code {
                ScanCode::UP => return Some(BrowserAction::MoveFocusUp),
                ScanCode::DOWN => return Some(BrowserAction::MoveFocusDown),
                ScanCode::LEFT => return Some(BrowserAction::PreviousLink),
                ScanCode::RIGHT => return Some(BrowserAction::NextLink),
                ScanCode::PAGE_UP => return Some(BrowserAction::PageUp),
                ScanCode::PAGE_DOWN => return Some(BrowserAction::PageDown),
                ScanCode::HOME => return Some(BrowserAction::Top),
                ScanCode::END => return Some(BrowserAction::Bottom),
                ScanCode::ESCAPE => return Some(BrowserAction::ClearFocus),
                _ => {}
            },
            None => {
                uefi::boot::stall(core::time::Duration::from_micros(2_000));
            }
        }
    }
}

fn terminal_dimensions() -> (usize, usize) {
    let mut dimensions = (80usize, 25usize);
    let _ = system::with_stdout(|output| {
        if let Ok(Some(mode)) = output.current_mode() {
            dimensions = (mode.columns().max(20), mode.rows().max(10));
        }
    });
    dimensions
}

fn render_terminal_page(
    page: &BrowserPage,
    lines: &[RenderLine],
    first_line: usize,
    content_height: usize,
    selected_link: Option<usize>,
    selected_control: Option<(usize, usize)>,
    navigation_error: Option<&str>,
    status: &str,
) {
    let (width, height) = terminal_dimensions();
    let width = width.max(20);
    let content_height = content_height.min(height.saturating_sub(5).max(1));

    let header = format!(
        " UEFI BROWSER  |  HTTP {}{}  |  {}",
        page.status,
        if page.from_cache { " [DISK CACHE]" } else { "" },
        page.document.title
    );
    let address = format!(" URL  {}", page.url.as_string());
    let status_line = navigation_error.unwrap_or(status);
    let footer = " TAB focus  arrows move  TYPE edit  ENTER submit/open  PGUP/PGDN scroll  q quit";

    let _ = system::with_stdout(|output| {
        let _ = output.clear();
        write_console_row(output, 0, width, Color::LightCyan, Color::Blue, &header);
        write_console_row(output, 1, width, Color::White, Color::Black, &address);
        write_console_row(
            output,
            2,
            width,
            Color::DarkGray,
            Color::Black,
            &"-".repeat(width),
        );

        for row in 0..content_height {
            let line_index = first_line + row;
            let screen_row = 3 + row;
            let _ = output.set_cursor_position(0, screen_row);
            let _ = output.set_color(Color::LightGray, Color::Black);
            if let Some(line) = lines.get(line_index) {
                let focused_control = line
                    .block_index
                    .and_then(|index| page.document.blocks.get(index))
                    .is_some_and(|block| match &block.kind {
                        BlockKind::FormControl {
                            form_index,
                            control_index,
                        } => selected_control == Some((*form_index, *control_index))
                        _ => false,
                    });
                write_render_line(output, line, width, selected_link, focused_control);
            } else {
                write_console_text(output, " ");
            }
            let remaining = width.saturating_sub(
                lines
                    .get(line_index)
                    .map_or(0, |line| line.width.min(width)),
            );
            if remaining > 0 {
                let _ = output.set_color(Color::LightGray, Color::Black);
                let _ = write!(output, "{}", " ".repeat(remaining));
            }
        }

        let status_row = height.saturating_sub(2);
        write_console_row(
            output,
            status_row,
            width,
            if navigation_error.is_some() {
                Color::LightRed
            } else {
                Color::Yellow
            },
            Color::Black,
            &format!(
                " {}  |  line {}/{}",
                status_line,
                first_line.saturating_add(1).min(lines.len().max(1)),
                lines.len()
            ),
        );
        write_console_row(
            output,
            height.saturating_sub(1),
            width,
            Color::LightCyan,
            Color::Black,
            footer,
        );
        let _ = output.set_cursor_position(0, height.saturating_sub(1));
    });
}

fn write_console_row(
    output: &mut uefi::proto::console::text::Output,
    row: usize,
    width: usize,
    foreground: Color,
    background: Color,
    text: &str,
) {
    let _ = output.set_cursor_position(0, row);
    let _ = output.set_color(foreground, background);
    let clipped = clip_text(text, width);
    write_console_text(output, &clipped);
    let used = clipped
        .chars()
        .map(renderer::character_width)
        .sum::<usize>();
    if used < width {
        let _ = write!(output, "{}", " ".repeat(width - used));
    }
}

fn uefi_color(color: TermColor) -> Color {
    match color {
        TermColor::Black => Color::Black,
        TermColor::DarkRed => Color::Red,
        TermColor::DarkGreen => Color::Green,
        TermColor::Brown => Color::Brown,
        TermColor::DarkBlue => Color::Blue,
        TermColor::DarkMagenta => Color::Magenta,
        TermColor::DarkCyan => Color::Cyan,
        TermColor::LightGray => Color::LightGray,
        TermColor::DarkGray => Color::DarkGray,
        TermColor::LightRed => Color::LightRed,
        TermColor::LightGreen => Color::LightGreen,
        TermColor::Yellow => Color::Yellow,
        TermColor::LightBlue => Color::LightBlue,
        TermColor::LightMagenta => Color::LightMagenta,
        TermColor::LightCyan => Color::LightCyan,
        TermColor::White => Color::White,
    }
}

fn uefi_background_color(color: TermColor) -> Color {
    match color {
        TermColor::Black => Color::Black,
        TermColor::DarkRed => Color::Red,
        TermColor::DarkGreen => Color::Green,
        TermColor::Brown => Color::Brown,
        TermColor::DarkBlue => Color::Blue,
        TermColor::DarkMagenta => Color::Magenta,
        TermColor::DarkCyan => Color::Cyan,
        TermColor::LightGray => Color::LightGray,
        _ => Color::Black,
    }
}

fn write_render_line(
    output: &mut uefi::proto::console::text::Output,
    line: &RenderLine,
    width: usize,
    selected_link: Option<usize>,
    focused_control: bool,
) {
    let mut used = 0usize;
    for span in &line.spans {
        if used >= width {
            break;
        }
        let selected = focused_control || (span.link.is_some() && span.link == selected_link);
        let default_foreground = if span.link.is_some() {
            Color::LightCyan
        } else if span.style.code {
            Color::LightGreen
        } else if span.style.strong {
            Color::Yellow
        } else if span.style.emphasis {
            Color::LightMagenta
        } else {
            Color::LightGray
        };
        let foreground = if selected {
            Color::Black
        } else {
            span.style
                .foreground
                .map(uefi_color)
                .unwrap_or(default_foreground)
        };
        let background = if selected {
            Color::Cyan
        } else {
            span.style
                .background
                .map(uefi_background_color)
                .unwrap_or(Color::Black)
        };
        let _ = output.set_color(foreground, background);
        let remaining = width.saturating_sub(used);
        let clipped = clip_text(&span.text, remaining);
        write_console_text(output, &clipped);
        let span_width = clipped
            .chars()
            .map(renderer::character_width)
            .sum::<usize>();
        used = used.saturating_add(span_width);
    }
    let _ = output.set_color(Color::LightGray, Color::Black);
}

fn clip_text(text: &str, width: usize) -> String {
    let mut clipped = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let char_width = renderer::character_width(ch);
        if used.saturating_add(char_width) > width {
            break;
        }
        clipped.push(ch);
        used = used.saturating_add(char_width);
    }
    clipped
}

fn write_console_text(output: &mut uefi::proto::console::text::Output, text: &str) {
    let mut safe = String::new();
    for ch in text.chars() {
        if ch.is_control() || (ch as u32) > 0xFFFF {
            // Remote text must never be able to issue console control actions.
            safe.push('?');
        } else {
            safe.push(ch);
        }
    }
    let _ = write!(output, "{}", safe);
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

fn print_help() {
    uefi::println!("");
    uefi::println!("UEFI Browser keyboard and command reference");
    uefi::println!("  UP / DOWN       Move to nearby link or form control; otherwise scroll");
    uefi::println!("  LEFT / RIGHT    Move focus between links and controls");
    uefi::println!("  PAGE UP/DOWN    Scroll one screen");
    uefi::println!("  HOME / END      Jump to top or bottom");
    uefi::println!("  TAB / [         Focus next / previous link or form control");
    uefi::println!("  TYPE / BACKSPACE Edit a focused text field");
    uefi::println!("  SPACE           Toggle a checkbox or radio option");
    uefi::println!("  ENTER           Submit the focused form or open a focused link");
    uefi::println!("  g or o          Enter a URL");
    uefi::println!("  /               Search the rendered document; n finds next");
    uefi::println!("  :               Open the command prompt");
    uefi::println!("  b / f / r       Back / forward / reload");
    uefi::println!("  m / v           Save bookmark / show saved bookmarks");
    uefi::println!("  l               List links; q quits to firmware");
    uefi::println!(
        "  Commands: open URL, open N, open-bookmark N, bookmark, bookmarks, delete-bookmark N"
    );
    uefi::println!(
        "            form N (focus its controls), cache-stats, clear-cache, search WORD, back, forward, reload, quit"
    );
    uefi::println!("");
}

fn clear_screen() {
    let _ = system::with_stdout(|output| output.clear());
}

fn read_line(prompt: &str, network: &mut uefi_browser::snp_network::SnpNetwork) -> Option<String> {
    read_line_with_echo(prompt, network, false)
}

fn read_line_masked(
    prompt: &str,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Option<String> {
    read_line_with_echo(prompt, network, true)
}

fn read_line_with_echo(
    prompt: &str,
    network: &mut uefi_browser::snp_network::SnpNetwork,
    mask: bool,
) -> Option<String> {
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
                            if mask {
                                uefi::print!("*");
                            } else {
                                uefi::print!("{value}");
                            }
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
