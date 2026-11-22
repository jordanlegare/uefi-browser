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

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
unsafe extern "C" {
    fn uefi_mbedtls_link_anchor() -> i32;
}


#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_tls_log(stage: i32, detail: i32) {
    let message = match stage {
        1 => "TLS init: entering psa_crypto_init",
        2 => "TLS init: PSA crypto initialized",
        3 => "TLS init: parsing embedded CA bundle",
        4 => "TLS init: CA bundle parsed",
        5 => "TLS init: applying Mbed TLS client defaults",
        6 => "TLS init: Mbed TLS defaults applied",
        7 => "TLS init: allocating SSL session",
        8 => "TLS init: SSL session allocated",
        9 => "TLS init: setting SNI and hostname",
        10 => "TLS init: session configured",
        11 => "TLS handshake: entering mbedtls_ssl_handshake",
        12 => "TLS handshake: Mbed TLS returned",
        20 => "TLS entropy: entering EFI_RNG_PROTOCOL",
        21 => "TLS entropy: EFI_RNG_PROTOCOL returned",
        _ => "TLS diagnostic",
    };
    uefi::println!("{} (detail={})", message, detail);
}

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

    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("|                         UEFI BROWSER                         |");
    uefi::println!("|               standalone x86_64 pre-OS browser               |");
    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("Rust DNS: Hickory | IP stack: smoltcp over UEFI SNP");
    uefi::println!("TLS: embedded Mbed TLS | Rendering: UEFI text console");
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

    #[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
    {
        // Touch the allocator and clock exports so their definitions remain
        // reachable for the statically linked C bridge.
        let allocation = uefi_browser::uefi_memory::uefi_mbedtls_calloc(1, 16);
        if !allocation.is_null() {
            uefi_browser::uefi_memory::uefi_mbedtls_free(allocation);
        }
        let bridge_linked = unsafe { uefi_mbedtls_link_anchor() } == 0;
        uefi::println!("Mbed TLS 4.3 static bridge: {}", bridge_linked);
        uefi::println!(
            "UEFI clock suitable for X.509: {}",
            uefi_browser::firmware_time::uefi_browser_time_unix() >= 0
        );
    }

    #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked)))]
    uefi::println!("Mbed TLS bridge: unavailable (build with scripts/build-uefi.sh)");

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
    #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle)))]
    if url.scheme == Scheme::Https {
        return Err(String::from(
            "HTTPS unavailable: this EFI image needs the linked Mbed TLS bridge and embedded CA bundle",
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
            #[cfg(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle))]
            {
                let ca_bundle = uefi_browser::ca_bundle::pem()
                    .ok_or_else(|| String::from("no embedded CA trust bundle"))?;
                uefi::println!("Starting TLS handshake and X.509 verification...");
                // The TCP stream's normal navigation timeout is 15 seconds.
                // Use a shorter per-I/O timeout for TLS so a peer that accepts
                // TCP but never sends a ServerHello cannot freeze the UI.
                connection.peer.stream.set_io_timeout_ms(5_000);
                let mut tls = connection
                    .start_tls(ca_bundle)
                    .map_err(|error| format!("TLS initialization failed: {error:?}"))?;
                uefi::println!("TLS session initialized; beginning handshake.");
                tls.handshake().map_err(|error| {
                    format!("TLS handshake / certificate verification failed: {error:?}")
                })?;
                uefi::println!("TLS verified. Sending HTTPS request...");
                let response = http::exchange_get(&mut tls, url, MAX_BODY_BYTES)
                    .map_err(|error| format!("HTTPS transaction failed: {error:?}"))?;
                uefi::println!("HTTPS response received ({} bytes).", response.body.len());
                Ok(response)
            }

            #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle)))]
            {
                let _ = connection;
                Err(String::from(
                    "HTTPS unavailable: this EFI image has no linked Mbed TLS bridge and embedded CA bundle",
                ))
            }
        }
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
