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
    uefi::println!("Rust DNS: Hickory | Firmware networking: UDP4 + TCP4");
    uefi::println!("TLS: embedded Mbed TLS | Rendering: UEFI text console");
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

    uefi::println!("");
    uefi::println!("Enter a hostname or URL. Bare hostnames default to HTTPS.");
    uefi::println!("Type 'help' for commands, or Ctrl+C to return to firmware.");
    uefi::println!("");

    let Some(address) = read_line("Open address: ") else {
        return Status::SUCCESS;
    };

    let first_url = match Url::parse(&address) {
        Ok(url) => url,
        Err(error) => {
            uefi::println!("Invalid address: {error}");
            return Status::SUCCESS;
        }
    };

    let mut history = Vec::new();
    history.push(first_url);
    let mut history_index = 0usize;

    let mut page = match fetch_document(&history[history_index]) {
        Ok(page) => page,
        Err(error) => {
            uefi::println!("Navigation failed: {error}");
            return Status::SUCCESS;
        }
    };

    loop {
        render_page(&page);
        let prompt = format!("\n{} > ", page.url.as_string());
        let Some(command) = read_line(&prompt) else {
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
            render_page(&page);
            continue;
        }
        if let Some(query) = command.strip_prefix("search ") {
            search_page(&page, query);
            continue;
        }

        let mut target_index = None;
        let mut target_url = None;
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

        match fetch_document(&target) {
            Ok(next_page) => {
                if let Some(index) = target_index {
                    history_index = index;
                } else if add_history {
                    history.truncate(history_index + 1);
                    history.push(next_page.url.clone());
                    history_index = history.len() - 1;
                }
                page = next_page;
            }
            Err(error) => {
                uefi::println!("Navigation failed: {error}");
            }
        }
    }

    uefi::println!("\nLeaving UEFI Browser and returning to firmware.");
    Status::SUCCESS
}

fn fetch_document(initial_url: &Url) -> Result<BrowserPage, String> {
    let mut current = initial_url.clone();

    for redirect_index in 0..=MAX_REDIRECTS {
        let response = fetch_response(&current)?;
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

fn fetch_response(url: &Url) -> Result<HttpResponse, String> {
    #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle)))]
    if url.scheme == Scheme::Https {
        return Err(String::from(
            "HTTPS unavailable: this EFI image needs the linked Mbed TLS bridge and embedded CA bundle",
        ));
    }

    let mut connection = connect_firmware_url(url, 15_000)
        .map_err(|error| format!("firmware network setup failed: {error:?}"))?;

    match url.scheme {
        Scheme::Http => http::exchange_get(&mut connection.peer.stream, url, MAX_BODY_BYTES)
            .map_err(|error| format!("HTTP transaction failed: {error:?}")),
        Scheme::Https => {
            #[cfg(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle))]
            {
                let ca_bundle = uefi_browser::ca_bundle::pem()
                    .ok_or_else(|| String::from("no embedded CA trust bundle"))?;
                let mut tls = connection
                    .start_tls(ca_bundle)
                    .map_err(|error| format!("TLS initialization failed: {error:?}"))?;
                tls.handshake()
                    .map_err(|error| format!("TLS peer verification failed: {error:?}"))?;
                http::exchange_get(&mut tls, url, MAX_BODY_BYTES)
                    .map_err(|error| format!("HTTPS transaction failed: {error:?}"))
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

fn render_page(page: &BrowserPage) {
    clear_screen();
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("| UEFI BROWSER                                                             |");
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("Title:  {}", page.title);
    uefi::println!("URL:    {}", page.url.as_string());
    uefi::println!("HTTP:   {}", page.status);
    uefi::println!("--------------------------------------------------------------------------");
    uefi::println!("{}", page.text);
    if !page.links.is_empty() {
        uefi::println!("");
        render_links(&page.links);
    }
    uefi::println!("");
    uefi::println!("Commands: open N | URL | back | forward | reload | links | search WORD | help | quit");
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

fn read_line(prompt: &str) -> Option<String> {
    uefi::print!("{prompt}");
    let mut line = String::new();

    loop {
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
