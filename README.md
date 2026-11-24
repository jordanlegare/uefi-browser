# UEFI Browser

UEFI Browser is a standalone Rust application for x86-64 UEFI firmware. It is a keyboard-driven text browser designed to run directly from firmware, before an operating system is started. The project combines an in-application IPv4 network stack, mandatory wolfSSL HTTPS verification, a bounded HTML document engine, terminal-oriented CSS/layout, and persistent bookmarks and page caching.

> **Build status:** The portable-core tests, x86-64 UEFI target check, embedded wolfSSL build, standalone EFI link, and PE32+ image verification pass in GitHub Actions. **Firmware runtime validation is still outstanding.** A successful build does not establish that every firmware/NIC combination boots, obtains a lease, or browses reliably. This is an experimental pre-OS browser, not a release-verified replacement for an operating-system browser.

## Features

| Area | Current implementation |
|---|---|
| Firmware application | Rust `no_std` x86-64 UEFI application, packaged as a PE32+ EFI executable |
| Ethernet and IP | Firmware Simple Network Protocol (SNP) NIC driver with smoltcp Ethernet, ARP, IPv4, DHCPv4, UDP and TCP |
| DNS and time | Hickory A/AAAA queries, bounded CNAME traversal, UDP with DNS/TCP retry for truncated replies; SNTP bootstrap over UDP |
| HTTP and HTTPS | HTTP/1.1 GET/POST, bounded response parsing, redirects, ETag/Last-Modified conditional GET revalidation, wolfSSL 5.9.4 TLS |
| TLS trust | Mandatory peer-chain and host-identity verification against embedded CA roots; no certificate bypass |
| HTML | Bounded tokenizer and HTML5-style tree construction, including implied document/table nodes and common omitted-tag repair |
| CSS and layout | Terminal CSS subset with type/class/ID/descendant, attribute and basic structural selectors, `!important` cascade, reflow and measured tables |
| Navigation | Link focus/following, history, in-page search, same-document fragment navigation |
| Forms | URL-encoded GET and POST controls; password input is masked and POST requires confirmation |
| Persistence | Boot-volume bookmarks, 100-entry recent history, and an eight-entry HTML/text cache with conditional validators |

This is a deliberately bounded HTML5/CSS subset. It does not implement the complete WHATWG HTML parsing algorithm, full CSS layout, JavaScript, or ELinks feature parity.

## Architecture

The browser does not use an operating-system network stack or firmware IPv4/UDP4/TCP4 services. UEFI supplies the Ethernet NIC driver through SNP; smoltcp implements the network protocols inside the application.

    URL
      |
      v
    UEFI Simple Network Protocol (firmware NIC driver)
      |
      v
    smoltcp
      Ethernet, ARP, IPv4, DHCPv4, UDP and TCP
      |
      +--------------------+-------------------+
      |                    |                   |
      v                    v                   v
    Hickory DNS          SNTP              TCP stream
    over UDP             over UDP               |
                                                 v
                                           wolfSSL 5.9.4
                                           TLS 1.3 client
                                           mandatory X.509 checks
                                                 |
                                                 v
                                           HTTP/1.1
                                                 |
                                                 v
                                     HTML tree -> CSS -> layout
                                                 |
                                                 v
                                        UEFI text console

DHCPv4 configures the interface address, default route and DNS resolver. Hickory constructs and validates DNS wire messages; the application transports them through smoltcp UDP sockets. The browser retains the original URL hostname for TLS SNI and certificate identity checks even though DNS resolution produces a numeric address.

The browser requires firmware that exposes an Ethernet-capable SNP driver, EFI_RNG_PROTOCOL, and UEFI Runtime Services. It does not bundle a hardware-specific NIC driver. IPv4 networking is implemented by smoltcp in the EFI application.

## HTTPS and certificate verification

HTTPS uses wolfSSL 5.9.4 statically linked into the EFI image. The browser embeds a build-generated CA bundle and configures wolfSSL for mandatory peer verification, hostname/IP identity checking, and certificate validity-time checks. TLS randomness comes from EFI_RNG_PROTOCOL; certificate time comes from the validated UEFI Runtime Services clock. If the required trust material, RNG, time, chain, or hostname validation is unavailable or invalid, HTTPS fails closed.

There is no certificate-acceptance prompt, insecure verification mode, or fallback that retries a rejected HTTPS connection without verification. Redirects from HTTPS to HTTP are rejected.

When local verification fails, the browser can capture the wolfSSL error, failing chain depth, and rejected-certificate details. For DNS hostnames it can optionally compare the observed fingerprints with the independently TLS-verified GRC chain page. That comparison is diagnostic evidence only: it cannot add trust anchors or override wolfSSL's rejection. A chain difference is not, by itself, proof of interception.

See [TLS Certificate and Chain-of-Trust Verification](docs/TLS-CHAIN-VERIFICATION.md) for the verification sequence, diagnostics, comparison rules and limitations.

### Trust bundle

The build obtains the curl/Mozilla-derived CA bundle, verifies its published checksum, applies the repository's additional pinned-root preparation/filtering steps, and embeds the resulting PEM data in the EFI image. The generated trust bundle is a build input and is not committed as a periodically refreshed binary asset by default.

Prepare and build with:

    ./scripts/build-uefi.sh

That script fetches and checksum-verifies the pinned wolfSSL source, builds the static library and UEFI C bridge, prepares the trust bundle, and builds the EFI executable.

## HTML, CSS and rendering

### HTML tree construction

The parser uses bounded token and tree storage. It handles quoted and unquoted attributes, text and character references, raw-text/RCDATA elements, implied html/head/body nodes, common optional end tags, and common table repairs such as implied table sections and rows. The document builder retains semantic blocks, inline formatting, links, anchors, forms and table-cell structure.

The parser is not a complete WHATWG HTML implementation. It includes common implied-node and optional-tag repairs plus basic table foster parenting for misplaced text/elements, but full insertion-mode behaviour, adoption-agency formatting repair, and the complete named character-reference set are not implemented. Resource limits prevent unbounded remote documents from consuming arbitrary memory: the tree is capped at 16,384 nodes, nesting at 128 levels, attributes at 64 per element, and token storage is bounded. Remote scripts are inert; they are never executed.

### CSS and terminal layout

The style engine applies rules from embedded style elements, up to four linked external stylesheets, and inline style attributes. External stylesheets are limited to 32 KiB each. An HTTPS document does not load an HTTP stylesheet.

Supported selector forms include type, universal, class, ID, descendant, attribute-presence/equality, and basic structural pseudo-classes (`:first-child`, `:last-child`, `:only-child`, `:empty`, and numeric `:nth-child(n)`). Normal and `!important` declarations participate in the implemented author-style cascade, including inline declarations. Supported terminal-relevant properties include display, font weight/style, text decoration, foreground/background colors, whitespace handling, margins, indentation, text alignment and percentage width. Colors are mapped to the UEFI 16-color console palette.

The renderer reflows text to the active console width and measures table columns from cell contents. Long cells wrap, colspan contributes to column sizing, and bounded rowspan placement reserves columns across subsequent rows. Row-group IDs keep row spans inside their thead/tbody/tfoot group; rowspan=0 extends to the end of that group. This is a text-console table model, not the full HTML table layout algorithm.

Not implemented: the complete CSS cascade and selector grammar, pseudo-elements, most pseudo-classes/combinators, media queries, @import, floats, positioned layout, flexbox, grid, browser font metrics, and complete HTML table algorithms. The new selectors and cascade rules are deliberate bounded subsets, not browser-grade CSS conformance.

### Navigation, fragments and forms

Element IDs and legacy named anchors are retained as fragment targets. Navigating to a fragment in the current document moves the viewport locally without another HTTP request. Fragments remain part of the browser's visible/history URL but are omitted from the HTTP request target.

Forms render as visible ASCII objects in the document flow: text fields have a bordered `+-----+` frame, an editable interior row, and a trailing `_` insertion marker. The focus highlight lands on that interior row, not on the border or a detached prompt. Use **Tab** or the arrow keys to move between links and fields, type directly into the focused box, and use **Backspace** to edit. Controls are emitted at their original HTML positions so surrounding labels and text stay in order. **Enter** submits the focused form; it does not open a second series of prompts. Space toggles checkboxes and radio options, while Left/Right changes the selected option in a select control. Labels associated with inputs are retained, and password values are masked in the rendered field. GET and POST submissions use application/x-www-form-urlencoded; POST still requires explicit confirmation, and request bodies are capped at 8 KiB.

File upload, multipart form encoding, JavaScript-driven forms, cookies/session state, and full HTML constraint validation are not implemented.

## Bookmarks and persistent cache

Persistent records are stored in the **UEFI_BROWSER** directory on the filesystem volume from which the EFI image was loaded. Records are versioned and bounded; writes use a temporary file followed by a rename.

- Bookmarks: up to 64 saved entries.
- Page cache: up to 8 URL-hashed entries, with a maximum body size of 256 KiB per entry.
- Expiry: entries without validators use a six-hour local freshness window, evaluated using the validated UEFI UTC clock.
- Revalidation: cached entries carrying ETag or Last-Modified are checked with conditional GET requests; a 304 response reuses the stored body.
- Cached content: successful HTML/plain-text GET responses only.
- Browsing history: up to 100 recent URLs/titles/timestamps, with duplicate URLs moved to the newest position.
- Exclusions: responses marked no-store, no-cache or private, and responses containing Set-Cookie, are not persisted.

Pages served from disk cache are visibly marked in the browser status/header. The `history` command lists persistent visits, `open-history N` reopens an entry, and `clear-history` removes the history file. If the EFI image's filesystem is unavailable or read-only, the browser continues without persistent storage.

## Keyboard and command reference

| Key | Action |
|---|---|
| Up / Down | Move to the nearest link or form control above/below; scroll if none |
| Left / Right | Move focus between links/controls; change a focused select value |
| j / k | Scroll one line |
| Page Up / Page Down | Scroll one page |
| Home / End | Move to document boundaries |
| Tab / [ | Move to the next/previous focusable link or form control |
| Printable keys / Backspace | Edit the focused text field |
| Space | Toggle a focused checkbox or radio option |
| Enter | Submit the focused form or follow the focused link |
| l | List links |
| g / o | Enter or open a URL |
| b / f | Back / forward |
| r | Reload |
| /, n | Search within the current page / next match |
| m / v | Save current page as a bookmark / view bookmarks |
| : | Open the command prompt |
| q | Quit to firmware |

The command prompt supports URL opening, opening a numbered link or bookmark, bookmark management, focusing a form, cache inspection and cache clearing. The `form N` command moves focus to the first visible control in form N; edit the visible fields and press Enter to submit. Commands include:

    open URL
    open N
    open-bookmark N
    bookmark
    bookmarks
    delete-bookmark N
    form N
    history
    open-history N
    clear-history
    cache-stats
    clear-cache
    search WORD

Use `form N` to focus the first visible control in a numbered form. You can also focus links and controls with Tab or the arrow keys. Enter submits the form using the values currently shown in the fields. The browser asks for confirmation before sending a POST request.

## Build and test

### Prerequisites

- Rust stable 1.91 or newer.
- The x86-64 UEFI target.
- CMake and Ninja.
- Clang/LLVM, lld and llvm-ar with x86-64 COFF support.
- MinGW-w64 x86-64 development headers.
- curl, unzip, tar and sha256sum.
- Firmware with an SNP-capable Ethernet NIC driver, EFI_RNG_PROTOCOL and Runtime Services time.

On Debian/Ubuntu, the C build tools can be installed with:

    sudo apt-get install cmake ninja-build clang llvm lld curl unzip mingw-w64-x86-64-dev

Install the Rust target:

    rustup update stable
    rustup target add x86_64-unknown-uefi

### Portable checks

Run formatting and the host-side portable-core tests:

    cargo fmt --all -- --check
    cargo test --lib

Check that the Rust application compiles for UEFI:

    cargo check --target x86_64-unknown-uefi

A host-side build without the UEFI target does not activate target-specific UEFI dependencies and is not a substitute for the UEFI check.

### Complete EFI image

Build the standalone image, including wolfSSL and the embedded trust bundle:

    ./scripts/build-uefi.sh

Expected outputs:

    target/x86_64-unknown-uefi/release/uefi-browser.efi
    dist/EFI/BOOT/BOOTX64.EFI

The removable-media path is **EFI/BOOT/BOOTX64.EFI**. Copying the file to that path does not guarantee networking: firmware must still provide a working SNP NIC driver and the network must provide a DHCPv4 lease, gateway and DNS resolver.

Do not run the EFI executable as a Linux program. Start it through UEFI firmware, an EFI shell, or a UEFI virtual machine such as OVMF.

### Continuous integration

The GitHub Actions workflow runs:

1. rustfmt validation;
2. portable library tests;
3. an x86-64 UEFI target compile;
4. strict RFC 5280 date-validation and freestanding C-runtime tests;
5. the wolfSSL static cross-build and Rust EFI link; and
6. PE/COFF image inspection and EFI artifact upload.

The recorded validation for the HTML/CSS/persistence implementation passed **45 portable-core tests**, the UEFI target check, the wolfSSL bridge/static build, and standalone PE32+ EFI image verification. See the [CI workflow](https://github.com/jordanlegare/uefi-browser/actions/workflows/ci.yml) and [implementation validation run](https://github.com/jordanlegare/uefi-browser/actions/runs/45357072690).

**Important:** CI verifies compilation and image structure; it does not boot the image. OVMF network testing and physical-firmware testing—including SNP interoperability, DHCP, DNS, NTP, HTTP and HTTPS—remain required before treating the browser as release-ready.

## Repository map

| Path | Responsibility |
|---|---|
| src/main.rs | UEFI entry point, interactive browser loop, navigation and form handling |
| src/html5.rs | Bounded HTML tokenizer and tree construction |
| src/css.rs | Stylesheet parsing, selector matching and computed terminal styles |
| src/document.rs | DOM-to-document conversion, links, anchors, forms and tables |
| src/renderer.rs | Width-aware reflow, text styling and measured table layout |
| src/url.rs | URL parsing, relative resolution and fragment handling |
| src/http.rs | HTTP/1.1 request construction, response parsing and body decoding |
| src/persistence.rs | Versioned bookmark/cache records and storage abstraction |
| src/uefi_storage.rs | UEFI boot-volume filesystem adapter |
| src/snp_network.rs | SNP adapter and persistent smoltcp network interface |
| src/dns.rs | Hickory DNS query construction and response validation |
| src/firmware_ntp.rs, src/firmware_time.rs | SNTP bootstrap and validated UEFI clock handling |
| src/tls.rs | Rust wolfSSL boundary and TCP I/O callbacks |
| src/firmware_rng.rs, src/uefi_memory.rs | UEFI entropy and wolfSSL memory hooks |
| vendor/wolfssl-bridge/ | wolfSSL TLS, platform, date and freestanding C bridges |
| scripts/ | wolfSSL retrieval/build and CA bundle preparation |
| docs/TLS-CHAIN-VERIFICATION.md | TLS verification and certificate-failure diagnostics |
| docs/FIRMWARE-TESTING.md | OVMF and physical UEFI runtime test procedures and evidence checklist |
| docs/ELINKS-COMPATIBILITY.md | ELinks behavioural reference and licensing boundary |

## Scope and security limitations

This application runs with firmware privileges and processes untrusted network content. Parser, memory, networking or TLS integration defects can affect the machine before the operating system starts. Use it as an experimental project, not to handle secrets or replace a maintained browser.

Current limitations include:

- No JavaScript execution, DOM scripting, cookies, session management or service workers.
- No file uploads, multipart forms, downloads or full HTML form validation.
- No complete HTML Living Standard parser or complete CSS layout engine.
- Basic rowspan-aware table cell placement is implemented; the full HTML table layout algorithm, flexbox, grid, floats and positioned elements remain unsupported.
- DNS supports A and AAAA query construction/answer parsing with bounded CNAME traversal, and retries truncated UDP answers over DNS/TCP. DNS transport to the configured resolver and browser TCP sockets are still IPv4-only; IPv6-only destinations are not yet reachable. DNSSEC and DNS-over-TLS/HTTPS are not implemented.
- Conditional HTTP cache revalidation supports ETag and Last-Modified with 304 reuse; full RFC 9111 freshness, Vary, heuristic caching and cache-control semantics are not implemented.
- Table layout supports measured columns, colspan, row-group-aware bounded rowspan and rowspan=0; the full HTML table layout algorithm remains incomplete.
- Firmware boot/runtime interoperability has not yet been demonstrated across OVMF and physical machines. See [Firmware Runtime Test Plan](docs/FIRMWARE-TESTING.md).

The SNTP bootstrap is not authenticated time. Packet validation helps reject unrelated or malformed replies but does not prevent an on-path attacker from forging a response. TLS validation remains mandatory; the browser does not disable certificate date checks when time is unavailable.

## ELinks compatibility and licensing

The project is a clean-room Rust implementation inspired by ELinks' text-browser behaviour. It does not link ELinks' GPLv2-only C application into this GPL-3.0-only EFI image. The reused ELinks entity mapping data is public domain; details and the source boundary are documented in [ELinks reuse and UEFI porting boundary](docs/ELINKS-COMPATIBILITY.md).

## Roadmap

- [x] Standalone Rust no_std x86-64 UEFI application and PE32+ EFI image.
- [x] SNP-backed Ethernet and in-application smoltcp IPv4/DHCP/UDP/TCP stack.
- [x] Hickory DNS A queries, bounded CNAME chains and SNTP bootstrap.
- [x] DNS AAAA query/answer parsing and bounded CNAME traversal.
- [x] DNS-over-TCP retry when a UDP answer is marked truncated.
- [x] wolfSSL TLS with mandatory certificate-chain, validity-time and hostname validation.
- [x] Bounded HTML tree construction, implied nodes, optional end-tag repairs and basic table foster parenting.
- [ ] Complete WHATWG HTML parsing, adoption-agency formatting repair and full character-reference coverage.
- [x] Terminal CSS type/class/ID/descendant, attribute-presence/equality and basic structural selectors.
- [x] Normal/important cascade ordering for the supported CSS declarations.
- [ ] Complete CSS grammar, pseudo-elements, flexbox, grid, floats, positioned layout and media queries.
- [x] Width-aware text reflow, measured table columns, colspan and bounded rowspan placement.
- [x] Respect thead/tbody/tfoot row-group boundaries and rowspan=0 when laying out table cells.
- [ ] Complete the remaining HTML table layout algorithms and intrinsic width calculations.
- [x] Fragment navigation and URL-encoded GET/POST forms.
- [x] Visible ASCII form controls, direct editing, focus movement and Enter submission.
- [x] Persistent bookmarks, bounded page cache, ETag/Last-Modified revalidation and 304 body reuse.
- [x] Persistent bounded browsing history with list, reopen and clear commands.
- [ ] Full RFC 9111 caching semantics, including Vary and complete Cache-Control handling.
- [ ] IPv6 network configuration and IPv6 TCP/HTTPS connections (DNS AAAA answers alone do not provide IPv6 reachability).
- [ ] Automated OVMF boot/network/form smoke testing.
- [ ] Physical-firmware and NIC interoperability testing.

The current branch implements a substantially broader, tested terminal-browser subset, but this project is not yet a fully conformant WHATWG browser. Firmware runtime checks remain separate from compile-time CI and must be completed in OVMF and on target hardware.
## References

- [Hickory DNS protocol crate](https://docs.rs/hickory-proto/0.26.3/hickory_proto/)
- [wolfSSL](https://github.com/wolfSSL/wolfssl)
- [UEFI specifications](https://uefi.org/specifications)
- [Rust UEFI crate](https://docs.rs/uefi/)
- [Rust UEFI target](https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html)

## License

The project is licensed under GPL-3.0-only. The GPLv3 text is included in **COPYING**, and wolfSSL copyright and license notices are retained.
