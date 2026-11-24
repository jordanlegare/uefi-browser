# UEFI Browser

A standalone Rust application for x86-64 UEFI firmware, intended to grow into a full terminal web browser in the style of ELinks. It is packaged as a PE32+ EFI application and designed to run before an operating system.

> **Status: wolfSSL-linked EFI image build is CI-verified; this renderer expansion is awaiting its own CI and firmware runtime test.** The browser includes SNP Ethernet, smoltcp IPv4/DHCP/UDP/TCP, Hickory DNS, mandatory wolfSSL 5.9.4 certificate validation, a bounded HTML tree builder, a CSS subset, width-aware table layout, GET/POST forms, fragments, boot-volume bookmarks, and an eight-slot persistent page cache. This is not full HTML5/CSS conformance or ELinks feature parity. Boot and interactive rendering of this new engine still require OVMF and physical-firmware testing.

## TLS certificate failure diagnostics

HTTPS certificate verification is mandatory. If wolfSSL rejects a peer certificate, the browser blocks the original connection, reports the verifier error and failing certificate details when available, and attempts an independently TLS-verified GRC fingerprint comparison for DNS hostnames. GRC is corroborating evidence only: it cannot override local verification or add trust anchors. A chain mismatch is reported as a possible interception/path discrepancy, not proof of MITM.

See [TLS Certificate and Chain-of-Trust Verification](docs/TLS-CHAIN-VERIFICATION.md) for the step-by-step verification flow, failure handling, comparison semantics, coverage, and limitations.

## Goals

- Run directly as an x86-64 UEFI application without Linux, initramfs, shell, or host userspace.
- Run while UEFI Boot Services remain active; use the firmware NIC driver through SNP and acquire IPv4 configuration with the in-application DHCPv4 client.
- Use UEFI Simple Network Protocol only for Ethernet frames; implement ARP, IPv4, DHCPv4, UDP, and TCP in the EFI application with smoltcp.
- Use a Rust DNS client library for DNS packet encoding and decoding.
- Bundle wolfSSL into the EFI image so HTTPS does not depend on a firmware TLS service.
- Require X.509 chain and hostname verification; never offer a certificate-bypass mode.
- Provide a keyboard-first terminal interface with URL navigation, history, link following, and search.
- Keep the final executable self-contained, including cryptographic code and trust anchors.

## Network and TLS architecture

DNS and TLS are separate protocols. DNS is a short request/response exchange over UDP (normally port 53); TLS is a stream protocol layered over TCP (normally port 443). There is no DNS4 stream adapter in wolfSSL, and wolfSSL does not resolve hostnames itself.

The project uses this pipeline:

~~~text
URL: https://www.example.org/path
       |
       v
EFI Simple Network Protocol (SNP)
  - firmware NIC driver transmits/receives Ethernet frames
  - no firmware IPv4, UDP4, or TCP4 protocol required
       |
       v
smoltcp (Rust, no_std)
  - Ethernet framing, ARP, IPv4 and routing
  - DHCPv4 lease, default gateway, and DNS-server discovery
  - bounded UDP and TCP sockets with polling/timeouts
       |
       +--------------------------+
       |                          |
       v                          v
Hickory DNS over UDP         NTP over UDP/123
  - DNS A / IN query          - validates response fields
  - source endpoint check    - sets UEFI Runtime Services clock
       |                          |
       +------------+-------------+
                    |
                    v
              IPv4 endpoint
                    |
                    v
             smoltcp TCP socket
                    |
                    v
              wolfSSL 5.9.4
  - original hostname retained for SNI and X.509 identity
  - mandatory chain and hostname verification
  - CA roots embedded in EFI image
  - entropy from EFI_RNG_PROTOCOL
  - certificate time from UEFI Runtime Services
                    |
                    v
              HTTP/1.1 client
                    |
                    v
bounded HTML tree -> CSS cascade -> table/block layout -> firmware-console renderer -> keyboard navigation
~~~

The firmware path is implemented in src/snp_network.rs. It locates an EFI_SIMPLE_NETWORK_PROTOCOL handle, starts and initializes the NIC, enables unicast/broadcast/multicast reception, and exposes complete Ethernet frames through smoltcp's Device trait. smoltcp performs ARP, IPv4 routing, DHCPv4, UDP, and TCP in the EFI application. DHCP configuration supplies the address, default route, and DNS resolver; no EFI IPv4 Config2 protocol is consulted. The browser creates the SNP/smoltcp stack once at startup, acquires its DHCP lease, synchronizes the clock, and retains the interface for the entire navigation session. Each connect_firmware_url() call resolves the requested hostname with Hickory over a smoltcp UDP socket and opens a smoltcp TCP socket on that already-configured interface. The returned FirmwareConnection temporarily borrows the persistent stack while HTTP/TLS I/O runs; dropping the connection closes only its TCP socket, not the DHCP lease or NIC state. The original URL hostname remains available for TLS SNI and certificate identity checks.

The SNP adapter polls the firmware receive queue and emits complete Ethernet frames through smoltcp TxTokens. smoltcp owns protocol state and socket buffers; the application polls the interface while waiting for DHCP, UDP replies, TCP connection completion, and stream I/O. The keyboard input loop also polls the interface during idle prompt time so DHCP renewals and protocol timers continue while the user is reading or typing. No UEFI IP4 Config2, UDP4, or TCP4 Service Binding interfaces are opened. The NIC's SNP driver remains firmware-provided; this project does not bundle a hardware-specific Ethernet driver.

The UEFI handoff is implemented by connect_firmware_url() in src/network.rs: it borrows the long-lived SnpNetwork, resolves the hostname via Hickory/UDP, opens a smoltcp TCP socket, and returns a stream wrapper borrowing the interface. The portable connect_url()/Tcp4Connector abstraction remains available for host-side testing; the UEFI browser does not use EFI_TCP4_PROTOCOL. In both paths, ConnectedPeer retains the original URL hostname so ConnectedPeer::start_tls() can pass it to TlsConnection::new() for SNI and X.509 identity checks.

This separation matters for HTTPS: TCP connects to the numeric IP address, while wolfSSL must still receive the DNS hostname so that SNI and certificate identity checks use the expected server name.

### DNS policy and transport

This implementation does not use EFI_DNS4_PROTOCOL or any firmware IP-layer resolver. Hickory builds and validates DNS wire messages; the application transports them through smoltcp UDP sockets over the SNP-backed Ethernet interface. DHCPv4 supplies the resolver address, and responses are accepted only from the selected resolver IPv4 address and UDP source port. Temporary UDP sockets use bounded packet buffers and timeout loops. The same UDP transport is used for SNTP.

The DNS policy uses hickory-proto 0.26.3 with default features disabled. It sends IPv4 A/IN queries with a secure random transaction ID, retries a timeout once, and validates transaction ID, response/opcode, truncation flag, response code, question type/class/name, and answer owner/class. It currently does not chase CNAME chains, issue AAAA queries, use DNSSEC, cache answers, expand search domains, or retry truncated UDP messages over DNS/TCP.

## Current implementation status

| Component | Status |
|---|---|
| Rust no_std UEFI application crate | Present |
| x86-64 UEFI target configuration | Present |
| Firmware console startup and interactive input | Implemented |
| HTTP/HTTPS URL parser and relative URL resolution | Implemented in portable core |
| Bounded HTML5-style tokenization and DOM tree construction | Implemented in portable core; not full WHATWG conformance |
| CSS cascade and console-oriented layout subset | Implemented for internal/linked stylesheets and inline declarations |
| Width-calculated terminal tables | Implemented for columns and colspan; rowspan layout is not yet implemented |
| Fragment navigation | Implemented without an extra HTTP request for same-document fragments |
| GET/POST URL-encoded forms | Implemented with masked password input and explicit POST confirmation |
| Persistent bookmarks and bounded page cache | Implemented on the EFI image's boot volume |
| Hickory DNS message encoding/decoding | Implemented with default std features disabled |
| DNS A-query client and response validation | Implemented with bounded retries and response checks |
| SNP Ethernet driver adapter | Implemented using EFI_SIMPLE_NETWORK_PROTOCOL |
| DHCPv4, IPv4 routing, ARP, UDP and TCP | Implemented in the application with smoltcp |
| Hickory DNS and SNTP over UDP | Implemented on the persistent smoltcp interface |
| TCP connect/send/receive timeout handling | Implemented with bounded smoltcp polling and socket cleanup |
| Secure random source abstraction and EFI RNG implementation | Implemented; no weak fallback |
| Firmware UTC conversion and fail-closed date policy | Implemented; unspecified timezone, DST flags, invalid RTC and implausibly old time are rejected |
| DNS-to-TCP-to-TLS orchestration | Implemented; hostname is retained for SNI and certificate checks |
| TCP stream-to-wolfSSL callback bridge | Implemented in Rust/C |
| wolfSSL 5.9.4 source fetch and archive checksum verification | Implemented |
| UEFI Boot Services allocator hooks for wolfSSL | Implemented; static-link verification pending |
| wolfSSL certificate-time hook | Implemented in C/Rust source and configured for the build |
| wolfSSL static libraries and PE/COFF link integration | Build and link job added; CI verification pending |
| Mozilla-derived CA bundle update script | Implemented with checksum verification |
| Build-time CA bundle embedding | Implemented; bundle asset is generated locally, not committed by default |
| HTTP/1.1 GET and response parsing | Implemented |
| Content-Length, chunked and close-delimited response bodies | Implemented with bounded response sizes |
| Redirect following | Implemented with a hop limit and HTTPS-to-HTTP downgrade rejection |
| HTTP fetch over smoltcp TCP | Integrated in the browser loop |
| HTTPS fetch over wolfSSL | Adapter integrated; end-to-end firmware test pending |
| Terminal navigation loop | Implemented: open URL, links, back, forward, reload, search, help, quit |
| ELinks-style viewport, keyboard link focus and scrolling controls | Implemented |
| HTML5-style DOM construction and CSS-aware layout | Implemented subset; no full browser conformance |
| Forms (GET/POST URL-encoded) and fragment navigation | Implemented; file uploads, multipart and JavaScript are not supported |
| Bookmarks and persistent page cache | Implemented on the UEFI boot volume; cache is bounded and time-limited |
| Cookies, JavaScript, downloads and full CSS layout | Not implemented |
| QEMU/OVMF network integration test | Not yet run |
| EFI image | Produced and uploaded as a CI artifact; OVMF/physical-firmware validation remains pending |

The SNP adapter and smoltcp integration are concrete implementations, not just traits. This branch adds a wolfSSL 5.9.4 static cross-build, UEFI C bridge, final EFI link, and PE/COFF verification to CI. Those checks have not yet completed for this branch. SNP driver interoperability, DHCP, DNS, NTP, HTTP, and HTTPS must still be verified under OVMF and on physical hardware.

## Repository layout

| Path | Responsibility |
|---|---|
| src/main.rs | UEFI entry point, interactive terminal navigation, redirect policy and page rendering |
| src/url.rs | HTTP/HTTPS URL parsing, default ports, authority validation and relative URL resolution |
| src/html5.rs | Bounded HTML tokenizer and HTML5-style DOM construction with implied document/table nodes |
| src/css.rs | Bounded stylesheet parser, selector matching and inherited terminal-oriented computed styles |
| src/document.rs | DOM-to-document conversion, links, anchors, forms, tables and public-domain ELinks named entities |
| src/renderer.rs | Width-aware reflow, computed text styles, measurable table columns and link/anchor line positions |
| src/persistence.rs | Versioned bookmark and page-cache records, expiry, size limits and storage abstraction |
| src/uefi_storage.rs | Persistent storage adapter for the EFI image's boot-volume filesystem |
| src/http.rs | HTTP/1.1 GET builder, response parsing, chunked decoding and stream exchange |
| src/dns.rs | Hickory DNS A-query construction, bounded UDP exchange contract and response validation |
| src/entropy.rs | Secure-random provider interface used by DNS; TLS uses wolfCrypt's EFI_RNG entropy driver |
| src/firmware_rng.rs | EFI_RNG_PROTOCOL-backed DNS RNG and C-ABI entropy provider for wolfCrypt |
| src/snp_network.rs | SNP Ethernet device and persistent smoltcp interface, DHCPv4, UDP/DNS, TCP streams |
| src/firmware_ntp.rs | SNTP time bootstrap over smoltcp UDP and UEFI Runtime Services SetTime |
| src/firmware_time.rs | Runtime Services UTC conversion with fail-closed validity and DST policy |
| src/network.rs | DNS-to-TCP orchestration, firmware composition helper and retained-hostname wolfSSL handoff |
| src/tls.rs | Rust wolfSSL FFI boundary and TCP BIO callback adapter; wolfCrypt supplies TLS randomness |
| src/uefi_memory.rs | UEFI Boot Services pool allocator hooks for wolfSSL |
| src/ca_bundle.rs | Optional build-time embedded PEM trust bundle |
| vendor/wolfssl-bridge/uefi_tls.c | wolfSSL client setup, BIO callbacks, handshake and mandatory X.509 verification |
| vendor/wolfssl-bridge/uefi_platform.c | UEFI AllocatePool allocator, EFI_RNG entropy callback, and validated UEFI time callback |
| vendor/wolfssl-bridge/uefi_crt.c | Minimal freestanding C string primitives required by wolfSSL without a host CRT |
| vendor/wolfssl-bridge/include/ | wolfSSL and wolfCrypt UEFI configurations plus freestanding platform headers |
| scripts/fetch-wolfssl.sh | Downloads and checksum-verifies the pinned wolfSSL source archive |
| scripts/build-uefi.sh | Builds static wolfSSL libraries and the UEFI C bridge, then invokes the Rust EFI build |
| scripts/update-ca-bundle.sh | Fetches and verifies the Mozilla-derived PEM trust bundle for image embedding |
| build.rs | Adds static link inputs and optionally stages a NUL-terminated CA bundle |
| .github/workflows/ci.yml | Formatting, portable tests and x86-64 UEFI target compilation |

## Rust DNS dependency

The project pins hickory-proto 0.26.3 with default features disabled:

~~~toml
hickory-proto = { version = "0.26.3", default-features = false }
~~~

Disabling default features disables std. No host socket, thread, or operating-system DNS resolver is pulled into this firmware code path. We use Message, Query, Name, RecordType, and RData to construct and parse DNS messages.

Hickory does not own the UDP device. The UEFI adapter owns packet I/O, while Hickory owns DNS wire-format handling and validation. This avoids using EFI_DNS4_PROTOCOL as a black-box firmware resolver and lets the application control transaction IDs, timeouts, packet bounds, and accepted answers.

## wolfSSL selection and packaging

The TLS backend is pinned to wolfSSL 5.9.4. The source archive is downloaded from a public distribution mirror and verified against the published SHA-256 digest before extraction:

~~~text
Archive: wolfssl-5.9.4.zip
SHA-256: 9cd0d69d208d025b16836c177658cc0deebc2a85c4b60898c9bc546bc6cbdf18
~~~

The source is built as a static x86-64 COFF library and linked into the EFI image. The runtime does not require a DLL, shared object, firmware TLS protocol, or operating-system crypto service.

The C bridge uses the TLS 1.3 client method, sets `WOLFSSL_VERIFY_PEER`, loads the embedded Mozilla-derived CA bundle with `wolfSSL_CTX_load_verify_buffer()`, sends SNI with `wolfSSL_UseSNI()`, and checks the URL hostname with `wolfSSL_check_domain_name()`. The handshake fails if certificate-chain, validity-time, or hostname verification fails. There is no `WOLFSSL_VERIFY_NONE` path.

wolfSSL's custom I/O callbacks connect directly to the Rust `TlsStreamIo` trait, which retains ownership of the existing smoltcp TCP socket. The port does not use wolfSSL's default BSD socket functions.

wolfCrypt obtains entropy through `CUSTOM_RAND_GENERATE_BLOCK`, which calls the Rust C-ABI adapter backed exclusively by EFI_RNG_PROTOCOL. Certificate time is supplied through wolfSSL's `USER_TIME`/`XTIME` hook and a freestanding `XGMTIME` UTC calendar conversion, both using the validated UEFI Runtime Services clock. The custom `XMALLOC_USER` allocator routes memory to UEFI Boot Services AllocatePool/FreePool; no host malloc, OS clock, or weak random fallback is permitted.

The shared `vendor/wolfssl-bridge/include/user_settings.h` is used for both wolfSSL and the bridge build. It selects a single-threaded, no-filesystem, no-socket TLS 1.3 client while retaining RSA and ECC certificate verification algorithms, P-256/P-384/P-521, X25519, AES-GCM, ChaCha20-Poly1305, SHA-384 and SHA-512. TLS 1.2 is intentionally disabled in this first wolfSSL port.

Build the full standalone EFI image with:

~~~sh
./scripts/update-ca-bundle.sh
./scripts/build-uefi.sh
~~~

The script downloads and verifies wolfSSL, cross-compiles its static library and UEFI bridge, embeds the CA bundle, and invokes the Rust UEFI build. The full wolfSSL build and EFI link are pending CI verification for this integration branch.

### Trust bundle

The image does not silently inherit a CA store from firmware or an operating system. scripts/update-ca-bundle.sh downloads the curl/Mozilla-derived CA bundle and its published SHA-256 file, verifies the digest, and stages assets/cacert.pem. Review and commit the resulting trust roots as part of a release process. build.rs embeds the file as a NUL-terminated PEM byte slice when UEFI_CA_BUNDLE_PATH is set.

Prepare the trust bundle before a full build:

~~~sh
./scripts/update-ca-bundle.sh
./scripts/build-uefi.sh
~~~

The repository does not commit a periodically refreshed CA bundle by default. HTTPS is refused by the browser unless the wolfSSL bridge and embedded bundle are present.

### TLS security requirements

1. Mandatory peer verification; never use VERIFY_NONE.
2. Hostname verification against the URL hostname and SNI during the handshake.
3. Chain validation against the CA bundle embedded in the image.
4. Validity-time checks using trustworthy UTC from UEFI Runtime Services. Invalid clock, unspecified timezone, daylight-adjustment flags, or an implausibly old clock cause HTTPS to fail closed.
5. wolfCrypt entropy is sourced only from EFI_RNG_PROTOCOL through `wolfssl_platform_get_entropy`. A failed read aborts initialization; no timestamp, counter, host random device, or predictable pseudo-random fallback is allowed.
6. No HTTPS-to-HTTP redirect downgrade and no certificate-error bypass.
7. Bounded network operations and correct release of TCP and TLS resources.
8. A maintained wolfSSL release with security fixes.

## ELinks-inspired HTML and terminal engine

This is a clean-room Rust implementation inspired by the behaviour of ELinks. The upstream GPLv2-only C application is not linked into the GPL-3.0-only EFI image; the separately public-domain entity table remains the only ELinks source data reused.

### HTML tree construction

The html5 module implements a bounded tokenizer and tree builder. It constructs implied html, head, and body nodes, preserves attributes and text nodes, handles quoted and unquoted attribute values, decodes character references, consumes raw-text/RCDATA elements, inserts table sections for common table markup, and repairs common omitted end tags for paragraphs, list items, headings, table rows/cells, and options.

Resource limits are explicit: 16,384 nodes, 128 stack levels, 64 attributes per element, and bounded token storage. Remote script contents are retained only as inert raw text and are never executed. This is an HTML5-style tree-building subset, not a full implementation of the WHATWG parsing algorithm: adoption-agency formatting repair, foster parenting, complete insertion modes, all named references, and many obscure error-recovery cases remain unsupported.

### CSS and layout

The CSS engine applies internal style rules, up to four linked external stylesheets, and inline style attributes. Supported selectors are type, class, ID, and descendant combinations. Supported declarations include display, font weight/style, text decoration, foreground/background colors, whitespace preservation, margins, left indentation, text alignment, and percentage width. CSS colors are quantized to UEFI's 16-color palette.

The layout engine renders semantic blocks and reflows text to the active console width. Tables measure cell content, allocate bounded column widths, wrap long cells, and account for colspan. Rowspan is parsed and retained but does not yet merge cells across rendered rows. CSS floats, positioned layout, flex/grid algorithms, pseudo-classes/elements, media queries, @import, font metrics, and full cascade details such as !important are not implemented.

### Navigation and forms

Element IDs and legacy named anchors are retained as fragment targets. Following a same-document #fragment scrolls locally instead of issuing another HTTP request. Browser history stores fragments as part of the URL while HTTP request targets omit them.

Forms expose text, password, email, search, number, checkbox, radio, select, textarea, hidden, and submit controls. GET and POST use application/x-www-form-urlencoded; POST requires explicit confirmation, password entry is masked, and request bodies are capped at 8 KiB. File uploads, multipart encoding, script-driven form behaviour, cookie/session handling, and full HTML constraint validation are not implemented.

### Persistent bookmarks and cache

Persistent data is stored in the UEFI_BROWSER directory on the same UEFI filesystem volume from which the EFI application was loaded. Bookmark records and cache records are versioned, size-bounded, written to a temporary file and renamed into place. The cache holds at most eight URL-hashed entries, each at most 256 KiB, and expires entries after six hours using the validated UEFI UTC clock.

The cache stores only successful HTML/plain-text GET responses. Cache-Control no-store, no-cache, or private and Set-Cookie responses are not persisted. Responses served from the disk cache are visibly marked in the browser header. If the boot volume is unavailable or read-only, the browser continues without persistent features.

Keyboard and command interface:

- **Up / Down**, **j / k**: scroll one line; **Page Up / Page Down**, **Space**: scroll a page; **Home / End**: document boundaries.
- **Tab / [**, **Enter**: focus and follow links; **l**: list links.
- **g / o**, **b / f / r**: URL entry, back, forward and reload.
- **/** and **n**: in-page search; **m / v**: save current bookmark and list bookmarks.
- **:** opens the command prompt. Commands include open URL, open N, open-bookmark N, bookmark, bookmarks, delete-bookmark N, form N, cache-stats, clear-cache, and search WORD.
- **q** returns to firmware.

HTTPS continues to use the existing wolfSSL path. DNS, smoltcp, TCP, SNI, peer-chain verification, validity-time checks, hostname verification, and HTTPS downgrade rejection are unchanged. External stylesheets and form submissions use that same verified HTTPS path; no certificate override is available.

## URL and HTML core

ELinks reuse is intentionally limited to its public-domain SGML/Unicode named-entity mapping table. The build generates a compact Rust decoder from `assets/elinks-entities.txt`; the EFI image does not link the ELinks GPLv2-only C application. See [ELinks reuse and UEFI porting boundary](docs/ELINKS-COMPATIBILITY.md) for the licensing and runtime rationale.


src/url.rs accepts http:// and https://, defaults a bare hostname to HTTPS, applies ports 80 and 443, and resolves common absolute, scheme-relative, root-relative, and path-relative references. It rejects unknown schemes and URL user-information. IPv6 literal parsing is not implemented in this first pass.

src/document.rs builds a structured document from common HTML block and inline elements, retaining headings, paragraphs, lists, quotations, preformatted text, definition lists, table rows, inline emphasis/code, and resolved HTTP/HTTPS links. It skips comments and common non-visible elements such as scripts, styles, templates, noscript, and SVG. The parser is intentionally bounded and is not a complete HTML5 tree builder. src/renderer.rs lays out those blocks for the active UEFI text-console width and preserves link identity through wrapping. CSS layout, JavaScript, DOM mutation, form submission, cookies, media, and modern web application behaviour are not implemented.

## Important: compile for the UEFI target

The `uefi` crate is intentionally declared under Cargo's target-specific dependency section:

```toml
[target.'cfg(target_os = "uefi")'.dependencies]
uefi = { version = "0.41.0", ... }
```

Therefore, a plain `cargo build` or `cargo check` on Linux compiles for Linux. It does **not** activate `target_os = "uefi"`. That is why a host build reports unresolved `uefi` imports, hides `connect_firmware_url` and `ca_bundle` behind their UEFI cfg gates, and then reports that the UEFI binary's allocator and panic handler are missing. These are cascading target-selection errors; do not fix them by adding another copy of the `uefi` dependency.

Install and explicitly select the UEFI target:

```sh
rustup update stable
rustup target add x86_64-unknown-uefi
cargo check --target x86_64-unknown-uefi
```

That last command checks Rust code for the firmware target. It is not the complete, statically linked browser image. To build the actual `.efi` application, including wolfSSL 5.9.4 and the embedded CA bundle, run the full build procedure below.

Do not run the generated `.efi` file as a Linux executable. Boot it through UEFI firmware, an EFI shell, or a configured OVMF virtual machine.

## Build prerequisites

The complete build requires:

- Rust stable 1.91 or newer and the x86_64-unknown-uefi target.
- CMake and Ninja.
- Clang/LLVM capable of emitting x86-64 COFF objects and llvm-ar.
- curl, sha256sum and tar to obtain the pinned wolfSSL source and trust bundle.
- UEFI firmware exposing an Ethernet-capable Simple Network Protocol (SNP) NIC driver, EFI_RNG_PROTOCOL, and Runtime Services time. IPv4/UDP4/TCP4 firmware protocols are not required.
- An Ethernet link and a DHCPv4 server providing an address, router, and DNS resolver. smoltcp implements the in-application IP stack; firmware must still provide the underlying NIC driver.

Install the Rust target:

~~~sh
rustup update stable
rustup target add x86_64-unknown-uefi
~~~

Run portable-core tests and formatting checks:

~~~sh
cargo test --lib
cargo fmt --all -- --check
~~~

Prepare trust roots and build the packaged EFI application:

~~~sh
./scripts/update-ca-bundle.sh
./scripts/build-uefi.sh
~~~

The intended output is:

~~~text
target/x86_64-unknown-uefi/release/uefi-browser.efi
dist/EFI/BOOT/BOOTX64.EFI
~~~

build.rs also supports manual static-link input through UEFI_WOLFSSL_LIB_DIR, UEFI_WOLFSSL_BRIDGE_DIR and UEFI_CA_BUNDLE_PATH. The build script sets those values for the standard workflow.

**Historical verification record (22 November 2026):** GitHub Actions run [#44998906870](https://github.com/jordanlegare/uefi-browser/actions/runs/44998906870) passed the earlier firmware-transport implementation. It is not the artifact for the SNP/smoltcp stack. The full-build job compiled Mbed TLS 4.3.0 and its UEFI bridge, linked the then-current standalone EFI application, and verified it with `file` and `llvm-readobj` as a PE32+ x86-64 EFI application (`IMAGE_SUBSYSTEM_EFI_APPLICATION`). It does not validate this wolfSSL replacement. The uploaded artifact is [uefi-browser-x86_64](https://github.com/jordanlegare/uefi-browser/actions/runs/44998906870/artifacts/14745231086); its ZIP contains both `target/x86_64-unknown-uefi/release/uefi-browser.efi` and `dist/EFI/BOOT/BOOTX64.EFI`. The `BOOTX64.EFI` SHA-256 is `553d4c7c5757a921adf53fcddf55bf9f6cb45a15e6618dfc63352ce0fe45d0cb` (1,382,400 bytes). This confirms compilation and image format only—not successful firmware boot, protocol interoperability, TLS handshakes, or real web browsing. Run under network-enabled OVMF and on physical firmware before treating it as release-ready.

## Firmware adapter details

### SNP Ethernet adapter and smoltcp

src/snp_network.rs wraps EFI_SIMPLE_NETWORK_PROTOCOL in smoltcp's `phy::Device` interface. It discovers a NIC, starts and initializes SNP, validates the Ethernet MAC/link/MTU, enables the required unicast and broadcast receive filters, and polls complete Ethernet frames into smoltcp. The interface advertises the NIC MTU and uses firmware RNG material for smoltcp's random seed and ephemeral local ports.

smoltcp owns the rest of the network stack: Ethernet framing, ARP, IPv4, routing, DHCPv4, UDP, and TCP. Its DHCP socket configures the interface address, default gateway, and DNS resolver. Hickory DNS and SNTP use temporary bounded smoltcp UDP sockets with resolver/source endpoint checks. Browser TCP sessions use smoltcp TCP sockets with bounded polling and 16 KiB receive/transmit buffers. The TCP socket and SNP device remain owned by `SnpTcpStream` while wolfSSL reads and writes through the `TlsStreamIo` interface.

The application requires the firmware's SNP implementation and an Ethernet link, but does not require EFI IPv4 Config2, EFI UDP4, or EFI TCP4. It cannot provide a missing NIC driver. Runtime interoperability still needs testing across multiple firmware implementations and NICs; successful compilation does not validate SNP hardware behavior.

### DHCP and NTP clock bootstrap

At startup, the browser creates an SNP/smoltcp stack and runs its DHCPv4 client. The DHCP lease supplies the station address, default route, and DNS resolver. `src/firmware_ntp.rs` resolves `time.cloudflare.com` with Hickory over smoltcp UDP, sends an SNTP request over UDP port 123, validates response length, LI/version/mode/stratum and the echoed originate timestamp, then sets and reads back UTC using UEFI Runtime Services. The DHCP/UDP/TCP operations share the same application-owned IP stack.

**Security limitation:** ordinary NTP is unauthenticated. The nonce and packet checks prevent unrelated or malformed replies from being accepted, but do not prevent an on-path attacker from forging a response. This is a best-effort clock bootstrap, not a cryptographic time authority. Certificate verification remains mandatory and no TLS date-check bypass is introduced. Authenticated Network Time Security (NTS) is a future hardening item; it itself requires an initially trustworthy TLS time or a separately provisioned trust mechanism.

### Firmware randomness and time

src/firmware_rng.rs wraps EFI_RNG_PROTOCOL and requests the firmware-selected default algorithm. It provides both the DNS transaction-ID source and the wolfCrypt C-ABI entropy callback. wolfCrypt uses the `CUSTOM_RAND_GENERATE_BLOCK` hook, which calls the Rust C-ABI adapter. Each entropy request opens EFI_RNG_PROTOCOL for the duration of its read; failure to locate or read the RNG is propagated; there is no clock, counter, OS random device, or weak PRNG fallback.

src/firmware_time.rs reads UEFI Runtime Services time, validates the structure, requires a defined timezone, rejects daylight-adjustment flags, rejects dates earlier than the configured policy floor, and converts the civil time to Unix seconds. Its C ABI function returns -1 if time is not trustworthy. The wolfSSL user configuration and C platform bridge route certificate-time operations through these hooks. The C bridge and final EFI link are part of the new CI job; results are pending. Runtime operation against real firmware network drivers is still unverified.

### C runtime and wolfSSL platform hooks

The C bridge no longer uses POSIX allocation: TLS allocations use wolfSSL's `XMALLOC_USER` callbacks backed by `uefi_browser_alloc` and `uefi_browser_free` in src/uefi_memory.rs. Those functions use UEFI AllocatePool/FreePool and are valid only while Boot Services remain active.

The wolfSSL `USER_TIME`/`XTIME` hook obtains certificate time from the validated UEFI Runtime Services clock. There is no host socket, libc clock, or firmware TLS dependency in the intended runtime path. The full cross-build and final EFI link have not yet been validated for this branch.

### Previous Mbed TLS CI image (historical)

The following artifact is from the previous Mbed TLS implementation. It is historical only and is not a wolfSSL build artifact.

- Workflow: [run #44998906870](https://github.com/jordanlegare/uefi-browser/actions/runs/44998906870)
- Artifact: [uefi-browser-x86_64.zip](https://github.com/jordanlegare/uefi-browser/actions/runs/44998906870/artifacts/14745231086)
- Image path inside the ZIP: `dist/EFI/BOOT/BOOTX64.EFI`
- Image format: PE32+, x86-64, EFI application subsystem
- Image size: 1,382,400 bytes
- SHA-256: `553d4c7c5757a921adf53fcddf55bf9f6cb45a15e6618dfc63352ce0fe45d0cb`

The artifact is not Secure Boot signed. A Secure Boot deployment must sign it with a key trusted by the target firmware. The image has not been boot-tested under OVMF or on physical hardware.

## Installation target

The intended x86-64 removable-media path is:

~~~text
EFI/BOOT/BOOTX64.EFI
~~~

Copying a binary to this path does not guarantee network access. Firmware must expose an Ethernet-capable SNP NIC driver, and the machine must have an active Ethernet link and a DHCPv4 server. The browser supplies its own IPv4, UDP, and TCP stack through smoltcp; it still relies on firmware for the NIC driver, EFI_RNG_PROTOCOL, and Runtime Services time.

## Roadmap

- [x] Establish a Rust no_std UEFI application crate and x86-64 EFI target.
- [x] Add portable HTTP/HTTPS URL parsing, relative URL resolution and fragments.
- [x] Add a bounded HTML tokenizer and HTML5-style DOM construction.
- [x] Add CSS cascade subset, external stylesheet fetching and terminal-oriented computed layout.
- [x] Add width-aware block reflow and measured table columns with colspan.
- [x] Add links, heading/ID anchors, GET/POST URL-encoded forms and form confirmation.
- [x] Add boot-volume bookmarks and a bounded persistent HTML/text page cache.
- [x] Add Hickory DNS, SNP/smoltcp networking and mandatory wolfSSL certificate validation.
- [x] Add HTTP/1.1 GET/POST request construction, response parsing and downgrade-safe redirects.
- [ ] Complete HTML5 insertion modes, formatting adoption-agency repair, foster parenting and complete entity references.
- [ ] Implement table rowspan layout and more complex table border/column algorithms.
- [ ] Extend CSS support with proper !important, selector pseudo-classes, media queries, and layout algorithms where useful in a text terminal.
- [ ] Add file uploads/multipart only with an explicit UEFI file-picker model.
- [ ] Add cookies/session policy, conditional cache revalidation and persistent history.
- [ ] Add downloads and bookmarks import/export.
- [ ] Run the new HTML/CSS/forms/cache engine under OVMF and physical UEFI firmware across multiple console modes and filesystems.
- [ ] Add DNS CNAME/AAAA, DNS-over-TCP fallback and answer caching.

## Security and scope

This is pre-OS code running with firmware privileges. Bugs in parsers, TLS callbacks, allocation, or protocol lifetime handling can crash the machine or compromise the boot chain. Remote content is untrusted. The browser must not execute remote JavaScript in the firmware environment.

The project is not yet release-verified. Do not use it to handle secrets or replace a maintained operating-system browser until wolfSSL CI, the final EFI link, CA-bundle review, and real firmware integration tests have passed.

## References

- [Hickory DNS protocol crate](https://docs.rs/hickory-proto/0.26.3/hickory_proto/)
- [Hickory protocol feature flags](https://docs.rs/crate/hickory-proto/0.26.3/features)
- [wolfSSL upstream](https://github.com/wolfSSL/wolfssl)
- [wolfSSL downloads and release information](https://www.wolfssl.com/download/)
- [UEFI 2.11 network protocols](https://uefi.org/specs/UEFI/2.11/29_Network_Protocols_ARP_and_DHCP.html)
- [Rust UEFI crate](https://docs.rs/uefi/)
- [Rust UEFI target](https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html)

## License

The combined browser distribution is licensed under GPLv3 to comply with the selected wolfSSL open-source distribution. The GPLv3 text is included in `COPYING`, and wolfSSL's upstream copyright and license notices are retained.
