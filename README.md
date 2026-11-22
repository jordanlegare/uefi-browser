# UEFI Browser

A standalone Rust application for x86-64 UEFI firmware, intended to grow into a full terminal web browser in the style of ELinks. It is packaged as a PE32+ EFI application and designed to run before an operating system.

> **Status: CI-built standalone EFI image; runtime firmware/network tests still pending.** The source includes concrete UEFI UDP4/TCP4 adapters, Hickory DNS, firmware RNG/time providers, HTTP/1.1 stream fetching, basic HTML text/link extraction, history, link following, and an interactive firmware-console loop. GitHub Actions now builds and inspects the final Mbed TLS 4.3.0 PE32+ x86-64 EFI application. It has not yet been boot-tested under OVMF or on physical firmware, and it is not feature-equivalent to ELinks.

## Goals

- Run directly as an x86-64 UEFI application without Linux, initramfs, shell, or host userspace.
- Start after firmware has initialized networking and acquired IPv4 configuration.
- Use UEFI UDP4 and TCP4 protocols directly; do not call host OS socket APIs.
- Use a Rust DNS client library for DNS packet encoding and decoding.
- Bundle Mbed TLS into the EFI image so HTTPS does not depend on a firmware TLS service.
- Require X.509 chain and hostname verification; never offer a certificate-bypass mode.
- Provide a keyboard-first terminal interface with URL navigation, history, link following, and search.
- Keep the final executable self-contained, including cryptographic code and trust anchors.

## Network and TLS architecture

DNS and TLS are separate protocols. DNS is a short request/response exchange over UDP (normally port 53); TLS is a stream protocol layered over TCP (normally port 443). There is no DNS4 stream adapter in Mbed TLS, and Mbed TLS does not resolve hostnames itself.

The project uses this pipeline:

~~~text
URL: https://www.example.org/path
       |
       v
Hickory DNS protocol client (Rust, no_std)
  - builds DNS A / IN query
  - transaction ID from EFI_RNG_PROTOCOL
  - validates transaction ID, response code, question and answer owner
       |
       v
EFI_UDP4_PROTOCOL adapter (implemented)
  - DNS datagram to configured resolver:53
  - validates response source IPv4 address and UDP source port
  - bounded packet buffer and timeout
       |
       v
IPv4 address
       |
       v
EFI_TCP4_PROTOCOL adapter (implemented)
  - active TCP4 connect to resolved IPv4 address and URL port
  - bounded transmit/receive operations and cancellation
  - preserves completion-token storage until firmware signals completion
       |
       v
Mbed TLS 4.3.0 (static-link build path configured)
  - receives the original hostname, not the numeric IP
  - SNI and hostname verification
  - mandatory X.509 chain verification
  - optional embedded CA trust anchors
  - random bytes from EFI_RNG_PROTOCOL
  - certificate time hooks wired to UEFI Runtime Services
       |
       v
HTTP/1.1 request/response codec over TCP4 or Mbed TLS streams
       |
       v
HTML text/link parser -> firmware-console renderer -> keyboard navigation
~~~

The high-level firmware path is provided by connect_firmware_url() in src/network.rs. It reads DNS server addresses from EFI IPv4 Config2, opens EFI RNG for the DNS query, resolves the hostname using Hickory over the UDP4 adapter, then connects TCP4 to the resulting address. The returned FirmwareConnection retains the stream and original hostname for SNI and certificate identity. Mbed TLS 4.3 obtains its later PSA entropy requests independently through the TF-PSA firmware RNG hook.

The low-level firmware adapters use UEFI Service Binding child handles. TCP4 and UDP4 completion tokens are asynchronous: the code uses EVT_NOTIFY_SIGNAL events at TPL_CALLBACK and paired plain wait events for application-side polling. Pending operation tokens are cancelled and drained before their memory, event, or protocol child is released. This is important because firmware may continue referencing token and fragment memory until the completion event is signalled.

The key handoff is implemented in src/network.rs:

- connect_url() calls the Hickory-backed dns::resolve_a().
- It passes the resulting IPv4 address and URL port to Tcp4Connector::connect_tcp4().
- It retains the original URL hostname in ConnectedPeer.
- ConnectedPeer::start_tls() passes that hostname and the connected TCP stream to TlsConnection::new().

This separation matters for HTTPS: TCP connects to the numeric IP address, while Mbed TLS must still receive the DNS hostname so that SNI and certificate identity checks use the expected server name.

### UEFI DNS4 versus UDP4

This implementation intentionally does **not** call EFI_DNS4_PROTOCOL. Hickory performs DNS wire-format encoding and decoding in Rust. Its packets are transported by the concrete EFI_UDP4_PROTOCOL adapter in src/uefi_udp4.rs.

The adapter creates a UDP4 service-binding child, configures the firmware-provided default IPv4 address, sends to the configured resolver on UDP port 53, and waits for both transmit and receive completion. It rejects a reply unless the source IPv4 address and UDP source port match the selected resolver. The receive fragments are copied into the bounded DNS response buffer, then the driver's recycle event is signalled to return the packet buffers to firmware.

DNS server discovery reads EFI IPv4 Config2 DNS_SERVER data, normally provisioned by DHCP. The adapter does not implement DHCP itself; the firmware network stack remains responsible for NIC initialization, address configuration, routing, and resolver provisioning.

The DNS policy uses hickory-proto 0.26.3 with default features disabled. It sends IPv4 A/IN queries with a secure random transaction ID, retries a timeout once, and validates transaction ID, response/opcode, truncation flag, response code, question type/class/name, and answer owner/class. It currently does not chase CNAME chains, issue AAAA queries, use DNSSEC, cache answers, expand search domains, or retry truncated UDP messages over DNS/TCP.

## Current implementation status

| Component | Status |
|---|---|
| Rust no_std UEFI application crate | Present |
| x86-64 UEFI target configuration | Present |
| Firmware console startup and interactive input | Implemented |
| HTTP/HTTPS URL parser and relative URL resolution | Implemented in portable core |
| HTML title/text/anchor extraction | Implemented in portable core |
| Hickory DNS message encoding/decoding | Implemented with default std features disabled |
| DNS A-query client and response validation | Implemented with bounded retries and response checks |
| DNS server discovery from EFI IPv4 Config2 | Implemented |
| UEFI UDP4 concrete adapter | Implemented using a local UEFI 2.11 ABI binding |
| UEFI TCP4 concrete adapter | Implemented using TCP4 Service Binding and child protocols |
| TCP connect/send/receive timeout handling | Implemented with polling, cancellation, and token draining |
| Secure random source abstraction and EFI RNG implementation | Implemented; no weak fallback |
| Firmware UTC conversion and fail-closed date policy | Implemented; unspecified timezone, DST flags, invalid RTC and implausibly old time are rejected |
| DNS-to-TCP-to-TLS orchestration | Implemented; hostname is retained for SNI and certificate checks |
| TCP stream-to-Mbed-TLS callback bridge | Implemented in Rust/C |
| Mbed TLS 4.3.0 source fetch and archive checksum verification | Implemented |
| UEFI Boot Services allocator hooks for Mbed TLS | Implemented and exercised in the successful static link |
| Mbed TLS platform clock and gmtime hooks | Implemented in C/Rust source and configured for the build |
| Mbed TLS static libraries and PE/COFF link integration | Full cross-build and final EFI link passed in CI |
| Mozilla-derived CA bundle update script | Implemented with checksum verification |
| Build-time CA bundle embedding | Implemented; bundle asset is generated locally, not committed by default |
| HTTP/1.1 GET and response parsing | Implemented |
| Content-Length, chunked and close-delimited response bodies | Implemented with bounded response sizes |
| Redirect following | Implemented with a hop limit and HTTPS-to-HTTP downgrade rejection |
| HTTP fetch over TCP4 | Integrated in the browser loop |
| HTTPS fetch over Mbed TLS | Integrated conditionally; requires the static bridge and embedded CA bundle |
| Terminal navigation loop | Implemented: open URL, links, back, forward, reload, search, help, quit |
| Reflowing ELinks-style viewport, keyboard link focus and scrolling controls | Not yet implemented |
| CSS, JavaScript, forms, cookies, bookmarks and downloads | Not implemented |
| QEMU/OVMF network integration test | Not yet run |
| EFI image | Produced and uploaded as a CI artifact; OVMF/physical-firmware validation remains pending |

The UEFI UDP4/TCP4 adapters are concrete source implementations, not just traits. The latest CI run passes Rust formatting, portable-core tests, the x86-64 UEFI target check, Mbed TLS 4.3.0 static compilation, UEFI C bridge compilation, final Rust+Mbed TLS link, PE/COFF inspection, and artifact upload. Firmware protocol behavior and real network browsing under OVMF/physical firmware remain release gates.

## Repository layout

| Path | Responsibility |
|---|---|
| src/main.rs | UEFI entry point, interactive terminal navigation, redirect policy and page rendering |
| src/url.rs | HTTP/HTTPS URL parsing, default ports, authority validation and relative URL resolution |
| src/document.rs | Basic HTML visible-text and anchor extraction |
| src/http.rs | HTTP/1.1 GET builder, response parsing, chunked decoding and stream exchange |
| src/dns.rs | Hickory DNS A-query construction, bounded UDP exchange contract and response validation |
| src/entropy.rs | Secure-random provider interface used by DNS; TLS uses PSA Crypto's EFI_RNG entropy driver |
| src/firmware_rng.rs | EFI_RNG_PROTOCOL-backed DNS RNG and C-ABI entropy provider for TF-PSA-Crypto |
| src/firmware_time.rs | Runtime Services UTC conversion with fail-closed validity and DST policy |
| src/network.rs | DNS-to-TCP orchestration, firmware composition helper and retained-hostname Mbed TLS handoff |
| src/uefi_udp4.rs | UDP4 service-binding child, DNS datagrams, source filtering and DNS-server discovery |
| src/uefi_tcp4.rs | TCP4 service-binding child, bounded connect/transmit/receive, cancellation and cleanup |
| src/tls.rs | Rust Mbed TLS FFI boundary and TCP BIO callback adapter; PSA Crypto supplies TLS randomness |
| src/uefi_memory.rs | UEFI Boot Services pool allocator hooks for Mbed TLS |
| src/ca_bundle.rs | Optional build-time embedded PEM trust bundle |
| vendor/mbedtls-bridge/uefi_tls.c | Mbed TLS client setup, BIO callbacks, handshake and mandatory X.509 verification |
| vendor/mbedtls-bridge/uefi_platform.c | EFI_RNG entropy provider, UEFI time/gmtime hooks, monotonic-time adapter, and volatile zeroization |
| vendor/mbedtls-bridge/uefi_crt.c | Minimal freestanding C string primitives required by Mbed TLS without a host CRT |
| vendor/mbedtls-bridge/include/ | Mbed TLS and TF-PSA-Crypto UEFI configurations plus freestanding platform headers |
| scripts/fetch-mbedtls.sh | Downloads and checksum-verifies the pinned Mbed TLS source archive |
| scripts/build-uefi.sh | Builds static Mbed TLS libraries and the UEFI C bridge, then invokes the Rust EFI build |
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

## Mbed TLS selection and packaging

The TLS backend is pinned to the official upstream **Mbed TLS 4.3.0** release, published on 16 November 2026. The selected release includes security fixes published in November 2026. The official release archive is downloaded and checked against its SHA-256 hash before extraction.

~~~text
Archive: mbedtls-4.3.0.tar.bz2
SHA-256: 1c87cba094cb40f097ebe0eba440a74939b71dab4e1d0d566bc90749ff381d18
~~~

The intended final image contains static Mbed TLS libraries and the UEFI-specific C bridge. It must not require a DLL, shared object, firmware TLS protocol, or operating-system crypto service at runtime.

The C bridge configures mandatory X.509 verification (MBEDTLS_SSL_VERIFY_REQUIRED), installs the supplied CA chain, initializes PSA Crypto before TLS setup, sets the original URL hostname for SNI and identity checks, and installs stream BIO callbacks. The Rust TlsConnection provides the BIO callbacks over the TCP4 stream. Mbed TLS 4.3 no longer uses the legacy `mbedtls_ssl_conf_rng` API: TF-PSA-Crypto's `MBEDTLS_PSA_DRIVER_GET_ENTROPY` hook calls a Rust C-ABI function that opens EFI_RNG_PROTOCOL and fills the requested buffer. Only successful firmware reads report full entropy; there is no libc or OS random source.

The UEFI port routes allocation to src/uefi_memory.rs using UEFI Boot Services AllocatePool/FreePool, and routes certificate time to src/firmware_time.rs through vendor/mbedtls-bridge/uefi_platform.c. The C-side Gregorian conversion implements the `mbedtls_platform_gmtime_r` hook; rejected or unavailable firmware time fails certificate validity checks closed.

Mbed TLS 4.x separates the TLS/X.509 configuration from the TF-PSA-Crypto configuration. The build supplies both `MBEDTLS_USER_CONFIG_FILE=uefi_mbedtls_config.h` and `TF_PSA_CRYPTO_USER_CONFIG_FILE=uefi_tf_psa_config.h`. The TF-PSA configuration exposes the shared UEFI platform declarations and defines the allocator, time, gmtime, and printf hooks there. Those platform macros must not be duplicated in the Mbed TLS user configuration: Mbed TLS 4.x explicitly checks for that split. The Mbed TLS user configuration remains responsible for TLS/X.509-facing options and the common platform feature toggles. The configured printf macro points to a C no-op: firmware has no stdio stream, and Mbed TLS self-test/diagnostic output must not introduce a host CRT dependency. The two configuration hooks are required because TF-PSA-Crypto consumes its own user-configuration file in Mbed TLS 4.x.

scripts/build-uefi.sh fetches the pinned source, configures an x86-64 COFF static-library build, compiles the UEFI C bridge, and sets the link environment consumed by build.rs. The script is the verified full-image build entry point; the full Mbed TLS build and final PE/COFF link passed in the latest GitHub Actions run.



### Trust bundle

The image does not silently inherit a CA store from firmware or an operating system. scripts/update-ca-bundle.sh downloads the curl/Mozilla-derived CA bundle and its published SHA-256 file, verifies the digest, and stages assets/cacert.pem. Review and commit the resulting trust roots as part of a release process. build.rs embeds the file as a NUL-terminated PEM byte slice when UEFI_CA_BUNDLE_PATH is set.

Prepare the trust bundle before a full build:

~~~sh
./scripts/update-ca-bundle.sh
./scripts/build-uefi.sh
~~~

The repository does not commit a periodically refreshed CA bundle by default. HTTPS is refused by the browser unless both the Mbed TLS bridge and the embedded bundle are present.

### TLS security requirements

1. Mandatory peer verification; never use VERIFY_NONE.
2. Hostname verification against the URL hostname and SNI during the handshake.
3. Chain validation against the CA bundle embedded in the image.
4. Validity-time checks using trustworthy UTC from UEFI Runtime Services. Invalid clock, unspecified timezone, daylight-adjustment flags, or an implausibly old clock cause HTTPS to fail closed.
5. PSA Crypto entropy is sourced only from EFI_RNG_PROTOCOL through `mbedtls_platform_get_entropy`. A failed read aborts initialization; no timestamp, counter, host random device, or predictable pseudo-random fallback is allowed.
6. No HTTPS-to-HTTP redirect downgrade and no certificate-error bypass.
7. Bounded network operations and correct release of TCP and TLS resources.
8. A maintained Mbed TLS release with security fixes.

## URL and HTML core

src/url.rs accepts http:// and https://, defaults a bare hostname to HTTPS, applies ports 80 and 443, and resolves common absolute, scheme-relative, root-relative, and path-relative references. It rejects unknown schemes and URL user-information. IPv6 literal parsing is not implemented in this first pass.

src/document.rs extracts a page title, visible text, and numbered anchor links. It skips comments and common non-visible elements such as scripts, styles, templates, noscript, and SVG, and decodes a limited set of named and numeric entities. It is a lightweight text extractor, not a complete HTML5 tree builder. CSS layout, JavaScript, DOM mutation, form submission, cookies, media, and modern web application behaviour are not implemented.

## Build prerequisites

The complete build requires:

- Rust stable 1.91 or newer and the x86_64-unknown-uefi target.
- CMake and Ninja.
- Clang/LLVM capable of emitting x86-64 COFF objects and llvm-ar.
- curl, sha256sum and tar to obtain the pinned Mbed TLS source and trust bundle.
- UEFI firmware exposing UDP4, TCP4, EFI_RNG_PROTOCOL, IPv4 Config2 DNS data and Runtime Services time.
- A firmware network stack that has already initialized the NIC and configured IPv4.

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

build.rs also supports manual static-link input through UEFI_MBEDTLS_LIB_DIR, UEFI_MBEDTLS_BRIDGE_DIR and UEFI_CA_BUNDLE_PATH. The build script sets those values for the standard workflow.

**Verification record (22 November 2026):** GitHub Actions run [#44998678202](https://github.com/jordanlegare/uefi-browser/actions/runs/44998678202) passed both jobs on commit `5fe2cbc39c55d83032c358993dca74b8eb49008c`. The full-build job compiled Mbed TLS 4.3.0 and the UEFI bridge, linked the standalone EFI application, and verified it with `file` and `llvm-readobj` as a PE32+ x86-64 EFI application (`IMAGE_SUBSYSTEM_EFI_APPLICATION`). The uploaded artifact is [uefi-browser-x86_64](https://github.com/jordanlegare/uefi-browser/actions/runs/44998678202/artifacts/14744857088); its ZIP contains both `target/x86_64-unknown-uefi/release/uefi-browser.efi` and `dist/EFI/BOOT/BOOTX64.EFI`. The `BOOTX64.EFI` SHA-256 is `c02ec159295384d395f20966a2d1023c753d83ceefbb592554bbaaec8c3605d1` (1,382,400 bytes). This confirms compilation and image format only—not successful firmware boot, protocol interoperability, TLS handshakes, or real web browsing. Run under network-enabled OVMF and on physical firmware before treating it as release-ready.

## Firmware adapter details

### UDP4 DNS transport

The concrete UdpDnsTransport implementation is in src/uefi_udp4.rs. The pinned uefi-raw release does not expose UDP4 bindings, so this module declares the small ABI surface from the UEFI 2.11 specification locally: UDP4 Service Binding, UDP4 protocol entry points, configuration, session, transmit, receive, and completion-token layouts.

Each request creates a UDP4 child and an ephemeral local source port selected using EFI_RNG_PROTOCOL. It configures the default address and sends a single bounded DNS datagram. Receive processing verifies the sender address and port before Hickory sees the packet. All protocol children, events, and receive recycle notifications are handled in the adapter.

Because the UDP4 binding is locally declared, it requires hardware/firmware integration testing on real UEFI network stacks. A successful Rust cross-check cannot validate firmware ABI conformance at runtime.

### TCP4 stream transport

The concrete Tcp4Connector and TlsStreamIo implementation is in src/uefi_tcp4.rs. It discovers TCP4 service bindings, creates a child protocol instance, configures an active open to the resolved IPv4 address and destination port, and performs the asynchronous three-way handshake.

Transmit and receive use bounded 16 KiB fragments. The TlsStreamIo send method reports partial progress so Mbed TLS can retry the remainder. Connect and I/O waits poll the TCP4 instance and enforce timeouts. On timeout, the adapter cancels the corresponding token and keeps its token, fragment, and event storage alive until firmware signals completion. Dropping the stream aborts/closes the connection, releases the TCP protocol interface, and destroys the service-binding child.

Each TCP4 completion token uses an EVT_NOTIFY_SIGNAL event at TPL_CALLBACK. The callback signals a separate plain wait event because CheckEvent must not be called on the notify event itself.

### Firmware randomness and time

src/firmware_rng.rs wraps EFI_RNG_PROTOCOL and requests the firmware-selected default algorithm. It provides both the DNS transaction-ID source and the TF-PSA-Crypto C-ABI entropy callback. The TLS stack uses the `MBEDTLS_PSA_DRIVER_GET_ENTROPY` path, not the removed Mbed TLS 3.x `mbedtls_ssl_conf_rng` hook. Each PSA entropy request opens the firmware protocol for the duration of its read; failure to locate or read the RNG is propagated; there is no clock, counter, OS random device, or weak PRNG fallback.

src/firmware_time.rs reads UEFI Runtime Services time, validates the structure, requires a defined timezone, rejects daylight-adjustment flags, rejects dates earlier than the configured policy floor, and converts the civil time to Unix seconds. Its C ABI function returns -1 if time is not trustworthy. The Mbed TLS user configuration and C platform bridge route certificate-time operations through these hooks. The static C bridge and final EFI link pass in CI. Runtime operation against real firmware network drivers is still unverified.

### C runtime and Mbed TLS platform hooks

The C bridge no longer uses POSIX allocation: TLS session allocations use Mbed TLS platform macros backed by uefi_mbedtls_calloc and uefi_mbedtls_free in src/uefi_memory.rs. Those functions use UEFI AllocatePool/FreePool and are valid only while Boot Services remain active.

The custom Mbed TLS platform configuration also routes time/gmtime operations through the UEFI Runtime Services callback and a freestanding Gregorian conversion. There is no host socket, libc clock, or firmware TLS dependency in the intended runtime path. The Mbed TLS library and C bridge compilation passed in the most recent full-build attempt. Cargo then stopped in build.rs because it incorrectly required a PEM begin marker at byte zero; the official Mozilla bundle includes descriptive comments before the first certificate. The build script now validates bounded PEM marker presence and embeds from the first certificate, and the next CI run must confirm the final EFI link.

### Latest CI image

The current CI artifact is the removable-media EFI application. The GitHub artifact expires on 20 February 2027.

- Workflow: [run #44998678202](https://github.com/jordanlegare/uefi-browser/actions/runs/44998678202)
- Artifact: [uefi-browser-x86_64.zip](https://github.com/jordanlegare/uefi-browser/actions/runs/44998678202/artifacts/14744857088)
- Image path inside the ZIP: `dist/EFI/BOOT/BOOTX64.EFI`
- Image format: PE32+, x86-64, EFI application subsystem
- Image size: 1,382,400 bytes
- SHA-256: `c02ec159295384d395f20966a2d1023c753d83ceefbb592554bbaaec8c3605d1`

The artifact is not Secure Boot signed. A Secure Boot deployment must sign it with a key trusted by the target firmware. The image has not been boot-tested under OVMF or on physical hardware.

## Installation target

The intended x86-64 removable-media path is:

~~~text
EFI/BOOT/BOOTX64.EFI
~~~

Copying a binary to this path does not guarantee network access. Firmware must have initialized and exposed the NIC, UDP4, TCP4, RNG, and time protocols before the app starts.

## Roadmap

- [x] Establish a Rust no_std UEFI application crate and x86-64 EFI target.
- [x] Add portable HTTP/HTTPS URL parsing and relative URL resolution.
- [x] Add basic HTML visible-text extraction and numbered links.
- [x] Add Hickory DNS protocol support without default std features.
- [x] Implement DNS A-query construction, response validation and bounded retries.
- [x] Implement EFI IPv4 Config2 DNS-server discovery.
- [x] Implement concrete UEFI UDP4 transport with source filtering and receive-buffer recycling.
- [x] Implement concrete UEFI TCP4 active connect, partial I/O, timeouts, cancellation and cleanup.
- [x] Implement EFI_RNG_PROTOCOL and UEFI UTC clock adapters with fail-closed policy.
- [x] Connect Hickory DNS -> UDP4 -> TCP4 -> Mbed TLS while retaining the server hostname for SNI.
- [x] Add Mbed TLS 4.3.0 source pin and archive checksum verification.
- [x] Add UEFI allocator, platform time/gmtime hooks, and static COFF build/link scaffolding for Mbed TLS.
- [x] Add optional CA-bundle update and build-time embedding support.
- [x] Implement HTTP/1.1 GET, header/status parsing, Content-Length, chunked and close-delimited responses.
- [x] Implement a keyboard-driven terminal navigation loop with links, history, back/forward, reload and search.
- [x] Implement bounded redirects and reject HTTPS-to-HTTP redirect downgrade.
- [x] Run and verify the complete Mbed TLS 4.3.0 C cross-build and final PE/COFF link in CI.
- [x] Build and inspect an EFI binary containing the CA roots and Mbed TLS libraries.
- [ ] Run the browser under OVMF with UDP4/TCP4 network drivers and test real HTTP/HTTPS sites.
- [ ] Test on multiple physical UEFI implementations and NIC drivers.
- [ ] Add DNS CNAME/AAAA, DNS-over-TCP fallback, and cache.
- [ ] Add terminal viewport scrolling, reflow, heading/list/table rendering, and keyboard link focus.
- [ ] Add forms, bookmarks, downloads, persisted history, and cache storage.
- [ ] Add character-set handling and more complete HTML parsing.
- [ ] Evaluate mature text-browser feature parity; CSS layout and JavaScript are out of scope unless separately designed.

## Security and scope

This is pre-OS code running with firmware privileges. Bugs in parsers, TLS callbacks, allocation, or protocol lifetime handling can crash the machine or compromise the boot chain. Remote content is untrusted. The browser must not execute remote JavaScript in the firmware environment.

The project is not yet release-verified. Do not use it to handle secrets or replace a maintained operating-system browser until the Mbed TLS cross-build, final EFI link, CA-bundle review, and real firmware integration tests have passed.

## References

- [Hickory DNS protocol crate](https://docs.rs/hickory-proto/0.26.3/hickory_proto/)
- [Hickory protocol feature flags](https://docs.rs/crate/hickory-proto/0.26.3/features)
- [Mbed TLS upstream](https://github.com/Mbed-TLS/mbedtls)
- [TF-PSA-Crypto configuration split in Mbed TLS 4.x](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/psa-transition.md#compile-time-configuration)
- [Mbed TLS 4.3.0 release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0)
- [UEFI 2.11 network protocols](https://uefi.org/specs/UEFI/2.11/29_Network_Protocols_ARP_and_DHCP.html)
- [Rust UEFI crate](https://docs.rs/uefi/)
- [Rust UEFI target](https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html)

## License

Original project code is intended to be dual-licensed under MIT or Apache-2.0. Mbed TLS is separately licensed upstream; review and preserve its license notices when redistributing an EFI image that includes it.
