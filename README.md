# UEFI Browser

A standalone Rust application for x86-64 UEFI firmware, intended to grow into a full terminal web browser in the style of ELinks. It is packaged as a PE32+ EFI application and designed to run before an operating system.

> **Status: early implementation foundation. Not yet a working network browser or an ELinks replacement.** The portable URL and HTML-to-text core, Hickory DNS packet client, DNS-to-TCP endpoint orchestration, UEFI application entry point, and Mbed TLS C/Rust integration boundary are present. Concrete UEFI UDP4/TCP4 protocol adapters, the EFI-safe C allocator, firmware entropy and clock callbacks, embedded CA bundle, and final static link are not complete. The current EFI application is a startup diagnostic; it does not fetch pages.

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
Mbed TLS 4.3.0 (intended static link into BOOTX64.EFI)
  - receives the original hostname, not the numeric IP
  - SNI and hostname verification
  - mandatory X.509 chain verification
  - intended embedded CA trust anchors
  - random bytes from EFI_RNG_PROTOCOL
  - intended certificate time validation from Runtime Services
       |
       v
HTTP/1.1 request/response codec (implemented, not yet wired to stream)
       |
       v
HTML parser -> terminal renderer -> keyboard navigation
~~~

The high-level firmware path is provided by connect_firmware_url() in src/network.rs. It reads DNS server addresses from EFI IPv4 Config2, opens EFI RNG, resolves the hostname using Hickory over the UDP4 adapter, then connects TCP4 to the resulting address. The returned FirmwareConnection retains the RNG and original hostname so start_tls() can create the Mbed TLS session with the correct SNI and certificate identity.

The low-level firmware adapters use UEFI Service Binding child handles. TCP4 and UDP4 completion tokens are asynchronous: the code uses EVT_NOTIFY_SIGNAL events at TPL_CALLBACK and paired plain wait events for application-side polling. Pending operation tokens are cancelled and drained before their memory, event, or protocol child is released. This is important because firmware may continue referencing token and fragment memory until the completion event is signalled.

The key handoff is implemented in src/network.rs:The key handoff is implemented in src/network.rs:

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
| Firmware console startup diagnostic | Present |
| HTTP/HTTPS URL parser and relative URL resolution | Implemented in portable core |
| HTML title/text/anchor extraction | Implemented in portable core |
| Hickory DNS message encoding/decoding | Implemented, no_std feature set |
| DNS A-query client and response validation | Implemented with bounded retries and response checks |
| DNS server discovery from EFI IPv4 Config2 | Implemented; reads configured DNS server addresses |
| UEFI UDP4 concrete adapter | Implemented using a local UEFI 2.11 ABI binding |
| UEFI TCP4 concrete adapter | Implemented using TCP4 Service Binding and TCP4 child protocols |
| TCP connect/send/receive timeout handling | Implemented with polling, cancellation, and token draining |
| Secure random source abstraction | Implemented |
| EFI RNG implementation | Implemented through EFI_RNG_PROTOCOL; no weak fallback |
| Firmware UTC clock conversion | Implemented with fail-closed checks for invalid/unspecified time |
| DNS-to-TCP-to-TLS orchestration | Implemented through firmware composition helper and retained hostname |
| TCP stream-to-Mbed-TLS callback bridge | Implemented as Rust/C interfaces |
| Mbed TLS 4.3.0 source fetch and archive checksum verification | Implemented |
| HTTP/1.1 GET request generation | Implemented in portable core |
| HTTP status/header parsing | Implemented in portable core |
| Content-Length and chunked body decoding | Implemented with body-size bounds |
| Redirect metadata extraction | Implemented; redirect-follow policy not yet wired |
| Embedded CA bundle and update process | Not yet embedded |
| UEFI-safe C allocator for Mbed TLS | Not yet connected |
| Mbed TLS platform clock and certificate-date hook | Rust clock exists; not yet wired into Mbed TLS build |
| Mbed TLS static link into final PE/COFF EFI image | Not yet completed |
| Integrated TLS HTTP fetch loop | Not yet connected end-to-end |
| Integrated navigation loop and terminal page renderer | Not yet implemented |
| Tested network-capable browser image | Not produced |

The UDP4 and TCP4 adapters are concrete source implementations, not just traits. They have not yet been exercised against physical firmware or a network-enabled OVMF configuration. The current EFI entry point remains a diagnostic screen until the Mbed TLS link, CA bundle, HTTP stream loop, and terminal UI are integrated.

## Repository layout

| Path | Responsibility |
|---|---|
| src/main.rs | UEFI entry point and current diagnostic shell |
| src/url.rs | HTTP/HTTPS URL parsing, default ports, and relative URL resolution |
| src/document.rs | Basic HTML visible-text and anchor extraction |
| src/http.rs | HTTP/1.1 GET builder, response headers/status, Content-Length and chunked decoding |
| src/dns.rs | Hickory DNS A-query construction and response validation |
| src/entropy.rs | Shared cryptographic-randomness interface |
| src/firmware_rng.rs | EFI_RNG_PROTOCOL-backed random source |
| src/firmware_time.rs | Runtime Services UTC conversion with fail-closed validity policy |
| src/network.rs | DNS-to-TCP orchestration and retained-hostname Mbed TLS handoff |
| src/uefi_udp4.rs | UDP4 service-binding child, DNS datagrams, source filtering, and DNS-server discovery |
| src/uefi_tcp4.rs | TCP4 service-binding child, bounded connect/transmit/receive, cancellation, and cleanup |
| src/tls.rs | Rust Mbed TLS FFI boundary and TCP BIO callback adapter |
| vendor/mbedtls-bridge/uefi_tls.c | Mbed TLS client setup, BIO callbacks, and mandatory X.509 verification |
| scripts/fetch-mbedtls.sh | Downloads and checksum-verifies the pinned Mbed TLS source archive |
| scripts/build-uefi.sh | Experimental freestanding Mbed TLS cross-build scaffold; final link is unfinished |
| .github/workflows/ci.yml | Formatting, portable tests, and x86-64 UEFI target compilation |

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

Mbed TLS is intended to be built as static libraries and linked into the EFI PE/COFF image. The final image must not require a DLL, shared object, firmware TLS protocol, or operating-system crypto service at runtime.

The C bridge configures mandatory X.509 verification (MBEDTLS_SSL_VERIFY_REQUIRED), installs a CA chain, configures the supplied RNG callback, sets the original URL hostname, and installs stream BIO callbacks. The Rust TlsConnection provides those callbacks over the stream returned by ConnectedPeer.

**The Mbed TLS bridge is not yet linked into the EFI executable.** The build script currently downloads/verifies the release and configures an experimental freestanding static-library build. The UEFI C runtime/allocator, cryptographic configuration, platform callbacks, and final linker integration remain outstanding.

### TLS security requirements

1. Mandatory peer verification; never use VERIFY_NONE.
2. Hostname verification against the URL hostname and SNI during the handshake.
3. Chain validation against a CA bundle embedded in the EFI image.
4. Validity-time checks using a trustworthy UTC clock from UEFI Runtime Services. If the RTC is invalid or unavailable, HTTPS must fail closed.
5. Cryptographically secure random bytes from EFI_RNG_PROTOCOL. No timestamp, counter, or predictable pseudo-random fallback.
6. No HTTPS-to-HTTP downgrade and no certificate-error bypass.
7. Bounded network operations and correct release of TCP and TLS resources.
8. Maintained Mbed TLS versions with security fixes.

The firmware RNG is shared with the DNS layer: the DNS transaction ID and Mbed TLS handshake both consume the same secure-random interface, which must be backed by EFI_RNG_PROTOCOL in the final UEFI adapter.

## URL and HTML core

src/url.rs accepts http:// and https://, defaults a bare hostname to HTTPS, applies ports 80 and 443, and resolves common absolute, scheme-relative, root-relative, and path-relative references. It rejects unknown schemes and URL user-information. IPv6 literal parsing is not implemented in this first pass.

src/document.rs extracts a page title, visible text, and numbered anchor links. It skips comments and common non-visible elements such as scripts, styles, templates, noscript, and SVG, and decodes a limited set of named and numeric entities. It is a lightweight text extractor, not a complete HTML5 tree builder. CSS layout, JavaScript, DOM mutation, form submission, cookies, media, and modern web application behaviour are not implemented.

## Build prerequisites

The intended complete build requires:

- Rust stable 1.91 or newer.
- The x86_64-unknown-uefi Rust target.
- CMake and Ninja.
- Clang/LLVM capable of emitting x86-64 COFF objects.
- curl, sha256sum, and tar for the pinned Mbed TLS source.
- An EFI-compatible C allocation/runtime shim for Mbed TLS.
- Firmware exposing UDP4, TCP4, RNG, and Runtime Services time.
- A configured recursive DNS server address.

Install the Rust target:

~~~sh
rustup update stable
rustup target add x86_64-unknown-uefi
~~~

Run portable-core tests:

~~~sh
cargo test --lib
cargo fmt --all -- --check
~~~

Prepare the Mbed TLS source and experimental static-library build:

~~~sh
./scripts/build-uefi.sh
~~~

The current script does **not** produce a complete browser EFI image. A final build command will be documented once the UEFI protocol adapters, C runtime, and static link are implemented and verified.

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

src/firmware_rng.rs wraps EFI_RNG_PROTOCOL and requests the firmware-selected default algorithm. Failure to locate or read the RNG is propagated; the code has no clock, counter, or weak PRNG fallback.

src/firmware_time.rs reads UEFI Runtime Services time, validates the structure, requires a defined timezone, rejects dates earlier than the configured policy floor, and converts the resulting civil time to Unix seconds. Its C ABI function returns -1 if time is not trustworthy. The Mbed TLS C bridge and build configuration do not yet call this function, so certificate validity-time enforcement is **not yet active in the final TLS path**.

### C runtime and Mbed TLS platform hooks

Mbed TLS still needs a freestanding UEFI build configuration and runtime integration. The current C bridge calls calloc/free and has not yet installed an EFI allocator through mbedtls_platform_set_calloc_free. The Rust UTC callback has not yet been connected through Mbed TLS's platform-time hook, and the build does not yet enable and verify X.509 date checking. These are blocking items for a complete secure HTTPS build.

## Installation target

The intended x86-64 removable-media path is:

~~~text
EFI/BOOT/BOOTX64.EFI
~~~

Copying a binary to this path does not guarantee network access. Firmware must have initialized and exposed the NIC, UDP4, TCP4, RNG, and time protocols before the app starts.

## Roadmap

- [x] Establish a Rust no_std UEFI application crate.
- [x] Add portable HTTP/HTTPS URL parsing and relative URL resolution.
- [x] Add initial HTML visible-text and link extraction.
- [x] Add Hickory DNS protocol dependency without default std features.
- [x] Add DNS A-query construction, response validation, and bounded UDP transport contract.
- [x] Connect DNS resolution output to a TCP4 connector interface.
- [x] Add a Mbed TLS TCP BIO callback boundary and hostname-preserving TLS handoff.
- [x] Pin and checksum-verify the upstream Mbed TLS release archive.
- [ ] Implement concrete EFI UDP4 and TCP4 adapters.
- [ ] Read DNS resolver configuration from DHCP/firmware network configuration.
- [ ] Implement EFI RNG and trustworthy UTC callbacks.
- [ ] Embed and maintain a Mozilla-derived CA bundle.
- [ ] Complete freestanding Mbed TLS build, C runtime, and static PE/COFF link.
- [ ] Implement HTTP/1.1 framing, redirects, content encodings, and character sets.
- [ ] Build a scrolling/reflowing terminal renderer with keyboard link focus.
- [ ] Add back/forward, reload, find, bookmarks, downloads, and persistent history.
- [ ] Expand QEMU/OVMF and physical-firmware integration tests.
- [ ] Work toward ELinks-level feature parity.

## Security and scope

This is pre-OS code running with firmware privileges. Bugs in parsers, TLS callbacks, allocation, or protocol lifetime handling can crash the machine or compromise the boot chain. Remote content is untrusted. The browser must not execute remote JavaScript in the firmware environment.

The project is not feature-complete and is not presently suitable for browsing, handling secrets, or replacing a maintained operating-system browser.

## References

- [Hickory DNS protocol crate](https://docs.rs/hickory-proto/0.26.3/hickory_proto/)
- [Hickory protocol feature flags](https://docs.rs/crate/hickory-proto/0.26.3/features)
- [Mbed TLS upstream](https://github.com/Mbed-TLS/mbedtls)
- [Mbed TLS 4.3.0 release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.3.0)
- [UEFI 2.11 network protocols](https://uefi.org/specs/UEFI/2.11/29_Network_Protocols_ARP_and_DHCP.html)
- [Rust UEFI crate](https://docs.rs/uefi/)
- [Rust UEFI target](https://doc.rust-lang.org/rustc/platform-support/unknown-uefi.html)

## License

Original project code is intended to be dual-licensed under MIT or Apache-2.0. Mbed TLS is separately licensed upstream; review and preserve its license notices when redistributing an EFI image that includes it.
