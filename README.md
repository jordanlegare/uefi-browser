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
  - transaction ID supplied by EFI_RNG_PROTOCOL
  - checks response ID, QR/opcode, question, RCODE, TC and answer owner
       |
       v
EFI_UDP4_PROTOCOL adapter (to be implemented)
  - datagram to configured DNS resolver:53
  - verifies response source IP and source port
  - timeout and bounded 512-byte DNS packet
       |
       v
IPv4 address
       |
       v
EFI_TCP4_PROTOCOL adapter (to be implemented)
  - connect to resolved IPv4 address:443
  - bounded connect/read/write and cleanup
       |
       v
Mbed TLS 4.3.0 (statically linked into BOOTX64.EFI)
  - receives the original hostname, not the numeric IP
  - SNI and hostname verification
  - mandatory X.509 chain verification
  - CA trust anchors embedded in the image
  - random bytes from EFI_RNG_PROTOCOL
  - certificate time validation from UEFI Runtime Services
       |
       v
HTTP/1.1 over the TLS byte stream
       |
       v
HTML parser -> text renderer -> keyboard navigation
~~~

The key handoff is implemented in src/network.rs:

- connect_url() calls the Hickory-backed dns::resolve_a().
- It passes the resulting IPv4 address and URL port to Tcp4Connector::connect_tcp4().
- It retains the original URL hostname in ConnectedPeer.
- ConnectedPeer::start_tls() passes that hostname and the connected TCP stream to TlsConnection::new().

This separation matters for HTTPS: TCP connects to the numeric IP address, while Mbed TLS must still receive the DNS hostname so that SNI and certificate identity checks use the expected server name.

### UEFI DNS4 versus UDP4

This implementation intentionally does **not** call EFI_DNS4_PROTOCOL. The DNS client is Hickory in Rust. Its wire-format packets are sent through an adapter implemented with EFI_UDP4_PROTOCOL. The adapter must use the configured DNS server address (normally learned from DHCP option 6 or supplied by a static network configuration); this project does not yet read that setting from firmware.

hickory-proto is the low-level DNS protocol crate used by the higher-level Hickory DNS project. It supports no_std builds when the std feature is disabled. This makes it suitable for firmware packet serialization and response parsing; the project supplies the UEFI UDP4 transport because a normal host UDP socket resolver cannot run in UEFI. The src/dns.rs module is the DNS client policy layer, and UdpDnsTransport is the adapter contract.

Current DNS scope: IPv4 A queries through UDP, with secure random transaction IDs, two bounded timeout attempts, and strict response validation. The 512-byte packet limit follows classic DNS-over-UDP sizing. Truncated responses fail closed; DNS-over-TCP fallback, CNAME chain chasing, AAAA/IPv6, DNSSEC validation, caching, and search-domain expansion are not yet implemented.

## Current implementation status

| Component | Status |
|---|---|
| Rust no_std UEFI application crate | Present |
| x86-64 UEFI target configuration | Present |
| Firmware console startup diagnostic | Present |
| HTTP/HTTPS URL parser and relative URL resolution | Implemented in portable core |
| HTML title/text/anchor extraction | Implemented in portable core |
| Hickory DNS message encoding/decoding | Implemented |
| DNS A-query stub client and response validation | Implemented |
| Secure random source abstraction shared by DNS and TLS | Implemented as an interface |
| DNS-to-TCP endpoint orchestration | Implemented through adapter traits |
| TCP stream-to-Mbed-TLS callback bridge | Implemented as an interface |
| Mbed TLS 4.3.0 fetch and archive checksum verification | Implemented |
| UEFI UDP4 concrete adapter | Not implemented |
| UEFI TCP4 concrete adapter | Not implemented |
| DNS server discovery from DHCP/configuration | Not implemented |
| EFI RNG implementation | Not implemented |
| Valid UTC clock integration for certificate dates | Not implemented |
| Embedded CA bundle and update process | Not implemented |
| EFI-safe C allocator/runtime shims | Not implemented |
| Mbed TLS static link into final PE/COFF EFI image | Not implemented |
| HTTP/1.1 request/response engine | Not implemented |
| Integrated navigation loop and page renderer | Not implemented |
| Tested network-capable browser image | Not produced |

## Repository layout

| Path | Responsibility |
|---|---|
| src/main.rs | UEFI entry point and current startup diagnostic |
| src/url.rs | HTTP/HTTPS URL parsing, default ports, authority validation, relative URL resolution |
| src/document.rs | Basic HTML visible-text and anchor extraction |
| src/dns.rs | Hickory-backed DNS A query construction, UDP exchange contract, and response validation |
| src/entropy.rs | Secure random provider contract shared by DNS transaction IDs and Mbed TLS |
| src/network.rs | DNS-resolve -> EFI TCP4 connect -> Mbed TLS handoff |
| src/tls.rs | Rust Mbed TLS FFI boundary and TCP BIO callback adapter |
| vendor/mbedtls-bridge/uefi_tls.c | Mbed TLS configuration, BIO callbacks, handshake, and certificate verification |
| scripts/fetch-mbedtls.sh | Downloads and SHA-256 verifies the official upstream Mbed TLS release archive |
| scripts/build-uefi.sh | Experimental Mbed TLS static-library cross-build setup; final EFI link is not complete |
| Cargo.toml | Rust package, UEFI dependency, Hickory DNS dependency, release profile |

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

## Firmware adapter requirements

### UDP4 DNS adapter

The concrete UdpDnsTransport implementation must:

- create/configure a child using EFI_UDP4_SERVICE_BINDING_PROTOCOL and EFI_UDP4_PROTOCOL;
- send a single bounded DNS datagram to the configured resolver on UDP port 53;
- receive into a 512-byte packet buffer;
- reject datagrams whose source IPv4 address or source port does not match the configured resolver;
- apply a bounded timeout and release events/tokens/child handles on every path;
- return the response bytes to dns::resolve_a() for Hickory validation.

The DNS module checks the transaction ID, response/opcode bits, truncation flag, response code, question name/type/class, and the owner name/class of returned A records.

### TCP4 stream adapter

The concrete Tcp4Connector implementation must:

- create/configure a child using EFI_TCP4_SERVICE_BINDING_PROTOCOL and EFI_TCP4_PROTOCOL;
- connect to the IPv4 address returned by the Hickory resolver;
- implement the TlsStreamIo send/receive contract with bounded waits;
- correctly process partial writes, EOF, reset, cancellation, and timeout;
- close the connection and destroy the child on all error paths.

ConnectedPeer::start_tls() then creates the Mbed TLS session over this stream, passing the original DNS hostname and embedded CA bundle.

### Entropy and time

SecureRandom must be implemented with EFI_RNG_PROTOCOL. The implementation must propagate failures.

Certificate date checks need trustworthy UTC from UEFI Runtime Services. If the platform does not have a valid real-time clock, HTTPS must fail closed; disabling certificate time checks is not an acceptable default.

### C runtime and memory

Mbed TLS is a C library. A UEFI target does not provide a POSIX libc. The final link must provide the minimal C ABI functionality required by the chosen Mbed TLS configuration and route allocation to UEFI Boot Services pool allocation while Boot Services remain active. The current bridge uses calloc and free, so those symbols must be supplied by the UEFI compatibility layer before linking.

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
