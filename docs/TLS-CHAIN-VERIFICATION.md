# TLS Certificate and Chain-of-Trust Verification

This document describes what UEFI Browser does when opening an HTTPS URL, what wolfSSL verifies, what is recorded when certificate verification fails, and how the optional GRC fingerprint comparison is used as corroborating evidence.

## Security boundary

The browser's local wolfSSL verification against the CA bundle embedded in the EFI image is the authoritative TLS trust decision. The GRC fingerprint page is an external comparison source only. It is not a CA, it is not added to the trust store, and it cannot make a locally rejected certificate acceptable.

**A certificate verification failure always blocks the original HTTPS connection.** The diagnostic path does not retry the original site with weaker settings, suppress an X.509 error, add a root certificate, or accept a chain because GRC lists it.

A difference between the browser's chain and GRC's chain is a warning signal. It is not, by itself, proof of a man-in-the-middle (MITM) attack.

## Normal HTTPS connection: verification sequence

1. **Parse the requested URL and retain its identity.** The browser extracts the hostname from the HTTPS URL. It keeps that hostname for TLS Server Name Indication (SNI) and certificate identity validation; DNS resolution does not replace the hostname with an IP address for those checks.

2. **Resolve the hostname and establish TCP.** Hickory DNS sends a DNS query over the browser's smoltcp UDP socket. The browser then opens a TCP connection through smoltcp over the UEFI Simple Network Protocol (SNP) NIC. DNS resolution and TCP connectivity do not establish the site's identity.

3. **Create the TLS 1.3 client.** Rust passes the original hostname, embedded CA bundle, and TCP stream callbacks to the wolfSSL bridge. wolfSSL is configured with mandatory `WOLFSSL_VERIFY_PEER`. The browser does not expose a `VERIFY_NONE` or certificate-override mode.

4. **Load the local trust anchors.** The EFI image contains the build-generated CA bundle derived from `assets/cacert.pem`. Build-time filtering removes roots outside their validity window. The bridge loads each PEM root into the same wolfSSL context and fails TLS initialization if a certificate cannot be loaded. These certificates are the browser's local trust anchors; the server's presented leaf and intermediates do not become trust anchors merely by being presented.

5. **Provide time and entropy.** wolfSSL obtains time through the UEFI-backed time function. The firmware clock is synchronized through the browser's NTP bootstrap when available. The strict UEFI date hook parses RFC 5280 UTCTime and GeneralizedTime values, checks calendar fields, and compares certificate validity bounds to the current firmware time. Invalid or unsupported encodings and an unavailable/invalid clock fail closed. Cryptographic randomness is supplied through the UEFI RNG provider.

6. **Set the expected server identity.** For DNS names, the bridge sets SNI and configures wolfSSL to check the requested domain name against the certificate. For IPv4 literals, it configures IP-address identity validation. A certificate for a different host must not pass merely because it chains to a trusted CA.

7. **Receive and validate the peer chain.** During `wolfSSL_connect()`, wolfSSL processes the server's certificate message and builds/verifies a path to a locally trusted CA. Its X.509 validation checks certificate signatures and path/trust relationships, validity dates, and the configured hostname/IP identity. The diagnostic verify callback records information but returns wolfSSL's original `preverify_ok` value unchanged. It never turns a failed check into a successful one.

8. **Apply a second fail-closed guard.** Rust checks the handshake result and then checks wolfSSL's verification result before allowing HTTP data to flow. A successful TCP connection or completed server hello is not sufficient; certificate verification must also succeed.

## What is captured during certificate verification

The C callback in `vendor/wolfssl-bridge/uefi_tls.c` records:

- The X.509 verification error code from wolfSSL.
- The chain depth associated with the first reported verification failure (depth 0 is the leaf/server certificate).
- The SHA-256 fingerprint of the exact certificate wolfSSL reports as failing, when the certificate DER is available.
- SHA-1 fingerprints of certificates exposed to the verification callback, indexed by wolfSSL's reported chain depth, up to the diagnostic limit of eight entries.

The SHA-256 fingerprint identifies the rejected certificate in the diagnostic report. SHA-1 is captured solely because GRC publishes SHA-1 fingerprints for its chain page and the browser needs a comparable representation. Neither diagnostic fingerprint replaces wolfSSL's signature verification or is used as a trust decision.

The callback's captured chain is the path information wolfSSL exposes through its verification callback. If wolfSSL does not expose a certificate at a depth, a fingerprint cannot be reported for that entry. The report must treat unavailable data as unavailable, not infer a certificate.

## What happens when certificate verification fails

1. **The handshake returns an error.** Rust receives the wolfSSL handshake failure, its X.509 error, failing depth, and SHA-256 fingerprint (if captured).
2. **The original TLS connection is abandoned.** The browser obtains the captured peer-chain fingerprints for diagnostics, then drops the failed TLS session and its TCP connection. It does not send an HTTP request to the original site.
3. **The browser explains the local failure.** The report includes the wolfSSL error, X.509 error, failing chain depth, and SHA-256 fingerprint of the rejected certificate when available. It explains the known error where possible and warns the user not to enter credentials or sensitive data.
4. **The browser attempts an external reference lookup.** For an ASCII DNS hostname, it constructs:
   `https://www.grc.com/fingerprints.htm?chain=<requested-hostname>`
   IP literals and malformed hostnames are not sent to this lookup.
5. **The GRC connection is itself verified.** The browser resolves `www.grc.com`, opens a separate TCP connection, and establishes a new TLS session using the same embedded CA trust bundle and normal mandatory peer/hostname verification. The request has a five-second stream I/O timeout and the response body is bounded to 128 KiB. If GRC's TLS certificate cannot be verified, the browser reports the reference as unavailable. It does not weaken verification to obtain the reference.
6. **The response is checked before parsing.** Only HTTP status 200 is accepted. The Rust parser extracts the visible text, requires the expected “Chain of Trust for” heading and requested hostname, and requires at least one syntactically valid SHA-1 fingerprint. It recognizes Root, Intermediate, and Server roles and limits the parsed chain to 16 certificates. An unexpected page, hostname mismatch, missing fingerprints, or unsupported page structure makes the comparison unavailable.
7. **Fingerprints are compared.** The parser's GRC reference is compared with the fingerprints captured by the local wolfSSL callback. The server/leaf fingerprint is checked against the local leaf at depth 0. Root certificates are not reported as missing merely because the server did not send them; TLS servers commonly omit the root trust anchor. Reference certificates not found in the local callback path and local fingerprints absent from GRC's reference are listed as discrepancies.
8. **The failing certificate is identified where possible.** The browser uses wolfSSL's failing depth to select the local fingerprint and looks for that fingerprint in GRC's list. If it matches, the report can name the corresponding GRC role and certificate. If it does not match, the report gives the local fingerprint and says that it is not listed by GRC. If the callback did not capture that depth, the certificate identity is reported as unavailable.
9. **The security result remains fail-closed.** Whether the GRC comparison matches, diverges, or is unavailable, the original site's connection remains blocked. A GRC match does not override wolfSSL's failure.

## Interpreting the comparison

| Result | Meaning | What the browser reports |
|---|---|---|
| Match | The captured leaf and non-root peer-chain fingerprints agree with the GRC reference entries that are expected to be sent by the server. | Reference corroborates the observed path, but does not override the local failure. |
| Chain divergence | One or more expected non-root GRC fingerprints are absent locally, the leaf differs, or the local path contains fingerprints absent from GRC's reference. | Possible interception or a different certificate path/edge; investigation is warranted. |
| Unavailable | No usable local path was captured, or GRC could not be reached, verified, or parsed. | No independent comparison can be made. The original TLS failure still blocks the connection. |

### Why a divergence is not proof of MITM

GRC observes the requested hostname from its own network location. The browser observes the hostname from the user's network. They can legitimately receive different certificates or paths because of:

- CDN and geographic edge selection.
- Certificate rotation between observations.
- Cross-signed or alternate intermediate paths.
- Different intermediate certificates sent by different server edges.
- Changes to the site's certificate chain between the two connections.
- A server or proxy that presents a different chain on the user's network.

An unexpected locally presented certificate, especially one issued by an enterprise or locally installed interception CA that is not in the browser's trust bundle, can be consistent with TLS interception. It can also be caused by a misconfigured server or incomplete local trust bundle. The browser therefore uses “possible TLS interception” or “chain divergence” language rather than claiming an attack is proven.

## Validation coverage and limitations

| Validation or evidence | Current implementation |
|---|---|
| Peer certificate chain/path verification | wolfSSL, mandatory peer verification |
| Certificate signature/path and trust-anchor validation | wolfSSL |
| Certificate validity period | wolfSSL with the strict UEFI-backed date hook |
| DNS hostname identity | wolfSSL SNI plus domain-name validation |
| IPv4 address identity | wolfSSL IP-address validation |
| Embedded CA trust anchors | Build-generated CA bundle |
| Failing X.509 error and chain depth | Captured from wolfSSL verification callback |
| Rejected certificate SHA-256 | Captured when DER is available |
| Peer-chain SHA-1 fingerprints | Captured for comparison with GRC's published format |
| External chain comparison | GRC HTTPS reference, if its connection and response validate |
| CRL / OCSP revocation status | Not currently checked |
| Certificate Transparency (CT) proof/SCT validation | Not currently checked |
| DNSSEC / DANE authentication | Not currently checked |
| Pinned certificate or public-key identity | Not currently implemented |
| Independent second network vantage controlled by the browser | Not available; GRC is a third-party reference service |

The current comparison checks fingerprint membership and leaf identity; it does not independently reconstruct and cryptographically validate GRC's certificate path, enforce the exact ordering of all intermediate certificates, or prove that both observations reached the same CDN edge. Those path-validation responsibilities remain with wolfSSL for the browser's actual connection.

## Source-code map

- `src/main.rs`: HTTPS navigation, fail-closed handshake handling, user-facing failure report, GRC HTTPS fetch, and comparison report.
- `src/tls.rs`: Rust TLS session wrapper and access to wolfSSL diagnostic values.
- `src/grc_chain.rs`: GRC page parser, hostname check, fingerprint formatting, and comparison logic.
- `vendor/wolfssl-bridge/uefi_tls.c`: mandatory peer-verification configuration, hostname/IP identity configuration, certificate callback diagnostics, CA loading, and TLS handshake.
- `vendor/wolfssl-bridge/uefi_date.c`: strict certificate validity-date parsing and comparison with UEFI time.
- `vendor/wolfssl-bridge/include/user_settings.h`: wolfSSL UEFI configuration.
- `build.rs` and `scripts/build-uefi.sh`: build-time CA bundle generation and wolfSSL/EFI integration.

## User guidance

When the browser reports a certificate failure, do not bypass it and do not submit credentials or sensitive information to that site. A matching GRC chain does not make the failed connection safe; a mismatch is a reason to investigate the network, DNS, proxy configuration, certificate chain, and trust bundle. The user should only retry after the underlying certificate-validation failure has been understood and resolved.
