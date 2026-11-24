# Firmware Runtime Test Plan

This document separates checks that GitHub Actions can prove from tests that must be run in a UEFI environment. A successful cargo check or PE32+ link does **not** prove that firmware can boot the image, drive a NIC, obtain a DHCP lease, or exchange packets.

## 1. Build the removable-media image

On Debian/Ubuntu, install the build tools and (for the OVMF test) QEMU and OVMF:

    sudo apt-get install cmake ninja-build clang llvm lld curl unzip mingw-w64-x86-64-dev qemu-system-x86 ovmf dosfstools mtools

Install the UEFI target and build:

    rustup target add x86_64-unknown-uefi
    ./scripts/build-uefi.sh

The removable-media image is:

    dist/EFI/BOOT/BOOTX64.EFI

Keep the generated CA bundle manifest with the build record. The image must contain the wolfSSL bridge and embedded CA roots. Do not replace the normal build with a plain host-target binary.

## 2. OVMF smoke test

Create a small FAT EFI System Partition directory tree and writable OVMF variable store:

    mkdir -p /tmp/uefi-browser-esp/EFI/BOOT
    cp dist/EFI/BOOT/BOOTX64.EFI /tmp/uefi-browser-esp/EFI/BOOT/BOOTX64.EFI
    cp /usr/share/OVMF/OVMF_VARS.fd /tmp/uefi-browser-vars.fd

Boot with an emulated Intel Ethernet device and QEMU user-mode networking:

    qemu-system-x86_64 \
      -machine q35 -m 512 \
      -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
      -drive if=pflash,format=raw,file=/tmp/uefi-browser-vars.fd \
      -drive format=raw,file=fat:rw:/tmp/uefi-browser-esp \
      -netdev user,id=net0 \
      -device e1000,netdev=net0

The exact OVMF file names and NIC driver availability vary by distribution/build. If the firmware does not expose an SNP driver for the selected virtual NIC, the browser cannot configure networking; that is an environment limitation, not proof that the HTML layer failed.

### Boot and network checks

1. Confirm that the EFI application starts from the removable-media fallback path.
2. Confirm EFI_RNG_PROTOCOL is available and SNP initialization succeeds.
3. Confirm DHCPv4 supplies an address, default route and DNS resolver.
4. Confirm NTP reports a time synchronization result. A failed or unauthenticated NTP exchange must not disable certificate validation.
5. Open a plain HTTP test page, then an HTTPS page with a trusted chain and matching hostname.
6. Confirm a deliberately invalid hostname or untrusted chain is rejected. Do not add a certificate override to make the test pass.
7. Confirm navigation, reload, fragment navigation, back/forward and in-page search.

## 3. Form regression

Open https://www.google.com/ and inspect the first visible search form.

- The search field must appear as a bordered ASCII widget at its document position.
- Tab or arrow navigation must place the focus highlight on the field's editable interior row.
- Typing must update the visible value; Backspace must remove the last character.
- Enter must submit the form, and the resulting navigation must remain on the requested HTTPS origin unless the server provides a validated redirect.
- Verify that controls hidden by CSS do not prevent later visible fields from rendering.

Google's page is a useful regression target, but it is not a stable conformance fixture: it can change markup, serve consent/locale variants, and depend on JavaScript the firmware browser does not execute. Retain deterministic parser/renderer unit tests alongside this live-page check.

## 4. Persistence and cache checks

Use a writable boot-volume filesystem.

1. Add a bookmark, exit to firmware, reboot and confirm it remains.
2. Visit several pages, then run the history command; open-history N must reopen a listed entry.
3. Run clear-history, then confirm the listing is empty.
4. Visit a cacheable page twice and inspect the cache marker.
5. For a test origin that returns ETag or Last-Modified, confirm a later GET sends If-None-Match or If-Modified-Since and that a 304 response reuses the stored body.
6. Confirm no-store, no-cache, private, and Set-Cookie responses are not persisted by the existing cache policy.

The current cache implementation is intentionally bounded and does not claim full RFC 9111 semantics (for example, complete Vary handling or heuristic freshness).

## 5. Physical firmware / USB test

Copy the built BOOTX64.EFI to the USB filesystem at EFI/BOOT/BOOTX64.EFI, boot it through the machine's UEFI removable-media entry, and record:

- machine/firmware version and Secure Boot state;
- NIC model and whether firmware exposes an SNP driver;
- EFI_RNG_PROTOCOL availability;
- DHCP address, gateway and DNS server;
- NTP result and UEFI clock;
- HTTP and HTTPS test origins and final status;
- TLS failure behavior for a deliberately wrong hostname;
- Google search form visibility, keyboard focus, editing and submission;
- bookmark/history persistence after reboot.

Do not enter credentials or sensitive data into this experimental browser. It runs with firmware privileges and its HTML/CSS/networking implementation remains a bounded subset.

## 6. Evidence to retain

For each test run, save the source commit SHA, EFI image SHA-256, build workflow URL, firmware version, NIC details, and observed results. CI currently validates formatting, portable unit tests, the x86-64 UEFI compile, wolfSSL bridge build/link and PE32+ image structure. OVMF and physical-firmware observations are separate runtime evidence; do not mark those roadmap items complete until those tests have actually been run and recorded.
