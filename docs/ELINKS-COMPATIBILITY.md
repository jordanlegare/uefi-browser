# ELinks reuse and UEFI porting boundary

This project uses the upstream [rkd77/elinks](https://github.com/rkd77/elinks) source as a behavioural reference, but does not link the ELinks executable or its GPL-only C renderer into the EFI image.

## Reused upstream component

The project includes `assets/elinks-entities.txt`, copied unmodified from ELinks' `Unicode/entities.txt`. The source file explicitly states that its entity mapping data is public domain, and ELinks' `COPYING` also lists `Unicode/entities.txt` as public domain.

At build time, `build.rs` reads this data and generates a Rust named-entity decoder in Cargo's `OUT_DIR`. The generated decoder is used by `src/document.rs`. It includes all entries that map to one valid Unicode scalar. Legacy entries marked `0x????` are intentionally not guessed. The source table contains a duplicate `loz` name; the first mapping (U+25CA LOZENGE) is retained.

This is an older SGML/Unicode 2.0 table, not the complete current HTML Living Standard named-character-reference set. The parser keeps its existing common entities and numeric references, and uses the ELinks table as an additional fallback.

## Why the full ELinks code is not linked

The upstream ELinks `meson.build` declares the application as GPLv2. Its `COPYING` file says GPL version 2 is the default and only approved GPL version for its contributions unless an individual author explicitly states otherwise. This repository declares `GPL-3.0-only` and includes the selected wolfSSL GPLv3 integration. Importing ELinks' GPLv2-only application code into the same EFI executable would create a license incompatibility. The public-domain entity data is independently reusable.

There is also a substantial runtime boundary. ELinks' HTML parser and renderer are integrated with its own document, CSS, cache, URI, session, viewer, terminal, and utility subsystems. The sources use the C runtime and operating-system interfaces, while this browser is a `no_std` UEFI application with a UEFI console renderer, a Rust/smoltcp network stack, and a separately verified wolfSSL TLS transport. The ELinks viewer is not a standalone parser library that can be dropped into the existing firmware application.

## Porting direction

The appropriate path for this project is to implement ELinks-compatible behaviour in the native Rust/UEFI architecture: structured HTML blocks, line layout and terminal-width reflow, tables and lists, keyboard-focused link traversal, scrolling, anchors, forms, search, and browser history. This can preserve the existing smoltcp and mandatory wolfSSL verification pipeline without importing incompatible code or adding a POSIX runtime.

If the ELinks copyright holders ever provide an explicit GPLv3-compatible license grant for the required core modules, or the project adopts a compatible licensing arrangement for all components, direct code reuse can be reassessed. Until then, only separately and permissively licensed/public-domain upstream data is reused.
