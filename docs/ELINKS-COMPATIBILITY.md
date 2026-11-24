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

## Native Rust terminal renderer

The browser now has a native Rust document and terminal-rendering layer. It retains a bounded sequence of semantic HTML blocks and inline runs, rather than flattening the page before display. The current block model covers headings, paragraphs, preformatted regions, quotations, ordered/unordered list items, definition terms/descriptions, and table rows. Inline runs retain strong/emphasis/code/underline metadata and their originating link index.

The layout engine reflows those runs to the active UEFI text-console width and tracks the screen line for every link. The UEFI frontend draws a fixed header/address/status/footer, scrollable viewport, colored link text and a reverse-video focused link. Keyboard controls provide scrolling, link traversal/activation, URL entry, history, reload, and in-page text search. Plain-text responses are kept preformatted so line breaks and indentation survive.

This is a clean-room Rust implementation based on observable text-browser behaviour and the public-domain entity mapping data described above. It does not contain a port of ELinks' GPLv2-only C renderer. Current gaps include full HTML5 tokenization/tree construction, CSS selectors and layout, tables with computed column widths, URL fragments and named anchors, form controls/submission, character-set negotiation, script execution (intentionally out of scope in firmware), downloads, persistent cache, and bookmarks. UEFI text output is UCS-2, so code points outside the BMP are replaced with '?' at the final console boundary. These limitations are explicit and should guide subsequent parity work.

The new UI does not change network transport or trust policy. HTTPS requests continue through the existing wolfSSL path; certificate-chain, date, and hostname verification remain mandatory, and redirect downgrade protection remains in force.


## Native Rust HTML, CSS, layout and persistence engine

The renderer has moved beyond the original flat text extractor. The html5 module now builds a bounded DOM-like tree from a tokenizer, including implied document nodes, raw-text/RCDATA handling, common optional-end-tag repair, and automatic tbody insertion. The document converter turns that tree into bounded browser structures for block content, inline runs, links, fragment anchors, forms, and table cells.

The CSS module applies style declarations from embedded style elements, linked external stylesheets, and inline attributes. It supports type/class/ID and descendant selectors plus a limited set of terminal-relevant properties. External stylesheet retrieval is capped at four files and 32 KiB per file. HTTPS documents do not load HTTP stylesheets. The CSS engine does not execute @import and does not implement full CSS layout.

The layout engine computes line wraps and table column widths for the current UEFI console width. Long cell contents wrap; colspan contributes to column sizing. Table rowspan remains metadata-only. CSS widths are percentages, margins and padding are mapped to terminal cells, and CSS colors are reduced to the UEFI 16-color palette.

Same-document fragments are navigated by their recorded block position without a new HTTP request. GET/POST forms render visible input controls directly in the document flow. Text values are edited in place with printable keys and Backspace; Tab and arrow keys move focus between links and controls; Enter submits the focused form; Space toggles checkbox/radio controls; and Left/Right cycles select options. Associated labels are retained and password values are masked. POST still requires explicit confirmation. Multipart/file inputs, JavaScript, cookies and complete HTML form constraint validation are not implemented.

Bookmarks and the bounded page cache are persisted on the EFI image's boot filesystem under UEFI_BROWSER. The cache retains up to eight hashed HTML/text GET entries, each no larger than 256 KiB, with a six-hour expiry. no-store, no-cache, private, and Set-Cookie responses are excluded. Writes use a temporary record followed by filesystem rename; if the boot volume is not available or writable, the browser continues without persistent storage.

The new code is an HTML5-style subset, not a claim of WHATWG HTML or CSS conformance. Remaining parser gaps include complete insertion modes, adoption-agency formatting repair, foster parenting and the complete named character reference set. Remaining rendering gaps include rowspan, pseudo-selectors, floats, flex/grid/positioned layout and full CSS cascade priority semantics. No remote script is executed, and the network/TLS chain of trust is unchanged.
