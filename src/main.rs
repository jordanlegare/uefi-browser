#![no_main]
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char};
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
use core::hint::spin_loop;
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

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

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
const TLS_DEBUG_CAPACITY: usize = 24;
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
const TLS_DEBUG_SOURCE_BYTES: usize = 32;
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
const TLS_DEBUG_MESSAGE_BYTES: usize = 768;

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
#[derive(Clone, Copy)]
struct TlsDebugEntry {
    level: i32,
    line: i32,
    source_len: u8,
    message_len: u16,
    source: [u8; TLS_DEBUG_SOURCE_BYTES],
    message: [u8; TLS_DEBUG_MESSAGE_BYTES],
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
impl TlsDebugEntry {
    const EMPTY: Self = Self {
        level: 0,
        line: 0,
        source_len: 0,
        message_len: 0,
        source: [0; TLS_DEBUG_SOURCE_BYTES],
        message: [0; TLS_DEBUG_MESSAGE_BYTES],
    };
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
struct TlsDebugRing {
    locked: AtomicBool,
    next: AtomicUsize,
    entries: UnsafeCell<[TlsDebugEntry; TLS_DEBUG_CAPACITY]>,
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
// Access to entries is serialized by locked; callbacks and report rendering
// run synchronously on the single UEFI application thread.
unsafe impl Sync for TlsDebugRing {}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_DEBUG_RING: TlsDebugRing = TlsDebugRing {
    locked: AtomicBool::new(false),
    next: AtomicUsize::new(0),
    entries: UnsafeCell::new([TlsDebugEntry::EMPTY; TLS_DEBUG_CAPACITY]),
};

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_debug_lock() {
    while TLS_DEBUG_RING
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        spin_loop();
    }
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_debug_unlock() {
    TLS_DEBUG_RING.locked.store(false, Ordering::Release);
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_debug_reset() {
    tls_debug_lock();
    TLS_DEBUG_RING.next.store(0, Ordering::Relaxed);
    unsafe {
        *TLS_DEBUG_RING.entries.get() = [TlsDebugEntry::EMPTY; TLS_DEBUG_CAPACITY];
    }
    tls_debug_unlock();
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_debug_record(level: i32, source: &[u8], line: i32, message: &[u8]) {
    let source = &source[source.len().saturating_sub(TLS_DEBUG_SOURCE_BYTES)..];
    let message = &message[..message.len().min(TLS_DEBUG_MESSAGE_BYTES)];

    tls_debug_lock();
    let sequence = TLS_DEBUG_RING.next.load(Ordering::Relaxed);
    let entries = unsafe { &mut *TLS_DEBUG_RING.entries.get() };
    let entry = &mut entries[sequence % TLS_DEBUG_CAPACITY];
    *entry = TlsDebugEntry::EMPTY;
    entry.level = level;
    entry.line = line;
    entry.source_len = source.len() as u8;
    entry.message_len = message.len() as u16;
    entry.source[..source.len()].copy_from_slice(source);
    entry.message[..message.len()].copy_from_slice(message);
    TLS_DEBUG_RING.next.store(sequence + 1, Ordering::Relaxed);
    tls_debug_unlock();
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_debug_report() -> String {
    let mut snapshot = [TlsDebugEntry::EMPTY; TLS_DEBUG_CAPACITY];
    tls_debug_lock();
    let next = TLS_DEBUG_RING.next.load(Ordering::Relaxed);
    let count = next.min(TLS_DEBUG_CAPACITY);
    let entries = unsafe { &*TLS_DEBUG_RING.entries.get() };
    let first = next.saturating_sub(count);
    for (offset, sequence) in (first..next).enumerate() {
        snapshot[offset] = entries[sequence % TLS_DEBUG_CAPACITY];
    }
    tls_debug_unlock();

    let mut report = format!("TLS diagnostic tail: {} recent Mbed TLS messages", count);
    for entry in snapshot.iter().take(count) {
        let source =
            core::str::from_utf8(&entry.source[..entry.source_len as usize]).unwrap_or("?");
        let message = core::str::from_utf8(&entry.message[..entry.message_len as usize])
            .unwrap_or("<non-UTF-8>");
        report.push_str(&format!(
            "\n  L{} {}:{} {}",
            entry.level, source, entry.line, message
        ));
    }
    report
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_HANDSHAKE_START_UNIX: AtomicI64 = AtomicI64::new(-1);

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_HANDSHAKE_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_TRACE_STAGE: AtomicI64 = AtomicI64::new(0);
#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
static TLS_TRACE_DETAIL: AtomicI64 = AtomicI64::new(0);

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
fn tls_handshake_elapsed_seconds() -> Option<i64> {
    let start = TLS_HANDSHAKE_START_UNIX.load(Ordering::Relaxed);
    let now = uefi_browser::firmware_time::uefi_browser_time_unix();
    (start >= 0 && now >= start).then_some(now - start)
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_tls_log(stage: i32, detail: i32) {
    if stage == 11 {
        TLS_TRACE_COUNT.store(0, Ordering::Relaxed);
        TLS_TRACE_STAGE.store(0, Ordering::Relaxed);
        TLS_TRACE_DETAIL.store(0, Ordering::Relaxed);
        TLS_HANDSHAKE_START_UNIX.store(
            uefi_browser::firmware_time::uefi_browser_time_unix(),
            Ordering::Relaxed,
        );
        TLS_HANDSHAKE_ACTIVE.store(true, Ordering::Release);
    } else if stage == 12 {
        // Stage 12 is called after the final handshake step has returned.
        TLS_HANDSHAKE_ACTIVE.store(false, Ordering::Release);
    } else if matches!(
        stage,
        42 | 50
            | 51
            | 52
            | 54
            | 55
            | 56
            | 57
            | 58
            | 59
            | 60
            | 61
            | 62
            | 63
            | 64
            | 65
            | 66
            | 67
            | 68
            | 69
            | 70
            | 71
            | 72
            | 73
            | 74
            | 75
            | 76
            | 77
            | 78
            | 79
            | 80
            | 81
            | 82
            | 83
            | 84
            | 85
            | 86
            | 87
            | 88
            | 89
            | 90
            | 91
            | 92
            | 93
            | 94
            | 95
            | 96
            | 97
            | 98
            | 99
            | 100
            | 101
            | 102
            | 103
            | 104
            | 105
            | 106
            | 107
            | 108
            | 110
            | 111
            | 112
            | 113
            | 114
            | 115
            | 116
            | 117
            | 140
            | 141
            | 142
            | 143
            | 144
            | 145
            | 146
            | 147
            | 148
            | 149
            | 150
            | 151
            | 152
            | 153
            | 154
            | 155
            | 156
            | 157
            | 158
            | 159
            | 160
            | 161
            | 162
            | 163
            | 164
            | 165
            | 166
            | 167
            | 168
            | 171
            | 172
            | 173
            | 174
            | 175
    ) {
        // These explicit checkpoints are emitted at safe function boundaries,
        // never from the BIO or Mbed TLS debug callbacks.
        let message = match stage {
            42 => format!(
                "X.509: verification flags after handshake failure=0x{:08x}",
                detail as u32
            ),
            50 => format!("TLS handshake step {}: entering", detail),
            51 => format!("TLS handshake step returned; state={}", detail),
            52 => format!("TLS handshake step failed: {}", detail),
            54 => format!("TLS handshake state before step: {}", detail),
            55 => format!("TLS 1.2: entering server-certificate parser (state 3)"),
            56 => format!(
                "TLS 1.2: server-certificate parser returned (result={})",
                detail
            ),
            57 => format!("TLS 1.3: entering server-certificate processor (state 3)"),
            58 => format!(
                "TLS 1.3: server-certificate processor returned (result={})",
                detail
            ),
            59 => "TLS 1.3: entered certificate processor before debug callback".to_string(),
            60 => format!(
                "TLS 1.3: Certificate message fetch returned (result={})",
                detail
            ),
            67 => "TLS 1.3: initial debug callback returned".to_string(),
            68 => "X.509: entering firmware-time conversion".to_string(),
            69 => format!(
                "X.509: firmware-time conversion returned (result={})",
                detail
            ),
            70 => "X.509: entering certificate-chain construction".to_string(),
            71 => format!(
                "X.509: certificate-chain construction returned (result={})",
                detail
            ),
            72 => format!("X.509: searching for issuer (chain depth={})", detail),
            73 => format!("X.509: issuer search returned (result={})", detail),
            74 => format!(
                "X.509: hashing certificate signature input (bytes={})",
                detail
            ),
            75 => format!(
                "X.509: certificate signature hash returned (status={})",
                detail
            ),
            76 => format!(
                "X.509: entering public-key signature verification (algorithm={})",
                detail
            ),
            77 => format!(
                "X.509: public-key signature verification returned (result={})",
                detail
            ),
            78 => format!("PK ECDSA adapter entered (curve_bits={})", detail),
            79 => format!(
                "PK ECDSA: PSA public-key import returned (status={})",
                detail
            ),
            80 => format!(
                "PK ECDSA: DER-to-raw signature conversion returned (result={})",
                detail
            ),
            81 => format!(
                "PK ECDSA: entering psa_verify_hash (signature_bytes={})",
                detail
            ),
            82 => format!("PK ECDSA: psa_verify_hash returned (status={})", detail),
            83 => "PK ECDSA: entering PSA key destruction".to_string(),
            84 => format!("PK ECDSA: PSA key destruction returned (status={})", detail),
            85 => format!("PSA: verify_internal entered (input_is_message={})", detail),
            86 => format!(
                "PSA: dispatching verify_hash to crypto driver (algorithm={})",
                detail
            ),
            87 => format!("PSA: verify_hash driver returned (status={})", detail),
            88 => format!(
                "PSA: built-in ECDSA verification selected (curve_bits={})",
                detail
            ),
            89 => format!(
                "PSA: built-in ECDSA verification returned (status={})",
                detail
            ),
            90 => format!(
                "PSA ECDSA: entering key representation loader (key_bits={})",
                detail
            ),
            91 => format!(
                "PSA ECDSA: key representation loader returned (status={})",
                detail
            ),
            92 => "PSA ECDSA: entering public-point loader".to_string(),
            93 => format!(
                "PSA ECDSA: public-point loader returned (status={})",
                detail
            ),
            94 => format!(
                "PSA ECDSA: entering ECDSA arithmetic (curve_bits={})",
                detail
            ),
            95 => format!("PSA ECDSA: ECDSA arithmetic returned (status={})", detail),
            96 => format!(
                "ECDSA: verification arithmetic entered (curve_bits={})",
                detail
            ),
            97 => format!(
                "ECDSA: hashed-message reduction returned (result={})",
                detail
            ),
            98 => "ECDSA: entering modular inverse".to_string(),
            99 => format!("ECDSA: modular inverse returned (result={})", detail),
            100 => "ECDSA: entering EC point linear combination".to_string(),
            101 => format!(
                "ECDSA: EC point linear combination returned (result={})",
                detail
            ),
            102 => "ECDSA: entering final x-coordinate reduction".to_string(),
            103 => format!(
                "ECDSA: final x-coordinate reduction returned (result={})",
                detail
            ),
            104 => format!(
                "ECP: entering point linear-combination engine (curve_bits={})",
                detail
            ),
            105 => format!(
                "ECP: first scalar multiplication returned (result={})",
                detail
            ),
            106 => format!(
                "ECP: second scalar multiplication returned (result={})",
                detail
            ),
            107 => format!("ECP: point addition returned (result={})", detail),
            108 => format!(
                "ECP: projective point normalization returned (result={})",
                detail
            ),
            110 => "ECDSA: entering u1 = e * s_inv multiplication".to_string(),
            111 => format!("ECDSA: u1 multiplication returned (result={})", detail),
            112 => "ECDSA: entering u1 modulo curve-order reduction".to_string(),
            113 => format!("ECDSA: u1 modular reduction returned (result={})", detail),
            114 => "ECDSA: entering u2 = r * s_inv multiplication".to_string(),
            115 => format!("ECDSA: u2 multiplication returned (result={})", detail),
            116 => "ECDSA: entering u2 modulo curve-order reduction".to_string(),
            117 => format!("ECDSA: u2 modular reduction returned (result={})", detail),
            140 => "ECP: entering first scalar multiplication".to_string(),
            141 => format!(
                "ECP: first scalar multiplication returned (result={})",
                detail
            ),
            142 => "ECP: entering second scalar multiplication".to_string(),
            143 => format!(
                "ECP: second scalar multiplication returned (result={})",
                detail
            ),
            144 => "ECP: entering mixed point addition".to_string(),
            145 => format!("ECP: mixed point addition returned (result={})", detail),
            146 => "ECP: entering final point normalization".to_string(),
            147 => format!(
                "ECP: final point normalization returned (result={})",
                detail
            ),
            148 => "ECP: private-scalar validation returned; checking public point".to_string(),
            149 => format!(
                "ECP: scalar and point validation returned (result={})",
                detail
            ),
            150 => format!("ECP: entering comb multiplication (curve_bits={})", detail),
            151 => format!("ECP: comb multiplication returned (result={})", detail),
            152 => format!("ECP: comb engine entered (curve_bits={})", detail),
            153 => format!(
                "ECP: entering precomputed-point table generation (table_size={})",
                detail
            ),
            154 => format!(
                "ECP: precomputed-point table generation returned (result={})",
                detail
            ),
            155 => format!(
                "ECP: entering scalar evaluation with precomputed table (table_size={})",
                detail
            ),
            156 => format!("ECP: entering scalar recoding (comb_depth={})", detail),
            157 => format!("ECP: scalar recoding returned (result={})", detail),
            158 => "ECP: entering comb scalar-multiplication core".to_string(),
            159 => format!(
                "ECP: comb scalar-multiplication core returned (result={})",
                detail
            ),
            160 => "ECP: entering scalar-result normalization".to_string(),
            161 => format!(
                "ECP: scalar-result normalization returned (result={})",
                detail
            ),
            166 => format!("MPI modulo: entering division (A_limbs={})", detail),
            167 => format!("MPI modulo: division returned (R_limbs={})", detail),
            168 => "MPI modulo: negative-remainder correction completed".to_string(),
            171 => format!("MPI division: entered (A_limbs={})", detail),
            172 => format!("MPI division: aligned divisor (limb_shift={})", detail),
            173 => format!(
                "MPI division: leading quotient digit completed (X_limbs={})",
                detail
            ),
            174 => format!(
                "MPI division: entering quotient-digit loop (limb_span={})",
                detail
            ),
            175 => "MPI division: quotient-digit loop completed".to_string(),
            61 => format!(
                "TLS 1.3: parsing certificate list (message_bytes={})",
                detail
            ),
            62 => format!(
                "TLS 1.3: certificate-list parsing returned (result={})",
                detail
            ),
            63 => "TLS 1.3: validating certificate chain".to_string(),
            64 => format!(
                "TLS 1.3: certificate-chain validation returned (result={})",
                detail
            ),
            65 => format!(
                "TLS 1.3: adding Certificate message to transcript (bytes={})",
                detail
            ),
            66 => format!("TLS 1.3: transcript update returned (result={})", detail),
            _ => unreachable!(),
        };
        uefi::println!("{}", message);
        if stage == 51 {
            // Debug callbacks only append to the RAM ring while Mbed TLS runs.
            // Render their tail after each step has returned.
            uefi::println!("{}", tls_debug_report());
        }
        return;
    } else if TLS_HANDSHAKE_ACTIVE.load(Ordering::Acquire) {
        // These callbacks execute synchronously underneath Mbed TLS. Record
        // only the latest event; never call firmware console or clock APIs.
        TLS_TRACE_STAGE.store(stage as i64, Ordering::Relaxed);
        TLS_TRACE_DETAIL.store(detail as i64, Ordering::Relaxed);
        TLS_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let message = match stage {
        1 => "TLS init: entering psa_crypto_init",
        2 => "TLS init: PSA crypto initialized",
        3 => "TLS init: parsing embedded CA bundle",
        4 => "TLS init: CA bundle parsed",
        5 => "TLS init: applying Mbed TLS client defaults",
        6 => "TLS init: Mbed TLS defaults applied",
        7 => "TLS init: allocating SSL session",
        8 => "TLS init: SSL session allocated",
        9 => "TLS init: setting SNI and hostname",
        10 => "TLS init: session configured",
        11 => "TLS handshake: entering mbedtls_ssl_handshake",
        12 => "TLS handshake: Mbed TLS returned",
        20 => "TLS entropy: entering EFI_RNG_PROTOCOL",
        21 => "TLS entropy: EFI_RNG_PROTOCOL returned",
        30 => "TLS BIO: send callback entering",
        31 => "TLS BIO: send callback returned",
        32 => "TLS BIO: receive callback entering",
        33 => "TLS BIO: receive callback returned",
        34 => "TLS Rust: stream send entering",
        35 => "TLS Rust: stream send returned",
        36 => "TLS Rust: stream receive entering",
        37 => "TLS Rust: stream receive returned",
        40 => "TLS X.509: peer certificate chain depth",
        41 => "TLS X.509: verification flags (unchanged)",
        50 => "TLS handshake step entering",
        51 => "TLS handshake step returned",
        52 => "TLS handshake step failed",
        54 => "TLS handshake state",
        55 => "TLS 1.2 server-certificate parser entering",
        56 => "TLS 1.2 server-certificate parser returned",
        57 => "TLS 1.3 server-certificate processor entering",
        58 => "TLS 1.3 server-certificate processor returned",
        _ => "TLS diagnostic",
    };
    if stage == 11 {
        let firmware_utc_unix = TLS_HANDSHAKE_START_UNIX.load(Ordering::Relaxed);
        uefi::println!(
            "TLS handshake: entering Mbed TLS; firmware UTC Unix timestamp={}",
            firmware_utc_unix
        );
        return;
    }

    if let Some(elapsed) = tls_handshake_elapsed_seconds() {
        uefi::println!("{} (elapsed={}s detail={})", message, elapsed, detail);
    } else {
        uefi::println!("{} (elapsed=unknown detail={})", message, detail);
    }

    if stage == 12 {
        let count = TLS_TRACE_COUNT.load(Ordering::Relaxed);
        let last_stage = TLS_TRACE_STAGE.load(Ordering::Relaxed);
        let last_detail = TLS_TRACE_DETAIL.load(Ordering::Relaxed);
        uefi::println!(
            "TLS callback trace: {} events; last stage={} detail={}",
            count,
            last_stage,
            last_detail
        );
    }
}

#[cfg(all(target_os = "uefi", uefi_mbedtls_linked))]
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_tls_debug_log(
    level: i32,
    file: *const c_char,
    line: i32,
    message: *const c_char,
) {
    if message.is_null() {
        return;
    }

    let message_bytes = unsafe { CStr::from_ptr(message) }.to_bytes();
    let source_bytes = if file.is_null() {
        &b"?"[..]
    } else {
        unsafe { CStr::from_ptr(file) }.to_bytes()
    };
    // This callback runs synchronously inside Mbed TLS while the TLS
    // handshake is active. Never call UEFI console services here: firmware
    // console output can block or re-enter firmware code and stall the
    // handshake. Keep this path limited to copying into the RAM ring buffer;
    // the caller prints the captured tail after Mbed TLS returns.
    tls_debug_record(level, source_bytes, line, message_bytes);
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

    // UEFI arms a five-minute watchdog before launching a boot option.
    // This interactive browser intentionally remains in Boot Services.
    match uefi::boot::set_watchdog_timer(0, 0x1_0000, None) {
        Ok(()) => uefi::println!("UEFI boot watchdog disabled for interactive session."),
        Err(error) => uefi::println!("Warning: unable to disable UEFI boot watchdog: {:?}", error),
    }

    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("|                         UEFI BROWSER                         |");
    uefi::println!("|               standalone x86_64 pre-OS browser               |");
    uefi::println!("+--------------------------------------------------------------+");
    uefi::println!("Rust DNS: Hickory | IP stack: smoltcp over UEFI SNP");
    uefi::println!("TLS: embedded Mbed TLS | Rendering: UEFI text console");
    uefi::println!("");
    uefi::println!("Initializing SNP Ethernet and smoltcp IPv4/DHCP...");
    let mut network = match uefi_browser::firmware_rng::UefiRandom::open() {
        Ok(mut random) => match uefi_browser::snp_network::SnpNetwork::new(&mut random) {
            Ok(mut network) => match network.acquire_dhcp(60_000) {
                Ok(dns_server) => {
                    uefi::println!("smoltcp DHCP configured; DNS resolver: {}", dns_server);
                    uefi::println!("Synchronizing UTC clock from NTP...");
                    match uefi_browser::firmware_ntp::synchronize(&mut network, dns_server) {
                        Ok(unix) => uefi::println!("NTP synchronized; UTC Unix time: {}", unix),
                        Err(error) => uefi::println!("NTP synchronization failed: {}", error),
                    }
                    Some(network)
                }
                Err(error) => {
                    uefi::println!("smoltcp DHCP initialization failed: {:?}", error);
                    None
                }
            },
            Err(error) => {
                uefi::println!("SNP network initialization failed: {:?}", error);
                None
            }
        },
        Err(_) => {
            uefi::println!("Network unavailable: EFI_RNG_PROTOCOL could not seed smoltcp.");
            None
        }
    };
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

    let Some(network) = network.as_mut() else {
        uefi::println!("No usable DHCP configuration; returning to firmware.");
        return Status::SUCCESS;
    };

    uefi::println!("");
    uefi::println!("Enter a hostname or URL. Bare hostnames default to HTTPS.");
    uefi::println!("Type 'help' for commands, or Ctrl+C to return to firmware.");
    uefi::println!("");

    let mut first_url = loop {
        let Some(address) = read_line("Open address: ", network) else {
            return Status::SUCCESS;
        };
        match Url::parse(&address) {
            Ok(url) => break url,
            Err(error) => uefi::println!("Invalid address: {error}. Enter another URL."),
        }
    };

    let mut history = Vec::new();
    let (mut page, mut history_index) = loop {
        match fetch_document(&first_url, network) {
            Ok(page) => {
                history.push(first_url.clone());
                break (page, 0usize);
            }
            Err(error) => {
                uefi::println!("");
                uefi::println!("NAVIGATION FAILED: {error}");
                uefi::println!("The browser is staying open. Press ENTER to retry,");
                uefi::println!("enter another URL, or type 'quit' to return to firmware.");
                let Some(retry) = read_line("Retry URL: ", network) else {
                    return Status::SUCCESS;
                };
                match retry.trim() {
                    "" | "retry" => {}
                    "q" | "quit" | "exit" => return Status::SUCCESS,
                    value => match Url::parse(value) {
                        Ok(url) => first_url = url,
                        Err(error) => uefi::println!("Invalid address: {error}"),
                    },
                }
            }
        }
    };
    let mut navigation_error: Option<String> = None;

    loop {
        render_page(&page, navigation_error.as_deref());
        let prompt = format!("\n{} > ", page.url.as_string());
        let Some(command) = read_line(&prompt, network) else {
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
            continue;
        }
        if let Some(query) = command.strip_prefix("search ") {
            search_page(&page, query);
            continue;
        }

        let mut target_index = None;
        let target_url;
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

        match fetch_document(&target, network) {
            Ok(next_page) => {
                if let Some(index) = target_index {
                    history_index = index;
                } else if add_history {
                    history.truncate(history_index + 1);
                    history.push(next_page.url.clone());
                    history_index = history.len() - 1;
                }
                page = next_page;
                navigation_error = None;
            }
            Err(error) => {
                navigation_error = Some(error);
            }
        }
    }

    uefi::println!("\nLeaving UEFI Browser and returning to firmware.");
    Status::SUCCESS
}

fn fetch_document(
    initial_url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<BrowserPage, String> {
    let mut current = initial_url.clone();

    for redirect_index in 0..=MAX_REDIRECTS {
        let response = fetch_response(&current, network)?;
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

fn fetch_response(
    url: &Url,
    network: &mut uefi_browser::snp_network::SnpNetwork,
) -> Result<HttpResponse, String> {
    #[cfg(not(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle)))]
    if url.scheme == Scheme::Https {
        return Err(String::from(
            "HTTPS unavailable: this EFI image needs the linked Mbed TLS bridge and embedded CA bundle",
        ));
    }

    uefi::println!(
        "Resolving {} and opening TCP port {}...",
        url.host,
        url.port
    );
    let mut connection = match connect_firmware_url(network, url, 15_000) {
        Ok(connection) => connection,
        Err(failure) => {
            let d = failure.diagnostics;
            return Err(format!(
                "DNS/TCP connection failed: {:?}\nSNP TX: queued={} recycled={} failures={} queue-full={} last-status=0x{:x}\nSNP RX: frames={} errors={} last-status=0x{:x}\nUDP: sent={} received={} timeouts={}; TCP: attempts={} failures={} timeouts={}",
                failure.error,
                d.tx_queued,
                d.tx_recycled,
                d.tx_failures,
                d.tx_queue_full,
                d.tx_last_status,
                d.rx_frames,
                d.rx_errors,
                d.rx_last_status,
                d.udp_datagrams_sent,
                d.udp_datagrams_received,
                d.udp_timeouts,
                d.tcp_connect_attempts,
                d.tcp_connect_failures,
                d.tcp_connect_timeouts,
            ));
        }
    };
    uefi::println!(
        "TCP connected: {}:{}",
        connection.peer.address,
        connection.peer.port
    );

    match url.scheme {
        Scheme::Http => {
            uefi::println!("Sending HTTP request...");
            let response = http::exchange_get(&mut connection.peer.stream, url, MAX_BODY_BYTES)
                .map_err(|error| format!("HTTP transaction failed: {error:?}"))?;
            uefi::println!("HTTP response received ({} bytes).", response.body.len());
            Ok(response)
        }
        Scheme::Https => {
            #[cfg(all(target_os = "uefi", uefi_mbedtls_linked, uefi_ca_bundle))]
            {
                let ca_bundle = uefi_browser::ca_bundle::pem()
                    .ok_or_else(|| String::from("no embedded CA trust bundle"))?;
                uefi::println!("Starting TLS handshake and X.509 verification...");
                // The TCP stream's normal navigation timeout is 15 seconds.
                // Use a shorter per-I/O timeout for TLS so a peer that accepts
                // TCP but never sends a ServerHello cannot freeze the UI.
                connection.peer.stream.set_io_timeout_ms(5_000);
                let mut tls = connection
                    .start_tls(ca_bundle)
                    .map_err(|error| format!("TLS initialization failed: {error:?}"))?;
                uefi::println!("TLS session initialized; beginning handshake.");
                tls_debug_reset();
                if let Err(error) = tls.handshake() {
                    // Attach the RAM-buffered tail to the navigation error.
                    // The browser redraws its page after navigation attempts,
                    // so embedding it here preserves the report on screen.
                    let diagnostics = tls_debug_report();
                    return Err(format!(
                        "TLS handshake / certificate verification failed: {error:?}\n{diagnostics}"
                    ));
                }
                uefi::println!("TLS verified. Sending HTTPS request...");
                let response = http::exchange_get(&mut tls, url, MAX_BODY_BYTES)
                    .map_err(|error| format!("HTTPS transaction failed: {error:?}"))?;
                uefi::println!("HTTPS response received ({} bytes).", response.body.len());
                Ok(response)
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

fn render_page(page: &BrowserPage, navigation_error: Option<&str>) {
    clear_screen();
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("| UEFI BROWSER                                                             |");
    uefi::println!("+--------------------------------------------------------------------------+");
    uefi::println!("Title:  {}", page.title);
    uefi::println!("URL:    {}", page.url.as_string());
    uefi::println!("HTTP:   {}", page.status);
    uefi::println!("--------------------------------------------------------------------------");
    if let Some(error) = navigation_error {
        uefi::println!("NAVIGATION ERROR: {error}");
        uefi::println!("Previous page remains available. Enter a new URL or 'reload'.");
        uefi::println!(
            "--------------------------------------------------------------------------"
        );
    }
    uefi::println!("{}", page.text);
    if !page.links.is_empty() {
        uefi::println!("");
        render_links(&page.links);
    }
    uefi::println!("");
    uefi::println!(
        "Commands: open N | URL | back | forward | reload | links | search WORD | help | quit"
    );
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

fn read_line(prompt: &str, network: &mut uefi_browser::snp_network::SnpNetwork) -> Option<String> {
    uefi::print!("{prompt}");
    let mut line = String::new();

    loop {
        network.poll();
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
