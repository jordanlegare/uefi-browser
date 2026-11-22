//! SNTP bootstrap over the application-owned SNP/smoltcp UDP stack.
//!
//! Plain NTP is unauthenticated. This bootstrap validates packet structure,
//! server mode/stratum, and the echoed client nonce, but cannot authenticate
//! the time source against an on-path attacker. TLS certificate verification
//! remains mandatory; deployments needing authenticated time should add NTS.

use core::net::Ipv4Addr;
use uefi::runtime::{self, Daylight, Time, TimeParams};

use crate::dns::UdpDnsTransport;
use crate::dns::resolve_a;
use crate::entropy::SecureRandom;
use crate::firmware_rng::UefiRandom;
use crate::snp_network::SnpNetwork;

const NTP_HOST: &str = "time.cloudflare.com";
const NTP_PORT: u16 = 123;
const NTP_UNIX_DELTA: i64 = 2_208_988_800;
const NTP_ERA: i64 = 4_294_967_296;
const MIN_UNIX: i64 = 1_577_836_800; // 2020-01-01
const MAX_UNIX: i64 = 4_102_444_800; // 2100-01-01

/// Resolve the configured NTP hostname, fetch a server timestamp, and set the
/// UEFI real-time clock to UTC. Returns the accepted Unix timestamp.
pub fn synchronize(network: &mut SnpNetwork, dns_server: Ipv4Addr) -> Result<i64, &'static str> {
    let mut rng = UefiRandom::open().map_err(|_| "EFI_RNG_PROTOCOL unavailable")?;
    let server = resolve_a(network, &mut rng, dns_server, NTP_HOST, 3_000)
        .map_err(|_| "could not resolve NTP server")?;

    let mut request = [0u8; 48];
    request[0] = 0x23; // LI=0, VN=4, client mode.
    let mut nonce = [0u8; 8];
    rng.fill_bytes(&mut nonce)
        .map_err(|_| "firmware RNG failed")?;
    request[40..48].copy_from_slice(&nonce);

    let mut response = [0u8; 512];
    let length = network
        .exchange(server, NTP_PORT, &request, &mut response, 4_000)
        .map_err(|_| "NTP UDP exchange failed")?;
    if length < 48 {
        return Err("NTP response shorter than 48 bytes");
    }

    let leap = response[0] >> 6;
    let version = (response[0] >> 3) & 0x07;
    let mode = response[0] & 0x07;
    let stratum = response[1];
    if leap == 3 || !(3..=4).contains(&version) || mode != 4 || !(1..=15).contains(&stratum) {
        return Err("NTP response has invalid LI/version/mode/stratum");
    }
    if response[24..32] != nonce {
        return Err("NTP originate timestamp does not match client nonce");
    }

    let ntp_seconds = u32::from_be_bytes(response[40..44].try_into().unwrap()) as i64;
    let unix_seconds = (0..=2)
        .map(|era| ntp_seconds + era * NTP_ERA - NTP_UNIX_DELTA)
        .find(|seconds| (MIN_UNIX..MAX_UNIX).contains(seconds))
        .ok_or("NTP timestamp is outside the accepted 2020-2100 window")?;

    let time = unix_to_uefi_time(unix_seconds).ok_or("NTP timestamp cannot be represented")?;
    // SAFETY: The timestamp was range-checked and Time::new validated all fields.
    unsafe { runtime::set_time(&time) }.map_err(|_| "UEFI Runtime Services SetTime failed")?;

    let confirmed = runtime::get_time().map_err(|_| "UEFI GetTime failed after SetTime")?;
    let confirmed_unix = crate::firmware_time::time_to_unix_utc(&confirmed)
        .ok_or("firmware clock remains unsuitable for X.509 after NTP")?;
    if (confirmed_unix - unix_seconds).abs() > 3 {
        return Err("firmware clock did not retain the NTP time");
    }
    Ok(confirmed_unix)
}

fn unix_to_uefi_time(unix_seconds: i64) -> Option<Time> {
    let days = unix_seconds.div_euclid(86_400);
    let day_seconds = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days)?;
    if !(1900..=9999).contains(&year) {
        return None;
    }
    Time::new(TimeParams {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        hour: (day_seconds / 3_600) as u8,
        minute: ((day_seconds % 3_600) / 60) as u8,
        second: (day_seconds % 60) as u8,
        nanosecond: 0,
        time_zone: Some(0),
        daylight: Daylight::empty(),
    })
    .ok()
}

fn civil_from_days(days_since_epoch: i64) -> Option<(i64, i64, i64)> {
    let z = days_since_epoch.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    Some((year, month, day))
}
