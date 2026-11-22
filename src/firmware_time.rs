//! Firmware UTC clock support for certificate validity checks.
//!
//! UEFI_TIME is accepted only when it is fully valid and includes a specified
//! timezone. An unknown timezone is not silently treated as UTC.

use uefi::runtime::{self, Daylight, Time, TimeParams};

const MIN_TRUSTED_YEAR: u16 = 2020;

/// Get current UTC time as Unix seconds, or fail closed when firmware time is
/// invalid, implausible, or does not identify its timezone.
pub fn unix_time_utc() -> Option<i64> {
    let time = runtime::get_time().ok()?;
    time_to_unix_utc(&time)
}

pub fn time_to_unix_utc(time: &Time) -> Option<i64> {
    if time.is_valid().is_err()
        || time.year() < MIN_TRUSTED_YEAR
        || time.time_zone().is_none()
        || time.daylight() != Daylight::empty()
    {
        return None;
    }

    let days = days_from_civil(time.year() as i64, time.month() as i64, time.day() as i64)?;
    let local_seconds = days
        .checked_mul(86_400)?
        .checked_add((time.hour() as i64) * 3_600)?
        .checked_add((time.minute() as i64) * 60)?
        .checked_add(time.second() as i64)?;

    // UEFI TimeZone is minutes local time is ahead of UTC.
    local_seconds.checked_sub((time.time_zone()? as i64).checked_mul(60)?)
}

/// Convert a Gregorian civil date to days since 1970-01-01.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

/// C ABI callback for the Mbed TLS platform-time hook.
///
/// Returns -1 when the firmware clock cannot be trusted. The C bridge must
/// translate -1 into a platform time failure and must not skip X.509 date checks.
#[unsafe(no_mangle)]
pub extern "C" fn uefi_browser_time_unix() -> i64 {
    unix_time_utc().unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firmware_time(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        zone: Option<i16>,
        daylight: Daylight,
    ) -> Time {
        Time::new(TimeParams {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond: 0,
            time_zone: zone,
            daylight,
        })
        .unwrap()
    }

    #[test]
    fn converts_known_utc_instant() {
        let time = firmware_time(2026, 1, 1, 0, 0, 0, Some(0), Daylight::empty());
        assert_eq!(time_to_unix_utc(&time), Some(1_767_225_600));
    }

    #[test]
    fn applies_timezone_offset() {
        let utc = firmware_time(2026, 1, 1, 0, 0, 0, Some(0));
        let eastern_local = firmware_time(2025, 12, 31, 19, 0, 0, Some(-300), Daylight::empty());
        assert_eq!(time_to_unix_utc(&eastern_local), time_to_unix_utc(&utc));
    }

    #[test]
    fn rejects_daylight_adjusted_local_time() {
        assert_eq!(
            time_to_unix_utc(&firmware_time(
                2026,
                7,
                1,
                12,
                0,
                0,
                Some(-300),
                Daylight::IN_DAYLIGHT
            )),
            None
        );
    }

    #[test]
    fn rejects_unspecified_timezone_and_implausible_clock() {
        assert_eq!(
            time_to_unix_utc(&firmware_time(2026, 1, 1, 0, 0, 0, None, Daylight::empty())),
            None
        );
        assert_eq!(
            time_to_unix_utc(&firmware_time(
                2001,
                1,
                1,
                0,
                0,
                0,
                Some(0),
                Daylight::empty()
            )),
            None
        );
    }
}
