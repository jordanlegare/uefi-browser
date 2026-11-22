/*
 * Freestanding Mbed TLS time adapters for UEFI.
 *
 * Current time comes from UEFI Runtime Services through Rust. Invalid firmware
 * time returns -1; the broken-down-time adapter rejects it so X.509 validity
 * checks fail closed instead of skipping date validation.
 */

#include <stdint.h>
#include <stddef.h>
#include "platform_alt.h"
#include "mbedtls/platform.h"
#include <psa/crypto.h>

extern int64_t uefi_browser_time_unix(void);
extern int uefi_browser_fill_random(unsigned char *output, size_t output_size);

/*
 * TF-PSA-Crypto's Mbed TLS 4.x entropy-driver hook. EFI_RNG_PROTOCOL is the
 * sole source; report full entropy only after a successful firmware read.
 */
int mbedtls_platform_get_entropy(psa_driver_get_entropy_flags_t flags,
                                 size_t *estimate_bits,
                                 unsigned char *output, size_t output_size)
{
    if (flags != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (estimate_bits == NULL || (output == NULL && output_size != 0) ||
        output_size > SIZE_MAX / 8) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output_size == 0) {
        *estimate_bits = 0;
        return 0;
    }
    if (uefi_browser_fill_random(output, output_size) != 0) {
        *estimate_bits = 0;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *estimate_bits = output_size * 8;
    return 0;
}

/*
 * Mbed TLS self-test and optional diagnostic code may call mbedtls_printf.
 * A UEFI application has no C stdio stream, so intentionally discard this
 * output rather than pulling printf or a host CRT into the EFI image.
 */
int uefi_mbedtls_printf(const char *format, ...)
{
    (void)format;
    return 0;
}

int64_t uefi_mbedtls_time(int64_t *timer)
{
    const int64_t now = uefi_browser_time_unix();
    if (now < 0) {
        return (int64_t) -1;
    }
    if (timer != NULL) {
        *timer = now;
    }
    return now;
}

struct tm *mbedtls_platform_gmtime_r(const int64_t *unix_time, struct tm *result)
{
    int64_t seconds;
    int64_t days;
    int64_t day_seconds;
    int64_t z;
    int64_t era;
    int64_t day_of_era;
    int64_t year_of_era;
    int64_t year;
    int64_t day_of_year;
    int64_t month_prime;
    int64_t month;
    int64_t day;
    int64_t weekday;

    if (unix_time == NULL || result == NULL || *unix_time < 0) {
        return NULL;
    }

    seconds = *unix_time;
    days = seconds / 86400;
    day_seconds = seconds % 86400;

    z = days + 719468;
    era = z / 146097;
    day_of_era = z - era * 146097;
    year_of_era = (day_of_era - day_of_era / 1460
                   + day_of_era / 36524 - day_of_era / 146096) / 365;
    year = year_of_era + era * 400;
    day_of_year = day_of_era
                  - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    month_prime = (5 * day_of_year + 2) / 153;
    day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    month = month_prime + (month_prime < 10 ? 3 : -9);
    year += month <= 2;

    if (year > 9999) {
        return NULL;
    }

    weekday = (days + 4) % 7;
    if (weekday < 0) {
        weekday += 7;
    }

    result->tm_year = (int) year - 1900;
    result->tm_mon = (int) month - 1;
    result->tm_mday = (int) day;
    result->tm_hour = (int) (day_seconds / 3600);
    result->tm_min = (int) ((day_seconds % 3600) / 60);
    result->tm_sec = (int) (day_seconds % 60);
    result->tm_wday = (int) weekday;
    result->tm_yday = (int) day_of_year;
    result->tm_isdst = 0;

    return result;
}
