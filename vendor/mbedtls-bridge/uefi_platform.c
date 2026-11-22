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
/*
 * Small freestanding printf subset for Mbed TLS diagnostics. This avoids
 * pulling MinGW's __mingw_snprintf/__mingw_vsnprintf into the EFI image.
 * Supports the integer, pointer, character and string conversions used by
 * Mbed TLS' SSL/X.509 debug messages; floating-point formatting is omitted.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <limits.h>

static void fmt_char(char *buffer, size_t size, size_t *length, char value)
{
    if (size > 0 && *length < size - 1) {
        buffer[*length] = value;
    }
    if (*length < SIZE_MAX) {
        ++*length;
    }
}

static void fmt_repeat(char *buffer, size_t size, size_t *length,
                       char value, size_t count)
{
    while (count-- > 0) {
        fmt_char(buffer, size, length, value);
    }
}

static void fmt_bytes(char *buffer, size_t size, size_t *length,
                      const char *value, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        fmt_char(buffer, size, length, value[i]);
    }
}

static size_t fmt_strlen_limit(const char *value, size_t limit)
{
    size_t length = 0;
    while (length < limit && value[length] != '\0') {
        ++length;
    }
    return length;
}

static void fmt_number(char *buffer, size_t size, size_t *length,
                       uintmax_t value, bool negative, unsigned base,
                       bool uppercase, bool alternate, bool zero_pad,
                       bool left, bool plus, bool space,
                       int width, int precision)
{
    char digits[sizeof(uintmax_t) * 8 + 1];
    const char *alphabet = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    size_t digit_count = 0;

    if (precision != 0 || value != 0) {
        do {
            digits[digit_count++] = alphabet[value % base];
            value /= base;
        } while (value != 0 && digit_count < sizeof(digits));
    }

    char sign = negative ? '-' : (plus ? '+' : (space ? ' ' : '\0'));
    char prefix[2];
    size_t prefix_count = 0;
    if (alternate && base == 16 && digit_count > 0) {
        prefix[0] = '0';
        prefix[1] = uppercase ? 'X' : 'x';
        prefix_count = 2;
    } else if (alternate && base == 8 &&
               (digit_count == 0 || digits[digit_count - 1] != '0')) {
        prefix[0] = '0';
        prefix_count = 1;
    }

    size_t precision_zeros = precision > 0 && (size_t)precision > digit_count
        ? (size_t)precision - digit_count : 0;
    size_t content = digit_count + precision_zeros + prefix_count + (sign != '\0');
    size_t padding = width > 0 && (size_t)width > content
        ? (size_t)width - content : 0;

    if (!left && !zero_pad) {
        fmt_repeat(buffer, size, length, ' ', padding);
    }
    if (sign != '\0') {
        fmt_char(buffer, size, length, sign);
    }
    fmt_bytes(buffer, size, length, prefix, prefix_count);
    if (!left && zero_pad && precision < 0) {
        fmt_repeat(buffer, size, length, '0', padding);
    }
    fmt_repeat(buffer, size, length, '0', precision_zeros);
    while (digit_count > 0) {
        fmt_char(buffer, size, length, digits[--digit_count]);
    }
    if (left) {
        fmt_repeat(buffer, size, length, ' ', padding);
    }
}

int uefi_mbedtls_vsnprintf(char *buffer, size_t size,
                           const char *format, va_list args)
{
    if (format == NULL || (buffer == NULL && size != 0)) {
        return -1;
    }

    size_t length = 0;
    const char *cursor = format;
    while (*cursor != '\0') {
        if (*cursor != '%') {
            fmt_char(buffer, size, &length, *cursor++);
            continue;
        }
        ++cursor;
        if (*cursor == '%') {
            fmt_char(buffer, size, &length, *cursor++);
            continue;
        }

        bool left = false, zero = false, plus = false, space = false, alternate = false;
        bool parsing = true;
        while (parsing) {
            switch (*cursor) {
            case '-': left = true; ++cursor; break;
            case '0': zero = true; ++cursor; break;
            case '+': plus = true; ++cursor; break;
            case ' ': space = true; ++cursor; break;
            case '#': alternate = true; ++cursor; break;
            default: parsing = false; break;
            }
        }

        int width = 0;
        if (*cursor == '*') {
            width = va_arg(args, int);
            ++cursor;
            if (width < 0) {
                left = true;
                width = width == INT_MIN ? 1024 : -width;
            }
        } else {
            while (*cursor >= '0' && *cursor <= '9') {
                if (width < 1024) width = width * 10 + (*cursor - '0');
                if (width > 1024) width = 1024;
                ++cursor;
            }
        }

        int precision = -1;
        if (*cursor == '.') {
            ++cursor;
            precision = 0;
            if (*cursor == '*') {
                precision = va_arg(args, int);
                ++cursor;
                if (precision < 0) precision = -1;
            } else {
                while (*cursor >= '0' && *cursor <= '9') {
                    if (precision < 1024) precision = precision * 10 + (*cursor - '0');
                    if (precision > 1024) precision = 1024;
                    ++cursor;
                }
            }
        }

        enum { LEN_DEFAULT, LEN_HH, LEN_H, LEN_L, LEN_LL, LEN_Z, LEN_T, LEN_J } length_kind = LEN_DEFAULT;
        if (*cursor == 'h') {
            ++cursor;
            length_kind = (*cursor == 'h') ? (++cursor, LEN_HH) : LEN_H;
        } else if (*cursor == 'l') {
            ++cursor;
            length_kind = (*cursor == 'l') ? (++cursor, LEN_LL) : LEN_L;
        } else if (*cursor == 'z') {
            ++cursor; length_kind = LEN_Z;
        } else if (*cursor == 't') {
            ++cursor; length_kind = LEN_T;
        } else if (*cursor == 'j') {
            ++cursor; length_kind = LEN_J;
        }

        char conversion = *cursor;
        if (conversion == '\0') {
            break;
        }
        ++cursor;

        if (conversion == 's') {
            const char *value = va_arg(args, const char *);
            if (value == NULL) value = "(null)";
            size_t count = fmt_strlen_limit(value,
                precision >= 0 ? (size_t)precision : SIZE_MAX);
            size_t padding = width > 0 && (size_t)width > count
                ? (size_t)width - count : 0;
            if (!left) fmt_repeat(buffer, size, &length, ' ', padding);
            fmt_bytes(buffer, size, &length, value, count);
            if (left) fmt_repeat(buffer, size, &length, ' ', padding);
            continue;
        }
        if (conversion == 'c') {
            char value = (char)va_arg(args, int);
            size_t padding = width > 1 ? (size_t)width - 1 : 0;
            if (!left) fmt_repeat(buffer, size, &length, ' ', padding);
            fmt_char(buffer, size, &length, value);
            if (left) fmt_repeat(buffer, size, &length, ' ', padding);
            continue;
        }

        bool negative = false;
        uintmax_t value = 0;
        unsigned base = 10;
        bool is_signed = conversion == 'd' || conversion == 'i';
        bool valid = is_signed || conversion == 'u' || conversion == 'o' ||
                     conversion == 'x' || conversion == 'X' || conversion == 'p';
        if (conversion == 'p') {
            value = (uintptr_t)va_arg(args, void *);
            base = 16;
            alternate = true;
        } else if (is_signed) {
            intmax_t signed_value;
            switch (length_kind) {
            case LEN_L: signed_value = va_arg(args, long); break;
            case LEN_LL: signed_value = va_arg(args, long long); break;
            case LEN_Z:
            case LEN_T: signed_value = va_arg(args, ptrdiff_t); break;
            case LEN_J: signed_value = va_arg(args, intmax_t); break;
            case LEN_HH: signed_value = (signed char)va_arg(args, int); break;
            case LEN_H: signed_value = (short)va_arg(args, int); break;
            default: signed_value = va_arg(args, int); break;
            }
            negative = signed_value < 0;
            value = negative ? (uintmax_t)(-(signed_value + 1)) + 1
                             : (uintmax_t)signed_value;
        } else if (valid) {
            switch (length_kind) {
            case LEN_L: value = va_arg(args, unsigned long); break;
            case LEN_LL: value = va_arg(args, unsigned long long); break;
            case LEN_Z:
            case LEN_T: value = va_arg(args, size_t); break;
            case LEN_J: value = va_arg(args, uintmax_t); break;
            case LEN_HH: value = (unsigned char)va_arg(args, unsigned int); break;
            case LEN_H: value = (unsigned short)va_arg(args, unsigned int); break;
            default: value = va_arg(args, unsigned int); break;
            }
        }

        if (!valid) {
            fmt_char(buffer, size, &length, '%');
            fmt_char(buffer, size, &length, conversion);
            continue;
        }
        if (conversion == 'o') base = 8;
        if (conversion == 'x' || conversion == 'X' || conversion == 'p') base = 16;
        fmt_number(buffer, size, &length, value, negative, base,
                   conversion == 'X', alternate, zero, left, plus, space,
                   width, precision);
    }

    if (size > 0) {
        buffer[length < size ? length : size - 1] = '\0';
    }
    return length > (size_t)INT_MAX ? -1 : (int)length;
}

int uefi_mbedtls_snprintf(char *buffer, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = uefi_mbedtls_vsnprintf(buffer, size, format, args);
    va_end(args);
    return result;
}

#include "mbedtls/platform.h"
#include <psa/crypto.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>

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

/*
 * Mbed TLS asks for a monotonically nondecreasing millisecond clock. UEFI's
 * Runtime Services clock has one-second resolution, so use its UTC epoch
 * milliseconds and clamp backwards adjustments. Stream TLS does not use
 * DTLS retransmission timers; this hook avoids host GetSystemTimeAsFileTime.
 */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    static mbedtls_ms_time_t last = 0;
    const int64_t seconds = uefi_browser_time_unix();
    if (seconds < 0 || seconds > INT64_MAX / 1000) {
        return last;
    }

    const mbedtls_ms_time_t candidate = (mbedtls_ms_time_t)(seconds * 1000);
    if (candidate > last) {
        last = candidate;
    }
    return last;
}

/*
 * Volatile stores ensure the compiler cannot elide this secret wipe. This is
 * the TF-PSA-Crypto zeroization alternative for platforms without Win32 APIs.
 */
void mbedtls_platform_zeroize(void *buffer, size_t length)
{
    volatile unsigned char *cursor = (volatile unsigned char *)buffer;
    while (length-- > 0) {
        *cursor++ = 0;
    }
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
