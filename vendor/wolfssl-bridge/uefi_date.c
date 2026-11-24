/*
 * Strict UEFI-backed X.509 date validation hook for wolfSSL.
 *
 * wolfSSL calls XVALIDATE_DATE with the raw ASN.1 time contents. RFC 5280
 * certificate times are UTCTime (YYMMDDHHMMSSZ) through 2049 and
 * GeneralizedTime (YYYYMMDDHHMMSSZ) from 2050 onward. Parse those encodings
 * directly and compare their UTC epoch value with the validated firmware
 * clock. Unsupported or malformed encodings fail closed.
 */
#include <stdint.h>
#include <stddef.h>

#define UEFI_ASN_UTC_TIME          0x17U
#define UEFI_ASN_GENERALIZED_TIME  0x18U
#define UEFI_ASN_BEFORE            0
#define UEFI_ASN_AFTER             1

extern int64_t uefi_browser_time_unix(void);

static int read_decimal(const unsigned char *data, size_t offset,
                        size_t digits, int *value)
{
    size_t i;
    int parsed = 0;

    if (data == NULL || value == NULL) return 0;
    for (i = 0; i < digits; ++i) {
        unsigned char ch = data[offset + i];
        if (ch < (unsigned char)'0' || ch > (unsigned char)'9') return 0;
        parsed = parsed * 10 + (int)(ch - (unsigned char)'0');
    }
    *value = parsed;
    return 1;
}

static int is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

static int days_in_month(int year, int month)
{
    static const int month_days[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    if (month < 1 || month > 12) return 0;
    if (month == 2 && is_leap_year(year)) return 29;
    return month_days[month - 1];
}

/* Proleptic Gregorian calendar: days since 1970-01-01. */
static int64_t days_from_civil(int year, unsigned int month, unsigned int day)
{
    int64_t adjusted_year = (int64_t)year - (month <= 2U ? 1 : 0);
    int64_t era = (adjusted_year >= 0 ? adjusted_year
                                      : adjusted_year - 399) / 400;
    unsigned int year_of_era = (unsigned int)(adjusted_year - era * 400);
    unsigned int adjusted_month = month > 2U ? month - 3U : month + 9U;
    unsigned int day_of_year =
        (153U * adjusted_month + 2U) / 5U + day - 1U;
    unsigned int day_of_era =
        year_of_era * 365U + year_of_era / 4U - year_of_era / 100U
        + day_of_year;

    return era * 146097 + (int64_t)day_of_era - 719468;
}

/*
 * Return 1 when the encoded date is valid for the supplied comparison:
 * ASN_BEFORE means notBefore <= now; ASN_AFTER means now <= notAfter.
 */
int uefi_wolfssl_validate_date(const unsigned char *date, unsigned char format,
                               int date_type, int length)
{
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    size_t year_digits;
    size_t suffix_offset;
    int64_t now;
    int64_t certificate_time;
    int max_day;

    if (date == NULL || length <= 0) return 0;

    if (format == UEFI_ASN_UTC_TIME) {
        /* RFC 5280 UTCTime: YYMMDDHHMMSSZ, with the 1950/2050 pivot. */
        if (length != 13 || date[12] != (unsigned char)'Z') return 0;
        if (!read_decimal(date, 0, 2, &year)) return 0;
        year += year >= 50 ? 1900 : 2000;
        year_digits = 2;
        suffix_offset = 12;
    } else if (format == UEFI_ASN_GENERALIZED_TIME) {
        /* RFC 5280 GeneralizedTime: YYYYMMDDHHMMSSZ. */
        if (length != 15 || date[14] != (unsigned char)'Z') return 0;
        if (!read_decimal(date, 0, 4, &year)) return 0;
        year_digits = 4;
        suffix_offset = 14;
    } else {
        return 0;
    }

    if (!read_decimal(date, year_digits, 2, &month) ||
        !read_decimal(date, year_digits + 2, 2, &day) ||
        !read_decimal(date, year_digits + 4, 2, &hour) ||
        !read_decimal(date, year_digits + 6, 2, &minute) ||
        !read_decimal(date, year_digits + 8, 2, &second)) {
        return 0;
    }

    /* Keep the layout contract explicit and reject embedded/trailing data. */
    if (suffix_offset + 1U != (size_t)length) return 0;
    max_day = days_in_month(year, month);
    if (max_day == 0 || day < 1 || day > max_day ||
        hour > 23 || minute > 59 || second > 59) {
        return 0;
    }

    now = uefi_browser_time_unix();
    if (now < 0) return 0;

    certificate_time = days_from_civil(year, (unsigned int)month,
                                       (unsigned int)day) * INT64_C(86400)
                       + (int64_t)hour * INT64_C(3600)
                       + (int64_t)minute * INT64_C(60)
                       + (int64_t)second;

    if (date_type == UEFI_ASN_BEFORE) return now >= certificate_time;
    if (date_type == UEFI_ASN_AFTER) return now <= certificate_time;
    return 0;
}
