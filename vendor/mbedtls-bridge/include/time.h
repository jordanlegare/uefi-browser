/*
 * Minimal freestanding time.h for the Mbed TLS X.509 time conversion path.
 * Only fields consumed by Mbed TLS are declared; no host time APIs are linked.
 */
#ifndef UEFI_MBEDTLS_TIME_H
#define UEFI_MBEDTLS_TIME_H

#include <stdint.h>

typedef int64_t time_t;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

#endif
