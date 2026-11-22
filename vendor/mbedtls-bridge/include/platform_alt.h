/*
 * Mbed TLS UEFI platform alternatives.
 */
#ifndef UEFI_MBEDTLS_PLATFORM_ALT_H
#define UEFI_MBEDTLS_PLATFORM_ALT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

void *uefi_mbedtls_calloc(size_t count, size_t size);
void uefi_mbedtls_free(void *pointer);
int64_t uefi_mbedtls_time(int64_t *timer);

/* TF-PSA-Crypto platform alternatives. */
int64_t mbedtls_ms_time(void);
void mbedtls_platform_zeroize(void *buffer, size_t length);

/* Discard Mbed TLS self-test/diagnostic output; firmware has no stdio stream. */
int uefi_mbedtls_printf(const char *format, ...);
struct tm *mbedtls_platform_gmtime_r(const int64_t *unix_time, struct tm *result);

#endif
