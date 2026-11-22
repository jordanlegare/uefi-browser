/*
 * Mbed TLS 4.3 UEFI configuration.
 *
 * Mbed TLS owns the TLS/X.509 configuration. TF-PSA-Crypto has a separate
 * user-configuration hook; the same platform settings are repeated in
 * uefi_tf_psa_config.h so its configuration checker sees the UEFI hooks too.
 */
#ifndef UEFI_MBEDTLS_CONFIG_H
#define UEFI_MBEDTLS_CONFIG_H

#include <stdint.h>
#include "platform_alt.h"

/* UEFI supplies transport and memory; do not compile POSIX networking/timers. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C

/* Use the UEFI Boot Services allocator, never the host C runtime allocator. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO uefi_mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO uefi_mbedtls_free

/* X.509 validity checks use the UEFI Runtime Services clock. */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO uefi_mbedtls_time
#define MBEDTLS_PLATFORM_GMTIME_R_ALT

#endif
