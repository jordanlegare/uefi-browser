/*
 * Mbed TLS 4.3 UEFI configuration.
 *
 * Mbed TLS owns the TLS/X.509 configuration. TF-PSA-Crypto has a separate
 * user-configuration hook. UEFI platform hooks are intentionally configured
 * only in uefi_tf_psa_config.h, as required by the 4.x configuration split.
 */
#ifndef UEFI_MBEDTLS_CONFIG_H
#define UEFI_MBEDTLS_CONFIG_H

#include <stdint.h>
#include "platform_alt.h"

/* UEFI supplies networking and time; do not compile OS sockets, timers,
 * or filesystem parsers. Keep Mbed TLS diagnostics enabled for the UEFI
 * console callback; this does not enable a host CRT or host I/O backend. */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_FS_IO
#define MBEDTLS_DEBUG_C
#undef MBEDTLS_SELF_TEST

/* Platform allocator/time hooks are configured only in uefi_tf_psa_config.h. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY

/* X.509 validity checks use the clock configured by TF-PSA-Crypto. */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

#endif
