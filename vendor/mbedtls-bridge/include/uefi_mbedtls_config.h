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

/* Platform allocator/time hooks are configured only in uefi_tf_psa_config.h. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY

/* X.509 validity checks use the clock configured by TF-PSA-Crypto. */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

#endif
