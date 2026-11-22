/*
 * TF-PSA-Crypto 1.x platform configuration for the Mbed TLS 4.x build.
 *
 * TF-PSA-Crypto deliberately has a separate configuration namespace from
 * Mbed TLS. Keep these platform hooks here as well as in
 * uefi_mbedtls_config.h so the TF-PSA config checks and platform sources use
 * the exact same UEFI allocator and time implementation.
 */
#ifndef UEFI_TF_PSA_CONFIG_H
#define UEFI_TF_PSA_CONFIG_H

#include <stdint.h>
#include "platform_alt.h"

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO uefi_mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO uefi_mbedtls_free

#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO uefi_mbedtls_time
#define MBEDTLS_PLATFORM_GMTIME_R_ALT

#endif
