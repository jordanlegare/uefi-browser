/*
 * TF-PSA-Crypto 1.x platform configuration for the Mbed TLS 4.x build.
 *
 * TF-PSA-Crypto deliberately has a separate configuration namespace from
 * Mbed TLS. EFI_RNG_PROTOCOL is the only entropy provider; the built-in
 * Unix/Windows collector is explicitly disabled.
 */
#ifndef UEFI_TF_PSA_CONFIG_H
#define UEFI_TF_PSA_CONFIG_H

#include <stdint.h>
#include "platform_alt.h"

#undef MBEDTLS_FS_IO
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#undef MBEDTLS_ENTROPY_NV_SEED
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#define MBEDTLS_PSA_DRIVER_GET_ENTROPY

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO uefi_mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO uefi_mbedtls_free
#define MBEDTLS_PLATFORM_PRINTF_MACRO uefi_mbedtls_printf

#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_TYPE_MACRO int64_t
#define MBEDTLS_PLATFORM_TIME_MACRO uefi_mbedtls_time
#define MBEDTLS_PLATFORM_GMTIME_R_ALT
#define MBEDTLS_PLATFORM_MS_TIME_ALT
#define MBEDTLS_PLATFORM_ZEROIZE_ALT

#endif
