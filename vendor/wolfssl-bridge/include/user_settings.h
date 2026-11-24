/*
 * wolfSSL configuration for the x86-64 UEFI browser.
 * This header is shared by the wolfSSL library and its application bridge.
 */
#ifndef UEFI_BROWSER_WOLFSSL_USER_SETTINGS_H
#define UEFI_BROWSER_WOLFSSL_USER_SETTINGS_H

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdarg.h>
#include <time.h>
#endif

#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_USER_LOG
#define NO_STDIO_FILESYSTEM
#define NO_ERROR_STRINGS

/* TLS 1.3 client only. */
#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
#define NO_WOLFSSL_SERVER
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_SNI
#define WC_RSA_PSS

/* Preserve RSA and ECC verification for public Web PKI chains. */
#define HAVE_ECC
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_CURVE25519
#define ECC_TIMING_RESISTANT
#define ECC_SHAMIR
#define TFM_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL
#define WC_RSA_BLINDING

/* TLS 1.3 cipher suites and certificate signature hashes. */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_IP_ALT_NAME

/* No OS entropy source or deterministic fallback. */
#define WC_NO_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK uefi_wolfssl_rng

/* Certificate validity checks use the validated UEFI UTC clock. */
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
#define USER_TIME
#define XTIME uefi_wolfssl_time
#define XGMTIME uefi_wolfssl_gmtime

#define XSNPRINTF uefi_wolfssl_snprintf
#define XVSNPRINTF uefi_wolfssl_vsnprintf
#ifndef __ASSEMBLER__
extern int uefi_wolfssl_rng(unsigned char *output, unsigned int size);
extern time_t uefi_wolfssl_time(time_t *timer);
extern struct tm *uefi_wolfssl_gmtime(const time_t *timer, struct tm *result);
extern int uefi_wolfssl_snprintf(char *buffer, size_t size, const char *format, ...);
extern int uefi_wolfssl_vsnprintf(char *buffer, size_t size, const char *format, va_list args);
#endif

/* UEFI AllocatePool-backed allocator. Realloc is implemented with a size header. */
#define XMALLOC_USER

#endif
