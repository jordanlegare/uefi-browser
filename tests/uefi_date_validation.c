/*
 * Host-side tests for the UEFI wolfSSL X.509 date-validation hook.
 * Run with:
 *   clang -std=c11 -Wall -Wextra -Werror \
 *     tests/uefi_date_validation.c vendor/wolfssl-bridge/uefi_date.c \
 *     -o /tmp/uefi-date-validation && /tmp/uefi-date-validation
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

static int64_t test_now;

int64_t uefi_browser_time_unix(void)
{
    return test_now;
}

int uefi_wolfssl_validate_date(const unsigned char *date, unsigned char format,
                               int date_type, int length);

int main(void)
{
    static const unsigned char comodo_not_after[] = "380118235959Z";
    static const unsigned char equal_not_before[] = "261124015203Z";
    static const unsigned char expired_not_after[] = "251124015202Z";
    static const unsigned char future_not_before[] = "261124015204Z";
    static const unsigned char generalized_2050[] = "20500101000000Z";
    static const unsigned char malformed_month[] = "261324015203Z";
    static const unsigned char invalid_leap_day[] = "250229000000Z";
    static const unsigned char unsupported_offset[] = "380118235959+0000";

    /* The confirmed NTP/wolfSSL firmware time from the failing EFI run. */
    test_now = INT64_C(1795485123);

    assert(uefi_wolfssl_validate_date(
        comodo_not_after, 0x17U, 1, (int)(sizeof(comodo_not_after) - 1U)) == 1);
    assert(uefi_wolfssl_validate_date(
        equal_not_before, 0x17U, 0, (int)(sizeof(equal_not_before) - 1U)) == 1);
    assert(uefi_wolfssl_validate_date(
        expired_not_after, 0x17U, 1, (int)(sizeof(expired_not_after) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        future_not_before, 0x17U, 0, (int)(sizeof(future_not_before) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        generalized_2050, 0x18U, 1, (int)(sizeof(generalized_2050) - 1U)) == 1);
    assert(uefi_wolfssl_validate_date(
        malformed_month, 0x17U, 1, (int)(sizeof(malformed_month) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        invalid_leap_day, 0x17U, 1, (int)(sizeof(invalid_leap_day) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        unsupported_offset, 0x17U, 1, (int)(sizeof(unsupported_offset) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        comodo_not_after, 0x18U, 1, (int)(sizeof(comodo_not_after) - 1U)) == 0);
    assert(uefi_wolfssl_validate_date(
        comodo_not_after, 0x17U, 9, (int)(sizeof(comodo_not_after) - 1U)) == 0);

    /* A missing/untrusted firmware clock must never make a certificate valid. */
    test_now = -1;
    assert(uefi_wolfssl_validate_date(
        comodo_not_after, 0x17U, 1, (int)(sizeof(comodo_not_after) - 1U)) == 0);

    puts("UEFI wolfSSL date-validation tests passed");
    return 0;
}
