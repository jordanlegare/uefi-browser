/*
 * Regression tests for the freestanding case-insensitive string helper used
 * by wolfSSL's X.509 name and issuer matching.
 */
int uefi_wolfssl_stricmp(const char *left, const char *right);

int main(void)
{
    if (uefi_wolfssl_stricmp("GlobalSign Root CA - R3",
                             "globalsign root ca - r3") != 0) {
        return 1;
    }
    if (uefi_wolfssl_stricmp("R4", "R3") <= 0) return 2;
    if (uefi_wolfssl_stricmp("R3", "R4") >= 0) return 3;
    if (uefi_wolfssl_stricmp("", "") != 0) return 4;
    if (uefi_wolfssl_stricmp("A", "aX") >= 0) return 5;
    if (uefi_wolfssl_stricmp("aX", "A") <= 0) return 6;
    return 0;
}
