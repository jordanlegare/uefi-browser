/*
 * Minimal freestanding C string functions for Mbed TLS.
 *
 * The EFI target is linked with /NODEFAULTLIB; it must not pull in the MinGW
 * CRT just to parse in-memory certificates and compare protocol names. Keep
 * this deliberately small and implement only the primitives needed by the
 * selected Mbed TLS configuration.
 */
#include <stddef.h>

int strcmp(const char *left, const char *right)
{
    while (*left != '\0' && (unsigned char)*left == (unsigned char)*right) {
        ++left;
        ++right;
    }
    return (unsigned char)*left - (unsigned char)*right;
}

char *strchr(const char *string, int character)
{
    const unsigned char wanted = (unsigned char)character;
    for (;;) {
        if ((unsigned char)*string == wanted) {
            return (char *)string;
        }
        if (*string == '\0') {
            return NULL;
        }
        ++string;
    }
}

char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0') {
        return (char *)haystack;
    }

    for (; *haystack != '\0'; ++haystack) {
        const char *candidate = haystack;
        const char *pattern = needle;
        while (*candidate != '\0' && *pattern != '\0' &&
               *candidate == *pattern) {
            ++candidate;
            ++pattern;
        }
        if (*pattern == '\0') {
            return (char *)haystack;
        }
    }
    return NULL;
}
