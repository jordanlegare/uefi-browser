/*
 * Minimal freestanding C runtime string/memory primitives for the EFI image.
 * Do not pull the MinGW CRT into the standalone PE/COFF application.
 */
#include <stddef.h>

/* wolfSSL's freestanding replacements for MinGW CRT imports. */
static int uefi_errno_value;

int *uefi_wolfssl_errno(void)
{
    return &uefi_errno_value;
}

int uefi_wolfssl_tolower(int character)
{
    if (character >= 'A' && character <= 'Z') return character + ('a' - 'A');
    return character;
}

int uefi_wolfssl_isspace(int character)
{
    return character == ' ' || character == '\\t' || character == '\\n' ||
           character == '\\v' || character == '\\f' || character == '\\r';
}

int uefi_wolfssl_stricmp(const char *left, const char *right)
{
    while (*left != '\\0' && *right != '\\0') {
        unsigned char a = (unsigned char)*left++;
        unsigned char b = (unsigned char)*right++;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return (int)a - (int)b;
    }
    return (unsigned char)*left - (unsigned char)*right;
}

void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    size_t i;
    for (i = 0; i < length; ++i) out[i] = in[i];
    return destination;
}

void *memmove(void *destination, const void *source, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    if (out < in) {
        size_t i;
        for (i = 0; i < length; ++i) out[i] = in[i];
    } else if (out > in) {
        while (length > 0) {
            --length;
            out[length] = in[length];
        }
    }
    return destination;
}

void *memset(void *destination, int value, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    size_t i;
    for (i = 0; i < length; ++i) out[i] = (unsigned char)value;
    return destination;
}

int memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *a = (const unsigned char *)left;
    const unsigned char *b = (const unsigned char *)right;
    size_t i;
    for (i = 0; i < length; ++i) {
        if (a[i] != b[i]) return (int)a[i] - (int)b[i];
    }
    return 0;
}

void *memchr(const void *buffer, int value, size_t length)
{
    const unsigned char *p = (const unsigned char *)buffer;
    size_t i;
    for (i = 0; i < length; ++i) if (p[i] == (unsigned char)value) return (void *)(p + i);
    return NULL;
}

size_t strlen(const char *string)
{
    const char *p = string;
    while (*p != '\0') ++p;
    return (size_t)(p - string);
}

size_t strnlen(const char *string, size_t maximum)
{
    size_t length = 0;
    while (length < maximum && string[length] != '\0') ++length;
    return length;
}

int strcmp(const char *left, const char *right)
{
    while (*left != '\0' && (unsigned char)*left == (unsigned char)*right) {
        ++left;
        ++right;
    }
    return (unsigned char)*left - (unsigned char)*right;
}

int strncmp(const char *left, const char *right, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];
        if (a != b || a == 0) return (int)a - (int)b;
    }
    return 0;
}

char *strncpy(char *destination, const char *source, size_t length)
{
    size_t i = 0;
    for (; i < length && source[i] != '\0'; ++i) destination[i] = source[i];
    for (; i < length; ++i) destination[i] = '\0';
    return destination;
}

char *strchr(const char *string, int character)
{
    const unsigned char wanted = (unsigned char)character;
    for (;;) {
        if ((unsigned char)*string == wanted) return (char *)string;
        if (*string == '\0') return NULL;
        ++string;
    }
}

char *strrchr(const char *string, int character)
{
    const unsigned char wanted = (unsigned char)character;
    const char *last = NULL;
    do {
        if ((unsigned char)*string == wanted) last = string;
    } while (*string++ != '\0');
    return (char *)last;
}

char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0') return (char *)haystack;
    for (; *haystack != '\0'; ++haystack) {
        const char *candidate = haystack;
        const char *pattern = needle;
        while (*candidate != '\0' && *pattern != '\0' && *candidate == *pattern) {
            ++candidate;
            ++pattern;
        }
        if (*pattern == '\0') return (char *)haystack;
    }
    return NULL;
}

int strcasecmp(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        unsigned char a = (unsigned char)*left++;
        unsigned char b = (unsigned char)*right++;
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b) return (int)a - (int)b;
    }
    return (unsigned char)*left - (unsigned char)*right;
}

int strncasecmp(const char *left, const char *right, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned char a = (unsigned char)left[i];
        unsigned char b = (unsigned char)right[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + ('a' - 'A'));
        if (a != b || a == 0) return (int)a - (int)b;
    }
    return 0;
}
