/*
 * UEFI platform hooks for wolfSSL/wolfCrypt.
 * Entropy and time come only from EFI_RNG_PROTOCOL and UEFI Runtime Services.
 */
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

extern void *uefi_browser_alloc(size_t size);
extern void uefi_browser_free(void *pointer);
extern int uefi_browser_fill_random(unsigned char *output, size_t output_size);
extern int64_t uefi_browser_time_unix(void);

int uefi_wolfssl_vsnprintf(char *buffer, size_t size,
                           const char *format, va_list args)
{
    (void)format;
    (void)args;
    if (buffer != NULL && size != 0) buffer[0] = '\0';
    return -1;
}

int uefi_wolfssl_snprintf(char *buffer, size_t size, const char *format, ...)
{
    va_list args;
    int result;
    va_start(args, format);
    result = uefi_wolfssl_vsnprintf(buffer, size, format, args);
    va_end(args);
    return result;
}

typedef struct {
    size_t size;
    void *base;
} uefi_wolfssl_allocation;

#define UEFI_WOLFSSL_ALLOC_ALIGNMENT ((uintptr_t)64)

void *uefi_wolfssl_malloc(size_t size, void *heap, int type);
void *uefi_wolfssl_realloc(void *pointer, size_t size, void *heap, int type);
void uefi_wolfssl_free(void *pointer, void *heap, int type);

void *XMALLOC(size_t size, void *heap, int type)
{
    return uefi_wolfssl_malloc(size, heap, type);
}

void *XREALLOC(void *pointer, size_t size, void *heap, int type)
{
    return uefi_wolfssl_realloc(pointer, size, heap, type);
}

void XFREE(void *pointer, void *heap, int type)
{
    uefi_wolfssl_free(pointer, heap, type);
}

void *uefi_wolfssl_malloc(size_t size, void *heap, int type)
{
    void *base;
    uintptr_t aligned;
    uefi_wolfssl_allocation *allocation;
    size_t payload_size = size == 0 ? 1 : size;
    size_t overhead = sizeof(*allocation) + (size_t)UEFI_WOLFSSL_ALLOC_ALIGNMENT - 1U;
    (void)heap;
    (void)type;

    if (payload_size > SIZE_MAX - overhead) return NULL;
    base = uefi_browser_alloc(overhead + payload_size);
    if (base == NULL) return NULL;

    aligned = ((uintptr_t)base + sizeof(*allocation) +
               UEFI_WOLFSSL_ALLOC_ALIGNMENT - 1U) &
              ~(UEFI_WOLFSSL_ALLOC_ALIGNMENT - 1U);
    allocation = (uefi_wolfssl_allocation *)aligned - 1;
    allocation->size = size;
    allocation->base = base;
    return (void *)aligned;
}

void uefi_wolfssl_free(void *pointer, void *heap, int type)
{
    uefi_wolfssl_allocation *allocation;
    (void)heap;
    (void)type;

    if (pointer == NULL) return;
    allocation = (uefi_wolfssl_allocation *)pointer - 1;
    {
        volatile unsigned char *bytes = (volatile unsigned char *)pointer;
        size_t remaining = allocation->size;
        while (remaining-- > 0) *bytes++ = 0;
    }
    {
        void *base = allocation->base;
        allocation->size = 0;
        allocation->base = NULL;
        uefi_browser_free(base);
    }
}

void *uefi_wolfssl_realloc(void *pointer, size_t size, void *heap, int type)
{
    uefi_wolfssl_allocation *old_allocation;
    void *new_pointer;
    size_t copy_size;
    unsigned char *source;
    unsigned char *destination;

    if (pointer == NULL) return uefi_wolfssl_malloc(size, heap, type);
    if (size == 0) {
        uefi_wolfssl_free(pointer, heap, type);
        return NULL;
    }

    old_allocation = (uefi_wolfssl_allocation *)pointer - 1;
    new_pointer = uefi_wolfssl_malloc(size, heap, type);
    if (new_pointer == NULL) return NULL;

    copy_size = old_allocation->size < size ? old_allocation->size : size;
    source = (unsigned char *)pointer;
    destination = (unsigned char *)new_pointer;
    while (copy_size-- > 0) *destination++ = *source++;

    uefi_wolfssl_free(pointer, heap, type);
    return new_pointer;
}

int uefi_wolfssl_rng(unsigned char *output, unsigned int size)
{
    if (size == 0) return 0;
    return uefi_browser_fill_random(output, (size_t)size);
}

time_t uefi_wolfssl_time(time_t *timer)
{
    int64_t now = uefi_browser_time_unix();
    time_t result;

    if (now < 0) return (time_t)-1;
    result = (time_t)now;
    if (timer != NULL) *timer = result;
    return result;
}

static int64_t days_from_civil(int64_t year, unsigned int month, unsigned int day)
{
    int64_t era;
    unsigned int year_of_era;
    unsigned int day_of_year;
    unsigned int day_of_era;

    year -= month <= 2U;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = (unsigned int)(year - era * 400);
    day_of_year = (153U * (month + (month > 2U ? (unsigned int)-3 : 9U)) + 2U) / 5U
                  + day - 1U;
    day_of_era = year_of_era * 365U + year_of_era / 4U
                 - year_of_era / 100U + day_of_year;
    return era * 146097 + (int64_t)day_of_era - 719468;
}

static void civil_from_days(int64_t days, int64_t *year,
                            unsigned int *month, unsigned int *day)
{
    int64_t era;
    unsigned int day_of_era;
    unsigned int year_of_era;
    unsigned int day_of_year;
    unsigned int month_prime;

    days += 719468;
    era = (days >= 0 ? days : days - 146096) / 146097;
    day_of_era = (unsigned int)(days - era * 146097);
    year_of_era = (day_of_era - day_of_era / 1460U
                   + day_of_era / 36524U - day_of_era / 146096U) / 365U;
    *year = (int64_t)year_of_era + era * 400;
    day_of_year = day_of_era - (365U * year_of_era + year_of_era / 4U
                    - year_of_era / 100U);
    month_prime = (5U * day_of_year + 2U) / 153U;
    *day = day_of_year - (153U * month_prime + 2U) / 5U + 1U;
    *month = month_prime + (month_prime < 10U ? 3U : (unsigned int)-9);
    *year += *month <= 2U;
}

/* wolfSSL's XGMTIME hook. This avoids a host gmtime_r dependency entirely. */
struct tm *uefi_wolfssl_gmtime(const time_t *timer, struct tm *result)
{
    int64_t seconds;
    int64_t days;
    int64_t remainder;
    int64_t year;
    int64_t first_day;
    unsigned int month;
    unsigned int day;
    int weekday;

    if (timer == NULL || result == NULL) return NULL;
    seconds = (int64_t)*timer;
    days = seconds / 86400;
    remainder = seconds % 86400;
    if (remainder < 0) {
        remainder += 86400;
        --days;
    }

    civil_from_days(days, &year, &month, &day);
    if (year - 1900 < INT_MIN || year - 1900 > INT_MAX) return NULL;

    result->tm_sec = (int)(remainder % 60);
    result->tm_min = (int)((remainder / 60) % 60);
    result->tm_hour = (int)(remainder / 3600);
    result->tm_mday = (int)day;
    result->tm_mon = (int)month - 1;
    result->tm_year = (int)(year - 1900);
    result->tm_isdst = 0;

    weekday = (int)((days + 4) % 7);
    if (weekday < 0) weekday += 7;
    result->tm_wday = weekday;

    first_day = days_from_civil(year, 1U, 1U);
    result->tm_yday = (int)(days - first_day);
    return result;
}
