/*
 * UEFI platform hooks for wolfSSL/wolfCrypt.
 * Entropy and time come only from EFI_RNG_PROTOCOL and UEFI Runtime Services.
 */
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

extern void *uefi_browser_alloc(size_t size);
extern void uefi_browser_free(void *pointer);
extern int uefi_browser_fill_random(unsigned char *output, size_t output_size);
extern int64_t uefi_browser_time_unix(void);

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
