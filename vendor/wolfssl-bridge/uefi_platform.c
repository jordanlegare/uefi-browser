/*
 * UEFI platform hooks for wolfSSL/wolfCrypt.
 * Entropy and time come only from EFI_RNG_PROTOCOL and UEFI Runtime Services.
 */
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <wolfssl/wolfcrypt/settings.h>

extern void *uefi_browser_alloc(size_t size);
extern void uefi_browser_free(void *pointer);
extern int uefi_browser_fill_random(unsigned char *output, size_t output_size);
extern int64_t uefi_browser_time_unix(void);

typedef struct {
    size_t size;
} uefi_wolfssl_allocation;

void *uefi_wolfssl_malloc(size_t size, void *heap, int type)
{
    uefi_wolfssl_allocation *allocation;
    (void)heap;
    (void)type;

    if (size > SIZE_MAX - sizeof(*allocation)) return NULL;
    allocation = (uefi_wolfssl_allocation *)uefi_browser_alloc(
        sizeof(*allocation) + (size == 0 ? 1 : size));
    if (allocation == NULL) return NULL;
    allocation->size = size;
    return (void *)(allocation + 1);
}

void uefi_wolfssl_free(void *pointer, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (pointer != NULL) {
        uefi_browser_free((void *)((uefi_wolfssl_allocation *)pointer - 1));
    }
}

void *uefi_wolfssl_realloc(void *pointer, size_t size, void *heap, int type)
{
    uefi_wolfssl_allocation *old_allocation;
    uefi_wolfssl_allocation *new_allocation;
    size_t copy_size;
    unsigned char *source;
    unsigned char *destination;

    if (pointer == NULL) return uefi_wolfssl_malloc(size, heap, type);
    if (size == 0) {
        uefi_wolfssl_free(pointer, heap, type);
        return NULL;
    }

    old_allocation = (uefi_wolfssl_allocation *)pointer - 1;
    {
        void *new_pointer = uefi_wolfssl_malloc(size, heap, type);
        if (new_pointer == NULL) return NULL;
        new_allocation = (uefi_wolfssl_allocation *)new_pointer - 1;
    }

    copy_size = old_allocation->size < size ? old_allocation->size : size;
    source = (unsigned char *)(old_allocation + 1);
    destination = (unsigned char *)(new_allocation + 1);
    while (copy_size-- > 0) *destination++ = *source++;
    uefi_wolfssl_free(pointer, heap, type);
    return (void *)(new_allocation + 1);
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
