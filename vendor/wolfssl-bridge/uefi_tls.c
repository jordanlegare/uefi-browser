/*
 * wolfSSL TLS 1.3 client bridge for the UEFI browser.
 * wolfSSL handles TLS/X.509; Rust owns the SNP/smoltcp TCP stream.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

typedef int (*uefi_send_cb)(void *, const unsigned char *, size_t);
typedef int (*uefi_recv_cb)(void *, unsigned char *, size_t);

typedef struct {
    WOLFSSL_CTX *context;
    WOLFSSL *ssl;
    void *io_context;
    uefi_send_cb send_cb;
    uefi_recv_cb recv_cb;
    int handshake_complete;
} uefi_wolfssl_session;

extern void *uefi_wolfssl_malloc(size_t size, void *heap, int type);
extern void uefi_wolfssl_free(void *pointer, void *heap, int type);

static int is_ipv4_literal(const char *hostname)
{
    unsigned int octet = 0;
    unsigned int digits = 0;
    unsigned int dots = 0;
    const unsigned char *cursor = (const unsigned char *)hostname;

    if (hostname == NULL || *hostname == '\0') return 0;
    for (;;) {
        if (*cursor >= '0' && *cursor <= '9') {
            octet = octet * 10U + (unsigned int)(*cursor - '0');
            if (++digits > 3 || octet > 255U) return 0;
        } else if (*cursor == '.' || *cursor == '\0') {
            if (digits == 0) return 0;
            ++dots;
            if (*cursor == '\0') break;
            octet = 0;
            digits = 0;
        } else {
            return 0;
        }
        ++cursor;
    }
    return dots == 4;
}

static int bio_send(WOLFSSL *ssl, char *data, int length, void *context)
{
    uefi_wolfssl_session *session = (uefi_wolfssl_session *)context;
    int result;
    (void)ssl;

    if (session == NULL || session->send_cb == NULL || data == NULL || length < 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    result = session->send_cb(session->io_context,
                              (const unsigned char *)data, (size_t)length);
    return result < 0 ? WOLFSSL_CBIO_ERR_GENERAL : result;
}

static int bio_recv(WOLFSSL *ssl, char *data, int length, void *context)
{
    uefi_wolfssl_session *session = (uefi_wolfssl_session *)context;
    int result;
    (void)ssl;

    if (session == NULL || session->recv_cb == NULL || data == NULL || length < 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    result = session->recv_cb(session->io_context,
                              (unsigned char *)data, (size_t)length);
    return result < 0 ? WOLFSSL_CBIO_ERR_GENERAL : result;
}

int uefi_wolfssl_client_new(
    const unsigned char *hostname, size_t hostname_len,
    const unsigned char *ca_pem, size_t ca_pem_len,
    void *io_context, uefi_send_cb send_cb, uefi_recv_cb recv_cb,
    uefi_wolfssl_session **output)
{
    static int wolfssl_initialized;
    uefi_wolfssl_session *session;
    int ret;

    if (hostname == NULL || hostname_len == 0 || hostname_len > USHRT_MAX ||
        ca_pem == NULL || ca_pem_len == 0 || ca_pem_len > (size_t)LONG_MAX ||
        io_context == NULL || send_cb == NULL || recv_cb == NULL || output == NULL) {
        return -1;
    }
    *output = NULL;

    if (!wolfssl_initialized) {
        ret = wolfSSL_Init();
        if (ret != WOLFSSL_SUCCESS) return ret == 0 ? -1 : ret;
        wolfssl_initialized = 1;
    }

    session = (uefi_wolfssl_session *)uefi_wolfssl_malloc(sizeof(*session), NULL, 0);
    if (session == NULL) return -1;
    session->context = NULL;
    session->ssl = NULL;
    session->io_context = io_context;
    session->send_cb = send_cb;
    session->recv_cb = recv_cb;
    session->handshake_complete = 0;

    session->context = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (session->context == NULL) {
        ret = -2;
        goto fail;
    }

    /* Peer verification is mandatory. No VERIFY_NONE mode is exposed. */
    wolfSSL_CTX_set_verify(session->context, WOLFSSL_VERIFY_PEER, NULL);
    ret = wolfSSL_CTX_load_verify_buffer(
        session->context, ca_pem, (long)ca_pem_len, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) goto fail;

    wolfSSL_CTX_SetIORecv(session->context, bio_recv);
    wolfSSL_CTX_SetIOSend(session->context, bio_send);

    session->ssl = wolfSSL_new(session->context);
    if (session->ssl == NULL) {
        ret = -3;
        goto fail;
    }

    wolfSSL_SetIOReadCtx(session->ssl, session);
    wolfSSL_SetIOWriteCtx(session->ssl, session);

    /* DNS names use SNI plus hostname validation; IP literals use IP SAN validation. */
    if (is_ipv4_literal((const char *)hostname)) {
        ret = wolfSSL_check_ip_address(session->ssl, (const char *)hostname);
    } else {
        ret = wolfSSL_UseSNI(session->ssl, WOLFSSL_SNI_HOST_NAME,
                             hostname, (unsigned short)hostname_len);
        if (ret != WOLFSSL_SUCCESS) goto fail;
        ret = wolfSSL_check_domain_name(session->ssl, (const char *)hostname);
    }
    if (ret != WOLFSSL_SUCCESS) goto fail;

    *output = session;
    return 0;

fail:
    if (session->ssl != NULL) wolfSSL_free(session->ssl);
    if (session->context != NULL) wolfSSL_CTX_free(session->context);
    uefi_wolfssl_free(session, NULL, 0);
    return ret == 0 ? -4 : ret;
}

int uefi_wolfssl_handshake(uefi_wolfssl_session *session)
{
    int ret;
    int error;

    if (session == NULL || session->ssl == NULL) return -1;
    ret = wolfSSL_connect(session->ssl);
    if (ret == WOLFSSL_SUCCESS) {
        /* VERIFY_PEER makes wolfSSL_connect fail unless chain and host checks pass. */
        session->handshake_complete = 1;
        return 0;
    }
    error = wolfSSL_get_error(session->ssl, ret);
    return error == 0 ? -1 : -error;
}

int uefi_wolfssl_read(uefi_wolfssl_session *session,
                      unsigned char *output, size_t capacity)
{
    int ret;
    int error;

    if (session == NULL || session->ssl == NULL ||
        (output == NULL && capacity != 0) || capacity > INT_MAX) return -1;
    if (capacity == 0) return 0;

    ret = wolfSSL_read(session->ssl, output, (int)capacity);
    if (ret >= 0) return ret;
    error = wolfSSL_get_error(session->ssl, ret);
    return error == 0 ? -1 : -error;
}

int uefi_wolfssl_write(uefi_wolfssl_session *session,
                       const unsigned char *input, size_t length)
{
    int ret;
    int error;

    if (session == NULL || session->ssl == NULL ||
        (input == NULL && length != 0) || length > INT_MAX) return -1;
    if (length == 0) return 0;

    ret = wolfSSL_write(session->ssl, input, (int)length);
    if (ret > 0) return ret;
    error = wolfSSL_get_error(session->ssl, ret);
    return error == 0 ? -1 : -error;
}

uint32_t uefi_wolfssl_verify_result(uefi_wolfssl_session *session)
{
    if (session == NULL || session->ssl == NULL || !session->handshake_complete) {
        return UINT32_MAX;
    }
    /* A completed TLS 1.3 connect is only possible after VERIFY_PEER succeeds. */
    return 0U;
}

void uefi_wolfssl_client_free(uefi_wolfssl_session *session)
{
    if (session == NULL) return;
    if (session->ssl != NULL) wolfSSL_free(session->ssl);
    if (session->context != NULL) wolfSSL_CTX_free(session->context);
    uefi_wolfssl_free(session, NULL, 0);
}
