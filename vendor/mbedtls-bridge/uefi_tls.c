/*
 * UEFI Browser Mbed TLS bridge.
 * The upstream library is statically linked; I/O and entropy are callbacks.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

typedef int (*uefi_send_cb)(void *, const unsigned char *, size_t);
typedef int (*uefi_recv_cb)(void *, unsigned char *, size_t);
typedef int (*uefi_rng_cb)(void *, unsigned char *, size_t);

typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_x509_crt roots;
    void *io_context;
    uefi_send_cb send_cb;
    uefi_recv_cb recv_cb;
} uefi_tls_session;

static int bio_send(void *ctx, const unsigned char *data, size_t length) {
    uefi_tls_session *session = (uefi_tls_session *)ctx;
    return session->send_cb(session->io_context, data, length);
}

static int bio_recv(void *ctx, unsigned char *data, size_t length) {
    uefi_tls_session *session = (uefi_tls_session *)ctx;
    return session->recv_cb(session->io_context, data, length);
}

int uefi_mbedtls_client_new(
    const unsigned char *hostname, size_t hostname_len,
    const unsigned char *ca_pem, size_t ca_pem_len,
    void *io_context, uefi_send_cb send_cb, uefi_recv_cb recv_cb,
    void *random_context, uefi_rng_cb random_cb, uefi_tls_session **output
) {
    (void)hostname_len;
    if (!hostname || !ca_pem || !output || !send_cb || !recv_cb || !random_cb) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    uefi_tls_session *session = (uefi_tls_session *)calloc(1, sizeof(*session));
    if (!session) return MBEDTLS_ERR_SSL_ALLOC_FAILED;

    session->io_context = io_context;
    session->send_cb = send_cb;
    session->recv_cb = recv_cb;

    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->config);
    mbedtls_x509_crt_init(&session->roots);

    int ret = mbedtls_x509_crt_parse(&session->roots, ca_pem, ca_pem_len);
    if (ret != 0) goto fail;

    ret = mbedtls_ssl_config_defaults(
        &session->config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    if (ret != 0) goto fail;

    mbedtls_ssl_conf_authmode(&session->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&session->config, &session->roots, NULL);
    mbedtls_ssl_conf_rng(&session->config, random_cb, random_context);

    ret = mbedtls_ssl_setup(&session->ssl, &session->config);
    if (ret != 0) goto fail;

    ret = mbedtls_ssl_set_hostname(&session->ssl, (const char *)hostname);
    if (ret != 0) goto fail;

    mbedtls_ssl_set_bio(&session->ssl, session, bio_send, bio_recv, NULL);
    *output = session;
    return 0;

fail:
    mbedtls_x509_crt_free(&session->roots);
    mbedtls_ssl_config_free(&session->config);
    mbedtls_ssl_free(&session->ssl);
    free(session);
    return ret;
}

int uefi_mbedtls_handshake(uefi_tls_session *session) {
    if (!session) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    int ret;
    do {
        ret = mbedtls_ssl_handshake(&session->ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret != 0) return ret;
    return mbedtls_ssl_get_verify_result(&session->ssl) == 0
        ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

int uefi_mbedtls_read(uefi_tls_session *session, unsigned char *output, size_t capacity) {
    if (!session || !output) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_ssl_read(&session->ssl, output, capacity);
}

int uefi_mbedtls_write(uefi_tls_session *session, const unsigned char *input, size_t length) {
    if (!session || !input) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_ssl_write(&session->ssl, input, length);
}

uint32_t uefi_mbedtls_verify_result(uefi_tls_session *session) {
    if (!session) return UINT32_MAX;
    return mbedtls_ssl_get_verify_result(&session->ssl);
}

void uefi_mbedtls_client_free(uefi_tls_session *session) {
    if (!session) return;
    (void)mbedtls_ssl_close_notify(&session->ssl);
    mbedtls_x509_crt_free(&session->roots);
    mbedtls_ssl_config_free(&session->config);
    mbedtls_ssl_free(&session->ssl);
    free(session);
}
