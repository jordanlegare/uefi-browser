/*
 * UEFI Browser Mbed TLS bridge.
 * The upstream library is statically linked; I/O and entropy are callbacks.
 */

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include <psa/crypto.h>

typedef int (*uefi_send_cb)(void *, const unsigned char *, size_t);
typedef int (*uefi_recv_cb)(void *, unsigned char *, size_t);
extern void uefi_browser_tls_log(int stage, int detail);
extern void uefi_browser_tls_debug_log(int level, const char *file, int line, const char *message);

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
    uefi_browser_tls_log(30, (int)length);
    int ret = session->send_cb(session->io_context, data, length);
    uefi_browser_tls_log(31, ret);
    return ret;
}

static int bio_recv(void *ctx, unsigned char *data, size_t length) {
    uefi_tls_session *session = (uefi_tls_session *)ctx;
    uefi_browser_tls_log(32, (int)length);
    int ret = session->recv_cb(session->io_context, data, length);
    uefi_browser_tls_log(33, ret);
    return ret;
}

/* Mbed TLS diagnostics are routed to the firmware console, never libc/stdout. */
static void uefi_mbedtls_debug(void *ctx, int level, const char *file,
                               int line, const char *message) {
    (void)ctx;

    /*
     * Mbed TLS invokes this callback synchronously from its handshake path.
     * The Rust callback only copies the message into a RAM ring buffer; it
     * must not invoke UEFI console services while Mbed TLS is on the stack.
     */
    if (level <= 3) {
        uefi_browser_tls_debug_log(level, file, line, message);
    }
}

/*
 * Observe the verifier's per-certificate result without changing its flags.
 * Returning zero means this observer itself did not reject the certificate;
 * MBEDTLS_SSL_VERIFY_REQUIRED and the original verification flags remain in
 * force and are still checked by Mbed TLS.
 */
static int uefi_mbedtls_verify_observer(void *ctx, mbedtls_x509_crt *crt,
                                        int depth, uint32_t *flags) {
    (void)ctx;
    (void)crt;
    uefi_browser_tls_log(40, depth);
    uefi_browser_tls_log(41, flags != NULL ? (int)*flags : -1);
    return 0;
}

int uefi_mbedtls_client_new(
    const unsigned char *hostname, size_t hostname_len,
    const unsigned char *ca_pem, size_t ca_pem_len,
    void *io_context, uefi_send_cb send_cb, uefi_recv_cb recv_cb,
    uefi_tls_session **output
) {
    (void)hostname_len;
    if (!hostname || !ca_pem || !output || !send_cb || !recv_cb) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    uefi_tls_session *session = (uefi_tls_session *)mbedtls_calloc(1, sizeof(*session));
    if (!session) return MBEDTLS_ERR_SSL_ALLOC_FAILED;

    session->io_context = io_context;
    session->send_cb = send_cb;
    session->recv_cb = recv_cb;

    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->config);
    mbedtls_x509_crt_init(&session->roots);

    static int psa_initialized = 0;
    int ret = 0;
    if (!psa_initialized) {
        uefi_browser_tls_log(1, 0);
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS) {
            ret = (int)status;
            uefi_browser_tls_log(2, ret);
            goto fail;
        }
        psa_initialized = 1;
        uefi_browser_tls_log(2, 0);
    }

    uefi_browser_tls_log(3, (int)ca_pem_len);
    ret = mbedtls_x509_crt_parse(&session->roots, ca_pem, ca_pem_len);
    if (ret != 0) { uefi_browser_tls_log(4, ret); goto fail; }
    uefi_browser_tls_log(4, ret);

    uefi_browser_tls_log(5, 0);
    ret = mbedtls_ssl_config_defaults(
        &session->config,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    if (ret != 0) { uefi_browser_tls_log(6, ret); goto fail; }
    uefi_browser_tls_log(6, ret);

#if defined(MBEDTLS_DEBUG_C)
    /* Level 3 includes handshake and record-layer progress without full dumps. */
    mbedtls_debug_set_threshold(3);
    mbedtls_ssl_conf_dbg(&session->config, uefi_mbedtls_debug, NULL);
#endif
    mbedtls_ssl_conf_authmode(&session->config, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&session->config, &session->roots, NULL);
    mbedtls_ssl_conf_verify(&session->config, uefi_mbedtls_verify_observer, NULL);

    uefi_browser_tls_log(7, 0);
    ret = mbedtls_ssl_setup(&session->ssl, &session->config);
    if (ret != 0) { uefi_browser_tls_log(8, ret); goto fail; }
    uefi_browser_tls_log(8, ret);

    uefi_browser_tls_log(9, 0);
    ret = mbedtls_ssl_set_hostname(&session->ssl, (const char *)hostname);
    if (ret != 0) { uefi_browser_tls_log(9, ret); goto fail; }

    mbedtls_ssl_set_bio(&session->ssl, session, bio_send, bio_recv, NULL);
    uefi_browser_tls_log(10, 0);
    *output = session;
    return 0;

fail:
    mbedtls_x509_crt_free(&session->roots);
    mbedtls_ssl_config_free(&session->config);
    mbedtls_ssl_free(&session->ssl);
    mbedtls_free(session);
    return ret;
}

int uefi_mbedtls_handshake_state(uefi_tls_session *session) {
    if (!session) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return (int) session->ssl.MBEDTLS_PRIVATE(state);
}

/*
 * Execute exactly one Mbed TLS handshake state-machine step. Returning to
 * Rust between steps lets the firmware print the RAM-buffered debug tail
 * without invoking UEFI console services from inside Mbed TLS callbacks.
 */
int uefi_mbedtls_handshake_step(uefi_tls_session *session,
                                int *complete, int *state) {
    if (!session || !complete || !state) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    int ret = mbedtls_ssl_handshake_step(&session->ssl);
    *complete = mbedtls_ssl_is_handshake_over(&session->ssl);
    *state = (int) session->ssl.MBEDTLS_PRIVATE(state);
    return ret;
}

int uefi_mbedtls_read(uefi_tls_session *session, unsigned char *output, size_t capacity) {
    if (!session || (!output && capacity != 0)) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    int ret = mbedtls_ssl_read(&session->ssl, output, capacity);
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return 0;
    }
    return ret;
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
    mbedtls_free(session);
}

/* Force the linker to include this translation unit and its Mbed TLS references. */
int uefi_mbedtls_link_anchor(void) { return 0; }
