/*
 * UEFI Browser Mbed TLS bridge.
 * The upstream library is statically linked; I/O and entropy are callbacks.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
static void uefi_format_key_id(char *output, size_t output_size,
                                const mbedtls_x509_buf *key_id) {
    static const char hex[] = "0123456789abcdef";
    size_t offset = 0;

    if (output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (key_id == NULL || key_id->p == NULL || key_id->len == 0) {
        (void)mbedtls_snprintf(output, output_size, "<none>");
        return;
    }

    for (size_t i = 0; i < key_id->len && offset + 2 < output_size; i++) {
        output[offset++] = hex[key_id->p[i] >> 4];
        output[offset++] = hex[key_id->p[i] & 0x0f];
    }
    output[offset] = '\0';
}

static int uefi_mbedtls_verify_observer(void *ctx, mbedtls_x509_crt *crt,
                                        int depth, uint32_t *flags) {
    uefi_tls_session *session = (uefi_tls_session *)ctx;
    char subject[256];
    char issuer[256];
    char aki[96];
    char message[768];
    uint32_t cert_flags = flags != NULL ? *flags : UINT32_MAX;

    subject[0] = '\0';
    issuer[0] = '\0';
    aki[0] = '\0';

    if (crt != NULL) {
        (void)mbedtls_x509_dn_gets(subject, sizeof(subject), &crt->subject);
        (void)mbedtls_x509_dn_gets(issuer, sizeof(issuer), &crt->issuer);
        uefi_format_key_id(aki, sizeof(aki), &crt->authority_key_id.keyIdentifier);
        (void)mbedtls_snprintf(
            message, sizeof(message),
            "depth=%d flags=0x%08lx subject=%s issuer=%s AKI=%s "
            "not_before=%04d-%02d-%02dT%02d:%02d:%02dZ "
            "not_after=%04d-%02d-%02dT%02d:%02d:%02dZ",
            depth, (unsigned long)cert_flags, subject, issuer, aki,
            crt->valid_from.year, crt->valid_from.mon, crt->valid_from.day,
            crt->valid_from.hour, crt->valid_from.min, crt->valid_from.sec,
            crt->valid_to.year, crt->valid_to.mon, crt->valid_to.day,
            crt->valid_to.hour, crt->valid_to.min, crt->valid_to.sec);
    } else {
        (void)mbedtls_snprintf(message, sizeof(message),
                               "depth=%d flags=0x%08lx certificate=NULL",
                               depth, (unsigned long)cert_flags);
    }

    /* Preserve the certificate's own DN and AKI before formatting lookup results. */
    uefi_browser_tls_debug_log(1, "x509-verify", depth, message);

    /*
     * For each verified chain certificate, find trust-store certificates
     * whose subject DN matches its issuer DN. Also find an identical-subject
     * certificate in the trust store: this reveals whether the chain
     * certificate (for example GTS Root R4) is already available as a
     * potential trust anchor, and whether that stored certificate is
     * self-issued or cross-signed.
     */
    int issuer_dn_candidates = 0;
    int aki_matches = 0;
    int same_subject_candidates = 0;
    if (crt != NULL && session != NULL) {
        for (mbedtls_x509_crt *candidate = &session->roots;
             candidate != NULL && candidate->raw.p != NULL;
             candidate = candidate->next) {
            char candidate_subject[256];
            char candidate_issuer[256];
            char candidate_ski[96];
            char candidate_aki[96];
            (void)mbedtls_x509_dn_gets(candidate_subject, sizeof(candidate_subject),
                                       &candidate->subject);
            if (strcmp(subject, candidate_subject) != 0) {
                continue;
            }
            same_subject_candidates++;
            (void)mbedtls_x509_dn_gets(candidate_issuer, sizeof(candidate_issuer),
                                       &candidate->issuer);
            uefi_format_key_id(candidate_ski, sizeof(candidate_ski),
                               &candidate->subject_key_id);
            uefi_format_key_id(candidate_aki, sizeof(candidate_aki),
                               &candidate->authority_key_id.keyIdentifier);
            (void)mbedtls_snprintf(
                message, sizeof(message),
                "same-subject trust cert subject=%s issuer=%s SKI=%s AKI=%s self-issued=%s",
                candidate_subject, candidate_issuer, candidate_ski, candidate_aki,
                strcmp(candidate_subject, candidate_issuer) == 0 ? "yes" : "no");
            uefi_browser_tls_debug_log(1, "x509-trust-store", depth, message);
        }
    }
    if (crt != NULL && session != NULL) {
        for (mbedtls_x509_crt *root = &session->roots;
             root != NULL && root->raw.p != NULL; root = root->next) {
            char root_subject[256];
            char root_ski[96];
            (void)mbedtls_x509_dn_gets(root_subject, sizeof(root_subject),
                                       &root->subject);
            if (strcmp(issuer, root_subject) != 0) {
                continue;
            }

            issuer_dn_candidates++;
            uefi_format_key_id(root_ski, sizeof(root_ski), &root->subject_key_id);
            int aki_match =
                crt->authority_key_id.keyIdentifier.len != 0 &&
                root->subject_key_id.len == crt->authority_key_id.keyIdentifier.len &&
                memcmp(root->subject_key_id.p,
                       crt->authority_key_id.keyIdentifier.p,
                       root->subject_key_id.len) == 0;
            if (aki_match) {
                aki_matches++;
            }

            (void)mbedtls_snprintf(
                message, sizeof(message),
                "issuer candidate subject=%s SKI=%s child-AKI=%s match=%s",
                root_subject, root_ski, aki, aki_match ? "yes" : "no");
            uefi_browser_tls_debug_log(1, "x509-trust-store", depth, message);
        }
    }

    (void)mbedtls_snprintf(
        message, sizeof(message),
        "issuer lookup: DN candidates=%d AKI/SKI matches=%d same-subject trust certs=%d",
        issuer_dn_candidates, aki_matches, same_subject_candidates);
    uefi_browser_tls_debug_log(1, "x509-trust-store", depth, message);

    /*
     * The Rust callback only copies these lines into its RAM diagnostic ring.
     * Never call UEFI console or runtime services from the verifier callback.
     */
    uefi_browser_tls_log(40, depth);
    uefi_browser_tls_log(41, (int)cert_flags);
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

    /* Report the exact trust input before parsing it. */
    uefi_browser_tls_log(176, (int)ca_pem_len);
    ret = mbedtls_x509_crt_parse(&session->roots, ca_pem, ca_pem_len);
    uefi_browser_tls_log(177, ret);

    /* Count successfully linked certificates, not PEM blocks or parse attempts. */
    int parsed_certificates = 0;
    for (mbedtls_x509_crt *cert = &session->roots;
         cert != NULL && cert->raw.p != NULL;
         cert = cert->next) {
        parsed_certificates++;
    }
    uefi_browser_tls_log(178, parsed_certificates);

    if (ret != 0) {
        uefi_browser_tls_log(4, ret);
        goto fail;
    }
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
    mbedtls_ssl_conf_verify(&session->config, uefi_mbedtls_verify_observer, session);

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
