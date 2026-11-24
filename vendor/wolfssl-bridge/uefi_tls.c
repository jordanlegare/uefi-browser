/*
 * wolfSSL TLS 1.3 client bridge for the UEFI browser.
 * wolfSSL handles TLS/X.509; Rust owns the SNP/smoltcp TCP stream.
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>

typedef int (*uefi_send_cb)(void *, const unsigned char *, size_t);
typedef int (*uefi_recv_cb)(void *, unsigned char *, size_t);
typedef void (*uefi_tls_progress_cb)(int, int, int);

extern time_t uefi_wolfssl_time(time_t *timer);

static int uefi_last_ca_cert_index;
static int64_t uefi_last_time_unix;
static int uefi_last_verify_error;
static int uefi_last_verify_depth;
#define UEFI_MAX_PEER_CHAIN_CERTS 8
#define UEFI_MAX_BAD_CERT_DER_BYTES 16384U

static uefi_tls_progress_cb uefi_progress_callback;
static unsigned int uefi_peer_chain_reported_mask;
static unsigned char uefi_last_bad_cert_der[UEFI_MAX_BAD_CERT_DER_BYTES];
static int uefi_last_bad_cert_der_length;

static unsigned char uefi_last_bad_cert_sha256[32];
static unsigned char uefi_peer_chain_sha1[UEFI_MAX_PEER_CHAIN_CERTS][20];
static unsigned char uefi_peer_chain_present[UEFI_MAX_PEER_CHAIN_CERTS];
static int uefi_peer_chain_count;

int uefi_wolfssl_last_ca_cert_index(void) { return uefi_last_ca_cert_index; }
int64_t uefi_wolfssl_last_time_unix(void) { return uefi_last_time_unix; }
int uefi_wolfssl_last_verify_error(void) { return uefi_last_verify_error; }
int uefi_wolfssl_last_verify_depth(void) { return uefi_last_verify_depth; }
int uefi_wolfssl_peer_chain_count(void) { return uefi_peer_chain_count; }
int uefi_wolfssl_bad_cert_der_length(void)
{
    return uefi_last_bad_cert_der_length;
}
int uefi_wolfssl_copy_bad_cert_der(unsigned char *out, size_t capacity)
{
    if (out == NULL || uefi_last_bad_cert_der_length <= 0 ||
        capacity < (size_t)uefi_last_bad_cert_der_length) return -1;
    memcpy(out, uefi_last_bad_cert_der, (size_t)uefi_last_bad_cert_der_length);
    return uefi_last_bad_cert_der_length;
}
int uefi_wolfssl_copy_peer_chain_sha1(int depth, unsigned char *out,
                                      size_t capacity)
{
    if (depth < 0 || depth >= UEFI_MAX_PEER_CHAIN_CERTS ||
        !uefi_peer_chain_present[depth] || out == NULL || capacity < 20U) {
        return -1;
    }
    memcpy(out, uefi_peer_chain_sha1[depth], 20U);
    return 20;
}
int uefi_wolfssl_copy_bad_cert_sha256(unsigned char *out, size_t capacity)
{
    if (out == NULL || capacity < sizeof(uefi_last_bad_cert_sha256)) return -1;
    memcpy(out, uefi_last_bad_cert_sha256, sizeof(uefi_last_bad_cert_sha256));
    return (int)sizeof(uefi_last_bad_cert_sha256);
}

static void uefi_record_peer_certificate(WOLFSSL_X509_STORE_CTX *store)
{
    WOLFSSL_X509 *certificate;
    const unsigned char *der;
    int der_length = 0;
    int depth;
    wc_Sha sha;

    if (store == NULL) return;
    depth = wolfSSL_X509_STORE_CTX_get_error_depth(store);
    if (depth < 0 || depth >= UEFI_MAX_PEER_CHAIN_CERTS) return;

    certificate = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    if (certificate == NULL) return;
    der = wolfSSL_X509_get_der(certificate, &der_length);
    if (der == NULL || der_length <= 0) return;

    if (wc_InitSha(&sha) != 0) return;
    if (wc_ShaUpdate(&sha, der, (word32)der_length) == 0 &&
        wc_ShaFinal(&sha, uefi_peer_chain_sha1[depth]) == 0) {
        uefi_peer_chain_present[depth] = 1U;
        if (uefi_peer_chain_count < depth + 1) {
            uefi_peer_chain_count = depth + 1;
        }
    }
    wc_ShaFree(&sha);
}

static int uefi_verify_diagnostic_callback(int preverify_ok,
                                           WOLFSSL_X509_STORE_CTX *store)
{
    /* Collect path fingerprints without changing wolfSSL's verification result. */
    uefi_record_peer_certificate(store);

    if (preverify_ok && store != NULL) {
        int depth = wolfSSL_X509_STORE_CTX_get_error_depth(store);
        if (depth >= 0 && depth < UEFI_MAX_PEER_CHAIN_CERTS &&
            (uefi_peer_chain_reported_mask & (1U << (unsigned int)depth)) == 0U) {
            uefi_peer_chain_reported_mask |= (1U << (unsigned int)depth);
            if (uefi_progress_callback != NULL) uefi_progress_callback(1, depth, 0);
        }
    }

    if (!preverify_ok && store != NULL && uefi_last_verify_error == 0) {
        WOLFSSL_X509 *certificate;
        const unsigned char *der;
        int der_length = 0;
        wc_Sha256 sha256;

        /* Record the exact certificate wolfSSL rejected; never alter the result. */
        uefi_last_verify_error = wolfSSL_X509_STORE_CTX_get_error(store);
        uefi_last_verify_depth = wolfSSL_X509_STORE_CTX_get_error_depth(store);
        certificate = wolfSSL_X509_STORE_CTX_get_current_cert(store);
        if (certificate != NULL) {
            der = wolfSSL_X509_get_der(certificate, &der_length);
            if (der != NULL && der_length > 0 &&
                (unsigned int)der_length <= UEFI_MAX_BAD_CERT_DER_BYTES) {
                memcpy(uefi_last_bad_cert_der, der, (size_t)der_length);
                uefi_last_bad_cert_der_length = der_length;
            }
            if (der != NULL && der_length > 0 && wc_InitSha256(&sha256) == 0) {
                if (wc_Sha256Update(&sha256, der, (word32)der_length) == 0) {
                    (void)wc_Sha256Final(&sha256, uefi_last_bad_cert_sha256);
                }
                wc_Sha256Free(&sha256);
            }
        }
        if (uefi_progress_callback != NULL) {
            uefi_progress_callback(2, uefi_last_verify_depth, uefi_last_verify_error);
        }
    }
    return preverify_ok;
}

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
    uefi_tls_progress_cb progress_cb, uefi_wolfssl_session **output)
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
    uefi_last_ca_cert_index = 0;
    uefi_last_time_unix = (int64_t)uefi_wolfssl_time(NULL);
    uefi_last_verify_error = 0;
    uefi_last_verify_depth = -1;
    memset(uefi_last_bad_cert_sha256, 0, sizeof(uefi_last_bad_cert_sha256));
    memset(uefi_peer_chain_sha1, 0, sizeof(uefi_peer_chain_sha1));
    memset(uefi_peer_chain_present, 0, sizeof(uefi_peer_chain_present));
    uefi_peer_chain_count = 0;
    uefi_peer_chain_reported_mask = 0U;
    uefi_last_bad_cert_der_length = 0;
    uefi_progress_callback = progress_cb;

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
    wolfSSL_CTX_set_verify(session->context, WOLFSSL_VERIFY_PEER, uefi_verify_diagnostic_callback);
    /*
     * Load roots individually so ASN_AFTER_DATE_E can be tied to the exact
     * certificate position in the filtered bundle. Each successful call adds
     * a root to the same wolfSSL certificate store.
     */
    {
        static const char begin_marker[] = "-----BEGIN CERTIFICATE-----";
        static const char end_marker[] = "-----END CERTIFICATE-----";
        const char *cursor = (const char *)ca_pem;
        const char *limit = cursor + ca_pem_len;
        int cert_index = 0;

        while (cursor < limit) {
            const char *begin = strstr(cursor, begin_marker);
            const char *end;
            const char *after_end;
            size_t pem_len;

            if (begin == NULL || begin >= limit) break;
            end = strstr(begin, end_marker);
            if (end == NULL || end >= limit) {
                ret = -4;
                goto fail;
            }
            after_end = end + sizeof(end_marker) - 1U;
            if (after_end > limit) {
                ret = -4;
                goto fail;
            }
            pem_len = (size_t)(after_end - begin);
            ++cert_index;
            uefi_last_ca_cert_index = cert_index;
            ret = wolfSSL_CTX_load_verify_buffer(
                session->context, (const unsigned char *)begin,
                (long)pem_len, WOLFSSL_FILETYPE_PEM);
            if (ret != WOLFSSL_SUCCESS) goto fail;
            cursor = after_end;
        }
        if (cert_index == 0) {
            ret = -4;
            goto fail;
        }
        uefi_last_ca_cert_index = 0;
    }

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
    uefi_progress_callback = NULL;
    if (session->ssl != NULL) wolfSSL_free(session->ssl);
    if (session->context != NULL) wolfSSL_CTX_free(session->context);
    uefi_wolfssl_free(session, NULL, 0);
}
