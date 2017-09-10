#include <string.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>

#define MBEDTLS_ERROR_C
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>
#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

#include "babeld.h"
#include "util.h"
#include "net.h"
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "dtls.h"

const char *dtls_cert_file = NULL,
    *dtls_prvtkey_file = NULL,
    *dtls_cacert_file = NULL,
    *dtls_prvtkey_password = NULL;

static void
print_mbedtls_err(const char *func, int rc)
{
    static char buf[128];
    mbedtls_strerror(rc, buf, sizeof(buf));
    fprintf(stderr, "%s %#x: %s\n", func, rc, buf);
}

#ifdef MBEDTLS_DEBUG_C
static void
ssl_conf_dbg(void *ctx, int dbg_lvl, const char *file, int line,
             const char *msg)
{
    ((void)ctx);
    ((void)dbg_lvl);
    fprintf(stderr, "mbedtls %s:%d %s\n", file, line, msg);
}
#endif

static mbedtls_ssl_cookie_ctx dtls_cookie_ctx;
static mbedtls_entropy_context dtls_entropy;
static mbedtls_ctr_drbg_context dtls_ctr_drbg;

static mbedtls_ssl_config dtls_server_conf;
static mbedtls_ssl_config dtls_client_conf;
static mbedtls_x509_crt dtls_srvcert;
static mbedtls_pk_context dtls_pkey;
#ifdef MBEDTLS_SSL_CACHE_C
static mbedtls_ssl_cache_context dtls_cache;
#endif

/* BIO */
static unsigned char *dtls_buffer;
static size_t dtls_buflen;

static int dtls_cb_send(void *ctx, const unsigned char *buf, size_t len);
static int dtls_cb_recv(void *ctx, unsigned char *buf, size_t len);

static void dtls_cb_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms);
static int dtls_cb_get_timer(void *ctx);

int
dtls_init(void)
{
    int rc;

    mbedtls_ssl_config_init(&dtls_server_conf);
    mbedtls_ssl_config_init(&dtls_client_conf);
    mbedtls_ssl_cookie_init(&dtls_cookie_ctx);
#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_init(&dtls_cache);
#endif
    mbedtls_x509_crt_init(&dtls_srvcert);
    mbedtls_pk_init(&dtls_pkey);
    mbedtls_entropy_init(&dtls_entropy);
    mbedtls_ctr_drbg_init(&dtls_ctr_drbg);

#ifndef USE_MBEDTLS_TEST_CERTS
    rc = mbedtls_x509_crt_parse_file(&dtls_srvcert, dtls_cert_file);
    if(rc) {
        print_mbedtls_err("mbedtls_x509_crt_parse_file cert_file", rc);
        goto fail;
    }

    if(dtls_cacert_file) {
        rc = mbedtls_x509_crt_parse_file(&dtls_srvcert, dtls_cacert_file);
        if(rc) {
            print_mbedtls_err("mbedtls_x509_crt_parse cacert_file", rc);
            goto fail;
        }
    } else {
        fprintf(stderr, "No CA certificate was given.\n");
    }

    /* FIXME: ask user for password? */
    rc = mbedtls_pk_parse_keyfile(&dtls_pkey, dtls_prvtkey_file,
                                  dtls_prvtkey_password);
    if(rc) {
        print_mbedtls_err("mbedtls_pk_parse_keyfile", rc);
        goto fail;
    }
#else
    rc = mbedtls_x509_crt_parse(&dtls_srvcert,
                                (const unsigned char *)mbedtls_test_srv_crt,
                                mbedtls_test_srv_crt_len);
    if(rc) {
        print_mbedtls_err("mbedtls_x509_crt_parse srv_crt", rc);
        goto fail;
    }

    rc = mbedtls_x509_crt_parse(&dtls_srvcert,
                                (const unsigned char *)mbedtls_test_cas_pem,
                                mbedtls_test_cas_pem_len);
    if(rc) {
        print_mbedtls_err("mbedtls_x509_crt_parse cas_pem", rc);
        goto fail;
    }

    rc = mbedtls_pk_parse_key(&dtls_pkey,
                              (const unsigned char *)mbedtls_test_srv_key,
                              mbedtls_test_srv_key_len,
                              NULL, 0);
    if(rc) {
        print_mbedtls_err("mbedtls_pk_parse_key", rc);
        goto fail;
    }
#endif

    rc = mbedtls_ctr_drbg_seed(&dtls_ctr_drbg, mbedtls_entropy_func,
                               &dtls_entropy, NULL, 0);
    if(rc) {
        print_mbedtls_err("mbedtls_ctr_drbg_seed", rc);
        goto fail;
    }

    rc = mbedtls_ssl_config_defaults(&dtls_server_conf,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_config_defaults server", rc);
        goto fail;
    }

    rc = mbedtls_ssl_config_defaults(&dtls_client_conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_config_defaults client", rc);
        goto fail;
    }

    mbedtls_ssl_conf_rng(&dtls_server_conf, mbedtls_ctr_drbg_random,
                         &dtls_ctr_drbg);
    mbedtls_ssl_conf_rng(&dtls_client_conf, mbedtls_ctr_drbg_random,
                         &dtls_ctr_drbg);

#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_conf_session_cache(&dtls_server_conf, &dtls_cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&dtls_server_conf, dtls_srvcert.next, NULL);
    rc = mbedtls_ssl_conf_own_cert(&dtls_server_conf, &dtls_srvcert, &dtls_pkey);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_conf_own_cert", rc);
        goto fail;
    }

#ifdef USE_MBEDTLS_TEST_CERTS
    mbedtls_ssl_conf_authmode(&dtls_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#else
    mbedtls_ssl_conf_authmode(&dtls_client_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
    mbedtls_ssl_conf_ca_chain(&dtls_client_conf, dtls_srvcert.next, NULL);
    mbedtls_ssl_conf_rng(&dtls_client_conf, mbedtls_ctr_drbg_random, &dtls_ctr_drbg);

    rc = mbedtls_ssl_cookie_setup(&dtls_cookie_ctx,
                                  mbedtls_ctr_drbg_random, &dtls_ctr_drbg);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_cookie_setup", rc);
        goto fail;
    }

    mbedtls_ssl_conf_dtls_cookies(&dtls_server_conf, mbedtls_ssl_cookie_write,
                                  mbedtls_ssl_cookie_check,
                                  &dtls_cookie_ctx);

#ifdef MBEDTLS_DEBUG_C
    mbedtls_ssl_conf_dbg(&dtls_server_conf, ssl_conf_dbg, NULL);
    mbedtls_ssl_conf_dbg(&dtls_client_conf, ssl_conf_dbg, NULL);
#endif

    dtls_buflen = 8192;
    dtls_buffer = malloc(dtls_buflen);
    if(!dtls_buffer) {
        perror("malloc(dtls_buffer)");
        rc = -1;
        goto fail;
    }

 fail:
    return rc;
}

void
dtls_free(void)
{
    mbedtls_x509_crt_free(&dtls_srvcert);
    mbedtls_pk_free(&dtls_pkey);

    mbedtls_ssl_config_free(&dtls_server_conf);
    mbedtls_ssl_config_free(&dtls_client_conf);
    mbedtls_ssl_cookie_free(&dtls_cookie_ctx);
#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_free(&dtls_cache);
#endif
    mbedtls_ctr_drbg_free(&dtls_ctr_drbg);
    mbedtls_entropy_free(&dtls_entropy);

    free(dtls_buffer);
}

static int
dtls_setup_server(struct neighbour *neigh)
{
    int rc;

    rc = mbedtls_ssl_setup(&neigh->buf.dtls->ssl, &dtls_server_conf);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_setup", rc);
        return rc;
    }

    rc = mbedtls_ssl_set_client_transport_id(&neigh->buf.dtls->ssl,
                                             neigh->address,
                                             sizeof(neigh->address));
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_set_client_transport_id", rc);
        return rc;
    }

    return 0;
}

static int
dtls_setup_client(struct neighbour *neigh)
{
    int rc;

    rc = mbedtls_ssl_setup(&neigh->buf.dtls->ssl, &dtls_client_conf);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_setup", rc);
        return rc;
    }

    /* FIXME: don't check the Common Name */
#ifdef USE_MBEDTLS_TEST_CERTS
    rc = mbedtls_ssl_set_hostname(&neigh->buf.dtls->ssl, "localhost");
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_set_hostname", rc);
        return rc;
    }
#endif

    return 0;
}

int
dtls_setup_neighbour(struct neighbour *neigh)
{
    struct dtls *dtls;
    int rc;

    /* the router with the lowest address is the server */
    rc = memcmp(neigh->ifp->ll, neigh->address, 16);
    if(rc == 0) {
        fprintf(stderr, "server or client ? router is soliloquising.");
        return 1;
    }

    dtls = calloc(1, sizeof(struct dtls));
    if(dtls == NULL) {
        perror("malloc(neighbour->buf.dtls)");
        return 1;
    }

    mbedtls_ssl_init(&dtls->ssl);
    mbedtls_ssl_set_timer_cb(&dtls->ssl, &neigh,
                             dtls_cb_set_timer,
                             dtls_cb_get_timer);
    mbedtls_ssl_set_bio(&dtls->ssl, neigh,
                        dtls_cb_send, dtls_cb_recv, NULL);

    if(rc < 0) {
        rc = dtls_setup_client(neigh);
    } else if(rc > 0) {
        rc = dtls_setup_server(neigh);
    }
    return rc;
}

int
dtls_handshake(struct neighbour *neigh)
{
    struct dtls *dtls = neigh->buf.dtls;
    int rc;

    if(dtls->ssl.conf->endpoint == MBEDTLS_SSL_IS_SERVER)
        return 0;

    rc = mbedtls_ssl_handshake(&dtls->ssl);
    if(rc == MBEDTLS_ERR_SSL_WANT_READ ||
       rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        rc = 0;
    } else if(rc) {
        print_mbedtls_err("mbedtls_ssl_handshake", rc);
    }
    return rc;
}

void
dtls_flush_neighbour(struct neighbour *neigh)
{
    mbedtls_ssl_free(&neigh->buf.dtls->ssl);
}

static int
dtls_client_verify(mbedtls_ssl_context *ssl)
{
    uint32_t flags;
    flags = mbedtls_ssl_get_verify_result(ssl);
    if(flags != 0) {
        char buf[512];
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), NULL, flags);
        fprintf(stderr, "mbedtls_ssl_get_verify_result: %s\n", buf);
#ifdef USE_MBEDTLS_TEST_CERTS
        return 0;
#else
        return -1;
#endif
    }
    return 0;
}

void
dtls_parse_packet(const unsigned char *from, struct interface *ifp,
                  const unsigned char *packet, int packetlen)
{
    int rc;
    struct neighbour *neigh;
    struct dtls *dtls;

    if(!linklocal(from)) {
        fprintf(stderr, "Received packet from non-local address %s.\n",
                format_address(from));
        return;
    }

    /* allow unencrypted packets */
    if(packet[0] == 42) {
        fprintf(stderr, "dtls_parse_packet: "
                "received unencrypted packet.\n");
        parse_packet(from, ifp, packet, packetlen);
        return;
    }

    neigh = find_neighbour(from, ifp);
    dtls = neigh->buf.dtls;

    /* set the buffers so we can read them in the callbacks */
    dtls->packet = packet;
    dtls->packetlen = packetlen;
    dtls->has_data = 1;

    if(dtls->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        if(dtls->ssl.conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            rc = dtls_client_verify(&dtls->ssl);
            if(rc)
                goto flush;
        }

        rc = mbedtls_ssl_read(&dtls->ssl, dtls_buffer, dtls_buflen);
        if(rc <= 0) {
            switch(rc) {
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_WANT_READ:
                /* goto flush ? */
                return;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                goto close_notify;
            case 0:
            case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
            default:
                print_mbedtls_err("mbedtls_ssl_read", rc);
                goto flush;
            }
        } else {
            parse_packet(from, ifp, dtls_buffer, rc);
        }
    } else {
        rc = mbedtls_ssl_handshake(&dtls->ssl);
        if(rc == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
            goto flush;
        } else if(rc != MBEDTLS_ERR_SSL_WANT_READ &&
                  rc != MBEDTLS_ERR_SSL_WANT_WRITE && rc) {
            print_mbedtls_err("mbedtls_ssl_handshake", rc);
            goto flush;
        }
    }

    return;

 close_notify:
    rc = mbedtls_ssl_close_notify(&dtls->ssl);
    if (rc)
        print_mbedtls_err("mbedtls_ssl_close_notify", rc);

 flush:
    /* FIXME: what do we do? */
    flush_neighbour(neigh);
}

int
dtls_send(const void *buf1, int buflen1, const void *buf2, int buflen2,
          struct dtls *dtls)
{
    size_t len = buflen1 + buflen2;
    if(dtls->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        fprintf(stderr, "dtls_send: "
                "tried to send unicast packet but handshake is not over!\n");
        return len;
    } else {
        unsigned char *buf = dtls_buffer;
        int rc;
        /* FIXME: realloc */
        memcpy(buf, buf1, buflen1);
        memcpy(buf + buflen1, buf2, buflen2);

    partial_write:
        rc = mbedtls_ssl_write(&dtls->ssl, buf, len);
        if(rc <= 0) {
            switch(rc) {
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            case MBEDTLS_ERR_SSL_WANT_READ:
                goto partial_write;
            default:
                print_mbedtls_err("dtls_send mbedtls_ssl_write", rc);
                /* FIXME: what do we do? */
            }
        } else if ((size_t)rc < len) {
            buf += rc;
            len -= rc;
            goto partial_write;
        }
        return rc;
    }
}

static int
dtls_cb_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct neighbour *neigh = ctx;
    int rc;

    rc = babel_send(protocol_socket, buf, len, NULL, 0,
                    (const struct sockaddr *)&neigh->buf.sin6,
                    sizeof(neigh->buf.sin6));
    return rc;
}

static int
dtls_cb_recv(void *ctx, unsigned char *buf, size_t len)
{
    struct dtls *dtls = ((struct neighbour *)ctx)->buf.dtls;
    size_t recvlen;

    if(!dtls->has_data)
        return MBEDTLS_ERR_SSL_WANT_READ;

    recvlen = len < dtls->packetlen ? len : dtls->packetlen;
    memcpy(buf, dtls->packet, recvlen);
    dtls->has_data = recvlen > len;
    return recvlen;
}

static void
dtls_cb_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
    struct dtls *dtls = ((struct neighbour *)ctx)->buf.dtls;
    struct timeval zero = {0, 0};

    dtls->int_time_expired = 0;
    dtls->fin_time_expired = 0;

    if(int_ms == 0 && fin_ms == 0) {
        dtls->has_timer = 0;
        dtls->int_time = zero;
        dtls->fin_time = zero;
    } else {
        dtls->has_timer = 1;
        timeval_add_msec(&dtls->int_time, &now, int_ms);
        timeval_add_msec(&dtls->fin_time, &now, fin_ms);
    }
}

static int
dtls_cb_get_timer(void *ctx)
{
    struct dtls *dtls = ((struct neighbour *)ctx)->buf.dtls;

    if(!dtls->has_timer)
        return -1;
    else if(!dtls->int_time_expired && !dtls->fin_time_expired)
        return 0;
    else if(dtls->int_time_expired && !dtls->fin_time_expired)
        return 1;
    else
        return 2;
}
