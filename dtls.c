#ifndef USE_DTLS
#define USE_DTLS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "net.h"
#include "dtls.h"

#ifdef USE_MBEDTLS_TEST_CERTS
#include <mbedtls/certs.h>
static mbedtls_x509_crt dtls_srvcert;
static mbedtls_pk_context dtls_pkey;
#endif

const char *dtls_cert_file = NULL,
    *dtls_prvkey_file = NULL,
    *dtls_cacert_file = NULL,
    *dtls_prvtkey_password = NULL;

static mbedtls_ssl_config dtls_server_conf, dtls_client_conf;

static mbedtls_ssl_cookie_ctx dtls_cookie_ctx;
static mbedtls_entropy_context dtls_entropy;
static mbedtls_ctr_drbg_context dtls_ctr_drbg;

/* Buffer Input/Output. Protected packets are encrypted and decrypted
   in this buffer. */
static unsigned char *dtls_buffer = NULL;
static int dtls_buflen = 0;

static void
print_mbedtls_err(const char *func, int rc)
{
    static char buf[256];
    mbedtls_strerror(rc, buf, sizeof(buf));
    fprintf(stderr, "%s %#x: %s\n", func, rc, buf);
}

#ifdef MBEDTLS_CHECK_PARAMS
void
mbedtls_param_failed(const char *failure_condition, const char *file, int line)
{
    fprintf(stderr, "mbedtls_params: %s:%d: %s\n", file, line,
            failure_condition);
}
#endif

#ifdef MBEDTLS_DEBUG_C
static void
ssl_conf_dbg(void *ctx, int dbg_lvl, const char *file, int line,
             const char *msg)
{
    ((void)ctx);
    ((void)dbg_lvl);
    fprintf(stderr, "mbedtls_dbg: %s:%d: %s\n", file, line, msg);
}
#endif


int
dtls_init(void)
{
    int rc;

    mbedtls_entropy_init(&dtls_entropy);
    mbedtls_ctr_drbg_init(&dtls_ctr_drbg);
    mbedtls_ssl_cookie_init(&dtls_cookie_ctx);
    mbedtls_ssl_config_init(&dtls_server_conf);
    mbedtls_ssl_config_init(&dtls_client_conf);

#ifdef MBEDTLS_DEBUG_C
    /* Warn on mbedTLS errors. */
    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_dbg(&dtls_server_conf, ssl_conf_dbg, NULL);
    mbedtls_ssl_conf_dbg(&dtls_client_conf, ssl_conf_dbg, NULL);
#endif

    rc = mbedtls_ssl_config_defaults(&dtls_server_conf,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if(rc != 0) {
        print_mbedtls_err("mbedtls_ssl_config_defaults server", rc);
        mbedtls_ssl_config_free(&dtls_server_conf);
        return -1;
    }

    rc = mbedtls_ssl_config_defaults(&dtls_client_conf,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if(rc != 0) {
        print_mbedtls_err("mbedtls_ssl_config_defaults client", rc);
        mbedtls_ssl_config_free(&dtls_client_conf);
        return -1;
    }

    /* Nodes MUST only negotiate DTLS version 1.2 or higher */
    mbedtls_ssl_conf_min_version(&dtls_server_conf,
                                 MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&dtls_client_conf,
                                 MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);

    /* Nodes MUST use DTLS replay protection to prevent attackers from
       replaying stale information */
    mbedtls_ssl_conf_dtls_anti_replay(&dtls_server_conf,
                                      MBEDTLS_SSL_ANTI_REPLAY_ENABLED);
    mbedtls_ssl_conf_dtls_anti_replay(&dtls_client_conf,
                                      MBEDTLS_SSL_ANTI_REPLAY_ENABLED);

    rc = mbedtls_ctr_drbg_seed(&dtls_ctr_drbg, mbedtls_entropy_func,
                               &dtls_entropy, NULL, 0);
    if(rc) {
        print_mbedtls_err("mbedtls_ctr_drbg_seed", rc);
        return rc;
    }
    mbedtls_ssl_conf_rng(&dtls_server_conf, mbedtls_ctr_drbg_random,
                         &dtls_ctr_drbg);
    mbedtls_ssl_conf_rng(&dtls_client_conf, mbedtls_ctr_drbg_random,
                         &dtls_ctr_drbg);


    rc = mbedtls_ssl_cookie_setup(&dtls_cookie_ctx,
                                  mbedtls_ctr_drbg_random, &dtls_ctr_drbg);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_cookie_setup", rc);
        return rc;
    }

    mbedtls_ssl_conf_dtls_cookies(&dtls_server_conf, mbedtls_ssl_cookie_write,
                                  mbedtls_ssl_cookie_check,
                                  &dtls_cookie_ctx);

#ifdef USE_MBEDTLS_TEST_CERTS
    rc = mbedtls_x509_crt_parse(&dtls_srvcert,
                                (const unsigned char *)mbedtls_test_srv_crt,
                                mbedtls_test_srv_crt_len);
    if(rc) {
        print_mbedtls_err("mbedtls_x509_crt_parse srv_crt", rc);
        return rc;
    }

    rc = mbedtls_x509_crt_parse(&dtls_srvcert,
                                (const unsigned char *)mbedtls_test_cas_pem,
                                mbedtls_test_cas_pem_len);
    if(rc) {
        print_mbedtls_err("mbedtls_x509_crt_parse cas_pem", rc);
        return rc;
    }

    rc = mbedtls_pk_parse_key(&dtls_pkey,
                              (const unsigned char *)mbedtls_test_srv_key,
                              mbedtls_test_srv_key_len,
                              NULL, 0);
    if(rc) {
        print_mbedtls_err("mbedtls_pk_parse_key", rc);
        return rc;
    }
    mbedtls_ssl_conf_authmode(&dtls_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif

    dtls_buflen = 8192;
    dtls_buffer = malloc(dtls_buflen);
    if(!dtls_buffer) {
        perror("malloc(dtls_buffer)");
        return -1;
    }

    return 0;
}

void
dtls_free(void)
{
    mbedtls_ssl_config_free(&dtls_server_conf);
    mbedtls_ssl_config_free(&dtls_client_conf);
    mbedtls_ssl_cookie_free(&dtls_cookie_ctx);
    mbedtls_ctr_drbg_free(&dtls_ctr_drbg);
    mbedtls_entropy_free(&dtls_entropy);
}

static int
dtls_cb_send(void *ctx, const unsigned char *buf, size_t len)
{
    struct neighbour *neigh = ctx;
    int rc;

    rc = babel_send(neigh->buf.dtls->fd, buf, len, NULL, 0,
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

    recvlen = len < (size_t)dtls->packetlen ? len : (size_t)dtls->packetlen;
    memcpy(buf, dtls->packet, recvlen);
    dtls->has_data = recvlen > len;
    return recvlen;
}

static void
dtls_cb_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms)
{
    struct dtls *dtls = ((struct neighbour *)ctx)->buf.dtls;

    if(dtls->timer_status != -1) {
        dtls->timer_status = -1;
    } else {
        dtls->timer_status = 0;
        timeval_add_msec(&dtls->int_time, &now, int_ms);
        timeval_add_msec(&dtls->fin_time, &now, fin_ms);
    }

    return;
}

static int
dtls_cb_get_timer(void *ctx)
{
    struct dtls *dtls = ((struct neighbour *)ctx)->buf.dtls;
    return dtls->timer_status;
}

static int
dtls_setup_client_socket(void)
{
    /* This function is a duplicate of babel_socket, except that we
       don’t bind the DTLS client socket. */
    /* FIXME: the draft reads "Nodes SHOULD ensure that new client
       DTLS connections use different ephemeral ports from recently
       used connections to allow servers to differentiate between the
       new and old DTLS connections.";
       Is opening a new socket sufficient?
    */
    int s, rc;
    int saved_errno;
    int one = 1, zero = 0;
    const int ds = 0xc0;        /* CS6 - Network Control */

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                    &zero, sizeof(zero));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

#ifdef IPV6_TCLASS
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &ds, sizeof(ds));
    if(rc < 0)
#else
    errno = ENOSYS;
#endif
        perror("Couldn't set traffic class");

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

static int
dtls_setup_client(struct neighbour *neigh)
{
    int rc;

    rc = dtls_setup_client_socket();
    if(rc < 0) {
        perror("dtls_setup_client_socket");
        return -1;
    }
    neigh->buf.dtls->fd = rc;

    rc = mbedtls_ssl_setup(&neigh->buf.dtls->context, &dtls_client_conf);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_setup", rc);
        return rc;
    }

    return 0;
}

static int
dtls_setup_server(struct neighbour *neigh)
{
    unsigned char info[18];
    int rc;

    rc = mbedtls_ssl_setup(&neigh->buf.dtls->context, &dtls_server_conf);
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_setup", rc);
        return rc;
    }

    memcpy(info, neigh->address, 16);
    memcpy(info + 16, &neigh->buf.dtls->port, 2);
    rc = mbedtls_ssl_set_client_transport_id(&neigh->buf.dtls->context,
                                             info, sizeof(info));
    if(rc) {
        print_mbedtls_err("mbedtls_ssl_set_client_transport_id", rc);
        return rc;
    }

    return 0;
}

/* DTLS setup that is common to servers and clients */
int
dtls_setup_neighbour(struct neighbour *neigh)
{
    struct dtls *dtls;
    int rc;

    dtls = malloc(sizeof(struct dtls));
    if(dtls == NULL) {
        perror("malloc(dtls)");
        return -1;
    }
    neigh->buf.dtls = dtls;
    memset(dtls, 0, sizeof(*dtls));
    dtls->fd = -1;

    mbedtls_ssl_init(&dtls->context);
    mbedtls_ssl_set_timer_cb(&dtls->context,
                             neigh, /* closure */
                             dtls_cb_set_timer, dtls_cb_get_timer);
    mbedtls_ssl_set_bio(&dtls->context,
                        neigh,   /* closure */
                        dtls_cb_send, dtls_cb_recv, NULL); /* non-blocking IO */

    /* the node with the lowest address is the client */
    rc = memcmp(neigh->ifp->ll, neigh->address, 16);
    if(rc < 0) {
        rc = dtls_setup_client(neigh);
    } else if(rc > 0) {
        rc = dtls_setup_server(neigh);
    } else {
        fprintf(stderr, "dtls_setup_neighbour: router is soliloquising.\n");
        rc = -1;
    }

    if(rc)
        dtls_flush_neighbour(neigh);

    return rc;
}

void
dtls_parse_packet(const unsigned char *from, struct interface *ifp,
                  const unsigned char *packet, int packetlen)
{
    struct neighbour *neigh;

    if(!linklocal(from)) {
        fprintf(stderr, "Received packet from non-local address %s.\n",
                format_address(from));
        return;
    }

    neigh = find_neighbour(from, ifp);

    neigh->buf.dtls->packet = packet;
    neigh->buf.dtls->packetlen = packetlen;
    neigh->buf.dtls->has_data = 1;

    if(neigh->buf.dtls->context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        int rc;
        neigh->buf.dtls->has_data = 1;
        rc = mbedtls_ssl_read(&neigh->buf.dtls->context,
                              dtls_buffer, dtls_buflen);
        if(rc > 0) {
            parse_packet(from, ifp, dtls_buffer, rc, 0);
            /* mbedtls_ssl_check_pending */
        } else if(rc == MBEDTLS_ERR_SSL_WANT_READ ||
                  rc == MBEDTLS_ERR_SSL_WANT_WRITE ||
                  rc == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
            /* We’re supposed to call this function later, when
             * the underlying transport is ready, or when the
             * async or crypto operation has finished.  Let’s do
             * nothing and see what happens. */
            print_mbedtls_err("mbedtls_ssl_read", rc);
        } else if(rc == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
            /* FIXME: possible DoS here? */
            dtls_handshake(neigh);
        } else {
            dtls_flush_neighbour(neigh);
        }
    }
}

int
dtls_handshake(struct neighbour *neigh)
{
    int rc;
    /* Can this be called server-side? */
    rc = mbedtls_ssl_handshake(&neigh->buf.dtls->context);
    if(rc == 0) {
        return rc;
    } else if(rc == MBEDTLS_ERR_SSL_WANT_READ ||
              rc == MBEDTLS_ERR_SSL_WANT_WRITE ||
              rc == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
        /* We’re supposed to call this function later, when
         * the underlying transport is ready, or when the
         * async or crypto operation has finished.  Let’s do
         * nothing and see what happens. */
        print_mbedtls_err("mbedtls_ssl_handshake", rc);
        return rc;
    } else if(rc == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        goto flush;
    } else {
        goto flush;
    }

flush:
    dtls_flush_neighbour(neigh);
    return rc;
}

int
dtls_send(const void *buf1, int buflen1, const void *buf2, int buflen2,
          struct dtls *dtls)
{
    unsigned char *buf = dtls_buffer;
    int len = buflen1 + buflen2;
    int rc;

    if(len > dtls_buflen) {
        /* FIXME: realloc buffer? */
        fprintf(stderr, "dtls_send: buffer is not large enough.\n");
        return len;
    }

    memcpy(dtls_buffer, buf1, buflen1);
    memcpy(dtls_buffer + buflen1, buf2, buflen2);

    if(dtls->context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        fprintf(stderr, "dtls_send: "
                "tried to send unicast packet but handshake is not over!\n");
        return len;
    }

partial_write:
    rc = mbedtls_ssl_write(&dtls->context, buf, len);
    if(rc <= 0) {
        switch(rc) {
        case MBEDTLS_ERR_SSL_WANT_WRITE:
        case MBEDTLS_ERR_SSL_WANT_READ:
            goto partial_write;
        default:
            print_mbedtls_err("dtls_send mbedtls_ssl_write", rc);
            /* FIXME: what do we do? */
        }
    } else if (rc < len) {
        buf += rc;
        len -= rc;
        goto partial_write;
    }
    return rc;
}

void
dtls_flush_neighbour(struct neighbour *neigh)
{
    if(neigh->buf.dtls->fd != -1)
        close(neigh->buf.dtls->fd);
    mbedtls_ssl_free(&neigh->buf.dtls->context);
    free(&neigh->buf.dtls);
    neigh->buf.dtls = NULL;
}
