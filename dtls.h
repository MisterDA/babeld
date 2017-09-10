#include <mbedtls/ssl.h>

extern const char *dtls_cert_file,
    *dtls_prvtkey_file,
    *dtls_cacert_file,
    *dtls_prvtkey_password;

struct dtls {
    mbedtls_ssl_context ssl;
    int has_timer;
    struct timeval int_time;
    struct timeval fin_time;
    int int_time_expired;
    int fin_time_expired;
    int has_data;

    const unsigned char *packet;
    size_t packetlen;
};


int dtls_init(void);
void dtls_free(void);

int dtls_setup_neighbour(struct neighbour *neigh);
void dtls_flush_neighbour(struct neighbour *neigh);

int dtls_handshake(struct neighbour *neigh);

void dtls_parse_packet(const unsigned char *from, struct interface *ifp,
                       const unsigned char *packet, int packetlen);
int dtls_send(const void *buf1, int buflen1, const void *buf2, int buflen2,
              struct dtls *dtls);
