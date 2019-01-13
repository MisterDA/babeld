extern const char *dtls_cert_file,
    *dtls_prvtkey_file,
    *dtls_cacert_file,
    *dtls_prvtkey_password;

extern int dtls_protocol_port;
extern int dtls_protocol_socket;

struct dtls {
    mbedtls_ssl_context context;
    short port;
    int fd;                     /* Socket used if the neighbour is the server */
    int has_data;
    int has_timer;
    struct timeval int_time;
    struct timeval fin_time;

    const unsigned char *packet;
    int packetlen;
};

int dtls_init(void);
void dtls_free(void);

int dtls_setup_neighbour(struct neighbour *neigh);
int dtls_handshake(struct neighbour *neigh);
void dtls_parse_packet(const unsigned char *from, struct interface *ifp,
                       const unsigned char *packet, int packetlen);
int dtls_send(const void *buf1, int buflen1, const void *buf2, int buflen2,
              struct dtls *dtls);
void dtls_flush_neighbour(struct neighbour *neigh);
