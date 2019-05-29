/*
Copyright (c) 2017 - 2019 by Antonin Décimo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifdef HAVE_MBEDTLS

extern const char *dtls_cert_file,
    *dtls_prvtkey_file,
    *dtls_cacert_file,
    *dtls_prvtkey_password;

struct dtls {
    mbedtls_ssl_context context;
    unsigned short port; /* Client source port, network order */
    int fd;              /* Client fd or -1 */
    int has_data;
    /* -1 if cancelled, 0 if none of the delays have passed, 1 if only
       the intermediate delay has passed, 2 if the final delay has
       passed. */
    int timer_status;
    struct timeval int_time;
    struct timeval fin_time;

    const unsigned char *packet;
    int packetlen;
};

int dtls_init(void);
void dtls_free(void);

int dtls_setup_neighbour(struct neighbour *neigh);
int dtls_handshake(struct neighbour *neigh);
void dtls_parse_packet(const struct sockaddr_in6 *from, struct interface *ifp,
                       const unsigned char *packet, int packetlen);
int dtls_send(const void *buf1, int buflen1, const void *buf2, int buflen2,
              struct dtls *dtls);
void dtls_flush_neighbour(struct neighbour *neigh);

#endif
