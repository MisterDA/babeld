PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

HAVE_MBEDTLS = yes
ifeq ($(HAVE_MBEDTLS), yes)
DTLS_SRCS = dtls.c
DTLS_OBJS = dtls.o
DTLS_CFLAGS = -Imbedtls_build/include
DTLS_LDFLAGS = -Lmbedtls_build/library
DTLS_LDLIBS = -lmbedtls -lmbedx509 -lmbedcrypto
DTLS_DEFINES = -DHAVE_MBEDTLS -DUSE_MBEDTLS_TEST_CERTS
endif

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES) $(DTLS_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES) $(DTLS_CFLAGS)

LDFLAGS = $(DTLS_LDFLAGS)

LDLIBS = -lrt $(DTLS_LDLIBS)

SRCS = babeld.c net.c kernel.c util.c interface.c source.c neighbour.c \
       route.c xroute.c message.c resend.c configuration.c local.c \
       disambiguation.c rule.c $(DTLS_SRCS)

OBJS = babeld.o net.o kernel.o util.o interface.o source.o neighbour.o \
       route.o xroute.o message.o resend.o configuration.o local.o \
       disambiguation.o rule.o $(DTLS_OBJS)

babeld: $(OBJS)
	$(CC) $(LDFLAGS) -o babeld $(OBJS) $(LDLIBS)

babeld.o: babeld.c version.h

local.o: local.c version.h

kernel.o: kernel_netlink.c kernel_socket.c

version.h:
	./generate-version.sh > version.h

.SUFFIXES: .man .html

.man.html:
	mandoc -Thtml $< > $@

babeld.html: babeld.man

.PHONY: all install install.minimal uninstall clean

all: babeld babeld.man

install.minimal: babeld
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f babeld $(TARGET)$(PREFIX)/bin

install: install.minimal all
	mkdir -p $(TARGET)$(MANDIR)/man8
	cp -f babeld.man $(TARGET)$(MANDIR)/man8/babeld.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	-rm -f $(TARGET)$(MANDIR)/man8/babeld.8

clean:
	-rm -f babeld babeld.html version.h *.o *~ core TAGS gmon.out
