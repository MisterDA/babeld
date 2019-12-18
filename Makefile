PREFIX = /usr/local
MANDIR = $(PREFIX)/share/man

DEPFLAGS = -MMD -MP
CPPFLAGS += $(DEPFLAGS)

CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lrt

SRCS = babeld.c net.c kernel.c util.c interface.c source.c neighbour.c \
       route.c xroute.c message.c resend.c configuration.c local.c \
       disambiguation.c rule.c

OBJS = $(SRCS:%.c=$(BUILD)%.o)

$(BUILD)babeld: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(BUILD)babeld.o: $(BUILD)version.h

$(BUILD)local.o: $(BUILD)version.h

-include $(SRCS:%.c=$(BUILD)%.d)

$(BUILD)version.h:
	./generate-version.sh > $@

# GNU Make
$(BUILD)%.o: %.c
	@mkdir -p $(@D)
	$(COMPILE.c) $(OUTPUT_OPTION) -I./$(BUILD) $<

# BSD Make
.SUFFIXES: .c .o
.c.o:
	${COMPILE.c} ${.IMPSRC} -o $@

.SUFFIXES: .man .html

.man.html:
	mandoc -Thtml $< > $@

babeld.html: babeld.man

.PHONY: all install install.minimal uninstall clean

all: babeld babeld.man

install.minimal: babeld
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	mkdir -p $(TARGET)$(PREFIX)/bin
	cp -f $(BUILD)babeld $(TARGET)$(PREFIX)/bin

install: install.minimal all
	mkdir -p $(TARGET)$(MANDIR)/man8
	cp -f babeld.man $(TARGET)$(MANDIR)/man8/babeld.8

uninstall:
	-rm -f $(TARGET)$(PREFIX)/bin/babeld
	-rm -f $(TARGET)$(MANDIR)/man8/babeld.8

clean:
	-rm -f babeld babeld.html version.h *.d *.o *~ core TAGS gmon.out
