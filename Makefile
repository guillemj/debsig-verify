CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -lxmltok -lxmlparse

#TESTING=1

ifndef TESTING
DEBSIG_KEYRINGS_DIR=/usr/share/debsig/keyrings
DEBSIG_POLICIES_DIR=/etc/debsig/policies
else
DEBSIG_KEYRINGS_DIR=$(shell pwd)/testing/keyrings
DEBSIG_POLICIES_DIR=$(shell pwd)/testing/policies
endif

PROGRAM = debsig-verify
OBJS = xml-parse.o ar-parse.o gpg-parse.o debsig-verify.o misc.o

CFLAGS += -DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"

MANPAGES = debsig-verify.1

all: $(PROGRAM) $(MANPAGES)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

install: all
	install -d -m755 $(DESTDIR)/usr/bin
	install -m755 $(PROGRAM) $(DESTDIR)/usr/bin/$(PROGRAM)
	install -d -m755 $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	install -d -m755 $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)
	install -d -m755 $(DESTDIR)/usr/share/man/man1
	install docs/debsig-verify.1 \
		$(DESTDIR)/usr/share/man/man1/debsig-verify.1

clean:
	rm -f debsig-verify $(OBJS) $(MANPAGES)

%.o: %.c debsig.h
	$(CC) $(CFLAGS) -c $< -o $@

%.1: docs/%.1.in
	sed -e 's,@POLICIES_DIR@,$(DEBSIG_POLICIES_DIR),g' \
		-e 's,@KEYRINGS_DIR@,$(DEBSIG_KEYRINGS_DIR),g' < $< > $@
