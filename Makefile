CC = gcc
CFLAGS = -Wall -g -O2

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

MK_CPPFLAGS = \
	-DLIBDPKG_VOLATILE_API=1 \
	-DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
	-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"
MK_CFLAGS = $(shell pkg-config --cflags libdpkg)
MK_LDFLAGS = $(shell pkg-config --libs libdpkg) -lxmlparse

MANPAGES = debsig-verify.1

all: $(PROGRAM) $(MANPAGES)

$(PROGRAM): $(OBJS)
	$(CC) $(MK_CFLAGS) $(CFLAGS) $(OBJS) $(MK_LDFLAGS) $(LDFLAGS) -o $@

install: all
	install -d -m755 $(DESTDIR)/usr/bin
	install -m755 $(PROGRAM) $(DESTDIR)/usr/bin/$(PROGRAM)
	install -d -m755 $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	install -d -m755 $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)
	for mpage in $(MANPAGES); do \
		num=`echo $$mpage | sed 's,.*\.,,'`; \
		install -d -m755 $(DESTDIR)/usr/share/man/man$$num; \
		install $$mpage $(DESTDIR)/usr/share/man/man$$num/$$mpage; \
	done

check:
	# Do not ship this in the tarball or repository.
	ln -s /usr/share/keyrings/debian-keyring.gpg testing/keyrings/7CD73F641E04EC2D/
	# XXX: Do some actual testing here.

clean:
	rm -f debsig-verify $(OBJS) $(MANPAGES)
	rm -f testing/keyrings/7CD73F641E04EC2D/debian-keyring.gpg

%.o: %.c debsig.h
	$(CC) $(MK_CPPFLAGS) $(CPPFLAGS) $(MK_CFLAGS) $(CFLAGS) -c $< -o $@

%.1: docs/%.1.in
	sed -e 's,@POLICIES_DIR@,$(DEBSIG_POLICIES_DIR),g' \
		-e 's,@KEYRINGS_DIR@,$(DEBSIG_KEYRINGS_DIR),g' < $< > $@
