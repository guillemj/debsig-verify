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
	-DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
	-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"
MK_CFLAGS =
MK_LDFLAGS = -lxmlparse

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

clean:
	rm -f debsig-verify $(OBJS) $(MANPAGES)

%.o: %.c debsig.h
	$(CC) $(MK_CPPFLAGS) $(CPPFLAGS) $(MK_CFLAGS) $(CFLAGS) -c $< -o $@

%.1: docs/%.1.in
	sed -e 's,@POLICIES_DIR@,$(DEBSIG_POLICIES_DIR),g' \
		-e 's,@KEYRINGS_DIR@,$(DEBSIG_KEYRINGS_DIR),g' < $< > $@
