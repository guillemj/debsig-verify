CC = gcc
CFLAGS = -Wall -g -O2 $(shell xml-config --cflags)
LDFLAGS = $(shell xml-config --libs)

ifndef TESTING
DEBSIG_KEYRINGS_DIR=/usr/share/debsig/keyrings
DEBSIG_POLICIES_DIR=/etc/debsigs/policies
else
DEBSIG_KEYRINGS_DIR=$(shell pwd)/testing/keyrings
DEBSIG_POLICIES_DIR=$(shell pwd)/testing/policies
endif

CFLAGS += -DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"

all: debsig-verify

install: all
	install -d -m755 $(DESTDIR)/usr/bin
	install -m755 debsig-verify $(DESTDIR)/usr/bin/debsig-verify
	install -d -m755 $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	install -d -m755 $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)

clean:
	rm -f debsig-verify
