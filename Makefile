CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -lxmltok -lxmlparse

#TESTING=1

ifndef TESTING
DEBSIG_KEYRINGS_DIR=/usr/share/debsig/keyrings
DEBSIG_POLICIES_DIR=/etc/debsigs/policies
else
DEBSIG_KEYRINGS_DIR=$(shell pwd)/testing/keyrings
DEBSIG_POLICIES_DIR=$(shell pwd)/testing/policies
endif

PROGRAM = debsig-verify
OBJS = xml-parse.o ar-parse.o debsig-verify.o misc.o

CFLAGS += -DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

install: all
	install -d -m755 $(DESTDIR)/usr/bin
	install -m755 $(PROGRAM) $(DESTDIR)/usr/bin/$(PROGRAM)
	install -d -m755 $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	install -d -m755 $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)

clean:
	rm -f debsig-verify $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
