CC = gcc
CFLAGS = -Wall -g -O2 $(shell xml-config --cflags) -DDEBSIG_DEBUG
LDFLAGS = $(shell xml-config --libs)

all: debsig-verify

clean:
	rm -f debsig-verify
