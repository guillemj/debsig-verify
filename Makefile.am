DEBSIG_KEYRINGS_DIR = $(datadir)/debsig/keyrings
DEBSIG_POLICIES_DIR = $(sysconfdir)/debsig/policies

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-DLIBDPKG_VOLATILE_API=1 \
	-DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
	-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\"
AM_CFLAGS = \
	$(LIBDPKG_CFLAGS) \
	$(nil)
LDADD = \
	$(LIBDPKG_LIBS) \
	-lxmlparse


bin_PROGRAMS = debsig-verify

debsig_verify_SOURCES = \
	ar-parse.c \
	debsig.h \
	debsig-verify.c \
	gpg-parse.c \
	misc.c \
	xml-parse.c \
	$(nil)

EXTRA_DIST = \
	autogen \
	get-version \
	docs/TODO \
	docs/debsig-verify.1.in \
	docs/policy-syntax.txt \
	docs/policy.dtd \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/lintian-overrides \
	debian/rules \
	debian/source/format \
	$(nil)

do_man_subst = $(AM_V_GEN) \
	sed -e 's,@POLICIES_DIR@,$(DEBSIG_POLICIES_DIR),g' \
	    -e 's,@KEYRINGS_DIR@,$(DEBSIG_KEYRINGS_DIR),g'

%.1: docs/%.1.in
	$(do_man_subst) < $< > $@

man_MANS = \
	debsig-verify.1 \
	$(nil)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	$(MKDIR_P) $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)

clean-local:
	$(RM) debsig-verify.1
