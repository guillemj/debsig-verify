SUBDIRS = . test

DEBSIG_KEYRINGS_DIR = $(datadir)/debsig/keyrings
DEBSIG_POLICIES_DIR = $(sysconfdir)/debsig/policies

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-DLIBDPKG_VOLATILE_API=1 \
	-DDEBSIG_POLICIES_DIR=\"$(DEBSIG_POLICIES_DIR)\" \
	-DDEBSIG_KEYRINGS_DIR=\"$(DEBSIG_KEYRINGS_DIR)\" \
	# EOL
AM_CFLAGS = \
	$(LIBDPKG_CFLAGS) \
	# EOL
LDADD = \
	$(LIBDPKG_LIBS) \
	-lexpat \
	# EOL


bin_PROGRAMS = src/debsig-verify

src_debsig_verify_SOURCES = \
	src/ar-parse.c \
	src/debsig.h \
	src/debsig-verify.c \
	src/debug.c \
	src/openpgp.c \
	src/openpgp-gpg.c \
	src/policy-xml.c \
	# EOL

EXTRA_DIST = \
	autogen \
	get-version \
	doc/debsig-verify.1.in \
	doc/policy-syntax.txt \
	doc/policy.dtd \
	debian/changelog \
	debian/control \
	debian/copyright \
	debian/debsig-verify.docs \
	debian/debsig-verify.examples \
	debian/debsig-verify.lintian-overrides \
	debian/rules \
	debian/source/format \
	debian/tests/control \
	debian/tests/functional \
	# EOL

do_man_subst = $(AM_V_GEN) \
	sed -e 's,@POLICIES_DIR@,$(DEBSIG_POLICIES_DIR),g' \
	    -e 's,@KEYRINGS_DIR@,$(DEBSIG_KEYRINGS_DIR),g' \
	    -e 's,%RELEASE_DATE%,$(RELEASE_DATE),g' \
	    -e 's,%PACKAGE_VERSION%,$(PACKAGE_VERSION),g'

doc/%.1: doc/%.1.in
	$(MKDIR_P) doc
	$(do_man_subst) < $< > $@

man_MANS = \
	doc/debsig-verify.1 \
	# EOL

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(DEBSIG_POLICIES_DIR)
	$(MKDIR_P) $(DESTDIR)$(DEBSIG_KEYRINGS_DIR)

dist-hook:
	echo $(VERSION) >$(distdir)/.dist-version

clean-local:
	$(RM) doc/debsig-verify.1
