## Process this file with automake to produce Makefile.in

PACKAGE_M4 = $(srcdir)/package.m4
EXTRA_DIST = $(PACKAGE_M4)

TESTSUITE = $(srcdir)/testsuite
EXTRA_DIST += $(TESTSUITE)

TESTSUITE_AT = testsuite.at
TESTSUITE_AT += debsig-cmd.at
EXTRA_DIST += $(TESTSUITE_AT)

DISTCLEANFILES = atconfig

$(PACKAGE_M4): $(top_srcdir)/configure.ac
	{ \
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$@

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(PACKAGE_M4) $(TESTSUITE_AT)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) $(TESTSUITE) $(TESTSUITEFLAGS)

installcheck-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) $(TESTSUITE) $(TESTSUITEFLAGS) AUTOTEST_PATH='$(bindir)'

clean-local:
	test ! -f $(TESTSUITE) || $(SHELL) $(TESTSUITE) --clean
