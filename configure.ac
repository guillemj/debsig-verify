# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([debsig-verify], m4_esyscmd([./get-version]), [debian-dpkg@lists.debian.org])
AC_CONFIG_SRCDIR([src/debsig-verify.c])
AC_CONFIG_TESTDIR([test])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

CFLAGS="$CFLAGS -Wall"
CFLAGS="$CFLAGS -Wextra"
CFLAGS="$CFLAGS -Wno-unused-parameter"
CFLAGS="$CFLAGS -Wno-missing-field-initializers"
CFLAGS="$CFLAGS -Wmissing-declarations"
CFLAGS="$CFLAGS -Wmissing-format-attribute"
CFLAGS="$CFLAGS -Wformat -Wformat-security"
CFLAGS="$CFLAGS -Wsizeof-array-argument"
CFLAGS="$CFLAGS -Wpointer-arith"
CFLAGS="$CFLAGS -Wlogical-op"
CFLAGS="$CFLAGS -Wlogical-not-parentheses"
CFLAGS="$CFLAGS -Wswitch-bool"
CFLAGS="$CFLAGS -Wvla"
CFLAGS="$CFLAGS -Winit-self"
CFLAGS="$CFLAGS -Wwrite-strings"
CFLAGS="$CFLAGS -Wcast-align"
CFLAGS="$CFLAGS -Wshadow"
CFLAGS="$CFLAGS -Wduplicated-cond"
CFLAGS="$CFLAGS -Wnull-dereference"
CFLAGS="$CFLAGS -Wdeclaration-after-statement"
CFLAGS="$CFLAGS -Wnested-externs"
CFLAGS="$CFLAGS -Wbad-function-cast"
CFLAGS="$CFLAGS -Wstrict-prototypes"
CFLAGS="$CFLAGS -Wmissing-prototypes"
CFLAGS="$CFLAGS -Wold-style-definition"

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.11 foreign nostdinc subdir-objects no-dist-gzip dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AM_MISSING_PROG([AUTOM4TE], [autom4te]) dnl Needed by autotest

# Checks for libraries.
AC_CHECK_LIB([expat], [XML_ParserCreate])
PKG_CHECK_MODULES([LIBDPKG], [libdpkg >= 1.18.8])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_STRNLEN
AC_FUNC_OBSTACK

AC_CONFIG_FILES([
	Makefile
	test/Makefile
	test/atlocal
])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
