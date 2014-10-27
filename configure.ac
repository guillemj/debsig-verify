# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([debsig-verify], m4_esyscmd([./get-version]), [debian-dpkg@lists.debian.org])
AC_CONFIG_SRCDIR([src/debsig-verify.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter"
CFLAGS="$CFLAGS -Wno-missing-field-initializers"
CFLAGS="$CFLAGS -Wmissing-declarations"
CFLAGS="$CFLAGS -Wmissing-format-attribute"
CFLAGS="$CFLAGS -Wformat-security"
CFLAGS="$CFLAGS -Wpointer-arith"
CFLAGS="$CFLAGS -Wlogical-op"
CFLAGS="$CFLAGS -Wvla"
CFLAGS="$CFLAGS -Winit-self"
CFLAGS="$CFLAGS -Wwrite-strings"
CFLAGS="$CFLAGS -Wcast-align"
CFLAGS="$CFLAGS -Wshadow"
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

# Checks for libraries.
AC_CHECK_LIB([xmlparse], [XML_ParserCreate])
PKG_CHECK_MODULES([LIBDPKG], [libdpkg])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_FUNC_OBSTACK
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([dup2 memset strchr strerror strstr])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT