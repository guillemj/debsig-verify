# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([debsig-verify], m4_esyscmd([./get-version]), [debian-dpkg@lists.debian.org])
AC_CONFIG_SRCDIR([src/debsig-verify.c])
AC_CONFIG_TESTDIR([test])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.11 foreign nostdinc subdir-objects tar-ustar no-dist-gzip dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AM_MISSING_PROG([AUTOM4TE], [autom4te]) dnl Needed by autotest

# Checks for libraries.
AC_CHECK_LIB([expat], [XML_ParserCreate])
PKG_CHECK_MODULES_STATIC([LIBDPKG], [libdpkg >= 1.22.0])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_STRNLEN
AC_FUNC_OBSTACK

# Checks for the build machinery.
DPKG_CHECK_COMPILER_FLAG([-Wall])
DPKG_CHECK_COMPILER_FLAG([-Wextra])
DPKG_CHECK_COMPILER_FLAG([-Wno-unused-parameter])
DPKG_CHECK_COMPILER_FLAG([-Wno-missing-field-initializers])
DPKG_CHECK_COMPILER_FLAG([-Wmissing-declarations])
DPKG_CHECK_COMPILER_FLAG([-Wmissing-format-attribute])
DPKG_CHECK_COMPILER_FLAG([-Wformat -Wformat-security])
DPKG_CHECK_COMPILER_FLAG([-Wsizeof-array-argument])
DPKG_CHECK_COMPILER_FLAG([-Wpointer-arith])
DPKG_CHECK_COMPILER_FLAG([-Wlogical-op])
DPKG_CHECK_COMPILER_FLAG([-Wlogical-not-parentheses])
DPKG_CHECK_COMPILER_FLAG([-Wswitch-bool])
DPKG_CHECK_COMPILER_FLAG([-Wvla])
DPKG_CHECK_COMPILER_FLAG([-Winit-self])
DPKG_CHECK_COMPILER_FLAG([-Wwrite-strings])
DPKG_CHECK_COMPILER_FLAG([-Wcast-align])
DPKG_CHECK_COMPILER_FLAG([-Wshadow])
DPKG_CHECK_COMPILER_FLAG([-Wduplicated-cond])
DPKG_CHECK_COMPILER_FLAG([-Wnull-dereference])
DPKG_CHECK_COMPILER_FLAG([-Wdeclaration-after-statement])
DPKG_CHECK_COMPILER_FLAG([-Wnested-externs])
DPKG_CHECK_COMPILER_FLAG([-Wbad-function-cast])
DPKG_CHECK_COMPILER_FLAG([-Wstrict-prototypes])
DPKG_CHECK_COMPILER_FLAG([-Wmissing-prototypes])
DPKG_CHECK_COMPILER_FLAG([-Wold-style-definition])

AC_CONFIG_FILES([
	Makefile
	test/Makefile
	test/atlocal
])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
