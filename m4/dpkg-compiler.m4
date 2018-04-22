# Copyright © 2013-2016 Guillem Jover <guillem@debian.org>

# DPKG_CHECK_COMPILER_FLAG
# ------------------------
AC_DEFUN([DPKG_CHECK_COMPILER_FLAG], [
  m4_define([dpkg_check_flag], m4_bpatsubst([$1], [^-Wno-], [-W]))

  AC_LANG_CASE(
  [C], [
    m4_define([dpkg_compiler], [$CC])
    m4_define([dpkg_varname], [CFLAGS])
    m4_define([dpkg_varname_save], [dpkg_save_CFLAGS])
    m4_define([dpkg_varname_export], [COMPILER_CFLAGS])
    AS_VAR_PUSHDEF([dpkg_varname_cache], [dpkg_cv_cflags_$1])
  ],
  [C++], [
    m4_define([dpkg_compiler], [$CXX])
    m4_define([dpkg_varname], [CXXFLAGS])
    m4_define([dpkg_varname_save], [dpkg_save_CXXFLAGS])
    m4_define([dpkg_varname_export], [COMPILER_CXXFLAGS])
    AS_VAR_PUSHDEF([dpkg_varname_cache], [dpkg_cv_cxxflags_$1])
  ])
  AC_CACHE_CHECK([whether ]dpkg_compiler[ accepts $1], [dpkg_varname_cache], [
    AS_VAR_COPY([dpkg_varname_save], [dpkg_varname])
    AS_VAR_SET([dpkg_varname], ["-Werror dpkg_check_flag"])
    AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([[]])
    ], [
      AS_VAR_SET([dpkg_varname_cache], [yes])
    ], [
      AS_VAR_SET([dpkg_varname_cache], [no])
    ])
    AS_VAR_COPY([dpkg_varname], [dpkg_varname_save])
  ])
  AS_VAR_IF([dpkg_varname_cache], [yes], [
    AS_VAR_APPEND([dpkg_varname_export], [" $1"])
  ])
  AS_VAR_POPDEF([dpkg_varname_cache])
])
