dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.58)
AC_INIT([scheme-dict], [1.0.0], [nikolai+work.bugs@bitwi.se])
AM_INIT_AUTOMAKE([1.7 foreign dist-bzip2])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([src/scheme-dict.in])

dnl Checks for programs.
GUILE_PROGS
GUILE_SITE_DIR
AC_PROG_INSTALL
AM_MISSING_PROG([AUTOM4TE], [autom4te])

dnl Output files.
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/scheme-dict])
AC_CONFIG_COMMANDS([chmod],
                   [chmod +x src/scheme-dict])
AC_OUTPUT
