#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Sébastien Millet, December 2012

AC_PREREQ([2.68])

AC_INIT([tcprelay], [1.2], [sebastien.millet1@club-internet.fr])

AC_CONFIG_SRCDIR([src/tcprelay.h])
AC_CONFIG_AUX_DIR([admin])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

dnl ==================== Options ====================================

AC_ARG_ENABLE(debug,
              [  --enable-debug          enable debugging information],
              enable_debug="$enableval", enable_debug="no")

if test "${enable_debug}" = yes ; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_STDBOOL
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit gethostbyname gettimeofday inet_ntoa memset select socket strerror strrchr])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 src/Makefile])
AC_OUTPUT
