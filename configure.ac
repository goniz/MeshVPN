#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

AC_INIT([meshvpn], [0.1.44], [b.kuebler@kuebler-it.de])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([z], [compress])
AC_CHECK_LIB([ssl], [SSL_library_init])
AC_CHECK_LIB([crypto], [ENGINE_init])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h stdio.h unistd.h stdint.h string.h time.h signal.h])
AC_CHECK_HEADERS([fcntl.h seccomp.h netdb.h net/if.h netinet/in.h])
AC_CHECK_HEADERS([sys/types.h sys/stat.h sys/ioctl.h sys/select.h sys/socket.h])
AC_CHECK_HEADERS([grp.h pwd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset select socket])

# Sanity check for configure
AC_CONFIG_SRCDIR([src/meshvpn.c])

# Also initialize automake
AM_INIT_AUTOMAKE([-Wall -Werror])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
  Makefile
  src/Makefile])

AC_OUTPUT
