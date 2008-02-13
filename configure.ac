AC_INIT([pakchois], 0.3, [joe@manyfish.co.uk])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([pakchois.c])
AM_INIT_AUTOMAKE

AC_PROG_LIBTOOL

AC_ARG_ENABLE(nls, 
  [AS_HELP_STRING([--enable-nls], [enable NLS support])],
  [AC_SEARCH_LIBS(dgettext, intl,,
    [AC_MSG_ERROR([could not find dgettext])])
   AC_DEFINE([ENABLE_NLS], 1, [Defined if NLS is supported])])
                        
# libtool library version -- CURRENT:REVISION:AGE
PK_LTVERSINFO=1:0:1
AC_SUBST(PK_LTVERSINFO)

module_path="${libdir}:${libdir}/pkcs11"

AC_ARG_ENABLE(module-path, 
  [AS_HELP_STRING([--enable-module-path], 
                  [PKCS#11 module directory search path])],
  [test $enableval != "yes" && module_path=${enableval}])

CPPFLAGS="$CPPFLAGS -DPAKCHOIS_MODPATH=\\\"${module_path}\\\""

test x$GCC = xyes && CFLAGS="$CFLAGS -Wall"

AC_CONFIG_FILES([Makefile pakchois.pc])
AC_OUTPUT
