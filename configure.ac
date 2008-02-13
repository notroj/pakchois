AC_INIT([pakchois], 0.3, [joe@manyfish.co.uk])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([pakchois.c])
AM_INIT_AUTOMAKE

AC_PROG_LIBTOOL

LINGUAS=""
AM_GNU_GETTEXT([external], [need-ngettext])

# libtool library version -- CURRENT:REVISION:AGE
PK_LTVERSINFO=1:0:1

module_path="${libdir}:${libdir}/pkcs11"

AC_ARG_ENABLE(module-path, 
  [AS_HELP_STRING([--enable-module-path], 
                  [PKCS#11 module directory search path])],
  [test $enableval != "yes" && module_path=${enableval}])

CPPFLAGS="$CPPFLAGS -DPAKCHOIS_MODPATH=\\\"${module_path}\\\""

test x$GCC = xyes && CFLAGS="$CFLAGS -Wall"

AC_SUBST(PK_LTVERSINFO)
AC_SUBST(LINGUAS)

AC_CONFIG_FILES([Makefile pakchois.pc po/Makefile.in])
AC_OUTPUT
