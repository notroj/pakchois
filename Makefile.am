lib_LTLIBRARIES = libpakchois.la
libpakchois_la_SOURCES = pakchois.c errors.c pakchois11.h pakchois.h
libpakchois_la_LDFLAGS = -version-info $(PK_LTVERSINFO)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pakchois.pc

libpakchois_includedir = $(includedir)/pakchois
libpakchois_include_HEADERS = pakchois11.h pakchois.h

noinst_PROGRAMS = test
test_SOURCES = test.c
test_LDADD = libpakchois.la

SUBDIRS = po

EXTRA_DIST = COPYING COPYING.P11

