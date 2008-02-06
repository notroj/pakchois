lib_LTLIBRARIES = libpakchois.la
libpakchois_la_SOURCES = pakchois.c pakchois11.h pakchois.h
libpakchois_la_LDFLAGS = -version-info 0:0:0 -ldl

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pakchois.pc

libpakchois_includedir = $(includedir)/pakchois
libpakchois_include_HEADERS = pakchois11.h pakchois.h

bin_PROGRAMS = test
test_SOURCES = test.c
test_LDADD = libpakchois.la
