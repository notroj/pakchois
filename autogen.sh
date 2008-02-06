#!/bin/sh -ex
libtoolize --force --copy
aclocal
autoheader
autoconf
automake --ignore-deps --foreign --copy --force --add-missing
rm -rf autom4te*
