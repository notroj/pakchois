#!/bin/sh -ex
libtoolize --force --copy
aclocal
autoheader
automake --ignore-deps --foreign --copy --force
rm -rf autom4te*
