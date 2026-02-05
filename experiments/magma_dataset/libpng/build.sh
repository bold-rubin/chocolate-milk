#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/libpng" ]; then
    echo "libpng source must be available in $SRC/libpng"
    exit 1
fi

# build the libpng library
cd $SRC/libpng
autoreconf -f -i
./configure --with-libpng-prefix=MAGMA_ --disable-shared
make -j$(nproc) clean
make -j$(nproc) libpng16.la

cp .libs/libpng16.a "$OUT/"

LDFLAGS=""
LIBS=""
# build libpng_read_fuzzer.
$CXX $CXXFLAGS -std=c++11 -I. \
     -fsanitize=fuzzer \
     contrib/oss-fuzz/libpng_read_fuzzer.cc \
     -o $OUT/libpng_read_fuzzer \
     $LDFLAGS .libs/libpng16.a $LIBS -lz