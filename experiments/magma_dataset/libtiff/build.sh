#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/libtiff" ]; then
    echo "libtiff source must be available in $SRC/libtiff"
    exit 1
fi

WORK="$SRC/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

cd $SRC/libtiff
./autogen.sh
./configure --disable-shared --prefix="$WORK"
make -j$(nproc) clean
make -j$(nproc)
make install

cp "$WORK/bin/tiffcp" "$OUT/"

LDFLAGS="${LDFLAGS:-}"
LIBS="${LIBS:-}"

$CXX $CXXFLAGS -std=c++11 -I$WORK/include \
    -fsanitize=fuzzer \
    contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o $OUT/tiff_read_rgba_fuzzer \
    $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic \
    $LDFLAGS $LIBS
