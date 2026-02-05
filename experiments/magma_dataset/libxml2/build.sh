#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/libxml2" ]; then
    echo "libxml2 source must be available in $SRC/libxml2"
    exit 1
fi

cd $SRC/libxml2
./autogen.sh \
	--with-http=no \
	--with-python=no \
	--with-lzma=yes \
	--with-threads=no \
	--disable-shared
make -j$(nproc) clean
make -j$(nproc) all

cp xmllint "$OUT/"

LDFLAGS="${LDFLAGS:-}"
LIBS="${LIBS:-}"

for fuzzer in libxml2_xml_read_memory_fuzzer libxml2_xml_reader_for_file_fuzzer; do
  $CXX $CXXFLAGS -std=c++11 -Iinclude/ -I"$SRC/libxml2-fuzzers/" \
      -fsanitize=fuzzer \
      "$SRC/libxml2-fuzzers/$fuzzer.cc" -o "$OUT/$fuzzer" \
      .libs/libxml2.a $LDFLAGS $LIBS -lz -llzma
done
