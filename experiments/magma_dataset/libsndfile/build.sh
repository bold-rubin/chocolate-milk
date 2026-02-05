#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/libsndfile" ]; then
    echo "libsndfile source must be available in $SRC/libsndfile"
    exit 1
fi

cd $SRC/libsndfile
./autogen.sh
./configure --disable-shared --enable-ossfuzzers
make -j$(nproc) clean
make -j$(nproc)

cp -v ossfuzz/sndfile_fuzzer $OUT/