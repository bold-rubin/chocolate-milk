#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/lua" ]; then
    echo "lua source must be available in $SRC/lua"
    exit 1
fi

# build lua library
cd $SRC/lua
make -j$(nproc) clean
make -j$(nproc) liblua.a

cp liblua.a "$OUT/"

export LDFLAGS="-lasan"

# build driver
make -j$(nproc) lua
cp lua "$OUT/"
