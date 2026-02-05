#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/sqlite3" ]; then
    echo "sqlite3 source must be available in $SRC/sqlite3"
    exit 1
fi

# build the sqlite3 library
cd "$SRC/sqlite3"

export WORK="$SRC/work"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
               -DSQLITE_MAX_SQL_LENGTH=128000000 \
               -DSQLITE_MAX_MEMORY=25000000 \
               -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
               -DSQLITE_DEBUG=1 \
               -DSQLITE_MAX_PAGE_COUNT=16384"

"$SRC/sqlite3"/configure --disable-shared --enable-rtree
make clean
make -j$(nproc)
make sqlite3.c

LDFLAGS="${LDFLAGS:-}"
LIBS="${LIBS:-}"

$CC $CFLAGS -I. \
    -fsanitize=fuzzer \
    "$SRC/sqlite3/test/ossfuzz.c" "./sqlite3.o" \
    -o "$OUT/sqlite3_fuzz" \
    $LDFLAGS $LIBS -pthread -ldl -lm
