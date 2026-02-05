#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/php" ]; then
    echo "php source must be available in $SRC/php"
    exit 1
fi

cd $SRC/php
export ONIG_CFLAGS="-I$PWD/oniguruma/src"
export ONIG_LIBS="-L$PWD/oniguruma/src/.libs -l:libonig.a"

# PHP's zend_function union is incompatible with the object-size sanitizer
export EXTRA_CFLAGS="$CFLAGS -fno-sanitize=object-size"
export EXTRA_CXXFLAGS="$CXXFLAGS -fno-sanitize=object-size"
export LDFLAGS="-stdlib=libc++"

unset CFLAGS
unset CXXFLAGS

#build the php library
./buildconf
./configure \
    --disable-all \
    --enable-option-checking=fatal \
    --enable-fuzzer \
    --enable-exif \
    --enable-phar \
    --enable-intl \
    --enable-mbstring \
    --without-pcre-jit \
    --disable-phpdbg \
    --disable-cgi \
    --with-pic

make -j$(nproc) clean

# build oniguruma and link statically
pushd oniguruma
autoreconf -vfi
./configure --disable-shared
make -j$(nproc)
popd

make -j$(nproc)

# Generate seed corpora
sapi/cli/php sapi/fuzzer/generate_unserialize_dict.php
sapi/cli/php sapi/fuzzer/generate_parser_corpus.php

FUZZERS="php-fuzz-json php-fuzz-exif php-fuzz-mbstring php-fuzz-unserialize php-fuzz-parser"
for fuzzerName in $FUZZERS; do
	cp sapi/fuzzer/$fuzzerName "$OUT/${fuzzerName/php-fuzz-/}"
done

for fuzzerName in `ls sapi/fuzzer/corpus`; do
    mkdir -p "$SRC/corpus/${fuzzerName}"
    cp sapi/fuzzer/corpus/${fuzzerName}/* "$SRC/corpus/${fuzzerName}/"
done
