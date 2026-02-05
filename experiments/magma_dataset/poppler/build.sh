
#!/bin/bash
set -e

##
# Pre-requirements:
# - env SRC: path to source directory
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, CXXFLAGS, LDFLAGS, LIBS, etc...
##

if [ ! -d "$SRC/poppler" ]; then
    echo "poppler source must be available in $SRC/poppler"
    exit 1
fi

export WORK="$SRC/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CXXFLAGS="${CXXFLAGS/-stdlib=libc++/-stdlib=libstdc++}"

export CXXFLAGS="-D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -DHAVE_STRTOK_R=1 -DHAVE_DIRENT_H=1 -include unistd.h -include dirent.h $CXXFLAGS"
export CFLAGS="-D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -DHAVE_STRTOK_R=1 -DHAVE_DIRENT_H=1 -include unistd.h -include dirent.h ${CFLAGS:-}"

pushd "$SRC/freetype2"
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc) clean
make -j$(nproc)
make install

mkdir -p "$WORK/poppler"
cd "$WORK/poppler"
rm -rf *

EXTRA=""
AR=""
RANLIB=""
test -n "$AR" && EXTRA="$EXTRA -DCMAKE_AR=$AR"
test -n "$RANLIB" && EXTRA="$EXTRA -DCMAKE_RANLIB=$RANLIB"

LDFLAGS="${LDFLAGS:-}"
LIBS="${LIBS:-}"
LIBS="$LIBS -lbrotlidec -lbz2"

CPPFLAGS="${CPPFLAGS:-}"
export CPPFLAGS="-D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -DHAVE_DIRENT_H=1 $CPPFLAGS"

cmake "$SRC/poppler" \
  $EXTRA \
  -DCMAKE_BUILD_TYPE=debug \
  -DCMAKE_CXX_STANDARD=14 \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DBUILD_GTK_TESTS=OFF \
  -DBUILD_QT5_TESTS=OFF \
  -DBUILD_CPP_TESTS=OFF \
  -DENABLE_LIBPNG=ON \
  -DENABLE_LIBTIFF=ON \
  -DENABLE_LIBJPEG=ON \
  -DENABLE_SPLASH=ON \
  -DENABLE_UTILS=ON \
  -DWITH_Cairo=ON \
  -DENABLE_CMS=none \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_GLIB=OFF \
  -DENABLE_GOBJECT_INTROSPECTION=OFF \
  -DENABLE_QT5=OFF \
  -DENABLE_LIBCURL=OFF \
  -DWITH_NSS3=OFF \
  -DFREETYPE_INCLUDE_DIRS="$WORK/include/freetype2" \
  -DFREETYPE_LIBRARY="$WORK/lib/libfreetype.a" \
  -DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" \
  -DCMAKE_C_FLAGS="$CPPFLAGS $CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CPPFLAGS $CXXFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS_INIT="$LIBS"
make -j$(nproc) poppler poppler-cpp pdfimages pdftoppm
EXTRA=""

cp "$WORK/poppler/utils/"{pdfimages,pdftoppm} "$OUT/"
$CXX $CXXFLAGS -std=c++11 -I"$WORK/poppler/cpp" -I"$SRC/poppler/cpp" \
    -fsanitize=fuzzer \
    "$SRC/poppler-fuzzers/pdf_fuzzer.cc" -o "$OUT/pdf_fuzzer" \
    "$WORK/poppler/cpp/libpoppler-cpp.a" "$WORK/poppler/libpoppler.a" \
    "$WORK/lib/libfreetype.a" $LDFLAGS $LIBS -ljpeg -lz \
    -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread
