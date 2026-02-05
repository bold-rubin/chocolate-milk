# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install -y git make autoconf automake libtool pkg-config cmake \
    zlib1g-dev libjpeg-dev libopenjp2-7-dev libpng-dev libcairo2-dev \
    libtiff-dev liblcms2-dev libboost-dev libbrotli-dev libbz2-1.0 libbz2-dev

# Clone poppler repository and checkout specific commit
RUN git clone --no-checkout https://gitlab.freedesktop.org/poppler/poppler.git $SRC/poppler && \
    cd $SRC/poppler && \
    git checkout 1d23101ccebe14261c6afc024ea14f29d209e760

# Clone freetype2 dependency
RUN git clone --no-checkout git://git.sv.nongnu.org/freetype/freetype2.git $SRC/freetype2 && \
    cd $SRC/freetype2 && \
    git checkout 50d0033f7ee600c5f5831b28877353769d1f7d48

WORKDIR $SRC/poppler

# Copy custom fuzzer sources
COPY src/*.cc $SRC/poppler-fuzzers/

# Copy patch files
COPY patches/bugs/*.patch $SRC/bug-patches/

# Apply bug patches
RUN cd $SRC/poppler && \
    find $SRC/bug-patches -type f -name '*.patch' | while read patch; do \
        echo "Applying patch: $patch"; \
        name=${patch##*/}; \
        name=${name%.patch}; \
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1; \
    done

RUN git config --global user.email "foo@bar" && git config --global user.name "Foo Bar"
RUN cd $SRC/poppler && git add --all && \
    git commit -m "Applied MAGMA patches"

# Copy build script
COPY build.sh $SRC/
