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
    apt-get install -y git make autoconf automake libtool pkg-config zlib1g-dev \
    liblzma-dev

# Clone libxml2 repository and checkout specific commit
RUN git clone --no-checkout https://gitlab.gnome.org/GNOME/libxml2.git $SRC/libxml2 && \
    cd $SRC/libxml2 && \
    git checkout ec6e3efb06d7b15cf5a2328fabd3845acea4c815

WORKDIR $SRC/libxml2

# Copy custom fuzzer sources
COPY src/*.cc $SRC/libxml2-fuzzers/
COPY src/*.h $SRC/libxml2-fuzzers/

# Copy patch files
COPY patches/setup/*.patch $SRC/setup-patches/
COPY patches/bugs/*.patch $SRC/bug-patches/

# Apply setup patches
RUN for patch in $SRC/setup-patches/*.patch; do \
        [ -f "$patch" ] && patch -p1 < "$patch"; \
    done

# Apply bug patches
RUN find $SRC/bug-patches -type f -name '*.patch' | while read patch; do \
        echo "Applying patch: $patch"; \
        name=${patch##*/}; \
        name=${name%.patch}; \
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1; \
    done

RUN git config --global user.email "foo@bar" && git config --global user.name "Foo Bar"
RUN cd $SRC/libxml2 && git add --all && \
    git commit -m "Applied MAGMA patches"

# Copy build script
COPY build.sh $SRC/
