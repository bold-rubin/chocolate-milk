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
    apt-get install -y git make autoconf automake libtool bison re2c pkg-config \
    libicu-dev

# Clone php-src repository and checkout specific commit
RUN git clone --no-checkout https://github.com/php/php-src.git $SRC/php && \
    cd $SRC/php && \
    git checkout bc39abe8c3c492e29bc5d60ca58442040bbf063b

# Clone oniguruma dependency
RUN git clone --no-checkout https://github.com/kkos/oniguruma.git $SRC/php/oniguruma && \
    cd $SRC/php/oniguruma && \
    git checkout 227ec0bd690207812793c09ad70024707c405376

WORKDIR $SRC/php

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
RUN cd $SRC/php && git add --all && \
    git commit -m "Applied MAGMA patches"

# Copy build script
COPY build.sh $SRC/
