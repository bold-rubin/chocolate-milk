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
    apt-get install -y git make libreadline-dev

# Clone lua repository and checkout specific commit
RUN git clone --no-checkout https://github.com/lua/lua.git $SRC/lua && \
    cd $SRC/lua && \
    git checkout dbdc74dc5502c2e05e1c1e2ac894943f418c8431

WORKDIR $SRC/lua

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
RUN cd $SRC/lua && git add --all && \
    git commit -m "Applied MAGMA patches"

# Copy build script
COPY build.sh $SRC/
