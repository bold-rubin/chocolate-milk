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
    apt-get install -y git make autoconf automake libtool zlib1g-dev

# Clone libpng repository and checkout specific commit
RUN git clone --no-checkout https://github.com/glennrp/libpng.git $SRC/libpng && \
    cd $SRC/libpng && \
    git checkout a37d4836519517bdce6cb9d956092321eca3e73b

WORKDIR $SRC/libpng

# Copy patch files
COPY patches $SRC/patches

RUN find $SRC/patches -type f -name '*.patch' | while read patch; do \
        echo "Applying patch: $patch"; \
        name=${patch##*/}; \
        name=${name%.patch}; \
        sed "s/%MAGMA_BUG%/$name/g" "$patch" | patch -p1 -d "$SRC/libpng"; \
    done

RUN git config --global user.email "foo@bar" && git config --global user.name "Foo Bar"
RUN cd $SRC/libpng && git add --all && \
    git commit -m "Applied MAGMA patches"

# Copy build script
COPY build.sh $SRC/
