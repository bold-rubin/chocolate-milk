#!/bin/bash
set -e

# apt-get update && \
#     apt-get install -y make clang-14 llvm-14-dev libc++-14-dev libc++abi-14-dev \
#         build-essential git wget gcc-7-plugin-dev
apt-get update && apt-get install -y build-essential make git wget gcc-7-plugin-dev

update-alternatives \
  --install /usr/lib/llvm llvm /opt/llvm-14 200 \
  --slave   /usr/bin/llvm-config       llvm-config       /opt/llvm-14/bin/llvm-config \
  --slave   /usr/bin/llvm-ar           llvm-ar           /opt/llvm-14/bin/llvm-ar \
  --slave   /usr/bin/llvm-as           llvm-as           /opt/llvm-14/bin/llvm-as \
  --slave   /usr/bin/llvm-bcanalyzer   llvm-bcanalyzer   /opt/llvm-14/bin/llvm-bcanalyzer \
  --slave   /usr/bin/llvm-c-test       llvm-c-test       /opt/llvm-14/bin/llvm-c-test \
  --slave   /usr/bin/llvm-cov          llvm-cov          /opt/llvm-14/bin/llvm-cov \
  --slave   /usr/bin/llvm-diff         llvm-diff         /opt/llvm-14/bin/llvm-diff \
  --slave   /usr/bin/llvm-dis          llvm-dis          /opt/llvm-14/bin/llvm-dis \
  --slave   /usr/bin/llvm-dwarfdump    llvm-dwarfdump    /opt/llvm-14/bin/llvm-dwarfdump \
  --slave   /usr/bin/llvm-extract      llvm-extract      /opt/llvm-14/bin/llvm-extract \
  --slave   /usr/bin/llvm-link         llvm-link         /opt/llvm-14/bin/llvm-link \
  --slave   /usr/bin/llvm-mc           llvm-mc           /opt/llvm-14/bin/llvm-mc \
  --slave   /usr/bin/llvm-nm           llvm-nm           /opt/llvm-14/bin/llvm-nm \
  --slave   /usr/bin/llvm-objdump      llvm-objdump      /opt/llvm-14/bin/llvm-objdump \
  --slave   /usr/bin/llvm-ranlib       llvm-ranlib       /opt/llvm-14/bin/llvm-ranlib \
  --slave   /usr/bin/llvm-readobj      llvm-readobj      /opt/llvm-14/bin/llvm-readobj \
  --slave   /usr/bin/llvm-rtdyld       llvm-rtdyld       /opt/llvm-14/bin/llvm-rtdyld \
  --slave   /usr/bin/llvm-size         llvm-size         /opt/llvm-14/bin/llvm-size \
  --slave   /usr/bin/llvm-stress       llvm-stress       /opt/llvm-14/bin/llvm-stress \
  --slave   /usr/bin/llvm-symbolizer   llvm-symbolizer   /opt/llvm-14/bin/llvm-symbolizer \
  --slave   /usr/bin/llvm-tblgen       llvm-tblgen       /opt/llvm-14/bin/llvm-tblgen

update-alternatives \
  --install /usr/bin/clang     clang     /opt/llvm-14/bin/clang     200 \
  --slave   /usr/bin/clang++   clang++   /opt/llvm-14/bin/clang++ \
  --slave   /usr/bin/clang-cpp clang-cpp /opt/llvm-14/bin/clang-cpp

