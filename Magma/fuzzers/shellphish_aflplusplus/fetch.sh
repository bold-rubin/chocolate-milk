#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone -b v4.30c https://github.com/AFLplusplus/AFLplusplus "$FUZZER/repo"
