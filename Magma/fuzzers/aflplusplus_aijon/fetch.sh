#!/bin/bash
set -e

##
# Pre-requirements:
# - env FUZZER: path to fuzzer work dir
##

git clone --no-checkout https://github.com/AFLplusplus/AFLplusplus "$FUZZER/repo"
git -C "$FUZZER/repo" checkout 93a6e1dbd19da92702dd7393d1cd1b405a6c29ee

# Fix: CMake-based build systems fail with duplicate (of main) or undefined references (of LLVMFuzzerTestOneInput)
# sed -i '{s/^int main/__attribute__((weak)) &/}' $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c
# sed -i '{s/^int LLVMFuzzerTestOneInput/__attribute__((weak)) &/}' $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c
# cat >> $FUZZER/repo/utils/aflpp_driver/aflpp_driver.c << EOF
# __attribute__((weak))
# int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
# {
#   // assert(0 && "LLVMFuzzerTestOneInput should not be implemented in afl_driver");
#   return 0;
# }
# EOF

patch -p1 -d "$FUZZER/repo" << EOF
diff --git a/instrumentation/SanitizerCoveragePCGUARD.so.cc b/instrumentation/SanitizerCoveragePCGUARD.so.cc
index 1b831aaf..469b3f05 100644
--- a/instrumentation/SanitizerCoveragePCGUARD.so.cc
+++ b/instrumentation/SanitizerCoveragePCGUARD.so.cc
@@ -536,8 +536,8 @@ bool ModuleSanitizerCoverageAFL::instrumentModule(
   if (ijon_enabled) {

     // Always create __afl_ijon_enabled for IJON memory allocation
-    Constant *One32 = ConstantInt::get(Int32Ty, 1);
-    new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, One32,
+    // Constant *One32 = ConstantInt::get(Int32Ty, 1);
+    new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, nullptr,
                        "__afl_ijon_enabled");

     // Only create __afl_ijon_state if state-aware functions are used
diff --git a/instrumentation/afl-compiler-rt.o.c b/instrumentation/afl-compiler-rt.o.c
index 5b179f6d..9dcb232d 100644
--- a/instrumentation/afl-compiler-rt.o.c
+++ b/instrumentation/afl-compiler-rt.o.c
@@ -421,6 +421,10 @@ static void __afl_map_shm(void) {
     __afl_ijon_map_increased = 1;

   }
+  if (getenv("AFL_ENABLE_IJON")) {
+      fprintf(stderr, "DEBUG: Enabling IJON via AFL_ENABLE_IJON\n");
+      __afl_ijon_enabled = 1;
+  }

   char *id_str = getenv(SHM_ENV_VAR);
EOF
