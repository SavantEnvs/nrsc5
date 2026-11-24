#!/usr/bin/env bash
#
# mayhem/build.sh — build nrsc5's fuzz harnesses (sanitized libnrsc5_static + 4 harnesses, each also
# as a -standalone reproducer) and the nrsc5 CLI with normal flags for mayhem/test.sh.
# Runs in the commit image as `mayhem` in /mayhem; re-runnable and offline (FAAD2 comes from
# /opt/toolchains/deps, fftw/rtl-sdr/libao from apt).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FAAD2=/opt/toolchains/deps/faad2-2.11.2
# Upstream's INSTALLED_FAAD_IS_PATCHED path finds a pre-patched FAAD2 instead of git-fetching it, but its
# found-check tests the never-set FAAD2_LIBRARY, so we pass that cache variable too.
FAAD_ARGS=(
  -DINSTALLED_FAAD_IS_PATCHED=ON
  -DFAAD2_INCLUDE_DIRS="$FAAD2/include"
  -DFAAD2_LIBRARIES="$FAAD2/lib/libfaad_hdc.a"
  -DFAAD2_LIBRARY="$FAAD2/lib/libfaad_hdc.a"
)

# 1) The library, instrumented: sanitizers + SanCov (fuzzer-no-link, unconditionally) so the fuzzed
#    code carries coverage. build-fuzz/ is gitignored by upstream's /build*/.
cmake -S . -B build-fuzz -DBUILD_CLI=OFF "${FAAD_ARGS[@]}" \
      -DCMAKE_C_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target nrsc5_static

# 2) Harnesses: libFuzzer binary + standalone reproducer each, LSan off (mayhem/lsan_off.c).
HFLAGS=(-std=gnu11 -D_GNU_SOURCE -DHAVE_FAAD2 -I"$SRC/include" -I"$SRC/src"
        -I"$SRC/build-fuzz/src" -I"$FAAD2/include")
LIBS=("$SRC/build-fuzz/src/libnrsc5_static.a" "$FAAD2/lib/libfaad_hdc.a" -lfftw3f -lrtlsdr -lpthread -lm)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$SRC/build-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build-fuzz/standalone_main.o"
for h in fuzz_aas fuzz_frame fuzz_pids fuzz_pipe; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${HFLAGS[@]}" \
      "$SRC/mayhem/harnesses/$h.c" "$SRC/build-fuzz/lsan_off.o" "${LIBS[@]}" -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${HFLAGS[@]}" \
      "$SRC/mayhem/harnesses/$h.c" "$SRC/build-fuzz/standalone_main.o" "$SRC/build-fuzz/lsan_off.o" \
      "${LIBS[@]}" -o "$SRC/$h-standalone"
done

# 3) The nrsc5 CLI and the libnrsc5.so shared library (loaded by support/cli.py via ctypes) with
#    upstream's normal flags, for mayhem/test.sh (upstream CI's four sample decodes).
cmake -S . -B build-tests "${FAAD_ARGS[@]}" \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS" --target app nrsc5
