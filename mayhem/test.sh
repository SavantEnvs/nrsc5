#!/usr/bin/env bash
#
# mayhem/test.sh — upstream's own functional check (its CI "Test" step): decode the recorded HD Radio
# IQ capture support/sample.xz with the nrsc5 CLI and with support/cli.py (the Python ctypes binding over
# libnrsc5.so), each from a file and from stdin (built by build.sh with normal flags), and assert
# the decoded station metadata and audio. A no-op nrsc5 produces no log/audio and fails every check.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

NRSC5="$SRC/build-tests/src/nrsc5"
if [ ! -x "$NRSC5" ]; then
  echo "FATAL: $NRSC5 missing — run mayhem/build.sh first" >&2
  emit_ctrf "nrsc5-sample-decode" 0 1
  exit 1
fi
LIBDIR="$SRC/build-tests/src"
if [ ! -f "$LIBDIR/libnrsc5.so" ]; then
  echo "FATAL: $LIBDIR/libnrsc5.so missing — run mayhem/build.sh first" >&2
  emit_ctrf "nrsc5-sample-decode" 0 1
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/nrsc5-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
xz -d < support/sample.xz > "$work/sample"

passed=0 failed=0
check() { # check <name> <command...>
  local name="$1"; shift
  if "$@"; then echo "PASS: $name"; passed=$((passed+1)); else echo "FAIL: $name"; failed=$((failed+1)); fi
}

# 1) decode from a file (as upstream CI: nrsc5 -r sample -o sample.wav 0)
"$NRSC5" -r "$work/sample" -o "$work/file.wav" 0 2> "$work/file.log"
check "file: synchronized"        grep -q "Synchronized" "$work/file.log"
check "file: station name KUT"    grep -q "Station name: KUT" "$work/file.log"
check "file: ID3 title"           grep -q "Title: You're Listening to Q with Jian Ghomeshi" "$work/file.log"
check "file: SIS slogan"          grep -q "Slogan: The University of Texas at Austin" "$work/file.log"
check "file: facility id"         grep -q "FCC facility ID: 21" "$work/file.log"
check "file: audio service 0"     grep -q "Audio service 0: public" "$work/file.log"
check "file: wav has audio"       test "$(stat -c %s "$work/file.wav" 2>/dev/null || echo 0)" -gt 1000000

# 2) decode from stdin (upstream CI: cat sample | nrsc5 -r - ...)
"$NRSC5" -r - -o "$work/pipe.wav" 0 < "$work/sample" 2> "$work/pipe.log"
check "stdin: ID3 title"          grep -q "Title: You're Listening to Q" "$work/pipe.log"
check "stdin: same audio as file" cmp -s "$work/file.wav" "$work/pipe.wav"

# 3) the Python binding over libnrsc5.so, from a file (upstream CI: support/cli.py -r sample ...)
LD_LIBRARY_PATH="$LIBDIR" python3 support/cli.py -r "$work/sample" -o "$work/py.wav" 0 2> "$work/py.log"
check "cli.py file: ID3 title"    grep -q "Title: You're Listening to Q" "$work/py.log"
check "cli.py file: station KUT"  grep -q "Station name: KUT" "$work/py.log"
check "cli.py file: wav has audio" test "$(stat -c %s "$work/py.wav" 2>/dev/null || echo 0)" -gt 1000000

# 4) the Python binding from stdin (upstream CI: cat sample | support/cli.py -r - ...)
LD_LIBRARY_PATH="$LIBDIR" python3 support/cli.py -r - -o "$work/pypipe.wav" 0 < "$work/sample" 2> "$work/pypipe.log"
check "cli.py stdin: ID3 title"   grep -q "Title: You're Listening to Q" "$work/pypipe.log"
# (Python's wave module writes its own WAV header, so compare the two cli.py outputs with each other.)
check "cli.py stdin: same audio as file" cmp -s "$work/py.wav" "$work/pypipe.wav"

emit_ctrf "nrsc5-sample-decode" "$passed" "$failed"
