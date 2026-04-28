#!/usr/bin/env bash
# Copy KalynaMode plugin files into a hashcat checkout.
#
#   ./apply.sh /path/to/hashcat
#
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-hashcat>" >&2
  exit 2
fi

HC_ROOT=$1
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if [[ ! -d "$HC_ROOT/src/modules" || ! -d "$HC_ROOT/OpenCL" ]]; then
  echo "error: $HC_ROOT does not look like a hashcat checkout" >&2
  exit 1
fi

for m in 36000 36100 36200 36300 36400; do
  install -m 0644 "$SELF_DIR/src/modules/module_${m}.c" "$HC_ROOT/src/modules/"
done

install -m 0644 "$SELF_DIR/OpenCL/inc_cipher_kalyna.h"  "$HC_ROOT/OpenCL/"
install -m 0644 "$SELF_DIR/OpenCL/inc_cipher_kalyna.cl" "$HC_ROOT/OpenCL/"

# attack-mode kernels: a0/a1/a3 for 36000-36200 (small/medium keys),
# a0/a3 only for 36300/36400 (combinators on 64-byte raw keys are not
# a common workflow).
for m in 36000 36100 36200; do
  for a in a0 a1 a3; do
    install -m 0644 "$SELF_DIR/OpenCL/m${m}_${a}-pure.cl" "$HC_ROOT/OpenCL/"
  done
done
for m in 36300 36400; do
  for a in a0 a3; do
    install -m 0644 "$SELF_DIR/OpenCL/m${m}_${a}-pure.cl" "$HC_ROOT/OpenCL/"
  done
done

echo "Installed KalynaMode plugin into $HC_ROOT"
echo "Now run 'make -j' inside $HC_ROOT to build module_3600{0,1,2,3,4}.so"
