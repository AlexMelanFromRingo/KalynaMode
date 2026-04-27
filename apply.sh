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

install -m 0644 "$SELF_DIR/src/modules/module_36000.c" "$HC_ROOT/src/modules/"
install -m 0644 "$SELF_DIR/src/modules/module_36100.c" "$HC_ROOT/src/modules/"

for f in inc_cipher_kalyna.h inc_cipher_kalyna.cl \
         m36000_a0-pure.cl m36000_a1-pure.cl m36000_a3-pure.cl \
         m36100_a0-pure.cl m36100_a1-pure.cl m36100_a3-pure.cl; do
  install -m 0644 "$SELF_DIR/OpenCL/$f" "$HC_ROOT/OpenCL/"
done

echo "Installed KalynaMode plugin into $HC_ROOT"
echo "Now run 'make -j' inside $HC_ROOT to build module_36000.so / module_36100.so."
