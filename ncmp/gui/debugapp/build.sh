#!/usr/bin/env bash
#
# Token NCMP - Debug App build/run helper.
#
# Builds ncmp_dbg (the SHM inspector web server) directly with gcc, compiling in
# the ncmp common sources (IPC + SHM helpers). No PKCS#11 / facade dependency.
#
#   Browser --HTTP/JSON--> ncmp_dbg --ncmp_ipc handshake--> ncmpd conn_thread
#                                   --attach(read-only) SHM--> per-slot metadata
#
# Usage:
#   ncmp/gui/debugapp/build.sh           # build build/ncmp_dbg
#   ncmp/gui/debugapp/build.sh --run     # build, then serve on 0.0.0.0:8090
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
out="$here/build"; mkdir -p "$out"

echo "== building ncmp_dbg =="
gcc -std=gnu11 -D_GNU_SOURCE -O2 -Wall -Wextra \
    -I "$repo/ncmp/include" \
    "$here/server/ncmp_dbg.c" \
    "$repo/ncmp/stdll/ncmp_client.c" \
    "$repo"/ncmp/common/*.c \
    -lpthread -lrt -o "$out/ncmp_dbg"
echo "   -> $out/ncmp_dbg"

cat <<EOF

done. Run the Debug App (ncmpd must be running; share its NCMP_SOCK_PATH):
  export NCMP_SOCK_PATH=/tmp/ncmpd.sock          # same path ncmpd uses
  $out/ncmp_dbg --host 0.0.0.0 --port 8090 --webroot $here/web
Then open  http://<this-host>:8090/  from any machine on the network.
(Config file: $here/.config/config ; see docs/debugapp-deployment.md for
 firewall/systemd/auth setup.)
EOF

if [[ "${1:-}" == "--run" ]]; then
  exec "$out/ncmp_dbg" --host 0.0.0.0 --port 8090 --webroot "$here/web"
fi
