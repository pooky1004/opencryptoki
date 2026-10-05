#!/usr/bin/env bash
#
# Token NCMP - Web Test App build + run helper.
#
# Builds the C web server (ncmp_web) which compiles in the native app_* layer
# (native/ncmp_testapp.c) and serves the static web UI in web/. The server
# dlopen's the facade STDLL at runtime and can launch ncmpd itself.
#
#   Browser --HTTP/JSON--> ncmp_web --app_*--> libncmp_testapp
#       --dlopen C_*--> libpkcs11_ncmp.so(facade) --> ncmpd --> FX3(USB)
#
# Usage:
#   ncmp/gui/testapp/build.sh            # build facade/ncmpd + ncmp_web
#   ncmp/gui/testapp/build.sh --server   # build only ncmp_web
#   ncmp/gui/testapp/build.sh --run      # build, then run on 0.0.0.0:8080 (mock)
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"          # <repo>/ncmp/gui/testapp -> <repo>
out="$here/build"
mkdir -p "$out"

do_facade=1 do_run=0
case "${1:-}" in
  --server) do_facade=0 ;;
  --run) do_run=1 ;;
  "") ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

if [[ "$do_facade" == 1 ]]; then
  echo "== building standalone facade + ncmpd =="
  bash "$repo/ncmp/gui/build_standalone_p11.sh" || \
    echo "(facade build failed; the server can still load any libpkcs11_ncmp.so)" >&2
fi

echo "== building ncmp_web =="
gcc -std=gnu11 -D_GNU_SOURCE -O2 -Wall -Wextra \
    -I "$here/native" -I "$repo/usr/include" -I "$repo/ncmp/include" \
    "$here/webserver/ncmp_web.c" "$here/native/ncmp_testapp.c" \
    "$repo/ncmp/stdll/ncmp_client.c" "$repo"/ncmp/common/*.c \
    -lpthread -ldl -lcrypto -lrt -o "$out/ncmp_web"
echo "   -> $out/ncmp_web"

facade="$repo/ncmp/gui/build-standalone/libpkcs11_ncmp_p11.so"
ncmpd="$repo/ncmp/gui/build-standalone/ncmpd"

cat <<EOF

done. Run the web server (serves the UI + REST API):
  # (a) using the config file ($here/.config/config): run from the testapp dir
  (cd $here && build/ncmp_web)
  # (b) or pass everything explicitly:
  $out/ncmp_web \\
      --host 0.0.0.0 --port 8080 \\
      --webroot $here/web \\
      --module $facade \\
      --ncmpd $ncmpd --transport real
Then open  http://<this-host>:8080/  from any machine on the network.
Edit $here/.config/config to set the port, bind host, auth token, etc.
(Default transport is real (FX3 over USB); use --transport mock without
 hardware. See docs/testapp-web-deployment.md for firewall/systemd/auth setup.)
EOF

if [[ "$do_run" == 1 ]]; then
  echo "== running (0.0.0.0:8080, real) =="
  exec "$out/ncmp_web" --host 0.0.0.0 --port 8080 --webroot "$here/web" \
       --module "$facade" --ncmpd "$ncmpd" --transport real
fi
