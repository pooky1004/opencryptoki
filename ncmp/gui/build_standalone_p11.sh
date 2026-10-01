#!/bin/sh
# Build a runnable mode-2 demo WITHOUT a full opencryptoki build:
#   - libpkcs11_ncmp_p11.so : the standalone PKCS#11 provider facade
#       (usr/lib/ncmp_stdll/ncmp_p11.c) + the ncmp adapters/client/common.
#       Exports C_* only (mode 2). The production libpkcs11_ncmp.so additionally
#       carries SC_*/ST_Initialize (mode 1) and is built by opencryptoki autotools.
#   - ncmpd_mock : the daemon with the in-process mock transport.
#
# Then run (non-root; rendezvous via NCMP_SOCK_PATH):
#   export NCMP_SOCK_PATH=/tmp/ncmpd.sock
#   ./<out>/ncmpd_mock &
#   NCMP_PKCS11_MODULE=./<out>/libpkcs11_ncmp_p11.so \
#       python3 ncmp/gui/py/app_gui.py          # PKCS#11 (real stack) tab
#
# The tab's C_Initialize connects to ncmpd's conn thread + attaches the shared
# memory; C_OpenSession points at that slot in SHM; each C_* enqueues onto the
# slot's ring, which the daemon's comm thread drains via the mock token.
set -e

ROOT=$(cd "$(dirname "$0")/../.." && pwd)   # repo root
OUT=${1:-$ROOT/ncmp/gui/build-standalone}
mkdir -p "$OUT"

CFLAGS="-std=gnu11 -D_GNU_SOURCE -O2 -Wall -I$ROOT/usr/include -I$ROOT/ncmp/include"

echo "building $OUT/libpkcs11_ncmp_p11.so (mode-2 provider)"
gcc $CFLAGS -shared -fPIC \
    "$ROOT/usr/lib/ncmp_stdll/ncmp_p11.c" \
    "$ROOT/ncmp/stdll/ncmp_crypto.c" "$ROOT/ncmp/stdll/ncmp_admin.c" \
    "$ROOT/ncmp/stdll/ncmp_object.c" "$ROOT/ncmp/stdll/ncmp_client.c" \
    "$ROOT/ncmp/stdll/ncmp_ckr.c" \
    "$ROOT/ncmp/common/ncmp_wire.c" "$ROOT/ncmp/common/ncmp_shm.c" \
    "$ROOT/ncmp/common/ncmp_slot.c" "$ROOT/ncmp/common/ncmp_queue.c" \
    "$ROOT/ncmp/common/ncmp_mutex.c" "$ROOT/ncmp/common/ncmp_ipc.c" \
    "$ROOT/ncmp/common/ncmp_slotmap.c" \
    -lpthread -lrt -o "$OUT/libpkcs11_ncmp_p11.so"

echo "building $OUT/ncmpd_mock (daemon + mock transport)"
gcc -std=gnu11 -D_GNU_SOURCE -DNCMP_USE_MOCK_TRANSPORT=1 -O2 -Wall \
    -I"$ROOT/ncmp/include" -I"$ROOT/ncmp/mock" \
    "$ROOT/ncmp/daemon/main.c" "$ROOT/ncmp/daemon/conn_thread.c" \
    "$ROOT/ncmp/daemon/comm_thread.c" \
    "$ROOT/ncmp/mock/mock_transport.c" "$ROOT/ncmp/mock/fx3_dma.c" \
    "$ROOT/ncmp/mock/container.c" "$ROOT/ncmp/mock/mcu_scheduler.c" \
    "$ROOT"/ncmp/common/*.c \
    -lpthread -lrt -o "$OUT/ncmpd_mock"

echo "done. Run:"
echo "  export NCMP_SOCK_PATH=/tmp/ncmpd.sock"
echo "  $OUT/ncmpd_mock &"
echo "  NCMP_PKCS11_MODULE=$OUT/libpkcs11_ncmp_p11.so python3 $ROOT/ncmp/gui/py/app_gui.py"
