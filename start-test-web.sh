#!/bin/sh
#
# COPYRIGHT (c) International Business Machines Corp. 2001-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

REPO=/home/pooky/workspace/opencryptoki
ncmp/gui/testapp/build/ncmp_web \
    --host 0.0.0.0 --port 8080 \
    --webroot   $REPO/ncmp/gui/testapp/web \
    --module    $REPO/ncmp/gui/build-standalone/libpkcs11_ncmp_p11.so \
    --ncmpd     $REPO/ncmp/gui/build-standalone/ncmpd \
    --transport real        # 기본값 real (하드웨어 없으면 mock)
# 브라우저: http://<서버IP>:8080/
