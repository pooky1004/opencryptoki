#!/bin/sh
#
# COPYRIGHT (c) International Business Machines Corp. 2001-2017
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this software
# constitutes recipient's acceptance of CPL-1.0 terms which can be found
# in the file LICENSE file or at https://opensource.org/licenses/cpl1.0.php
#

export NCMP_SOCK_PATH=/tmp/ncmpd.sock     # ncmpd가 사용하는 것과 동일하게
ncmp/gui/debugapp/build/ncmp_dbg \
    --host 0.0.0.0 --port 8090 \
    --webroot ncmp/gui/debugapp/web
# 브라우저: http://<서버IP>:8090/
