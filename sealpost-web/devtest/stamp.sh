#!/bin/bash
# Stamp the server version onto every import between Sealpost Web's own
# modules (./x.js -> ./x.js?v=VERSION) so a phone can never mix cached old
# and new files. Run after changing SEALPOST_SERVER_VERSION in lib.php.
cd "$(dirname "$0")/../server/web"
V=$(grep -oP "SEALPOST_SERVER_VERSION = '\K[^']+" ../lib.php)
sed -i -E "s#(from '\./[a-z]+\.js)(\?v=[0-9.]+)?'#\1?v=$V'#g" *.js
sed -i -E "s#const CACHE = 'sealpost-shell-[0-9.]+'#const CACHE = 'sealpost-shell-$V'#" ../sw.js
echo "stamped $V"
