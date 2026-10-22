#!/bin/bash
# Stamp the server version onto every import between Sealpost Web's own
# modules (./x.js -> ./x.js?v=VERSION) so a phone can never mix cached old
# and new files. Run after changing SEALPOST_SERVER_VERSION in lib.php.
# (1.10.0: reads the version with sed — Git Bash's grep -P fails on Windows —
#  and stops if it finds none, so it can't stamp an empty version)
cd "$(dirname "$0")/../server/web" || exit 1
V=$(sed -n "s/.*SEALPOST_SERVER_VERSION = '\([0-9.]*\)'.*/\1/p" ../lib.php)
[ -n "$V" ] || { echo "No SEALPOST_SERVER_VERSION found in lib.php"; exit 1; }
sed -i -E "s#(from '\./[a-z]+\.js)(\?v=[0-9.]*)?'#\1?v=$V'#g" *.js
sed -i -E "s#const CACHE = 'sealpost-shell-[0-9.]*'#const CACHE = 'sealpost-shell-$V'#" ../sw.js
echo "stamped $V"
