#!/bin/bash

BIN=mid-bootstrap-server.linux-arm64.bin
[ ! -x "../$BIN" ] && echo "Expecting an excutable binary here: ../$BIN but found none" && exit 1
[ ! -x "$BIN" ] && echo "Expecting an excutable binary here: $BIN but found none" && exit 1
[ ! -x "./run_bootstrap.sh" ] && echo "No run_bootstrap.sh found, are you in the right folder?" && exit 2
[ ! -x "./kill_bootstrap.sh" ] && echo "No kill_bootstrap.sh found, are you in the right folder?" && exit 2

mv ../$BIN $BIN
./kill_bootstrap.sh
./kill_bootstrap.sh
mv ../$BIN $BIN
./run_bootstrap.sh
[ "$?" -eq 0 ] && echo "Done." && exit 0
echo "Failed to update"
exit 1
