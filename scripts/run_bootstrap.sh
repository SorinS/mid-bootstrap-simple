#!/bin/bash

# Detect platform
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)

BIN=./mid-bootstrap-server.${GOOS}-${GOARCH}.bin
OPTS='-vault-addr http://192.168.1.161:8200 -vault-token s.bmnuJy2AgW19hCLV2mwm42Ir -mid-auth-mount mid -mid-role vm -tls-cert cert.pem -tls-key key.pem'

if [ ! -f "$BIN" ]; then
    echo "Binary not found: $BIN"
    echo "Run 'make build' first"
    exit 1
fi

nohup $BIN $OPTS > bootstrap.log 2>&1 &
echo "Started bootstrap server (PID: $!)"
echo "Logs: bin/bootstrap.log"
