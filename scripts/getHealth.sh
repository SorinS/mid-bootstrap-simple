#!/bin/bash

[ -z "$BOOTSTRAP_URL" ] && echo "BOOTSTRAP_URL env var empty - pls source setenv.sh" && exit 1
curl -k $BOOTSTRAP_URL/health
