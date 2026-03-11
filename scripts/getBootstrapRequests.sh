#!/bin/bash

# Valid status: pending|approved|denied|expired|error

STATUS=pending
[ "$#" -gt 0 ] && STATUS=$1

[ -z "$BOOTSTRAP_URL" ] && echo "BOOTSTRAP_URL env var empty - pls source setenv.sh" && exit 2
[ -z "$BOOTSTRAP_USER" ] && echo "BOOTSTRAP_USER env var empty - pls source setenv.sh" && exit 3
[ -z "$BOOTSTRAP_PWD" ] && echo "BOOTSTRAP_PWD env var empty - pls source setenv.sh" && exit 4

curl -k -u $BOOTSTRAP_USER:$BOOTSTRAP_PWD $BOOTSTRAP_URL/api/requests?status=$STATUS
