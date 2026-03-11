#!/bin/bash

[ "$#" -lt 2 ] && echo "Usage: $0 <id> <approver>" && exit 1
ID=$1
APPROVER=$2
[ -z "$BOOTSTRAP_URL" ] && echo "BOOTSTRAP_URL env var empty - pls source setenv.sh" && exit 2
[ -z "$BOOTSTRAP_USER" ] && echo "BOOTSTRAP_USER env var empty - pls source setenv.sh" && exit 3
[ -z "$BOOTSTRAP_PWD" ] && echo "BOOTSTRAP_PWD env var empty - pls source setenv.sh" && exit 4

curl -k -u $BOOTSTRAP_USER:$BOOTSTRAP_PWD -d "{ \"approved_by\": \"$APPROVER\", \"comment\": \"api call\", \"request_id\": \"$ID\" }" $BOOTSTRAP_URL/api/generate-token
