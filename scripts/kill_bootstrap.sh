#!/bin/bash

PIDS=$(ps -efww | grep mid-bootstrap | grep -v grep | awk '{ print $2 }')
[ -z "$PIDS" ] && echo "process not running" && exit 0
for PID in $PIDS
do
  echo "=> killing $PID"
  kill $PID
done
echo "Done."

