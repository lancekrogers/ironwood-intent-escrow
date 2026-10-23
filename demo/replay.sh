#!/bin/sh
# Prints a captured run log line by line, 120 ms apart, so a recorded run can
# be replayed on screen. A run that polls prints the same "waiting for" line
# many times; each one is printed once.
#
# Usage: demo/replay.sh demo/logs/refund.log
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: replay.sh <log>" >&2
    exit 2
fi

last_wait=""
while IFS= read -r line || [ -n "$line" ]; do
    case $line in
    *"waiting for"*)
        if [ "$line" = "$last_wait" ]; then
            continue
        fi
        last_wait=$line
        ;;
    esac
    printf '%s\n' "$line"
    sleep 0.12
done <"$1"
