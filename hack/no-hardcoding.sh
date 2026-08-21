#!/bin/sh
set -eu

# forge-register knows ecosystems by design: an ecosystem names a discovery
# adapter. What it must never know is a project. A package name is data that
# arrives in a request, never a word in this repo's code.

BANNED="golden-rust golden-go golden-python golden-typescript golden-spec golden-e2e golden-configgen golden-factory poe-wayfinder opends gamesync testify serde fastapi fastify"

fail=0

FILES=$(find internal pkg -name '*.go' ! -name '*_test.go' ! -path 'internal/mocks/*' 2>/dev/null)

[ -n "$FILES" ] || { echo "no production code yet"; exit 0; }

for word in $BANNED; do
    hits=$(grep -rniF "$word" $FILES || true)

    if [ -n "$hits" ]; then
        echo "forge-register must not know about \"$word\". A package is data in a request, never a word in this code." >&2
        echo "$hits" >&2
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "forge-register names no project"
fi

exit "$fail"
