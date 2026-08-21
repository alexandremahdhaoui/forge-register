#!/bin/sh
set -eu

# Every verdict code and every policy parameter must appear in
# docs/concepts.md. A decision the docs cannot name is a decision nobody can
# act on.

fail=0

for term in adopted up-to-date held-worse-vector held-quarantined \
    held-canary-red pending-admission denied-over-floor denied-quarantined \
    denied-unknown-version denied-not-a-maintained-line \
    denied-security-regression denied-over-budget \
    quarantineDays admissionMaxSeverity deprecateAfterDays staleAfterDays \
    deprecatedGraceDays maxTracksPerPackage \
    track advisory deprecation request verdict; do
    if ! grep -q "$term" docs/concepts.md 2>/dev/null; then
        echo "docs/concepts.md does not mention \"$term\"" >&2
        fail=1
    fi
done

[ "$fail" -eq 0 ] && echo "every verdict code and parameter is documented"

exit "$fail"
