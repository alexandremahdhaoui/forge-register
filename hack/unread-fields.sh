#!/bin/sh
# Every field a captured record carries is either read or explicitly ignored.
#
# The parser read one field out of the OSV record for a year - the id - and
# every test passed, because the fixtures were written by the same mind as the
# parser and encoded the same blind spot. ecosystem_specific.imports was the
# field that decided whether a consumer could clear an advisory on the merits,
# and nothing ever looked at it.
#
# So the captured payloads get a vote. Walk them, collect every JSON path that
# occurs, subtract the paths the parser reads and the ones we have decided not
# to, and fail on what is left. A field we have never considered becomes a
# build failure rather than a discovery six months later.
set -eu

exec uv run --quiet python3 - "$@" <<'PY'
import json
import re
import sys
from pathlib import Path

records = json.load(open("testdata/osv-records.json"))["records"]

# Paths the parser reads. Taken from the struct tags in the adapter, so this
# list cannot drift from the code: a tag removed here shows up as unread.
source = Path("internal/adapter/osvadapter/osvadapter.go").read_text()
read = set(re.findall(r'json:"([a-z_]+)"', source))

# Paths we have looked at and decided not to read. Each one needs a reason,
# because an allowlist without reasons is how a blind spot comes back.
#
# Nothing that IS read belongs here. An entry saying "read" would mean the
# field could stop being read with the gate still green, which is the exact
# hole this exists to close.
ignored = {
    "schema_version": "the document version, not a fact about the package",
    "modified": "when the record last changed; adoption dates come from the register",
    "summary": "prose for a human, and we quote the register's own words instead",
    "details": "the long prose, stripped from the fixture entirely",
    "references": "links out; a consumer follows the id",
    "related": "adjacent records, not this one",
    "credits": "who reported it",
    "upstream": "the record this was derived from",
    "purl": "the same package, spelled another way",
    "source": "which database an affected block came from",
    "cwe_ids": "a weakness taxonomy, not a version range",
    "github_reviewed": "GitHub's own workflow state",
    "github_reviewed_at": "the same",
    "nvd_published_at": "NVD's date; the advisory's own published date is used",
    "review_status": "the publishing database's workflow state",
    "url": "a link out",
    "license": "the record's licence",
    "cvss": "a per-affected vector we do not read; the top-level one is used",
    "informational": "RustSec's advisory class",
    "last_known_affected_version_range": "prose, and the range events are authoritative",
    "malicious": "a package-level flag, not a version range",
    "categories": "RustSec's tags",
    "specs": "PyPI's own spec strings; the range events are authoritative",
    "import": "a spelling seen once; imports[].path is read",
    "osv_published": "when OSV ingested it, not when it was published",
    "patched": "prose; the fixed events are authoritative",
    "unaffected": "prose; the range events are authoritative",
    "date": "an ingestion date",
    "symbols": "the vulnerable function names, populated in 73 of these "
               "records. Nothing reads them yet: the reachability engine "
               "answers at import granularity, so a symbol list would be a "
               "field with no reader. A call-graph backend is what needs "
               "them, and plumbing them before it exists is decoration. "
               "Recorded in FOLLOWUP so it is a decision, not an oversight.",
    "affected_functions": "RustSec's spelling of the same thing, and null in "
                          "every record here",
    "affects": "RustSec's scope block: arch, os and functions, all empty in "
               "every record here",
    "functions": "inside affects; empty everywhere, see affected_functions",
    "arch": "inside affects; a CPU constraint, not a version range",
    "os": "inside affects; an OS constraint, not a version range",
    "repo": "the git repository a GIT range is anchored to. GIT ranges are "
            "skipped outright - comparing a semver against a commit hash "
            "answers nothing - so the anchor is not needed either",
    "contact": "how to reach a credited reporter",
    "cwes": "a weakness taxonomy on an affected block",
    "cweId": "inside cwes",
    "description": "inside cwes, prose for the taxonomy entry",
    "indicators": "GitHub's malware indicators: file hashes and evidence "
                  "files. This is a version-range gate, not a scanner",
    "package_integrity": "inside indicators",
    "evidence_files": "inside indicators",
    "hashes": "inside indicators",
    "sha256": "a file digest inside indicators",
    "md5": "the same",
    "blake2b_256": "the same",
    "tlsh": "a fuzzy file hash inside indicators",
    "filename": "inside indicators",
    "malicious-packages-origins": "provenance of a malicious-package report",
    "import_time": "when the malicious-package report was ingested",
    "modified_time": "when it last changed",
    "goos": "build constraints on a Go advisory's import entry",
    "goarch": "the same",
}

seen = {}


def walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            seen.setdefault(k, path + "." + k if path else k)
            walk(v, path + "." + k if path else k)
    elif isinstance(node, list):
        for v in node:
            walk(v, path)


for r in records.values():
    walk(r)

# An entry that names a field the parser DOES read is the hole this exists
# to close: the field could stop being read and the gate would stay green,
# because ignored is subtracted whether or not anything reads it. Six such
# entries sat here, so severity, score and four others were unguarded.
both = sorted(read & set(ignored))
if both:
    print("these are read AND listed as ignored, so nothing guards them:",
          file=sys.stderr)
    for k in both:
        print("  %s - %s" % (k, ignored[k]), file=sys.stderr)
    print("", file=sys.stderr)
    print("Remove them from `ignored`. A field is read or it is ignored, "
          "never both.", file=sys.stderr)
    sys.exit(1)

unread = sorted(k for k in seen if k not in read and k not in ignored)

if unread:
    print("captured records carry fields nothing reads and nothing has "
          "decided to ignore:", file=sys.stderr)

    for k in unread:
        print("  %s (at %s)" % (k, seen[k]), file=sys.stderr)

    print("", file=sys.stderr)
    print("Read it in the adapter, or add it to `ignored` with a reason. A "
          "field nobody has considered is how ecosystem_specific.imports went "
          "unread for a year while every test passed.", file=sys.stderr)
    sys.exit(1)

print("every field in %d captured records is read or explicitly ignored"
      % len(records))
PY
