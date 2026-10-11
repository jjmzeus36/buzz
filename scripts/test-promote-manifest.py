#!/usr/bin/env python3
"""Run the production candidate predicate with jq; never invoke GitHub."""

import argparse
import copy
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jq", default=shutil.which("jq"))
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).with_name("promote-oss-desktop-release.sh"),
    )
    args = parser.parse_args()
    if not args.jq:
        parser.error("jq is required")
    source = args.source.read_text(encoding="utf-8")
    predicate = re.search(
        r"^(?P<command>jq -e[^\n]*?) '\n(?P<program>.*?)\n' \"\$candidate\"",
        source,
        re.MULTILINE | re.DOTALL,
    )
    expected = re.search(r"^EXPECTED_PLATFORMS='([^']*)'$", source, re.MULTILINE)
    if predicate is None or expected is None:
        raise AssertionError("production candidate validation was not found")
    version = "1.2.3"
    replacements = {"$VERSION": version, "$EXPECTED_PLATFORMS": expected[1]}
    command = [args.jq] + [
        replacements.get(token, token)
        for token in shlex.split(predicate["command"])[1:]
    ] + [predicate["program"]]
    valid = {
        "version": version,
        "platforms": {
            platform: {
                "signature": "synthetic-signature",
                "url": "https://github.com/block/buzz/releases/download/desktop-v"
                + version + "/" + platform + ".zip",
            }
            for platform in json.loads(expected[1])
        },
    }
    document = json.dumps(valid)
    cases = [
        ("single document", document, True),
        ("surrounding whitespace", "\n \t" + document + "\n\t", True),
        ("empty input", "", False),
        ("whitespace only", "\n \t", False),
        ("malformed JSON", "{", False),
        ("trailing non-JSON", document + " trailing", False),
        ("two valid documents", document + "\n" + document, False),
        ("invalid then valid", "{}\n" + document, False),
        ("valid then invalid", document + "\n{}", False),
        ("array wrapper", "[" + document + "]", False),
        ("null", "null", False),
    ]
    for field in ("version", "platforms"):
        altered = copy.deepcopy(valid)
        del altered[field]
        cases.append(("missing " + field, json.dumps(altered), False))
    altered = copy.deepcopy(valid)
    altered["version"] = "1.2.4"
    cases.append(("wrong version", json.dumps(altered), False))
    for field, value in (("signature", ""), ("url", "https://example.invalid/a")):
        altered = copy.deepcopy(valid)
        altered["platforms"]["linux-x86_64"][field] = value
        cases.append(("invalid " + field, json.dumps(altered), False))
    results = []
    for name, payload, should_accept in cases:
        result = subprocess.run(
            command, input=payload, text=True, encoding="utf-8",
            capture_output=True, timeout=10, check=False,
        )
        accepted = result.returncode == 0
        results.append({
            "case": name, "exit_code": result.returncode,
            "expected_accept": should_accept, "accepted": accepted,
            "passed": accepted == should_accept,
        })
    print(json.dumps({"cases": results, "passed": all(r["passed"] for r in results)}, indent=2))
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
