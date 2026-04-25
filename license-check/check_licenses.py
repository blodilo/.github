#!/usr/bin/env python3
"""
Validate the licenses of every component in one or more CycloneDX SBOMs
against an organization-wide whitelist plus an optional project-local
exceptions file.

Exit status:
  0 — all components in green or covered by an exception
  1 — at least one violation (red, or yellow/unknown without exception)

The script is dependency-free (Python stdlib only) so it runs on any
runner without `pip install`.

Usage:
  check_licenses.py \\
      --whitelist license-whitelist.json \\
      --exceptions ./license-exceptions.json \\
      --sbom sbom-frontend.json --sbom sbom-backend.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable


def load_whitelist(path: Path) -> dict[str, set[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        bucket: {entry["spdx"] for entry in raw.get(bucket, {}).get("licenses", [])}
        for bucket in ("green", "yellow", "red")
    }


def load_exceptions(path: Path | None) -> list[dict]:
    """Return the raw exception entries; matching is done in match_exception().

    An exception entry has {name, version, spdx, reason}. `name` may end with
    `*` for prefix-match (e.g. `lightningcss*`). `version` may be `*` for any.
    """
    if path is None or not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw.get("package-exceptions", [])


def match_exception(name: str, version: str, exceptions: list[dict]) -> str | None:
    """Return the reason string of the first matching exception, else None."""
    for ex in exceptions:
        ex_name = ex.get("name", "")
        ex_ver = ex.get("version", "*")
        # Name match: exact or `*`-suffix wildcard prefix-match
        if ex_name.endswith("*"):
            if not name.startswith(ex_name[:-1]):
                continue
        elif ex_name != name:
            continue
        # Version match
        if ex_ver != "*" and ex_ver != version:
            continue
        return ex.get("reason", "")
    return None


def extract_components(sbom: dict) -> list[dict]:
    """CycloneDX 1.4+ uses top-level `components`. Some emitters nest dependencies."""
    return list(sbom.get("components", []))


# Common non-SPDX license names mapped to their SPDX equivalents.
# Includes PyPI "classifier"-style strings emitted by cyclonedx-py for
# Python packages.
LICENSE_ALIASES = {
    "Public Domain": "CC0-1.0",
    "Public-Domain": "CC0-1.0",
    "PD": "CC0-1.0",
    "Unlicense": "Unlicense",
    # PyPI classifier strings (cyclonedx-py output)
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0-only",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}


def _split_compound(spdx: str) -> list[str]:
    """Split combined license expressions ('A OR B' or 'A, B') into operands."""
    s = spdx.strip()
    # Comma-separated PyPI classifier multi-license becomes OR-expression
    if "," in s and " OR " not in s.upper() and " AND " not in s.upper():
        return [_normalise(p.strip()) for p in s.split(",") if p.strip()]
    return [_normalise(s)]


def _normalise(spdx: str) -> str:
    return LICENSE_ALIASES.get(spdx.strip(), spdx.strip())


def licenses_for(component: dict) -> list[str]:
    """Return SPDX expressions found on the component, expanding comma-multi
    licenses into separate entries (treated as OR by classify())."""
    out: list[str] = []
    for lic in component.get("licenses", []) or []:
        # CycloneDX shape: {"license": {"id": "MIT"}} or {"license": {"name": "..."}} or {"expression": "..."}
        raw = None
        if "expression" in lic:
            raw = lic["expression"]
        elif "license" in lic:
            ref = lic["license"]
            raw = ref.get("id") or ref.get("name")
        if raw:
            out.extend(_split_compound(raw))
    return out


def canonical_name(component: dict) -> str:
    """Return the canonical npm-style name including scope.

    CycloneDX splits `@scope/pkg` into `group="@scope"` and `name="pkg"`.
    """
    name = component.get("name", "<unnamed>")
    group = component.get("group")
    if group and not name.startswith(f"{group}/"):
        return f"{group}/{name}"
    return name


_OR_SPLIT = re.compile(r"\s+OR\s+", flags=re.IGNORECASE)


def classify(spdx_expr: str, whitelist: dict[str, set[str]]) -> str:
    """Return 'green', 'yellow', 'red', or 'unknown'.
    Compound 'A OR B' resolves to the highest-trust bucket among operands.
    """
    parts = [p.strip().strip("()") for p in _OR_SPLIT.split(spdx_expr)] if spdx_expr else []
    if not parts:
        return "unknown"
    buckets = [_classify_single(p, whitelist) for p in parts]
    for prefer in ("green", "yellow", "red", "unknown"):
        if prefer in buckets:
            return prefer
    return "unknown"


def _classify_single(spdx: str, whitelist: dict[str, set[str]]) -> str:
    if spdx in whitelist["green"]:
        return "green"
    if spdx in whitelist["yellow"]:
        return "yellow"
    if spdx in whitelist["red"]:
        return "red"
    return "unknown"


def check(
    sboms: list[Path],
    whitelist: dict[str, set[str]],
    exceptions: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Returns (violations, all_components)."""
    violations: list[dict] = []
    all_components: list[dict] = []

    for sbom_path in sboms:
        if not sbom_path.exists():
            print(f"warn: SBOM not found: {sbom_path}", file=sys.stderr)
            continue
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        for comp in extract_components(sbom):
            name = canonical_name(comp)
            version = comp.get("version", "")
            license_exprs = licenses_for(comp) or ["UNKNOWN"]
            best = "unknown"
            for expr in license_exprs:
                bucket = classify(expr, whitelist)
                if bucket == "green":
                    best = "green"
                    break
                if bucket == "yellow" and best != "green":
                    best = "yellow"
                if bucket == "red":
                    best = "red"
                    break

            entry = {
                "name": name,
                "version": version,
                "licenses": license_exprs,
                "bucket": best,
                "sbom": str(sbom_path),
            }
            all_components.append(entry)

            if best == "green":
                continue

            reason = match_exception(name, version, exceptions)
            if reason is not None:
                entry["exception"] = reason
                continue

            violations.append(entry)

    return violations, all_components


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="License whitelist check on CycloneDX SBOMs")
    parser.add_argument("--whitelist", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path, default=None)
    parser.add_argument("--sbom", type=Path, action="append", required=True)
    args = parser.parse_args(argv)

    whitelist = load_whitelist(args.whitelist)
    exceptions = load_exceptions(args.exceptions)

    violations, all_components = check(args.sbom, whitelist, exceptions)

    by_bucket: dict[str, int] = {"green": 0, "yellow": 0, "red": 0, "unknown": 0}
    for c in all_components:
        by_bucket[c["bucket"]] += 1
    total = len(all_components)

    print(f"Scanned {total} components across {len(args.sbom)} SBOM(s):")
    print(f"  green:   {by_bucket['green']}")
    print(f"  yellow:  {by_bucket['yellow']}")
    print(f"  red:     {by_bucket['red']}")
    print(f"  unknown: {by_bucket['unknown']}")
    print(f"  exceptions in effect: {len(exceptions)}")

    if violations:
        print("", file=sys.stderr)
        print(f"❌ {len(violations)} license violation(s):", file=sys.stderr)
        for v in violations:
            licenses = ", ".join(v["licenses"])
            print(
                f"  - {v['name']}@{v['version']}  [{v['bucket'].upper()}]  ({licenses})",
                file=sys.stderr,
            )
        return 1

    print("\n✅ All components green or covered by exceptions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
