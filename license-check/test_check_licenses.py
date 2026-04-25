"""
Unit tests for check_licenses.py.

Run: python3 -m unittest license-check/test_check_licenses.py
The check_licenses module is loaded with importlib because the directory name
contains a dash (not a valid module name).
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("check_licenses", HERE / "check_licenses.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["check_licenses"] = mod
spec.loader.exec_module(mod)


WHITELIST = {
    "version": "1.0",
    "green":  {"licenses": [{"spdx": "MIT"}, {"spdx": "Apache-2.0"}, {"spdx": "BSD-3-Clause"}]},
    "yellow": {"licenses": [{"spdx": "MPL-2.0"}, {"spdx": "LGPL-3.0"}]},
    "red":    {"licenses": [{"spdx": "GPL-3.0"}, {"spdx": "AGPL-3.0"}]},
}


def _wl():
    return mod.load_whitelist_dict(WHITELIST) if hasattr(mod, "load_whitelist_dict") else {
        bucket: {entry["spdx"] for entry in WHITELIST.get(bucket, {}).get("licenses", [])}
        for bucket in ("green", "yellow", "red")
    }


class TestClassify(unittest.TestCase):
    def test_green_license(self):
        self.assertEqual(mod.classify("MIT", _wl()), "green")

    def test_yellow_license(self):
        self.assertEqual(mod.classify("MPL-2.0", _wl()), "yellow")

    def test_red_license(self):
        self.assertEqual(mod.classify("GPL-3.0", _wl()), "red")

    def test_unknown_license(self):
        self.assertEqual(mod.classify("WeirdProprietary", _wl()), "unknown")

    def test_compound_or_picks_best_bucket(self):
        # MIT (green) OR GPL-3.0 (red) → green wins
        self.assertEqual(mod.classify("MIT OR GPL-3.0", _wl()), "green")
        self.assertEqual(mod.classify("GPL-3.0 OR MIT", _wl()), "green")

    def test_compound_yellow_red(self):
        # No green operand → yellow wins
        self.assertEqual(mod.classify("MPL-2.0 OR GPL-3.0", _wl()), "yellow")

    def test_empty_expression(self):
        self.assertEqual(mod.classify("", _wl()), "unknown")


class TestLicensesFor(unittest.TestCase):
    def test_id_form(self):
        comp = {"licenses": [{"license": {"id": "MIT"}}]}
        self.assertEqual(mod.licenses_for(comp), ["MIT"])

    def test_name_form(self):
        comp = {"licenses": [{"license": {"name": "WeirdLic"}}]}
        self.assertEqual(mod.licenses_for(comp), ["WeirdLic"])

    def test_expression_form(self):
        comp = {"licenses": [{"expression": "MIT OR Apache-2.0"}]}
        self.assertEqual(mod.licenses_for(comp), ["MIT OR Apache-2.0"])

    def test_no_licenses(self):
        self.assertEqual(mod.licenses_for({}), [])


class TestCheck(unittest.TestCase):
    def _run(self, sbom_components, exceptions=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            wl_path = tmp / "wl.json"
            wl_path.write_text(json.dumps(WHITELIST))
            sbom_path = tmp / "sbom.json"
            sbom_path.write_text(json.dumps({"components": sbom_components}))
            args = ["--whitelist", str(wl_path), "--sbom", str(sbom_path)]
            if exceptions is not None:
                ex_path = tmp / "ex.json"
                ex_path.write_text(json.dumps(exceptions))
                args += ["--exceptions", str(ex_path)]
            return mod.main(args)

    def test_all_green_passes(self):
        rc = self._run([
            {"name": "react", "version": "18.0.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"name": "lib2", "version": "1.0.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ])
        self.assertEqual(rc, 0)

    def test_red_fails(self):
        rc = self._run([
            {"name": "evil", "version": "1.0", "licenses": [{"license": {"id": "GPL-3.0"}}]},
        ])
        self.assertEqual(rc, 1)

    def test_yellow_without_exception_fails(self):
        rc = self._run([
            {"name": "lightningcss", "version": "1.32.0", "licenses": [{"license": {"id": "MPL-2.0"}}]},
        ])
        self.assertEqual(rc, 1)

    def test_yellow_with_exception_passes(self):
        rc = self._run(
            [{"name": "lightningcss", "version": "1.32.0", "licenses": [{"license": {"id": "MPL-2.0"}}]}],
            exceptions={
                "project-type": "commercial",
                "package-exceptions": [{"name": "lightningcss", "version": "*", "spdx": "MPL-2.0", "reason": "build-time"}],
            },
        )
        self.assertEqual(rc, 0)

    def test_exact_version_exception(self):
        rc = self._run(
            [{"name": "x", "version": "1.0.0", "licenses": [{"license": {"id": "MPL-2.0"}}]}],
            exceptions={
                "package-exceptions": [{"name": "x", "version": "1.0.0", "reason": "approved"}],
            },
        )
        self.assertEqual(rc, 0)

    def test_unknown_license_fails(self):
        rc = self._run([
            {"name": "mystery", "version": "0.0.1", "licenses": [{"license": {"name": "WeirdLic"}}]},
        ])
        self.assertEqual(rc, 1)

    def test_unknown_license_with_exception_passes(self):
        rc = self._run(
            [{"name": "mystery", "version": "0.0.1", "licenses": [{"license": {"name": "WeirdLic"}}]}],
            exceptions={"package-exceptions": [{"name": "mystery", "version": "*", "reason": "owned by us"}]},
        )
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
