"""Controls for the opt-in PowerShell custom-language integration.

The parser is a dynamic library ast-grep loads at scan time. That makes it a
security boundary: an absent, mismatched or broken library must never degrade
into "scan completed, zero findings", because a clean report is exactly what a
missing parser and a clean codebase look like from the outside.

These tests therefore assert two separable properties:

* the integration works when the parser is present (positive discovery), and
* it fails *closed* -- non-zero exit, diagnostic on stderr, no findings output
  -- for a missing parser, a wrong-architecture parser, and a parser that
  errors on the input.

They also pin the isolation property that motivates the separate config: the
native-language scan driven by `sgconfig.yml` must be unaffected whether or not
the PowerShell grammar has ever been built.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AST_GREP = ROOT / "node_modules" / ".bin" / "ast-grep"
NATIVE_CONFIG = ROOT / "sgconfig.yml"
LIBRARY = ROOT / "build" / "powershell" / "powershell.so"
BUILD_SCRIPT = ROOT / "tools" / "powershell" / "build-grammar.sh"

PROBE_SCRIPT = "Invoke-Expression $userInput\n"

# A rule that matches the probe script, written out per-test so the controls do
# not depend on the rule pack that later work adds.
PROBE_RULE = """
id: psh-control-probe
language: powershell
severity: warning
message: probe
rule:
  pattern: Invoke-Expression $A
"""


def library_available():
    return LIBRARY.is_file()


requires_parser = unittest.skipUnless(
    library_available(),
    f"PowerShell grammar not built; run {BUILD_SCRIPT.relative_to(ROOT)}",
)


class PowerShellHarness(unittest.TestCase):
    """Build a throwaway workspace whose config points at a chosen library."""

    def workspace(self, library_path, extensions=("ps1", "psm1", "psd1"),
                  script=PROBE_SCRIPT, filename="probe.ps1"):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "rules-powershell").mkdir()
        (tmp / "rules-powershell" / "probe.yml").write_text(PROBE_RULE)
        (tmp / "src").mkdir()
        (tmp / "src" / filename).write_text(script)
        exts = "\n".join(f"      - {e}" for e in extensions)
        (tmp / "sgconfig.yml").write_text(
            "ruleDirs:\n"
            "  - rules-powershell\n"
            "customLanguages:\n"
            "  powershell:\n"
            f"    libraryPath: {library_path}\n"
            "    extensions:\n"
            f"{exts}\n"
            "    expandoChar: 'µ'\n"
        )
        return tmp

    def scan(self, tmp, json_output=True):
        cmd = [str(AST_GREP), "scan", "-c", str(tmp / "sgconfig.yml")]
        if json_output:
            cmd.append("--json=compact")
        cmd.append(str(tmp / "src"))
        return subprocess.run(cmd, capture_output=True, text=True, check=False)


class TestPositiveDiscovery(PowerShellHarness):
    """The parser, when present, actually finds PowerShell code."""

    @requires_parser
    def test_ps1_is_discovered_and_matched(self):
        tmp = self.workspace(LIBRARY)
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = json.loads(result.stdout)
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0]["ruleId"], "psh-control-probe")
        self.assertTrue(findings[0]["file"].endswith("probe.ps1"))

    @requires_parser
    def test_psm1_is_discovered(self):
        tmp = self.workspace(LIBRARY, filename="module.psm1")
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

    @requires_parser
    def test_psd1_is_discovered(self):
        """`.psd1` registration is gated on this parsing cleanly.

        PowerShell data files are a subset of the script grammar, so the same
        parser handles them; the assertion here is that registering the
        extension actually yields a parsed, matchable tree rather than a file
        ast-grep walks past.
        """
        tmp = self.workspace(LIBRARY, filename="manifest.psd1")
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 1)

    @requires_parser
    def test_psd1_manifest_parses_without_error_nodes(self):
        """The evidence that justified registering `.psd1` at all."""
        manifest = (
            "@{\n"
            "    ModuleVersion = '1.0.0'\n"
            "    GUID = '11111111-2222-3333-4444-555555555555'\n"
            "    FunctionsToExport = @('Get-Thing')\n"
            "    PrivateData = @{ PSData = @{ Tags = @('a') } }\n"
            "}\n"
        )
        tmp = self.workspace(LIBRARY, script=manifest, filename="manifest.psd1")
        (tmp / "rules-powershell" / "probe.yml").write_text(
            "id: psh-parse-error\n"
            "language: powershell\n"
            "severity: error\n"
            "message: parse error\n"
            "rule:\n"
            "  kind: ERROR\n"
        )
        result = self.scan(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [], "manifest produced ERROR nodes")


class TestFailsClosed(PowerShellHarness):
    """A parser that is absent, wrong or broken must not report "clean"."""

    def assert_failed_closed(self, result):
        self.assertNotEqual(
            result.returncode, 0,
            "scan exited 0; an unusable parser must not look like a clean scan",
        )
        self.assertIn("custom language", result.stderr.lower())
        # No findings document may be emitted -- a consumer parsing stdout as
        # JSON must not receive an empty, successful-looking result set.
        self.assertNotEqual(result.stdout.strip(), "[]")

    def test_missing_parser_fails_closed(self):
        tmp = self.workspace("build/powershell/absent.so")
        self.assert_failed_closed(self.scan(tmp))

    def test_wrong_architecture_parser_fails_closed(self):
        """A library for another architecture is present but unloadable."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bogus = tmp / "wrong-arch.so"
        # A valid ELF header claiming an architecture the host loader will
        # refuse (EM_AARCH64 = 183 on an x86-64 host, and vice versa), followed
        # by nothing loadable. The point is that the file exists and is
        # readable, so only real loading -- not a stat() -- can reject it.
        header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        header += (3).to_bytes(2, "little")  # ET_DYN
        machine = 183 if os.uname().machine in ("x86_64", "AMD64") else 62
        header += machine.to_bytes(2, "little")
        header += b"\x00" * 64
        bogus.write_bytes(bytes(header))
        work = self.workspace(bogus)
        self.assert_failed_closed(self.scan(work))

    def test_corrupt_parser_fails_closed(self):
        """A file that is not a shared object at all."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bogus = tmp / "not-a-library.so"
        bogus.write_text("this is not a shared object\n")
        work = self.workspace(bogus)
        self.assert_failed_closed(self.scan(work))

    @requires_parser
    def test_parser_error_is_reported_not_swallowed(self):
        """Unparsable PowerShell surfaces as an ERROR node, not as silence.

        This is the fourth failure mode: the library loads fine, but the input
        defeats the grammar. A rule pack that cannot see ERROR nodes would
        report such a file as clean.
        """
        malformed = "function Broken {\n    param([string]$x\n    if ($x -eq\n}\n"
        tmp = self.workspace(LIBRARY, script=malformed)
        (tmp / "rules-powershell" / "probe.yml").write_text(
            "id: psh-parse-error\n"
            "language: powershell\n"
            "severity: error\n"
            "message: parse error\n"
            "rule:\n"
            "  kind: ERROR\n"
        )
        result = self.scan(tmp)
        findings = json.loads(result.stdout)
        self.assertGreater(
            len(findings), 0,
            "malformed PowerShell produced no ERROR node; parse failures would be invisible",
        )


class TestNativeScanUnaffected(unittest.TestCase):
    """The opt-in config must not change the default scan in either direction."""

    def test_native_config_declares_no_custom_language(self):
        text = NATIVE_CONFIG.read_text()
        self.assertNotIn(
            "customLanguages", text,
            "registering a custom language in sgconfig.yml aborts the whole scan "
            "when its library is absent, breaking all native-language rules",
        )

    def test_native_scan_succeeds_regardless_of_grammar(self):
        """Native rules run identically whether or not the grammar is built."""
        result = subprocess.run(
            [str(AST_GREP), "scan", "-c", str(NATIVE_CONFIG),
             "--json=compact", str(ROOT / "tests" / "python")],
            capture_output=True, text=True, cwd=ROOT, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        json.loads(result.stdout)

    def test_powershell_rules_are_not_in_the_native_rule_dir(self):
        """Native discovery counts stay untouched by the PowerShell pack."""
        native_langs = {p.name for p in (ROOT / "rules").iterdir() if p.is_dir()}
        self.assertNotIn("powershell", native_langs)


if __name__ == "__main__":
    unittest.main()
