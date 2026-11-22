"""Exercise the shell helper with real hashes/unzip and inert curl/gcc.

Only the copied helper's two archive pins are replaced with hashes of tiny test
archives. Production pins are documented against official SQLite release data.
"""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / ".github/actions/setup-sqlite-version/setup-sqlite-version.sh"
VERSIONS = {"3.46.0": "3460000", "3.25.0": "3250000"}
COMMANDS = ("uname", "mktemp", "mkdir", "rm", "mv", "ln", "tr", "unzip")
AVAILABLE = all(shutil.which(command) for command in (*COMMANDS, "bash", "sha256sum"))

STUB = """import json, os, pathlib, shutil, sys
kind = pathlib.Path(sys.argv[0]).name
record = {"command": kind}
if kind == "curl":
    url = sys.argv[-1]
    record["url"] = url
elif kind == "gcc":
    source = pathlib.Path(next(arg for arg in sys.argv[1:] if arg.endswith("sqlite3.c")))
    record.update(source=str(source), source_text=source.read_text())
with open(os.environ["SQLITE_TEST_EVENTS"], "a") as log:
    log.write(json.dumps(record) + "\\n")
if kind == "curl":
    responses = json.loads(os.environ["SQLITE_TEST_RESPONSES"])
    payload = responses.get(url, responses.get("default"))
    if payload is None:
        sys.exit(22)
    shutil.copyfile(payload, sys.argv[sys.argv.index("--output") + 1])
elif kind == "gcc":
    pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_bytes(b"inert test library")
elif kind == "unzip":
    os.execv(os.environ["SQLITE_TEST_UNZIP"], ["unzip", *sys.argv[1:]])
"""


@unittest.skipUnless(
    AVAILABLE, "requires bash, unzip and standard POSIX hash/file tools"
)
class SQLiteArchiveIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sqlite integrity ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixtures = {}
        hashes = []
        for version, archive_id in VERSIONS.items():
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    f"sqlite-amalgamation-{archive_id}/sqlite3.c",
                    f"trusted SQLite fixture {version}\n",
                )
            data = payload.getvalue()
            self.fixtures[version] = self.root / f"{archive_id}.zip"
            self.fixtures[version].write_bytes(data)
            hashes.append(hashlib.sha256(data).hexdigest())
        pins = iter(hashes)
        text, count = re.subn(
            r'amalgamation_sha256="[0-9a-f]{64}"',
            lambda match: f'amalgamation_sha256="{next(pins)}"',
            HELPER.read_text(),
        )
        self.assertEqual(count, len(VERSIONS))
        self.helper = self.root / "helper.sh"
        self.helper.write_text(text)
        self.counter = 0

    def run_helper(
        self,
        version="3.46.0",
        *,
        responses=None,
        cached=None,
        legacy_source=None,
        hash_tool="sha256sum",
        extra_urls="",
    ):
        self.counter += 1
        case = self.root / str(self.counter)
        case.mkdir()
        full_version = version if version in VERSIONS else version + ".0"
        filename = "sqlite-amalgamation-" + VERSIONS[full_version]
        runner = case / "runner"
        cache = runner / "sqlite-versions/downloads" / f"{filename}.zip"
        if cached is not None:
            cache.parent.mkdir(parents=True)
            cache.write_bytes(cached)
        legacy = runner / "sqlite-versions/source" / filename / "sqlite3.c"
        if legacy_source is not None:
            legacy.parent.mkdir(parents=True)
            legacy.write_text(legacy_source)
        toolbox = case / "bin"
        toolbox.mkdir()
        for command in (*COMMANDS, hash_tool):
            if command and command != "unzip":
                (toolbox / command).symlink_to(shutil.which(command))
        for command in ("curl", "gcc", "unzip"):
            stub = toolbox / command
            stub.write_text(f"#!{sys.executable}\n" + STUB)
            stub.chmod(0o755)
        events = case / "events.jsonl"
        environment = {
            **os.environ,
            "PATH": str(toolbox),
            "RUNNER_TEMP": str(runner),
            "SQLITE_VERSION": version,
            "SQLITE_SKIP_ACTIVATE": "true",
            "SQLITE_CFLAGS": "",
            "SQLITE_EXTRA_FALLBACK_URLS": extra_urls,
            "SQLITE_TEST_EVENTS": str(events),
            "SQLITE_TEST_RESPONSES": json.dumps(
                responses
                if responses is not None
                else {"default": str(self.fixtures[full_version])}
            ),
            "SQLITE_TEST_UNZIP": shutil.which("unzip"),
            "GITHUB_OUTPUT": str(case / "output"),
            "GITHUB_ENV": str(case / "environment"),
        }
        result = subprocess.run(
            [shutil.which("bash"), str(self.helper)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        records = (
            [json.loads(line) for line in events.read_text().splitlines()]
            if events.exists()
            else []
        )
        return result, records, cache

    def assert_compiled_fixture(self, result, records, version):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        compiled = [record for record in records if record["command"] == "gcc"]
        self.assertEqual(len(compiled), 1)
        self.assertEqual(
            compiled[0]["source_text"], f"trusted SQLite fixture {version}\n"
        )
        self.assertFalse(Path(compiled[0]["source"]).exists())

    def test_verified_downloads_and_both_version_aliases(self):
        for version in ("3.46", "3.46.0", "3.25", "3.25.0"):
            with self.subTest(version=version):
                result, records, cache = self.run_helper(version)
                full_version = version if version in VERSIONS else version + ".0"
                self.assert_compiled_fixture(result, records, full_version)
                self.assertEqual(
                    cache.read_bytes(), self.fixtures[full_version].read_bytes()
                )

    def test_changed_downloads_never_reach_extraction_or_compilation(self):
        bad = self.root / "changed.zip"
        bad.write_bytes(b"changed archive")
        result, records, cache = self.run_helper(responses={"default": str(bad)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertTrue(records)
        self.assertTrue(all(record["command"] == "curl" for record in records))
        self.assertFalse(cache.exists())
        self.assertFalse(cache.with_suffix(".zip.tmp").exists())

    def test_extra_fallback_must_match_the_same_pin(self):
        bad = self.root / "wrong.zip"
        bad.write_bytes(b"wrong release")
        fallback = "https://fixture.invalid/sqlite.zip"
        result, records, cache = self.run_helper(
            responses={"default": str(bad), fallback: str(self.fixtures["3.46.0"])},
            extra_urls=fallback,
        )
        self.assert_compiled_fixture(result, records, "3.46.0")
        requests = [record["url"] for record in records if record["command"] == "curl"]
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[-1], fallback)
        self.assertEqual(cache.read_bytes(), self.fixtures["3.46.0"].read_bytes())

    def test_changed_cache_cannot_be_bypassed_by_existing_source(self):
        result, records, _ = self.run_helper(
            cached=b"changed cached archive", legacy_source="untrusted cached source"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cached SQLite archive failed verification", result.stderr)
        self.assertEqual(records, [])

    def test_verified_cache_ignores_existing_source(self):
        result, records, _ = self.run_helper(
            cached=self.fixtures["3.46.0"].read_bytes(),
            legacy_source="untrusted cached source",
        )
        self.assert_compiled_fixture(result, records, "3.46.0")
        self.assertEqual([record["command"] for record in records], ["unzip", "gcc"])

    def test_existing_source_without_archive_still_requires_verified_download(self):
        result, records, _ = self.run_helper(legacy_source="untrusted cached source")
        self.assert_compiled_fixture(result, records, "3.46.0")
        self.assertEqual(records[0]["command"], "curl")

    def test_unrecognised_archive_paths_are_never_extracted(self):
        payload = io.BytesIO()
        escaped = self.root / "escaped"
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(str(escaped), "must not be extracted")
            archive.writestr("../escaped", "must not be extracted")
        result, records, _ = self.run_helper(cached=payload.getvalue())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(records, [])
        self.assertFalse(escaped.exists())

    @unittest.skipUnless(shutil.which("shasum"), "requires shasum")
    def test_shasum_fallback_verifies_real_fixture_hash(self):
        result, records, _ = self.run_helper(hash_tool="shasum")
        self.assert_compiled_fixture(result, records, "3.46.0")

    def test_missing_hash_tool_fails_before_extraction(self):
        result, records, _ = self.run_helper(
            cached=self.fixtures["3.46.0"].read_bytes(), hash_tool=None
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 verification requires", result.stderr)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
