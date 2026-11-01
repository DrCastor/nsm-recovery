"""Tests for the run manifest (``--manifest <file>``).

NEW FEATURE -- expected to FAIL until it is implemented:
``restore_videos.append_manifest`` does not exist yet, and ``restore_videos.main``
does not accept ``--manifest`` yet. These tests describe the contract:

* ``append_manifest(manifest_path, source, status, nsm_location="")`` appends
  exactly one CSV row and returns True;
* the header ``timestamp_utc,source,status,nsm_location`` is written once,
  when the file is created;
* the timestamp is UTC, formatted ``YYYY-MM-DDTHH:MM:SSZ``;
* a second call appends (it never rewrites the file);
* non-ASCII paths survive a round trip through the ``csv`` module;
* a missing parent directory is created;
* an unwritable path returns False instead of raising.
"""

import csv
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import restore_videos

HEADER = ["timestamp_utc", "source", "status", "nsm_location"]
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_rows(path):
    """Reads the manifest back with the standard csv module (UTF-8)."""
    with open(str(path), "r", encoding="utf-8", newline="") as fh:
        return list(csv.reader(fh))


def _append(path, source="video.nsm", status="ok", nsm_location=""):
    # AttributeError here is the expected state until the feature lands.
    return restore_videos.append_manifest(str(path), source, status,
                                          nsm_location=nsm_location)


# --------------------------------------------------------------------------
# append_manifest
# --------------------------------------------------------------------------

def test_append_manifest_creates_the_file_with_a_header_and_one_row(tmp_path):
    manifest = tmp_path / "run.csv"

    assert _append(manifest) is True

    rows = _read_rows(manifest)
    assert len(rows) == 2
    assert rows[0] == HEADER
    assert rows[1][0] == rows[1][0].strip()
    assert TIMESTAMP_RE.match(rows[1][0])
    assert rows[1][1:] == ["video.nsm", "ok", ""]


def test_append_manifest_writes_the_header_only_once(tmp_path):
    manifest = tmp_path / "run.csv"

    _append(manifest, "a.nsm", "ok")
    _append(manifest, "b.nsm", "error")

    rows = _read_rows(manifest)
    assert len(rows) == 3
    assert rows[0] == HEADER
    assert [row[1] for row in rows[1:]] == ["a.nsm", "b.nsm"]
    assert [row[2] for row in rows[1:]] == ["ok", "error"]
    # Appending must not rewrite the file: the first row is byte-identical.
    first_two = manifest.read_bytes().split(b"\n")[:2]
    _append(manifest, "c.nsm", "ok")
    assert manifest.read_bytes().split(b"\n")[:2] == first_two


def test_append_manifest_stamps_each_row_with_its_own_utc_timestamp(tmp_path):
    manifest = tmp_path / "run.csv"

    _append(manifest, "a.nsm", "ok")
    _append(manifest, "b.nsm", "ok")

    rows = _read_rows(manifest)
    for row in rows[1:]:
        assert TIMESTAMP_RE.match(row[0]), row[0]
    # Both rows were written "now": they may share a second, but neither may
    # be empty or out of order.
    assert rows[1][0] <= rows[2][0]


def test_append_manifest_records_the_nsm_location(tmp_path):
    manifest = tmp_path / "run.csv"

    _append(manifest, "photo.jpg", "ok",
            nsm_location="_to_delete/sub/photo.nsm")

    assert _read_rows(manifest)[0] == HEADER
    assert _read_rows(manifest)[1][1:] == ["photo.jpg", "ok",
                                          "_to_delete/sub/photo.nsm"]


def test_append_manifest_round_trips_non_ascii_and_commas_through_csv(tmp_path):
    manifest = tmp_path / "run.csv"
    source = "video_\u00e9\u00e0_\u00fcn\u00efcode.nsm"
    location = "C:\\path, with comma\\video_\u00e9\u00e0.nsm"

    _append(manifest, source, "ok", nsm_location=location)

    rows = _read_rows(manifest)
    assert rows[1][1:] == [source, "ok", location]
    # The file really is UTF-8: the non-ASCII characters are stored as such.
    assert "video_\u00e9\u00e0".encode("utf-8") in manifest.read_bytes()


def test_append_manifest_creates_the_missing_parent_directories(tmp_path):
    manifest = tmp_path / "reports" / "2026" / "run.csv"

    assert _append(manifest) is True

    assert manifest.is_file()
    assert _read_rows(manifest)[0] == HEADER


def test_append_manifest_returns_false_when_the_path_is_unwritable(tmp_path):
    # The parent of the manifest path is an existing FILE: creation is
    # impossible and the helper must report it instead of raising (a manifest
    # problem must never interrupt a recovery run).
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"")

    assert _append(blocker / "run.csv") is False


def test_append_manifest_keeps_every_previous_row_the_same(tmp_path):
    manifest = tmp_path / "run.csv"
    _append(manifest, "first.nsm", "ok")
    before = manifest.read_bytes()

    _append(manifest, "second.nsm", "error")

    # Pure append: the bytes already on disk are untouched.
    assert manifest.read_bytes().startswith(before)
    assert len(_read_rows(manifest)) == 3


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def test_cli_exposes_the_manifest_option(tmp_path):
    launcher = shutil.which("py")
    if launcher is None:
        pytest.skip("py launcher not available")
    probe = subprocess.run([launcher, "-3.13", "-c", "pass"],
                           capture_output=True, timeout=120)
    if probe.returncode != 0:
        pytest.skip("Python 3.13 not installed for the py launcher")

    proc = subprocess.run([launcher, "-3.13", str(REPO_ROOT / "restore_videos.py"),
                           "--help"],
                          capture_output=True, text=True, timeout=180,
                          cwd=str(REPO_ROOT))

    assert proc.returncode == 0, proc.stderr
    assert "--manifest" in proc.stdout
