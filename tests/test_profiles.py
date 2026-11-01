"""Tests for the cross-run SPS/PPS profile store.

The store is a single JSON file (``profiles.json``) inside a profile
directory; it is a list of entries:

    {"key": "<sha1>", "sps_hex": "...", "pps_hex": "...", "count": n,
     "first_seen": ..., "last_seen": ..., "sources": [...],
     "width": w, "height": h}                        # H.264

HEVC entries additionally carry ``"codec": "hevc"`` and ``"vps_hex"``; an
entry with no ``codec`` field is a historical H.264 entry.

Everything happens in ``tmp_path``: no test touches the real store, and
nothing calls ffmpeg.
"""

import json
import os
import re

import pytest

import restore_videos

SPS = bytes([0x67, 0x64, 0x00, 0x29, 0xAC, 0x2B, 0x40])
PPS = bytes([0x68, 0xEB, 0xE3, 0xCB, 0x22, 0xC0])
SPS2 = bytes([0x67, 0x4D, 0x00, 0x1F]) + b"\x11" * 4
PPS2 = bytes([0x68, 0xEE, 0x3C, 0x80])
VPS = bytes([0x40, 0x01, 0x0C, 0x01, 0xFF])

ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


def _store_file(profile_dir):
    return os.path.join(str(profile_dir), restore_videos.PROFILE_STORE_FILENAME)


def _raw_store(profile_dir):
    with open(_store_file(profile_dir), encoding="utf-8") as fh:
        return json.load(fh)


def _write_raw_store(profile_dir, content):
    with open(_store_file(profile_dir), "w", encoding="utf-8") as fh:
        fh.write(content)


# --------------------------------------------------------------------------
# load_profile_store / save_profile_store
# --------------------------------------------------------------------------

def test_load_profile_store_returns_an_empty_list_when_there_is_no_file(tmp_path):
    assert restore_videos.load_profile_store(str(tmp_path)) == []
    assert restore_videos.load_profile_store(str(tmp_path / "missing")) == []


def test_save_profile_store_creates_the_directory_and_round_trips(tmp_path):
    profile_dir = tmp_path / "not" / "yet" / "there"
    store = [{"key": "k", "sps_hex": SPS.hex(), "pps_hex": PPS.hex(),
              "count": 2, "sources": ["a.mp4"]}]

    restore_videos.save_profile_store(str(profile_dir), store)

    assert profile_dir.is_dir()
    assert restore_videos.load_profile_store(str(profile_dir)) == store


def test_save_profile_store_is_atomic_and_leaves_no_temporary_file(tmp_path):
    profile_dir = tmp_path / "profiles"
    restore_videos.save_profile_store(str(profile_dir), [{"key": "a"}])
    restore_videos.save_profile_store(str(profile_dir), [{"key": "b"}])

    # A single file, no leftover "<name>.tmp<pid>".
    assert sorted(os.listdir(str(profile_dir))) == [
        restore_videos.PROFILE_STORE_FILENAME]
    assert restore_videos.load_profile_store(str(profile_dir)) == [{"key": "b"}]


def test_save_profile_store_keeps_non_ascii_text_intact(tmp_path):
    profile_dir = tmp_path / "profiles"

    restore_videos.save_profile_store(
        str(profile_dir), [{"key": "a", "sources": ["video_\u00e9\u00e0.mp4"]}])

    assert restore_videos.load_profile_store(str(profile_dir))[0]["sources"] == [
        "video_\u00e9\u00e0.mp4"]


@pytest.mark.parametrize("payload", [
    "not json at all",
    '{"a": 1}',          # a dict instead of a list
    "[1, 2",             # truncated JSON
    "",
])
def test_load_profile_store_ignores_a_corrupt_store(tmp_path, payload):
    # A damaged store must never break a reconstruction: it is treated as
    # empty instead of raising.
    _write_raw_store(tmp_path, payload)

    assert restore_videos.load_profile_store(str(tmp_path)) == []


def test_register_profile_restarts_from_scratch_on_a_corrupt_store(tmp_path):
    _write_raw_store(tmp_path, "this is not json")

    is_new, count = restore_videos.register_profile(str(tmp_path), SPS, PPS,
                                                    "a.mp4")

    assert (is_new, count) == (True, 1)
    assert len(_raw_store(tmp_path)) == 1


# --------------------------------------------------------------------------
# register_profile
# --------------------------------------------------------------------------

def test_register_profile_creates_the_first_entry(tmp_path):
    is_new, count = restore_videos.register_profile(
        str(tmp_path), SPS, PPS, "first.mp4", dims=(1920, 1080))

    assert (is_new, count) == (True, 1)
    store = _raw_store(tmp_path)
    assert len(store) == 1
    entry = store[0]
    assert entry["key"] == restore_videos.profile_key(SPS, PPS)
    assert entry["sps_hex"] == SPS.hex()
    assert entry["pps_hex"] == PPS.hex()
    assert entry["count"] == 1
    assert entry["sources"] == ["first.mp4"]
    assert (entry["width"], entry["height"]) == (1920, 1080)
    assert entry["first_seen"] == entry["last_seen"]
    assert ISO_TIMESTAMP.match(entry["first_seen"])


def test_register_profile_increments_the_counter_instead_of_duplicating(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")

    is_new, count = restore_videos.register_profile(str(tmp_path), SPS, PPS,
                                                    "b.mp4")

    assert (is_new, count) == (False, 2)
    store = _raw_store(tmp_path)
    assert len(store) == 1
    assert store[0]["count"] == 2
    assert store[0]["sources"] == ["a.mp4", "b.mp4"]


def test_register_profile_counter_survives_a_reload(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")

    # A fresh read of the file: the counter is persisted, not kept in memory.
    assert restore_videos.load_profile_store(str(tmp_path))[0]["count"] == 2

    _is_new, count = restore_videos.register_profile(str(tmp_path), SPS, PPS,
                                                     "a.mp4")
    assert count == 3


def test_register_profile_does_not_repeat_a_source_label(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "same.mp4")

    restore_videos.register_profile(str(tmp_path), SPS, PPS, "same.mp4")

    entry = _raw_store(tmp_path)[0]
    assert entry["sources"] == ["same.mp4"]
    assert entry["count"] == 2


def test_register_profile_keeps_only_the_most_recent_sources(tmp_path):
    for i in range(5):
        restore_videos.register_profile(str(tmp_path), SPS, PPS,
                                        "file%d.mp4" % i, max_sources=3)

    entry = _raw_store(tmp_path)[0]
    assert entry["sources"] == ["file2.mp4", "file3.mp4", "file4.mp4"]
    assert entry["count"] == 5


def test_register_profile_records_hevc_entries_with_their_vps(tmp_path):
    is_new, count = restore_videos.register_profile(
        str(tmp_path), SPS, PPS, "hevc.mp4", vps=VPS)

    assert (is_new, count) == (True, 1)
    entry = _raw_store(tmp_path)[0]
    assert entry["codec"] == "hevc"
    assert entry["vps_hex"] == VPS.hex()
    assert entry["key"] == restore_videos.profile_key(SPS, PPS, VPS)


def test_register_profile_without_a_source_label_records_no_source(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "")

    assert _raw_store(tmp_path)[0]["sources"] == []


def test_register_profile_keeps_two_different_profiles_apart(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")
    restore_videos.register_profile(str(tmp_path), SPS2, PPS2, "b.mp4")

    store = _raw_store(tmp_path)
    assert len(store) == 2
    assert {e["key"] for e in store} == {
        restore_videos.profile_key(SPS, PPS),
        restore_videos.profile_key(SPS2, PPS2),
    }


def test_register_profile_does_not_raise_on_an_unusable_directory(tmp_path):
    # The profile directory path is an existing FILE: saving is impossible,
    # and the function must report failure rather than break the run.
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"")

    is_new, count = restore_videos.register_profile(str(blocker), SPS, PPS,
                                                    "a.mp4")

    assert (is_new, count) == (False, 0)


# --------------------------------------------------------------------------
# iter_profiles_sorted
# --------------------------------------------------------------------------

def test_iter_profiles_sorted_returns_sps_pps_and_entry(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4",
                                    dims=(640, 480))

    profiles = restore_videos.iter_profiles_sorted(str(tmp_path))

    assert len(profiles) == 1
    sps, pps, entry = profiles[0]
    assert (sps, pps) == (SPS, PPS)
    assert entry["count"] == 1


def test_iter_profiles_sorted_orders_from_most_to_least_frequent(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "rare.mp4")
    for _ in range(3):
        restore_videos.register_profile(str(tmp_path), SPS2, PPS2, "common.mp4")

    profiles = restore_videos.iter_profiles_sorted(str(tmp_path))

    assert [entry["sps_hex"] for _sps, _pps, entry in profiles] == [
        SPS2.hex(), SPS.hex()]


def test_iter_profiles_sorted_breaks_ties_on_the_most_recently_seen(tmp_path):
    # Two entries with the same count: the one seen most recently comes
    # first. The timestamps are written by hand so the test does not depend
    # on the machine clock.
    store = [
        {"key": "old", "sps_hex": SPS.hex(), "pps_hex": PPS.hex(), "count": 2,
         "last_seen": "2024-01-01T10:00:00"},
        {"key": "recent", "sps_hex": SPS2.hex(), "pps_hex": PPS2.hex(),
         "count": 2, "last_seen": "2024-06-01T10:00:00"},
    ]
    restore_videos.save_profile_store(str(tmp_path), store)

    profiles = restore_videos.iter_profiles_sorted(str(tmp_path))

    assert [entry["key"] for _sps, _pps, entry in profiles] == [
        "recent", "old"]


def test_iter_profiles_sorted_filters_by_codec(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "avc.mp4")
    restore_videos.register_profile(str(tmp_path), SPS2, PPS2, "hevc.mp4",
                                    vps=VPS)

    avc = restore_videos.iter_profiles_sorted(str(tmp_path), codec="avc")
    hevc = restore_videos.iter_profiles_sorted(str(tmp_path), codec="hevc")

    assert [e["sps_hex"] for _s, _p, e in avc] == [SPS.hex()]
    assert [e["sps_hex"] for _s, _p, e in hevc] == [SPS2.hex()]
    assert hevc[0][2]["vps_hex"] == VPS.hex()


def test_iter_profiles_sorted_skips_an_entry_with_unparsable_hex(tmp_path):
    store = [
        {"key": "broken", "sps_hex": "zz", "pps_hex": "00", "count": 9},
        {"key": "ok", "sps_hex": SPS.hex(), "pps_hex": PPS.hex(), "count": 1},
    ]
    restore_videos.save_profile_store(str(tmp_path), store)

    profiles = restore_videos.iter_profiles_sorted(str(tmp_path))

    assert [entry["key"] for _sps, _pps, entry in profiles] == ["ok"]


def test_iter_profiles_sorted_returns_an_empty_list_for_an_empty_store(tmp_path):
    assert restore_videos.iter_profiles_sorted(str(tmp_path)) == []


# --------------------------------------------------------------------------
# find_profile_match
# --------------------------------------------------------------------------

def test_find_profile_match_returns_none_when_ffmpeg_is_not_available(
        tmp_path, monkeypatch):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")
    # The profile store is only a candidate list: without the decoding
    # oracle nothing can be confirmed, so no profile is ever returned.
    monkeypatch.setattr(restore_videos.shutil, "which", lambda _name: None)

    assert restore_videos.find_profile_match(str(tmp_path), [b"\x00" * 8],
                                             b"") is None


def test_find_profile_match_returns_none_without_frame_nals(tmp_path):
    restore_videos.register_profile(str(tmp_path), SPS, PPS, "a.mp4")

    assert restore_videos.find_profile_match(str(tmp_path), [], b"") is None


def test_find_profile_match_returns_none_on_an_empty_store(tmp_path,
                                                           monkeypatch):
    monkeypatch.setattr(restore_videos.shutil, "which",
                        lambda _name: "/usr/bin/ffmpeg")

    assert restore_videos.find_profile_match(str(tmp_path), [b"\x00" * 8],
                                             b"") is None
