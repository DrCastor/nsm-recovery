"""Tests for ``strip_track_edit_lists`` (CASE B audio-track repair).

CASE B of the repair copies an intact AUDIO ``trak`` verbatim into a freshly
built ``moov`` whose ``mvhd`` uses a synthetic movie timescale (90000). The
copied track still carries its ``edts``/``elst`` edit list (and its ``tkhd``
duration) expressed in the ORIGINAL movie timescale, which is lost with the
deleted original moov. A conformant player then truncates playback (observed:
14.7 s on a 30 s file). The helper must drop the ``edts`` box from the copied
``trak`` and rewrite its ``tkhd`` duration in the new movie timescale.

Track boxes used below (all FullBoxes unless noted) -- every fixture is built
in memory, nothing touches ffmpeg or the network:

    tkhd v0 : version/flags | creation u32 | modification u32 | track_ID u32 |
              reserved u32 | duration u32 | 60 bytes of geometry
              -> duration at payload offset 20, i.e. box offset 8 + 20 = 28
    tkhd v1 : version/flags | creation u64 | modification u64 | track_ID u32 |
              reserved u32 | duration u64 | 60 bytes of geometry
              -> duration at payload offset 28, i.e. box offset 8 + 28 = 36
    mdhd v0 : version/flags | creation u32 | modification u32 |
              timescale u32 | duration u32 | language u16 | pre_defined u16
    edts    : container holding one elst
    elst v0 : version/flags | entry_count u32 | entry_count * (
              segment_duration u32, media_time i32, media_rate u16.16)
"""

import struct

import pytest

import restore_videos

MOVIE_TIMESCALE = 90000          # what the rebuilt moov's mvhd uses
AUDIO_TIMESCALE = 44100
AUDIO_DURATION = 1323000         # 30 s at 44100 samples per second


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------

def _box(tag, payload):
    return struct.pack(">I", 8 + len(payload)) + tag + payload


def _walk(raw, start=0, end=None):
    """Independent box walker: yields (tag, header offset, total size)."""
    end = len(raw) if end is None else end
    off = start
    while off < end:
        assert off + 8 <= end, f"truncated box header at {off}"
        size = struct.unpack(">I", raw[off:off + 4])[0]
        assert size >= 8, f"implausible size {size} at {off}"
        assert off + size <= end, f"box at {off} overflows its parent"
        yield raw[off + 4:off + 8], off, size
        off += size
    assert off == end, "boxes do not tile their parent exactly"


def _children(raw, start=0, end=None):
    return list(_walk(raw, start, end))


def _child(raw, tag, start=0, end=None):
    hits = [(off, size) for t, off, size in _walk(raw, start, end) if t == tag]
    assert len(hits) == 1, f"expected exactly one {tag!r} child, got {hits}"
    return hits[0]


def _trak_children(trak):
    """The DIRECT children of a trak box held in its own buffer."""
    assert trak[4:8] == b"trak", "buffer does not start with a trak box"
    return _children(trak, 8, len(trak))


def _trak_child(trak, tag):
    return _child(trak, tag, 8, len(trak))


# Geometry of a tkhd after its duration field (60 bytes: reserved[2], layer,
# alternate_group, volume, reserved, matrix[9], width, height).
_GEOMETRY = (struct.pack(">II", 0, 0)
             + struct.pack(">hhhh", 0, 0, 0x0100, 0)
             + struct.pack(">9i", 0x00010000, 0, 0,
                           0, 0x00010000, 0,
                           0, 0, 0x40000000)
             + struct.pack(">II", 0, 0))
assert len(_GEOMETRY) == 60

_TKHD_DURATION_OFF = {0: 28, 1: 36}
_TKHD_SIZE = {0: 92, 1: 104}


def _tkhd(track_id, duration, version=0, flags=7):
    vf = struct.pack(">I", (version << 24) | flags)
    if version == 0:
        head = struct.pack(">IIIII", 0, 0, track_id, 0, duration)
    else:
        head = struct.pack(">QQII", 0, 0, track_id, 0) + struct.pack(">Q", duration)
    return _box(b"tkhd", vf + head + _GEOMETRY)


def _elst_identity(segment_duration=AUDIO_DURATION):
    return _box(b"elst", struct.pack(">II", 0, 1)                    # v0, 1 entry
                + struct.pack(">Iihh", segment_duration, 0, 1, 0))   # rate 1.0


def _edts(segment_duration=AUDIO_DURATION):
    return _box(b"edts", _elst_identity(segment_duration))


def _mdhd(timescale, duration, version=0):
    vf = struct.pack(">I", version << 24)
    if version == 0:
        body = struct.pack(">IIII", 0, 0, timescale, duration)
    else:
        body = struct.pack(">QQIQ", 0, 0, timescale, duration)
    return _box(b"mdhd", vf + body + struct.pack(">HH", 0x55C4, 0))


def _audio_trak(*, tkhd_duration=AUDIO_DURATION, tkhd_version=0, with_edts=True,
                mdhd_timescale=AUDIO_TIMESCALE, mdhd_duration=AUDIO_DURATION,
                with_mdia=True, with_mdhd=True, extra_children=()):
    """The audio trak as CASE B copies it: tkhd, edts/elst, mdia/mdhd."""
    children = [_tkhd(2, tkhd_duration, version=tkhd_version)]
    if with_edts:
        children.append(_edts())
    if with_mdia:
        mdia_children = []
        if with_mdhd:
            mdia_children.append(_mdhd(mdhd_timescale, mdhd_duration))
        mdia_children.append(_box(b"free", b"\x5a" * 8))     # arbitrary payload
        mdia_children.append(_box(b"hdlr", b"\x00" * 24))
        children.append(_box(b"mdia", b"".join(mdia_children)))
    children.extend(extra_children)
    return _box(b"trak", b"".join(children))


# --------------------------------------------------------------------------
# Fixture readers (independent of the implementation)
# --------------------------------------------------------------------------

def _tkhd_duration(trak, version=0):
    off, _size = _trak_child(trak, b"tkhd")
    fmt = ">I" if version == 0 else ">Q"
    width = 4 if version == 0 else 8
    base = off + _TKHD_DURATION_OFF[version]
    return struct.unpack(fmt, trak[base:base + width])[0]


def _mdhd_fields(trak):
    """(timescale, duration) of the mdhd nested in trak/mdia."""
    mdia_off, mdia_size = _trak_child(trak, b"mdia")
    mdhd_off, _mdhd_size = _child(trak, b"mdhd", mdia_off + 8, mdia_off + mdia_size)
    version = trak[mdhd_off + 8]
    base = mdhd_off + 12                       # past the box header + version/flags
    if version == 0:
        timescale, duration = struct.unpack(">II", trak[base + 8:base + 16])
    else:
        timescale, duration = struct.unpack(">IQ", trak[base + 16:base + 28])
    return timescale, duration


# --------------------------------------------------------------------------
# 1. nominal case: edts removed, trak rebuilt consistently
# --------------------------------------------------------------------------

def test_removes_the_direct_edts_child_and_keeps_one_well_formed_trak():
    trak = _audio_trak()
    # Preconditions of the fixture itself.
    assert [tag for tag, _off, _size in _trak_children(trak)] == [
        b"tkhd", b"edts", b"mdia"]
    assert b"elst" in trak
    _tkhd_off, tkhd_size = _trak_child(trak, b"tkhd")
    _edts_off, edts_size = _trak_child(trak, b"edts")
    _mdia_off, mdia_size = _trak_child(trak, b"mdia")

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert isinstance(out, bytes)
    # No edit list of any kind survives.
    assert b"edts" not in out
    assert b"elst" not in out
    # Still a single, self-consistent trak box.
    assert out[4:8] == b"trak"
    assert struct.unpack(">I", out[:4])[0] == len(out)
    assert len(out) == len(trak) - edts_size
    assert [(tag, off, size) for tag, off, size in _trak_children(out)] == [
        (b"tkhd", 8, tkhd_size),
        (b"mdia", 8 + tkhd_size, mdia_size),
    ]


def test_rewrites_the_tkhd_duration_in_the_new_movie_timescale():
    trak = _audio_trak()
    assert _mdhd_fields(trak) == (AUDIO_TIMESCALE, AUDIO_DURATION)
    # 1323000 / 44100 = 30 s -> 30 * 90000 = 2700000.
    assert _tkhd_duration(trak) == AUDIO_DURATION

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert _tkhd_duration(out) == 2700000


def test_leaves_the_mdia_payload_byte_identical():
    trak = _audio_trak()
    in_off, in_size = _trak_child(trak, b"mdia")
    mdia_in = trak[in_off:in_off + in_size]

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    out_off, out_size = _trak_child(out, b"mdia")
    assert out_size == in_size
    assert out[out_off:out_off + out_size] == mdia_in
    # mdia is the trailing payload of trak: it ends the returned box verbatim.
    assert out.endswith(mdia_in)
    # The media timescale and duration are untouched.
    assert _mdhd_fields(out) == (AUDIO_TIMESCALE, AUDIO_DURATION)


def test_touches_only_the_tkhd_duration_field():
    trak = _audio_trak()
    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)
    b_off, b_size = _trak_child(trak, b"tkhd")
    a_off, a_size = _trak_child(out, b"tkhd")
    before = trak[b_off:b_off + b_size]
    after = out[a_off:a_off + a_size]

    assert len(before) == len(after) == _TKHD_SIZE[0]
    assert before[28:32] == struct.pack(">I", AUDIO_DURATION)
    assert after[28:32] == struct.pack(">I", 2700000)
    # Everything else in tkhd is bit-for-bit the same.
    assert before[:28] == after[:28]
    assert before[32:] == after[32:]


# --------------------------------------------------------------------------
# 2. a trak with no edts is not re-encoded at all
# --------------------------------------------------------------------------

def test_a_trak_without_edts_is_returned_byte_identical():
    # The tkhd duration (30000) disagrees with the media duration, but with no
    # edit list there is nothing to correct: the helper must not touch it.
    trak = _audio_trak(with_edts=False, tkhd_duration=30000)
    assert b"edts" not in trak and b"elst" not in trak

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert isinstance(out, bytes)
    assert out == trak
    assert _tkhd_duration(out) == 30000


# --------------------------------------------------------------------------
# 3. edts but no readable mdhd: still stripped, duration left alone
# --------------------------------------------------------------------------

def test_without_any_mdia_the_edts_is_still_removed_and_the_duration_kept():
    # No mdhd means no media timescale to convert from: the contract is to
    # drop the edit list and leave the tkhd duration as it stands.
    trak = _audio_trak(with_mdia=False)
    assert [tag for tag, _off, _size in _trak_children(trak)] == [b"tkhd", b"edts"]

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert b"edts" not in out and b"elst" not in out
    assert out[4:8] == b"trak"
    assert struct.unpack(">I", out[:4])[0] == len(out)
    assert [tag for tag, _off, _size in _trak_children(out)] == [b"tkhd"]
    assert out == _box(b"trak", _tkhd(2, AUDIO_DURATION))
    assert _tkhd_duration(out) == AUDIO_DURATION


def test_mdia_without_an_mdhd_also_leaves_the_duration_alone():
    trak = _audio_trak(with_mdhd=False)                # mdia = free + hdlr
    _in_off, in_size = _trak_child(trak, b"mdia")
    mdia_in = trak[_in_off:_in_off + in_size]

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert b"edts" not in out and b"elst" not in out
    assert _tkhd_duration(out) == AUDIO_DURATION
    out_off, out_size = _trak_child(out, b"mdia")
    assert out_size == in_size
    assert out[out_off:out_off + out_size] == mdia_in


# --------------------------------------------------------------------------
# 4. version-1 tkhd: 64-bit duration at its own offset
# --------------------------------------------------------------------------

def test_a_version_1_tkhd_duration_is_rewritten_as_a_64_bit_value():
    # mdhd: 960000 / 48000 = 20 s -> 20 * 90000 = 1800000.
    trak = _audio_trak(tkhd_duration=1000000, tkhd_version=1,
                       mdhd_timescale=48000, mdhd_duration=960000)
    assert _tkhd_duration(trak, version=1) == 1000000
    assert _mdhd_fields(trak) == (48000, 960000)

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    assert b"edts" not in out and b"elst" not in out
    assert _tkhd_duration(out, version=1) == 1800000
    b_off, b_size = _trak_child(trak, b"tkhd")
    a_off, a_size = _trak_child(out, b"tkhd")
    before = trak[b_off:b_off + b_size]
    after = out[a_off:a_off + a_size]
    assert len(before) == len(after) == _TKHD_SIZE[1]
    assert before[36:44] == struct.pack(">Q", 1000000)
    assert after[36:44] == struct.pack(">Q", 1800000)
    assert before[:36] == after[:36]
    assert before[44:] == after[44:]


# --------------------------------------------------------------------------
# 5. only a real DIRECT edts child is removed
# --------------------------------------------------------------------------

def test_edts_bytes_inside_another_box_payload_are_not_mistaken_for_a_box():
    # A 'free' box whose payload happens to look like a 16-byte 'edts' box.
    decoy_payload = struct.pack(">I", 16) + b"edts" + b"\xaa" * 8
    decoy = _box(b"free", decoy_payload)
    assert decoy[8:] == decoy_payload
    trak = _audio_trak(extra_children=[decoy])
    assert [tag for tag, _off, _size in _trak_children(trak)] == [
        b"tkhd", b"edts", b"mdia", b"free"]

    out = restore_videos.strip_track_edit_lists(trak, MOVIE_TIMESCALE)

    # The real direct child is gone, the decoy and its payload survive.
    assert [tag for tag, _off, _size in _trak_children(out)] == [
        b"tkhd", b"mdia", b"free"]
    assert b"elst" not in out
    assert out.count(b"edts") == 1          # only the decoy's payload
    assert out.endswith(decoy)


# --------------------------------------------------------------------------
# 6. caller contract: garbage in, same garbage out, no exception
# --------------------------------------------------------------------------

@pytest.mark.parametrize("garbage", [
    b"",
    b"\x00\x00\x00\x08",                          # size-only header, no tag
    b"\x00" * 7,                                  # 7 stray bytes
    struct.pack(">I", 64) + b"trak" + b"\x00" * 4,  # declares 64, 12 present
    b"not a box at all",
    struct.pack(">I", 4) + b"trak" + b"\x00" * 8,   # size below the header
], ids=["empty", "header_only", "seven_bytes", "truncated_trak", "ascii",
        "size_below_header"])
def test_garbage_input_is_returned_unchanged(garbage):
    assert restore_videos.strip_track_edit_lists(
        garbage, MOVIE_TIMESCALE) == garbage
