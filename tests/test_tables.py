"""Tests for the MP4 sample-table parsing and synthesis helpers.

ISO-BMFF sample tables used here (all are FullBoxes: 4 version/flags bytes
after the 8-byte header):

    stco  : version/flags | entry_count | entry_count * u32 offsets
    co64  : version/flags | entry_count | entry_count * u64 offsets
    stsz  : version/flags | sample_size(u32) | sample_count(u32) |
            sample_count * u32 sizes   (only if sample_size == 0)
    stsc  : version/flags | entry_count | entry_count * (first_chunk,
            samples_per_chunk, sample_description_index)  -- all u32
"""

import io
import struct

import restore_videos


def _box(tag, payload):
    return struct.pack(">I", 8 + len(payload)) + tag + payload


def _stco(offsets, tag=b"stco"):
    body = b"\x00" * 4 + struct.pack(">I", len(offsets))
    if tag == b"co64":
        body += b"".join(struct.pack(">Q", o) for o in offsets)
    else:
        body += b"".join(struct.pack(">I", o) for o in offsets)
    return _box(tag, body)


def _stsz(sizes, sample_size=0):
    body = (b"\x00" * 4 + struct.pack(">I", sample_size)
            + struct.pack(">I", len(sizes)))
    body += b"".join(struct.pack(">I", s) for s in sizes)
    return _box(b"stsz", body)


def _stsc_entries(stsc_raw):
    """Independent stsc reader used to check the synthesised boxes."""
    assert stsc_raw[4:8] == b"stsc"
    count = struct.unpack(">I", stsc_raw[12:16])[0]
    out = []
    for k in range(count):
        base = 16 + 12 * k
        out.append(struct.unpack(">III", stsc_raw[base:base + 12]))
    return out


def _stsz_sizes(stsz_raw):
    """Independent stsz reader: (sample_size, sizes)."""
    assert stsz_raw[4:8] == b"stsz"
    sample_size = struct.unpack(">I", stsz_raw[12:16])[0]
    count = struct.unpack(">I", stsz_raw[16:20])[0]
    if sample_size:
        return sample_size, [sample_size] * count
    sizes = list(struct.unpack(">" + "I" * count, stsz_raw[20:20 + 4 * count]))
    return 0, sizes


# --------------------------------------------------------------------------
# parse_stco_offsets
# --------------------------------------------------------------------------

def test_parse_stco_offsets_reads_a_32_bit_chunk_offset_table():
    raw = _stco([100, 2000, 30000])

    assert restore_videos.parse_stco_offsets(raw) == [100, 2000, 30000]


def test_parse_stco_offsets_reads_a_64_bit_chunk_offset_table():
    raw = _stco([5, 5 * 2 ** 32], tag=b"co64")

    assert restore_videos.parse_stco_offsets(raw) == [5, 5 * 2 ** 32]


def test_parse_stco_offsets_returns_an_empty_list_for_an_empty_table():
    assert restore_videos.parse_stco_offsets(_stco([])) == []
    assert restore_videos.parse_stco_offsets(_stco([], tag=b"co64")) == []


def test_parse_stco_offsets_stops_at_a_truncated_table():
    # entry_count says 3, only 2 offsets are actually present: the two
    # readable ones are returned instead of an exception.
    raw = _box(b"stco", b"\x00" * 4 + struct.pack(">I", 3)
               + struct.pack(">II", 100, 200))

    assert restore_videos.parse_stco_offsets(raw) == [100, 200]


def test_parse_stco_offsets_keeps_the_file_order():
    # Offsets are returned as stored (chunks are normally in file order, but
    # nothing is sorted here).
    raw = _stco([9000, 100, 5000])

    assert restore_videos.parse_stco_offsets(raw) == [9000, 100, 5000]


# --------------------------------------------------------------------------
# derive_synthetic_stsc_stsz
# --------------------------------------------------------------------------

def test_derive_synthetic_stsc_stsz_assumes_one_sample_per_chunk():
    # Video chunks at 1000 and 3000, the audio chunk at 2000 splits the first
    # one; mdat data ends at 4000. Every video chunk therefore spans exactly
    # 1000 bytes.
    video = _stco([1000, 3000])
    audio = _stco([2000])

    result = restore_videos.derive_synthetic_stsc_stsz(video, audio, 4000)

    assert result is not None
    stsc_raw, stsz_raw = result
    assert _stsc_entries(stsc_raw) == [(1, 1, 1)]
    assert _stsz_sizes(stsz_raw) == (0, [1000, 1000])


def test_derive_synthetic_stsc_stsz_without_a_second_track():
    video = _stco([1000, 3000])

    result = restore_videos.derive_synthetic_stsc_stsz(video, None, 4000)

    assert result is not None
    _stsc_raw, stsz_raw = result
    assert _stsz_sizes(stsz_raw) == (0, [2000, 1000])


def test_derive_synthetic_stsc_stsz_returns_none_without_video_chunks():
    assert restore_videos.derive_synthetic_stsc_stsz(
        _stco([]), _stco([2000]), 4000) is None


def test_derive_synthetic_stsc_stsz_returns_none_on_an_offset_collision():
    # A video and an audio chunk starting at the same byte cannot both be
    # true: the hypothesis is abandoned.
    video = _stco([1000, 2000])
    audio = _stco([2000])

    assert restore_videos.derive_synthetic_stsc_stsz(video, audio, 4000) is None


def test_derive_synthetic_stsc_stsz_returns_none_on_an_aberrant_sample_size():
    # The last chunk would be 100 MB long: rejected.
    video = _stco([0])

    assert restore_videos.derive_synthetic_stsc_stsz(
        video, None, 100 * 1024 * 1024) is None


# --------------------------------------------------------------------------
# derive_synthetic_stsc
# --------------------------------------------------------------------------

def test_derive_synthetic_stsc_accumulates_the_real_sample_sizes():
    # Video chunk 1 starts at 1000 and ends where the next chunk (audio at
    # 2000) starts; its two samples are 400 + 600. Video chunk 2 (3000) is
    # one 1000-byte sample up to mdat_data_end (4000).
    video_stco = _stco([1000, 3000])
    video_stsz = _stsz([400, 600, 1000])
    audio_stco = _stco([2000])

    stsc_raw = restore_videos.derive_synthetic_stsc(video_stco, video_stsz,
                                                   audio_stco, 4000)

    assert stsc_raw is not None
    assert _stsc_entries(stsc_raw) == [(1, 2, 1), (2, 1, 1)]


def test_derive_synthetic_stsc_collapses_consecutive_identical_chunk_sizes():
    # Two chunks of two samples each: a single stsc entry (first_chunk=1)
    # already covers both, so the second one is redundant.
    video_stco = _stco([1000, 2000])
    video_stsz = _stsz([500, 500, 500, 500])
    audio_stco = _stco([3000])

    stsc_raw = restore_videos.derive_synthetic_stsc(video_stco, video_stsz,
                                                   audio_stco, 4000)

    assert stsc_raw is not None
    assert _stsc_entries(stsc_raw) == [(1, 2, 1)]


def test_derive_synthetic_stsc_returns_none_when_the_sizes_do_not_tile():
    # 400 + 500 = 900, but the chunk is 1000 bytes long: the "contiguous
    # chunks" hypothesis is invalid for this file.
    video_stco = _stco([1000, 3000])
    video_stsz = _stsz([400, 500, 1000])
    audio_stco = _stco([2000])

    assert restore_videos.derive_synthetic_stsc(video_stco, video_stsz,
                                                audio_stco, 4000) is None


def test_derive_synthetic_stsc_returns_none_when_samples_are_left_over():
    # Only one video chunk is described by stco, but stsz declares 3 samples
    # and the first two already fill the chunk: the third would be orphaned.
    video_stco = _stco([1000])
    video_stsz = _stsz([500, 500, 500])
    audio_stco = _stco([2000])

    assert restore_videos.derive_synthetic_stsc(video_stco, video_stsz,
                                                audio_stco, 4000) is None


def test_derive_synthetic_stsc_returns_none_without_chunk_offsets():
    assert restore_videos.derive_synthetic_stsc(
        _stco([]), _stsz([100]), None, 4000) is None


def test_derive_synthetic_stsc_returns_none_for_an_empty_stsz():
    assert restore_videos.derive_synthetic_stsc(
        _stco([1000]), _stsz([]), None, 4000) is None


def test_derive_synthetic_stsc_handles_a_constant_sample_size_stsz():
    # stsz with a non-zero sample_size: every sample has that size, and no
    # per-sample table is stored.
    video_stco = _stco([1000, 2000])
    video_stsz = _box(b"stsz", b"\x00" * 4 + struct.pack(">I", 500)
                      + struct.pack(">I", 4))
    audio_stco = _stco([3000])

    stsc_raw = restore_videos.derive_synthetic_stsc(video_stco, video_stsz,
                                                    audio_stco, 4000)

    assert stsc_raw is not None
    # chunk 1 = 1000 -> 2000, chunk 2 = 2000 -> 3000: both hold 2 x 500 bytes,
    # so a single stsc entry covers the whole track.
    assert _stsc_entries(stsc_raw) == [(1, 2, 1)]


# --------------------------------------------------------------------------
# derive_video_tables_from_audio_gaps
# --------------------------------------------------------------------------
#
# Driven from a BytesIO: the function only needs seek/read on the mdat body
# (no ffmpeg involved in the historical NAL-by-NAL mode used here).

def _avcc_region(*sizes):
    out = b""
    for size in sizes:
        out += struct.pack(">I", size - 4) + b"\x00" * (size - 4)
    return out


def test_derive_video_tables_from_audio_gaps_rebuilds_every_video_table():
    # mdat body = [0, 2000). Audio occupies [0, 500) and [1000, 1200); the
    # two holes therefore contain 5 video samples of 100 bytes and 4 samples
    # of 200 bytes.
    buf = bytearray(2000)
    buf[500:1000] = _avcc_region(*([100] * 5))
    buf[1200:2000] = _avcc_region(*([200] * 4))
    audio_stco = _stco([0, 1000])
    audio_stsc = _box(b"stsc", b"\x00" * 4 + struct.pack(">I", 1)
                      + struct.pack(">III", 1, 1, 1))
    audio_stsz = _stsz([500, 200])

    result = restore_videos.derive_video_tables_from_audio_gaps(
        io.BytesIO(bytes(buf)), audio_stco, audio_stsc, audio_stsz, 0, 2000)

    assert result is not None
    stco_raw, stsc_raw, stsz_raw = result
    assert restore_videos.parse_stco_offsets(stco_raw) == [500, 1200]
    assert _stsc_entries(stsc_raw) == [(1, 5, 1), (2, 4, 1)]
    assert _stsz_sizes(stsz_raw) == (0, [100] * 5 + [200] * 4)


def test_derive_video_tables_from_audio_gaps_falls_back_to_one_sample_per_hole():
    # The video bytes cannot be parsed as length-prefixed NAL units: the
    # whole hole is kept as a single sample (the bytes and the chunk
    # boundary are unchanged -- only the container's sample split changes).
    buf = bytes([0xFF]) * 2000
    audio_stco = _stco([0])
    audio_stsc = _box(b"stsc", b"\x00" * 4 + struct.pack(">I", 1)
                      + struct.pack(">III", 1, 1, 1))
    audio_stsz = _stsz([500])

    result = restore_videos.derive_video_tables_from_audio_gaps(
        io.BytesIO(buf), audio_stco, audio_stsc, audio_stsz, 0, 2000)

    assert result is not None
    stco_raw, stsc_raw, stsz_raw = result
    assert restore_videos.parse_stco_offsets(stco_raw) == [500]
    assert _stsc_entries(stsc_raw) == [(1, 1, 1)]
    assert _stsz_sizes(stsz_raw) == (0, [1500])


def test_derive_video_tables_from_audio_gaps_returns_none_without_audio_chunks():
    assert restore_videos.derive_video_tables_from_audio_gaps(
        io.BytesIO(b"\x00" * 100), _stco([]), _box(b"stsc", b"\x00" * 4),
        _stsz([]), 0, 100) is None


def test_derive_video_tables_from_audio_gaps_returns_none_on_overlapping_audio():
    # Two audio chunks whose byte ranges overlap: the "mdat holds only audio
    # and video" hypothesis is false for this file.
    audio_stco = _stco([0, 300])
    audio_stsc = _box(b"stsc", b"\x00" * 4 + struct.pack(">I", 1)
                      + struct.pack(">III", 1, 1, 1))
    audio_stsz = _stsz([500, 200])

    assert restore_videos.derive_video_tables_from_audio_gaps(
        io.BytesIO(b"\x00" * 2000), audio_stco, audio_stsc, audio_stsz,
        0, 2000) is None


def test_derive_video_tables_from_audio_gaps_returns_none_when_audio_fills_mdat():
    # No hole at all -> nothing that could be video.
    audio_stco = _stco([0])
    audio_stsc = _box(b"stsc", b"\x00" * 4 + struct.pack(">I", 1)
                      + struct.pack(">III", 1, 1, 1))
    audio_stsz = _stsz([2000])

    assert restore_videos.derive_video_tables_from_audio_gaps(
        io.BytesIO(b"\x00" * 2000), audio_stco, audio_stsc, audio_stsz,
        0, 2000) is None


# --------------------------------------------------------------------------
# strip_track_edit_lists -- regression for the CASE B audio track
# --------------------------------------------------------------------------
#
# CASE B copies the intact audio 'trak' into a freshly built 'moov' whose
# mvhd uses a synthetic movie timescale (90000). The copied track kept its
# 'edts'/'elst' edit list and its 'tkhd' duration expressed in the ORIGINAL
# movie timescale (1000 in the example below), which is lost with the
# deleted moov: a conformant player then stopped playback after a fraction of
# a second (observed: 14.7 s of a 30 s file) even though the media data was
# complete.
#
# tkhd v0 layout: header(8) | version/flags(4) | creation(4) |
# modification(4) | track_ID(4) | reserved(4) | duration(4) | geometry(60)
# mdhd v0 layout: header(8) | version/flags(4) | creation(4) |
# modification(4) | timescale(4) | duration(4) | language(2) | pre_defined(2)

_GEOMETRY = (struct.pack(">II", 0, 0)
             + struct.pack(">hhhh", 0, 0, 0x0100, 0)
             + struct.pack(">9i", 0x00010000, 0, 0,
                           0, 0x00010000, 0,
                           0, 0, 0x40000000)
             + struct.pack(">II", 0, 0))


def _tkhd_v0(duration, track_id=2):
    return _box(b"tkhd", struct.pack(">I", 7)
                + struct.pack(">IIIII", 0, 0, track_id, 0, duration)
                + _GEOMETRY)


def _mdhd_v0(timescale, duration):
    return _box(b"mdhd", struct.pack(">I", 0)
                + struct.pack(">IIII", 0, 0, timescale, duration)
                + struct.pack(">HH", 0x55C4, 0))


def _audio_trak(tkhd_duration, mdhd_timescale, mdhd_duration):
    """The audio trak as CASE B copies it: tkhd + edts/elst + mdia/mdhd."""
    mdia = _box(b"mdia", _mdhd_v0(mdhd_timescale, mdhd_duration)
                + _box(b"hdlr", b"\x00" * 24))
    edts = _box(b"edts", _box(b"elst", struct.pack(">II", 0, 1)
                              + struct.pack(">Iihh", mdhd_duration, 0, 1, 0)))
    return _box(b"trak", _tkhd_v0(tkhd_duration) + edts + mdia)


def _find_child(raw, tag, start, end):
    off = start
    while off < end:
        size = struct.unpack(">I", raw[off:off + 4])[0]
        assert size >= 8 and off + size <= end
        if raw[off + 4:off + 8] == tag:
            return off, size
        off += size
    raise AssertionError(f"no {tag!r} in [{start}, {end})")


def test_strip_track_edit_lists_keeps_the_audio_duration_a_player_sees():
    # Media: 1323000 / 44100 = 30 s. The original moov described them as
    # 30000 ticks of a 1000 Hz movie timescale, also 30 s.
    trak = _audio_trak(tkhd_duration=30000, mdhd_timescale=44100,
                       mdhd_duration=1323000)
    assert 1323000 / 44100 == 30.0
    assert 30000 / 1000 == 30.0

    out = restore_videos.strip_track_edit_lists(trak, 90000)

    # The edit list carrying the lost timescale is gone...
    assert b"elst" not in out
    assert b"edts" not in out
    # ... the media description is untouched (same media duration) ...
    mdia_off, mdia_size = _find_child(out, b"mdia", 8, len(out))
    mdhd_off, _mdhd_size = _find_child(out, b"mdhd", mdia_off + 8,
                                       mdia_off + mdia_size)
    assert struct.unpack(">II", out[mdhd_off + 20:mdhd_off + 28]) == (
        44100, 1323000)
    # ... and the track header now agrees with it: 30 s at 90000 ticks/s.
    tkhd_off, _tkhd_size = _find_child(out, b"tkhd", 8, len(out))
    tkhd_duration = struct.unpack(">I", out[tkhd_off + 28:tkhd_off + 32])[0]
    assert tkhd_duration == 2700000
    assert tkhd_duration / 90000 == 1323000 / 44100
    # The old, unreachable value (30000 / 90000 = 0.33 s) is what the bug used.
    assert 30000 / 90000 < 1
    assert out[4:8] == b"trak"
    assert struct.unpack(">I", out[:4])[0] == len(out)
