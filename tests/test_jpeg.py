"""Tests for the JPEG marker scanners used to rebuild photos.

A JPEG is a chain of ``0xFF <marker> <len(2, big endian)> <payload>``
segments, from SOI (``FFD8``) to SOS (``FFDA``), then entropy-coded data up to
EOI (``FFD9``).

Two scanners exist:

* ``_jpeg_markers`` walks the chain but falls back to a one-byte advance
  whenever a declared length is not coherent, so it can resynchronise when the
  intact part starts in the middle of a segment (typically inside an EXIF
  preview). It never reports SOI/EOI/RSTn (0xD0-0xD9) nor stuffed bytes
  (``FF00``).
* ``_jpeg_strict_chain`` follows ONLY declared lengths and returns None as
  soon as the chain is broken; it stops after SOS.
"""

import struct

import restore_videos


def _seg(marker, payload=b""):
    return bytes([0xFF, marker]) + struct.pack(">H", 2 + len(payload)) + payload


SOI = b"\xff\xd8"
EOI = b"\xff\xd9"
APP1 = _seg(0xE1, b"Exif\x00\x00" + b"\x00" * 40)
DQT = _seg(0xDB, b"\x00" + b"\x10" * 64)
SOF0 = _seg(0xC0, b"\x08" + struct.pack(">HH", 480, 640) + b"\x03"
            + b"\x01\x11\x00" * 3)
DHT = _seg(0xC4, b"\x00" * 30)
SOS = _seg(0xDA, b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00")
ENTROPY = b"\x12\x9a\x00\x5c" * 16


def _chain():
    head = SOI + APP1 + DQT + SOF0 + DHT + SOS + ENTROPY + EOI
    # Offsets relative to the start of `head`, and the LENGTH DECLARED in
    # each segment (which excludes the two marker bytes themselves).
    app1_off = len(SOI)
    dqt_off = app1_off + len(APP1)
    sof_off = dqt_off + len(DQT)
    dht_off = sof_off + len(SOF0)
    sos_off = dht_off + len(DHT)
    return {
        "head": head,
        "app1": app1_off,
        "dqt": dqt_off,
        "sof": sof_off,
        "dht": dht_off,
        "sos": sos_off,
        "app1_len": len(APP1) - 2,
        "dqt_len": len(DQT) - 2,
        "sof_len": len(SOF0) - 2,
        "dht_len": len(DHT) - 2,
        "sos_len": len(SOS) - 2,
    }


# --------------------------------------------------------------------------
# _jpeg_markers
# --------------------------------------------------------------------------

def test_jpeg_markers_walks_a_complete_header_and_stops_at_the_entropy_data():
    c = _chain()

    markers = restore_videos._jpeg_markers(c["head"], 0)

    assert markers == [
        (c["app1"], 0xE1, c["app1_len"]),
        (c["dqt"], 0xDB, c["dqt_len"]),
        (c["sof"], 0xC0, c["sof_len"]),
        (c["dht"], 0xC4, c["dht_len"]),
        (c["sos"], 0xDA, c["sos_len"]),
    ]


def test_jpeg_markers_reports_no_soi_eoi_or_stuffed_byte():
    c = _chain()

    markers = restore_videos._jpeg_markers(c["head"], 0)
    found_markers = [m for _off, m, _ln in markers]

    # SOI/EOI/RSTn are deliberately not part of the walk (0xD0..0xD9), and
    # 0xFF00 is a stuffed byte inside entropy data, not a marker.
    assert 0xD8 not in found_markers
    assert 0xD9 not in found_markers
    assert 0x00 not in found_markers


def test_jpeg_markers_resynchronises_after_a_garbage_head():
    # The intact zone starts in the middle of a destroyed segment: the
    # garbage contains a stuffed 0xFF00 and an 0xFFD9 (EOI) that must both be
    # ignored, plus an 0xFFE0 with an impossible length (1).
    garbage = b"GARBAGE" + b"\xff\x00" + b"\xff\xd9" + b"\xff\xe0\x00\x01"
    assert len(garbage) == 15
    c = _chain()
    head = garbage + c["head"]

    markers = restore_videos._jpeg_markers(head, 0)

    assert markers == [
        (len(garbage) + c["app1"], 0xE1, c["app1_len"]),
        (len(garbage) + c["dqt"], 0xDB, c["dqt_len"]),
        (len(garbage) + c["sof"], 0xC0, c["sof_len"]),
        (len(garbage) + c["dht"], 0xC4, c["dht_len"]),
        (len(garbage) + c["sos"], 0xDA, c["sos_len"]),
    ]
    assert all(off >= len(garbage) for off, _m, _ln in markers)


def test_jpeg_markers_stops_at_the_limit():
    c = _chain()

    markers = restore_videos._jpeg_markers(c["head"], 0, limit=c["sos"])

    assert [(off, m) for off, m, _ln in markers] == [
        (c["app1"], 0xE1), (c["dqt"], 0xDB), (c["sof"], 0xC0), (c["dht"], 0xC4)]


def test_jpeg_markers_reports_nothing_for_a_buffer_without_markers():
    assert restore_videos._jpeg_markers(b"no marker here at all, sorry", 0) == []


# --------------------------------------------------------------------------
# _jpeg_strict_chain
# --------------------------------------------------------------------------

def test_jpeg_strict_chain_follows_declared_lengths_up_to_sos():
    c = _chain()

    chain = restore_videos._jpeg_strict_chain(c["head"], len(SOI))

    assert chain == [
        (c["app1"], 0xE1),
        (c["dqt"], 0xDB),
        (c["sof"], 0xC0),
        (c["dht"], 0xC4),
        (c["sos"], 0xDA),
    ]


def test_jpeg_strict_chain_returns_none_on_a_garbage_head():
    # No resynchronisation at all in the strict variant: starting on a
    # non-0xFF byte is an immediate failure.
    garbage = b"GARBAGE" + b"\xff\x00"
    c = _chain()

    assert restore_videos._jpeg_strict_chain(garbage + c["head"], 0) is None


def test_jpeg_strict_chain_rejects_a_start_on_soi():
    c = _chain()

    # 0xD8 is in the 0xD0..0xD8 range, which the strict walk refuses (it is
    # meant to start on the first real header segment, after SOI).
    assert restore_videos._jpeg_strict_chain(c["head"], 0) is None


def test_jpeg_strict_chain_returns_none_when_a_segment_runs_past_the_limit():
    c = _chain()
    # Cut in the middle of the DQT segment.
    cut = c["dqt"] + 10

    assert cut < c["sof"]
    assert restore_videos._jpeg_strict_chain(c["head"], len(SOI), limit=cut) is None


def test_jpeg_strict_chain_returns_none_on_a_zero_length_segment():
    head = b"\xff\xe1\x00\x00" + b"\x00" * 8

    assert restore_videos._jpeg_strict_chain(head, 0) is None


def test_jpeg_strict_chain_stops_on_eoi_without_a_sos():
    app1 = _seg(0xE1, b"x" * 6)
    head = app1 + EOI + b"\x00" * 8

    assert restore_videos._jpeg_strict_chain(head, 0) == [
        (0, 0xE1), (len(app1), 0xD9)]


def test_jpeg_strict_chain_reports_the_real_header_offsets_of_a_rebuilt_photo():
    # Reproduces the actual use case: the rebuilt file is SOI + the intact
    # part of a header whose beginning was destroyed. The chain must start
    # exactly at the first intact segment and tile down to SOS with no gap.
    c = _chain()
    rebuilt = SOI + c["head"][len(SOI):c["sos"] + len(SOS)]

    chain = restore_videos._jpeg_strict_chain(rebuilt, len(SOI))

    assert chain is not None
    offsets = [off for off, _m in chain]
    assert offsets == [c["app1"], c["dqt"], c["sof"], c["dht"], c["sos"]]
    # Each segment starts exactly where the previous one ended (no gap, no
    # overlap) -- that is precisely what makes the rebuilt photo decodable.
    assert offsets[1] == offsets[0] + len(APP1)
    assert offsets[2] == offsets[1] + len(DQT)
    assert offsets[3] == offsets[2] + len(SOF0)
    assert offsets[4] == offsets[3] + len(DHT)
