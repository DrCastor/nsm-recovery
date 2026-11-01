"""Tests for the ISO-BMFF (MP4) box scanning / validation primitives.

Boxes are hand-built here (a box is ``size(4) | tag(4) | payload``; a
``size`` of 1 means the real size follows on 64 bits, a ``size`` of 0 means
"up to the end of the enclosing range"). The synthetic layout used
throughout is the "moov after mdat" (CASE A) one:

    [0..20)      ftyp
    [20..4096)   free (padding, so that every interesting box starts at or
                 after the encrypted-zone length of 4096)
    [4096..)     mdat
    [..)         moov
"""

import io
import struct

import pytest

import restore_videos

ENC = restore_videos.ENC_HEADER_LEN     # 4096


def _box(tag, payload):
    return struct.pack(">I", 8 + len(payload)) + tag + payload


def _minimal_moov():
    """A structurally valid moov: mvhd + trak(...), tiling exactly."""
    stbl = _box(b"stbl",
                _box(b"stsd", b"\x00" * 8) + _box(b"stts", b"\x00" * 8)
                + _box(b"stsc", b"\x00" * 8) + _box(b"stsz", b"\x00" * 8)
                + _box(b"stco", b"\x00" * 8))
    minf = _box(b"minf", stbl)
    mdia = _box(b"mdia", _box(b"mdhd", b"\x00" * 24) + _box(b"hdlr", b"\x00" * 24)
                + minf)
    trak = _box(b"trak", _box(b"tkhd", b"\x00" * 84) + mdia)
    return _box(b"moov", _box(b"mvhd", b"\x00" * 100) + trak)


FTYP = _box(b"ftyp", b"mp42" + b"\x00" * 4 + b"isom")


def _layout(mdat_payload=b"\x11" * 1000, with_moov=True):
    """Builds the synthetic file.

    Returns (data, mdat_off, moov_off, moov_size); the last two are None when
    `with_moov` is False.
    """
    free = _box(b"free", b"\x00" * (ENC - len(FTYP) - 8))
    mdat = _box(b"mdat", mdat_payload)
    data = FTYP + free + mdat
    mdat_off = len(FTYP) + len(free)
    moov_off = moov_size = None
    if with_moov:
        moov = _minimal_moov()
        moov_off = len(data)
        moov_size = len(moov)
        data += moov
    return data, mdat_off, moov_off, moov_size


# --------------------------------------------------------------------------
# scan_boxes
# --------------------------------------------------------------------------

def test_layout_puts_the_first_interesting_box_at_the_encrypted_zone_length():
    data, mdat_off, moov_off, _moov_size = _layout()

    # Precondition of every offset asserted below.
    assert mdat_off == ENC == 4096
    assert moov_off > mdat_off


def test_scan_boxes_returns_absolute_offsets_tags_and_sizes():
    data, mdat_off, moov_off, moov_size = _layout()

    hits = restore_videos.scan_boxes(data, 0, limit_off=ENC, file_size=len(data))

    # abs_off is the position of the 4-byte size field, i.e. the box start.
    assert (mdat_off, b"mdat", 1008) in hits
    assert (moov_off, b"moov", moov_size) in hits
    # Boxes whose size field lies inside the encrypted zone are ignored.
    assert all(off >= ENC for off, _tag, _size in hits)
    assert (0, b"ftyp", len(FTYP)) not in hits
    # Results come out in file order.
    assert hits == sorted(hits)


def test_scan_boxes_reports_every_nested_box_of_a_valid_moov():
    data, _mdat_off, moov_off, moov_size = _layout()

    hits = restore_videos.scan_boxes(data, 0, limit_off=ENC, file_size=len(data))
    tags = {tag for _off, tag, _size in hits}

    assert {b"moov", b"mvhd", b"trak", b"tkhd", b"mdia", b"stbl", b"stco"} <= tags
    # The moov children are found at their real offsets.
    assert (moov_off + 8, b"mvhd", 108) in hits
    assert (moov_off + 8 + 108, b"trak", moov_size - 8 - 108) in hits


def test_scan_boxes_accepts_the_64_bit_largesize_form():
    largesize = 5000
    data = (struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", largesize)
            + b"\x00" * (largesize - 16))

    hits = restore_videos.scan_boxes(data, 0, limit_off=0, file_size=len(data))

    # The declared size is the 64-bit one, not the 4-byte "1" marker.
    assert hits == [(0, b"mdat", largesize)]


def test_scan_boxes_ignores_a_64_bit_size_smaller_than_its_own_header():
    data = (struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", 12)
            + b"\x00" * 84)

    assert restore_videos.scan_boxes(data, 0, limit_off=0,
                                     file_size=len(data)) == []


def test_scan_boxes_ignores_implausible_sizes():
    too_small = struct.pack(">I", 4) + b"mdat" + b"\x00" * 64
    beyond_file = struct.pack(">I", 100000) + b"mdat" + b"\x00" * 64

    assert restore_videos.scan_boxes(too_small, 0, limit_off=0,
                                     file_size=len(too_small)) == []
    assert restore_videos.scan_boxes(beyond_file, 0, limit_off=0,
                                     file_size=len(beyond_file)) == []


def test_scan_boxes_adds_base_off_to_the_offsets_it_reports():
    data = _box(b"mdat", b"\x00" * 8)

    assert restore_videos.scan_boxes(data, ENC, limit_off=ENC,
                                     file_size=ENC + len(data)) == [
        (ENC, b"mdat", 16)]


def test_scan_boxes_honours_limit_off_against_absolute_offsets():
    data = _box(b"mdat", b"\x00" * 8)

    # The box starts at absolute 4000 < 4096 -> rejected, even though it
    # would be the first thing in the buffer.
    assert restore_videos.scan_boxes(data, 4000, limit_off=ENC,
                                     file_size=9000) == []


# --------------------------------------------------------------------------
# _read_box_header
# --------------------------------------------------------------------------

def test_read_box_header_returns_tag_header_len_and_total_size():
    data = _box(b"test", b"abcd")

    assert restore_videos._read_box_header(io.BytesIO(data), 0, len(data)) == (
        b"test", 8, 12)


def test_read_box_header_handles_the_64_bit_largesize_form():
    data = (struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", 100)
            + b"\x00" * 84)

    tag, header_len, total_size = restore_videos._read_box_header(
        io.BytesIO(data), 0, len(data))

    assert (tag, header_len, total_size) == (b"mdat", 16, 100)


def test_read_box_header_reads_a_zero_size_as_up_to_the_end_of_the_range():
    data = struct.pack(">I", 0) + b"free" + b"\x00" * 20

    assert restore_videos._read_box_header(io.BytesIO(data), 0, len(data)) == (
        b"free", 8, 28)


def test_read_box_header_rejects_a_truncated_header():
    data = _box(b"test", b"abcd")

    assert restore_videos._read_box_header(io.BytesIO(data), 0, 4) is None
    assert restore_videos._read_box_header(io.BytesIO(data), 6, len(data)) is None


def test_read_box_header_rejects_a_size_running_past_the_range():
    data = _box(b"test", b"abcd")

    assert restore_videos._read_box_header(io.BytesIO(data), 0, len(data) - 1) is None


def test_read_box_header_rejects_a_size_smaller_than_its_header():
    data = struct.pack(">I", 4) + b"test" + b"abcd"

    assert restore_videos._read_box_header(io.BytesIO(data), 0, len(data)) is None


# --------------------------------------------------------------------------
# _walk_box_tree
# --------------------------------------------------------------------------

def test_walk_box_tree_accepts_a_case_a_moov_and_collects_its_tags():
    moov = _minimal_moov()
    found = set()

    ok = restore_videos._walk_box_tree(io.BytesIO(moov), 8, len(moov), 0, found)

    assert ok is True
    assert b"mvhd" in found and b"trak" in found
    assert {b"mdia", b"minf", b"stbl", b"stsc", b"stsz", b"stco"} <= found
    # Leaf boxes are recorded but not descended into.
    assert b"udta" not in found


def test_walk_box_tree_rejects_a_gap_between_two_boxes():
    # mvhd followed by 3 stray bytes: the tree no longer tiles exactly.
    data = _box(b"moov", _box(b"mvhd", b"\x00" * 100) + b"\x00\x00\x00")

    assert restore_videos._walk_box_tree(io.BytesIO(data), 8, len(data)) is False


def test_walk_box_tree_rejects_a_non_printable_tag():
    data = _box(b"moov", struct.pack(">I", 8) + b"\x00\x00\x00\x00")

    assert restore_videos._walk_box_tree(io.BytesIO(data), 8, len(data)) is False


def test_walk_box_tree_rejects_a_child_overlapping_its_parent():
    # Child declares 4096 bytes inside a 16-byte parent: it would run past
    # the parent's end.
    data = _box(b"moov", struct.pack(">I", 4096) + b"mvhd" + b"\x00" * 4)

    assert restore_videos._walk_box_tree(io.BytesIO(data), 8, len(data)) is False


def test_walk_box_tree_rejects_an_empty_range():
    # A container with no children is not "perfectly tiled": saw_any is False.
    assert restore_videos._walk_box_tree(io.BytesIO(b"\x00" * 8), 8, 8) is False


def test_walk_box_tree_tolerates_the_four_fullbox_bytes_of_meta():
    # 'meta' is an ISO FullBox: version/flags precede its children. The walk
    # tries the QuickTime layout too, so either form must be accepted.
    hdlr = _box(b"hdlr", b"\x00" * 24)
    meta = _box(b"meta", b"\x00\x00\x00\x00" + hdlr)
    data = _box(b"moov", _box(b"mvhd", b"\x00" * 100)
                + _box(b"udta", meta))
    found = set()

    assert restore_videos._walk_box_tree(io.BytesIO(data), 8, len(data),
                                         0, found) is True
    assert b"hdlr" in found


# --------------------------------------------------------------------------
# validate_moov_box
# --------------------------------------------------------------------------

def test_validate_moov_box_accepts_a_well_formed_moov(tmp_path):
    data, _mdat_off, moov_off, moov_size = _layout()
    path = tmp_path / "case_a.mp4"
    path.write_bytes(data)

    assert restore_videos.validate_moov_box(str(path), moov_off, moov_size,
                                            len(data)) is True


def test_validate_moov_box_rejects_a_mismatched_declared_size(tmp_path):
    data, _mdat_off, moov_off, moov_size = _layout()
    path = tmp_path / "case_a.mp4"
    path.write_bytes(data)

    assert restore_videos.validate_moov_box(str(path), moov_off,
                                            moov_size - 8, len(data)) is False
    assert restore_videos.validate_moov_box(str(path), moov_off,
                                            moov_size + 8, len(data)) is False


def test_validate_moov_box_rejects_an_offset_outside_the_file(tmp_path):
    data, _mdat_off, moov_off, moov_size = _layout()
    path = tmp_path / "case_a.mp4"
    path.write_bytes(data)

    assert restore_videos.validate_moov_box(str(path), -1, moov_size,
                                            len(data)) is False
    assert restore_videos.validate_moov_box(str(path), len(data) - 10, moov_size,
                                            len(data)) is False
    assert restore_videos.validate_moov_box(str(path), moov_off, 0,
                                            len(data)) is False


def test_validate_moov_box_requires_both_mvhd_and_trak(tmp_path):
    mvhd = _box(b"mvhd", b"\x00" * 100)
    trak = _box(b"trak", _box(b"tkhd", b"\x00" * 84))
    for name, body in (("no_trak.mp4", mvhd), ("no_mvhd.mp4", trak)):
        moov = _box(b"moov", body)
        path = tmp_path / name
        path.write_bytes(b"\x00" * 8 + moov)
        assert restore_videos.validate_moov_box(str(path), 8, len(moov),
                                                8 + len(moov)) is False


def test_validate_moov_box_rejects_a_child_that_overflows_the_box(tmp_path):
    # A plausible-looking 'mvhd' with a huge declared size: the tiling check
    # must reject the whole box.
    moov = _box(b"moov", struct.pack(">I", 1 << 30) + b"mvhd" + b"\x00" * 8)
    path = tmp_path / "corrupt.mp4"
    path.write_bytes(b"\x00" * 8 + moov)

    assert restore_videos.validate_moov_box(str(path), 8, len(moov),
                                            8 + len(moov)) is False


def test_validate_moov_box_rejects_a_candidate_that_is_not_a_moov(tmp_path):
    data = _box(b"mdat", b"\x11" * 64)
    path = tmp_path / "not_moov.mp4"
    path.write_bytes(data)

    assert restore_videos.validate_moov_box(str(path), 0, len(data),
                                            len(data)) is False


# --------------------------------------------------------------------------
# find_moov_and_mdat
# --------------------------------------------------------------------------

def test_find_moov_and_mdat_locates_both_boxes_of_a_case_a_file(tmp_path):
    data, mdat_off, moov_off, moov_size = _layout()
    path = tmp_path / "case_a.mp4"
    path.write_bytes(data)

    result = restore_videos.find_moov_and_mdat(str(path), len(data))

    assert result["moov"] == (moov_off, moov_size)
    assert result["mdat"] == (mdat_off, 1008)
    # Everything was found in the head window, so the tail scan was skipped.
    assert result["tail_hits"] == []
    assert result["head_hits"]


def test_find_moov_and_mdat_skips_a_false_moov_signature_inside_mdat(tmp_path):
    # A 'moov' tag with a plausible size planted inside the mdat payload
    # (exactly what compressed video data looks like to a signature scan).
    fake = struct.pack(">I", 32) + b"moov" + b"\xff" * 24
    assert len(fake) == 32
    payload = b"\x11" * 100 + fake + b"\x11" * (1000 - 100 - len(fake))
    data, mdat_off, moov_off, moov_size = _layout(mdat_payload=payload)
    path = tmp_path / "false_positive.mp4"
    path.write_bytes(data)
    fake_off = mdat_off + 8 + 100

    result = restore_videos.find_moov_and_mdat(str(path), len(data))

    # The counterfeit really was seen by the signature scan...
    assert (fake_off, b"moov", 32) in result["head_hits"]
    # ...but it does not validate, so the genuine moov is kept.
    assert result["moov"] == (moov_off, moov_size)
    assert restore_videos.validate_moov_box(str(path), fake_off, 32,
                                            len(data)) is False


def test_find_moov_and_mdat_returns_no_moov_when_there_is_none(tmp_path):
    data, mdat_off, _moov_off, _moov_size = _layout(with_moov=False)
    path = tmp_path / "no_moov.mp4"
    path.write_bytes(data)

    result = restore_videos.find_moov_and_mdat(str(path), len(data))

    assert result["moov"] is None
    assert result["mdat"] == (mdat_off, 1008)
    # Because the moov was missing, the fallback tail scan ran as well and
    # saw the very same boxes.
    assert (mdat_off, b"mdat", 1008) in result["tail_hits"]


def test_find_moov_and_mdat_honours_a_larger_encrypted_zone(tmp_path):
    # With enc_header_len above the moov offset, no box can be trusted.
    data, _mdat_off, _moov_off, _moov_size = _layout()
    path = tmp_path / "huge_zone.mp4"
    path.write_bytes(data)

    result = restore_videos.find_moov_and_mdat(str(path), len(data),
                                               enc_header_len=len(data))

    assert result["moov"] is None
    assert result["mdat"] is None
    assert result["head_hits"] == []


def test_find_moov_and_mdat_does_not_read_past_the_video_length(tmp_path):
    # `size` is the video content length (footer excluded). A file that is
    # longer than the announced content must not shift the offsets found:
    # here the extra bytes are a fake 'mdat' beyond `size`, which must be
    # invisible.
    data, mdat_off, moov_off, moov_size = _layout()
    fake_tail = struct.pack(">I", 64) + b"mdat" + b"\x00" * 56
    path = tmp_path / "with_footer.mp4"
    path.write_bytes(data + fake_tail)

    result = restore_videos.find_moov_and_mdat(str(path), len(data))

    assert result["moov"] == (moov_off, moov_size)
    assert result["mdat"] == (mdat_off, 1008)
    assert all(off <= len(data) for off, _tag, _size in result["head_hits"])
