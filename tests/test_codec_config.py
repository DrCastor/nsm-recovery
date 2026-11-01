"""Tests for the self-contained codec-configuration helpers.

These helpers build and parse H.264 / MPEG-4 Part 2 configuration records
without any external tool, so they can be exercised entirely in memory:

* ``build_fake_avc_sps`` <-> ``parse_sps_dimensions`` (SPS syntax);
* ``build_avcc`` <-> ``parse_avcc_box`` (AVCDecoderConfigurationRecord);
* ``snap_fps`` (rounding of a measured cadence to a standard one);
* ``profile_key`` / ``profile_codec``;
* ``build_mpeg4_vol`` (MPEG-4 Part 2 Video Object Layer bitstream).
"""

import struct

import pytest

import restore_videos


def _bits_of(value, width):
    return format(value, "0%db" % width)


class _BitReader:
    """Minimal big-endian bit reader, used to decode a VOL independently of
    the code that wrote it (the layout comes from ISO/IEC 14496-2 6.2.3)."""

    def __init__(self, data):
        self.bits = "".join(_bits_of(b, 8) for b in data)
        self.pos = 0

    def u(self, n):
        chunk = self.bits[self.pos:self.pos + n]
        assert len(chunk) == n
        self.pos += n
        return int(chunk, 2)


# --------------------------------------------------------------------------
# build_fake_avc_sps / parse_sps_dimensions
# --------------------------------------------------------------------------

@pytest.mark.parametrize("width,height", [
    (1920, 1080),
    (3840, 2160),
    (1280, 720),
    (854, 480),
    (640, 480),
    (176, 144),
    (320, 240),
])
def test_fake_sps_round_trips_the_dimensions(width, height):
    sps = restore_videos.build_fake_avc_sps(width, height)

    # NAL header: nal_ref_idc = 3, nal_unit_type = 7 (SPS).
    assert sps[0] == 0x67
    # parse_sps_dimensions() expects the SPS WITHOUT its NAL header byte.
    assert restore_videos.parse_sps_dimensions(sps[1:]) == (width, height)


def test_fake_sps_crops_to_an_exact_height_that_is_not_a_multiple_of_16():
    # 1080 is not a multiple of 16: the SPS stores 68 macroblock rows (1088)
    # plus a bottom crop of 4 chroma units, and the parser must undo it.
    sps = restore_videos.build_fake_avc_sps(1920, 1080)

    assert restore_videos.parse_sps_dimensions(sps[1:]) == (1920, 1080)

    # The same SPS built for 1088 needs no cropping at all and must not
    # produce the same bitstream.
    assert sps != restore_videos.build_fake_avc_sps(1920, 1088)
    assert restore_videos.parse_sps_dimensions(
        restore_videos.build_fake_avc_sps(1920, 1088)[1:]) == (1920, 1088)


def test_fake_sps_rounds_odd_cropping_up_to_the_next_even_dimension():
    # Empirical: the crop offsets are computed with a // 2 division (4:2:0
    # chroma units), so an odd request comes back one pixel larger.
    assert restore_videos.parse_sps_dimensions(
        restore_videos.build_fake_avc_sps(101, 101)[1:]) == (102, 102)
    assert restore_videos.parse_sps_dimensions(
        restore_videos.build_fake_avc_sps(100, 75)[1:]) == (100, 76)


def test_fake_sps_round_trips_for_a_non_high_profile():
    # profile_idc 77 (Main) has no chroma-format block in the SPS: the parser
    # must not read one.
    sps = restore_videos.build_fake_avc_sps(1280, 720, profile_idc=77,
                                            level_idc=31)

    assert sps[0] == 0x67
    assert restore_videos.parse_sps_dimensions(sps[1:]) == (1280, 720)


@pytest.mark.parametrize("poc_type", [0, 2])
def test_fake_sps_round_trips_for_both_poc_types(poc_type):
    sps = restore_videos.build_fake_avc_sps(640, 360, poc_type=poc_type)

    assert restore_videos.parse_sps_dimensions(sps[1:]) == (640, 360)


def test_parse_sps_dimensions_returns_none_on_an_unparsable_sps():
    # Non-blocking helper: garbage must yield None, never an exception.
    assert restore_videos.parse_sps_dimensions(b"") is None
    assert restore_videos.parse_sps_dimensions(b"\x00" * 8) is None


# --------------------------------------------------------------------------
# build_avcc / parse_avcc_box
# --------------------------------------------------------------------------

SPS = bytes([0x67, 0x64, 0x00, 0x29, 0xAC, 0x2B, 0x40])
PPS = bytes([0x68, 0xEB, 0xE3, 0xCB, 0x22, 0xC0])


def test_build_avcc_wraps_the_record_in_an_avcc_box():
    avcc = restore_videos.build_avcc(SPS, PPS)

    assert avcc[4:8] == b"avcC"
    assert struct.unpack(">I", avcc[:4])[0] == len(avcc)
    # version, profile_idc, compatibility, level_idc, 0xFF, 0xE1
    assert avcc[8:14] == bytes([1, SPS[1], SPS[2], SPS[3], 0xFF, 0xE1])
    assert avcc[14:16] == struct.pack(">H", len(SPS))
    # High profile (100) adds the four chroma/bit-depth bytes at the end.
    assert len(avcc) == 8 + 6 + 2 + len(SPS) + 1 + 2 + len(PPS) + 4
    assert avcc[-4:] == bytes([0xFD, 0xF9, 0xF9, 0x00])


def test_build_avcc_omits_the_high_profile_extension_for_main_profile():
    main_sps = bytes([0x67, 0x4D, 0x00, 0x1F]) + b"\x00" * 4

    avcc = restore_videos.build_avcc(main_sps, PPS)

    assert len(avcc) == 8 + 6 + 2 + len(main_sps) + 1 + 2 + len(PPS)


def test_parse_avcc_box_round_trips_the_sps_and_pps():
    avcc = restore_videos.build_avcc(SPS, PPS)

    sps, pps = restore_videos.parse_avcc_box(avcc[8:])

    assert sps == SPS
    assert pps == PPS


def test_parse_avcc_box_returns_none_none_on_a_truncated_record():
    avcc = restore_videos.build_avcc(SPS, PPS)

    assert restore_videos.parse_avcc_box(avcc[8:12]) == (None, None)
    assert restore_videos.parse_avcc_box(b"") == (None, None)


def test_parse_avcc_box_returns_the_first_sps_and_pps_of_a_record():
    # Two SPS in the record: only the first one is returned.
    other_sps = bytes([0x67, 0x64, 0x00, 0x28]) + b"\x00" * 3
    payload = (bytes([1, SPS[1], SPS[2], SPS[3], 0xFF, 0xE2])
               + struct.pack(">H", len(SPS)) + SPS
               + struct.pack(">H", len(other_sps)) + other_sps
               + bytes([1]) + struct.pack(">H", len(PPS)) + PPS)

    assert restore_videos.parse_avcc_box(payload) == (SPS, PPS)


# --------------------------------------------------------------------------
# snap_fps
# --------------------------------------------------------------------------

@pytest.mark.parametrize("measured,expected", [
    (23.976, 23.976),
    (23.98, 23.976),
    (24.0, 24.0),
    (24000 / 1001, 23.976),      # exact 23.9760239... cadence
    (25.0, 25.0),
    (29.971, 29.97),
    (30.0, 30.0),
    (50.1, 50.0),                # within 0.5 % of 50
    (59.94, 59.94),
    (60.0, 60.0),
])
def test_snap_fps_absorbs_a_tiny_rounding_error(measured, expected):
    assert restore_videos.snap_fps(measured) == pytest.approx(expected,
                                                              abs=1e-9)


@pytest.mark.parametrize("measured,expected", [
    (17.5, 17.5),
    (25.2, 25.2),                # 0.8 % away from 25 -> kept, rounded to 3 dp
    (59.0, 59.0),                # 1.6 % away from 59.94 -> kept
    (12.3456, 12.346),
])
def test_snap_fps_keeps_a_cadence_that_is_not_close_to_a_standard_one(
        measured, expected):
    assert restore_videos.snap_fps(measured) == expected


def test_snap_fps_always_returns_a_standard_cadence_when_it_is_close():
    standards = set(restore_videos.STANDARD_FPS)
    for value in (23.976, 24.0, 25.0, 29.97, 30.0, 50.0, 59.94, 60.0):
        assert restore_videos.snap_fps(value) in standards


# --------------------------------------------------------------------------
# profile_key / profile_codec
# --------------------------------------------------------------------------

def test_profile_key_is_the_sha1_of_the_sps_and_pps():
    # Documented layout of the key: sha1(sps + b"\x00" + pps), i.e. a 40-char
    # hex digest. The expected value below was cross-checked with an
    # independent sha1 computation.
    assert restore_videos.profile_key(SPS, PPS) == (
        "a29b3c39c24bfb56419440f44cf42fa89a88a687")


def test_profile_key_is_stable_and_input_sensitive():
    key = restore_videos.profile_key(SPS, PPS)
    assert restore_videos.profile_key(SPS, PPS) == key
    assert restore_videos.profile_key(PPS, SPS) != key
    assert len(key) == 40
    assert all(c in "0123456789abcdef" for c in key)


def test_profile_key_separates_hevc_profiles_from_avc_ones():
    # A distinct namespace for HEVC, and the VPS changes the key.
    vps = b"\x40\x01\x0c"
    avc_key = restore_videos.profile_key(SPS, PPS)
    hevc_key = restore_videos.profile_key(SPS, PPS, vps)

    assert hevc_key != avc_key
    assert hevc_key != restore_videos.profile_key(SPS, PPS, b"\x40\x01\x0d")
    assert len(hevc_key) == 40


@pytest.mark.parametrize("entry,expected", [
    ({"key": "abc"}, "avc"),
    ({"key": "abc", "codec": "avc"}, "avc"),
    ({"key": "abc", "codec": "hevc"}, "hevc"),
    ({"key": "abc", "codec": None}, "avc"),   # historical entries have no codec
])
def test_profile_codec_defaults_to_avc(entry, expected):
    assert restore_videos.profile_codec(entry) == expected


# --------------------------------------------------------------------------
# build_mpeg4_vol
# --------------------------------------------------------------------------

def test_build_mpeg4_vol_starts_with_the_vol_start_code():
    vol = restore_videos.build_mpeg4_vol(640, 480, 1001)

    # video_object_layer_start_code_plus_shape = 0x00000120
    assert vol[:4] == b"\x00\x00\x01\x20"


def test_build_mpeg4_vol_encodes_width_height_and_time_resolution():
    vol = restore_videos.build_mpeg4_vol(640, 480, 1001)

    br = _BitReader(vol)
    assert br.u(32) == 0x120         # start code + rectangular shape
    assert br.u(1) == 0              # random_accessible_vol
    assert br.u(8) == 1              # video_object_type_indication
    assert br.u(1) == 1              # is_object_layer_identifier
    assert br.u(4) == 1              # video_object_layer_verid
    assert br.u(3) == 1              # video_object_layer_priority
    assert br.u(4) == 1              # aspect_ratio_info = square
    assert br.u(1) == 0              # no control parameters
    assert br.u(2) == 0              # rectangular shape
    assert br.u(1) == 1              # marker_bit
    assert br.u(16) == 1001          # vop_time_increment_resolution
    assert br.u(1) == 1              # marker_bit
    assert br.u(1) == 0              # fixed_vop_rate
    assert br.u(1) == 1              # marker_bit
    assert br.u(13) == 640           # video_object_layer_width
    assert br.u(1) == 1              # marker_bit
    assert br.u(13) == 480           # video_object_layer_height
    assert br.u(1) == 1              # marker_bit
    assert br.u(1) == 0              # interlaced


@pytest.mark.parametrize("width,height,time_res", [
    (1280, 720, 1001),
    (1920, 1080, 1000),
    (176, 144, 25000),
])
def test_build_mpeg4_vol_round_trips_through_an_independent_reader(
        width, height, time_res):
    br = _BitReader(restore_videos.build_mpeg4_vol(width, height, time_res))
    br.u(32 + 1 + 8 + 1 + 4 + 3 + 4 + 1 + 2 + 1)
    assert br.u(16) == time_res
    br.u(1 + 1 + 1)
    assert br.u(13) == width
    br.u(1)
    assert br.u(13) == height


def test_build_mpeg4_vol_reflects_every_parameter():
    base = restore_videos.build_mpeg4_vol(640, 480, 1001)

    assert restore_videos.build_mpeg4_vol(640, 480, 1001) == base
    assert restore_videos.build_mpeg4_vol(641, 480, 1001) != base
    assert restore_videos.build_mpeg4_vol(640, 481, 1001) != base
    assert restore_videos.build_mpeg4_vol(640, 480, 1000) != base
    assert restore_videos.build_mpeg4_vol(640, 480, 1001,
                                          interlaced=1) != base
