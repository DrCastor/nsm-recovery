"""Tests for the ransomware footer ("HARR") parsing.

Footer layout, relative to the end of the file (see parse_footer):

    data[-4:]        == b"HARR"                (end marker)
    data[-49:-45]    == b"HARR"                (start marker)
    data[-50]        == length of the extension
    data[-50-L:-50]  == original extension, e.g. b".mp4"
    data[-45:-4]     == 41 bytes of payload    (mode/nonce/sizes)

so the footer length is ``ext_len + 50``.

Payload layout (see parse_footer_fields):

    [0]      mode (0x15 = HEAD, 0x17 = SPOTS, anything else = unknown)
    [1:25]   24-byte nonce
    [25:33]  original size, u64 big endian
    [33:37]  size of each encrypted zone, u32 big endian
    [37:41]  number of ADDITIONAL encrypted zones, u32 big endian
"""

import struct

import pytest

import restore_videos

MODE_HEAD = 0x15
MODE_SPOTS = 0x17


def _payload(mode, nonce, orig_size, zone_size, spot_count):
    """Builds the 41-byte footer payload."""
    assert len(nonce) == 24
    out = (bytes([mode]) + nonce + struct.pack(">Q", orig_size)
           + struct.pack(">I", zone_size) + struct.pack(">I", spot_count))
    assert len(out) == 41
    return out


def _write_nsm(path, body, extension=b".mp4", payload=None):
    """Writes body + footer to `path`, returns the full file content.

    Physical order, as read by parse_footer: <extension><ext_len><HARR>
    <41-byte payload><HARR> -- the length byte sits immediately before the
    start marker, the extension immediately before the length byte.
    """
    if payload is None:
        payload = _payload(MODE_HEAD, bytes(range(24)), 123456, 4096, 0)
    data = (body + extension + bytes([len(extension)])
            + b"HARR" + payload + b"HARR")
    path.write_bytes(data)
    return data


# --------------------------------------------------------------------------
# parse_footer
# --------------------------------------------------------------------------

def test_parse_footer_reads_extension_footer_length_payload_and_video_len(tmp_path):
    body = b"\xab" * 1000
    payload = _payload(MODE_HEAD, bytes(range(24)), 123456, 4096, 0)
    path = tmp_path / "video.nsm"
    data = _write_nsm(path, body, b".mp4", payload)

    extension, footer_len, got_payload, video_len = restore_videos.parse_footer(
        str(path))

    assert extension == ".mp4"
    assert footer_len == 54              # 4-byte extension + 50
    assert footer_len == len(b".mp4") + 50
    assert got_payload == payload
    assert len(got_payload) == 41
    assert video_len == 1000
    assert video_len == len(data) - footer_len


def test_parse_footer_video_len_is_zero_when_the_file_is_only_a_footer(tmp_path):
    path = tmp_path / "empty.nsm"
    data = _write_nsm(path, b"")

    extension, footer_len, _payload_bytes, video_len = restore_videos.parse_footer(
        str(path))

    assert extension == ".mp4"
    assert footer_len == len(data)
    assert video_len == 0


def test_parse_footer_supports_a_long_extension(tmp_path):
    # 5-char extension: the footer grows with the extension length.
    path = tmp_path / "photo.nsm"
    data = _write_nsm(path, b"\x00" * 10, b".jpeg")

    extension, footer_len, _payload_bytes, video_len = restore_videos.parse_footer(
        str(path))

    assert extension == ".jpeg"
    assert footer_len == 55
    assert video_len == len(data) - 55


def test_parse_footer_accepts_the_maximum_extension_length(tmp_path):
    path = tmp_path / "edge.nsm"
    extension = b"a" * 32
    data = _write_nsm(path, b"\x00" * 4, extension)

    got_extension, footer_len, _payload_bytes, video_len = restore_videos.parse_footer(
        str(path))

    assert got_extension == extension.decode("ascii")
    assert footer_len == 82              # 32 + 50
    assert video_len == len(data) - 82


def test_parse_footer_rejects_a_file_without_any_footer(tmp_path):
    path = tmp_path / "renamed-only.nsm"
    path.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x11" * 100)

    with pytest.raises(ValueError):
        restore_videos.parse_footer(str(path))


def test_parse_footer_rejects_a_file_with_a_truncated_footer(tmp_path):
    # Only the end marker survives: the start marker is corrupted.
    path = tmp_path / "truncated.nsm"
    payload = _payload(MODE_HEAD, b"\x00" * 24, 10, 4096, 0)
    path.write_bytes(b"\x11" * 200 + b".mp4\x04" + b"HARQ" + payload
                     + b"HARR")

    with pytest.raises(ValueError):
        restore_videos.parse_footer(str(path))


def test_parse_footer_rejects_a_zero_extension_length(tmp_path):
    path = tmp_path / "bad-ext.nsm"
    payload = _payload(MODE_HEAD, b"\x00" * 24, 10, 4096, 0)
    # ext_len == 0 (empty extension) while both HARR markers are present.
    path.write_bytes(b"\x11" * 100 + b"\x00" + b"HARR" + payload + b"HARR")

    with pytest.raises(ValueError):
        restore_videos.parse_footer(str(path))


def test_parse_footer_rejects_an_extension_longer_than_32_bytes(tmp_path):
    path = tmp_path / "bad-ext2.nsm"
    payload = _payload(MODE_HEAD, b"\x00" * 24, 10, 4096, 0)
    extension = b"a" * 33
    path.write_bytes(b"\x11" * 100 + extension + bytes([len(extension)])
                     + b"HARR" + payload + b"HARR")

    with pytest.raises(ValueError):
        restore_videos.parse_footer(str(path))


# --------------------------------------------------------------------------
# parse_footer_fields
# --------------------------------------------------------------------------

def test_parse_footer_fields_head_mode(tmp_path):
    nonce = bytes(range(24))
    payload = _payload(MODE_HEAD, nonce, 987654321012, 4096, 0)
    path = tmp_path / "head.nsm"
    _write_nsm(path, b"\x00" * 50, b".mp4", payload)

    _ext, _flen, got_payload, _vlen = restore_videos.parse_footer(str(path))
    fields = restore_videos.parse_footer_fields(got_payload)

    assert fields["mode"] == MODE_HEAD == 0x15
    assert fields["mode_label"] == "HEAD"
    assert fields["nonce"] == nonce
    assert fields["orig_size"] == 987654321012
    assert fields["zone_size"] == 4096
    assert fields["spot_count"] == 0


def test_parse_footer_fields_spots_mode(tmp_path):
    nonce = b"\x5a" * 24
    payload = _payload(MODE_SPOTS, nonce, 5 * 1024 ** 3, 262144, 4)
    path = tmp_path / "spots.nsm"
    _write_nsm(path, b"\x00" * 16, b".mkv", payload)

    _ext, _flen, got_payload, _vlen = restore_videos.parse_footer(str(path))
    fields = restore_videos.parse_footer_fields(got_payload)

    assert fields["mode"] == MODE_SPOTS == 0x17
    assert fields["mode_label"] == "SPOTS"
    assert fields["nonce"] == nonce
    assert fields["orig_size"] == 5 * 1024 ** 3
    assert fields["zone_size"] == 262144
    assert fields["spot_count"] == 4


def test_parse_footer_fields_does_not_label_an_unknown_mode_as_a_known_one():
    # Empirical: any mode byte other than 0x15/0x17 is reported as "unknown"
    # but the raw value is kept intact. We only check that it is not
    # mistaken for a known mode (the label wording itself is a message and
    # is being translated, so it is not asserted).
    payload = _payload(0x99, b"\x00" * 24, 10, 4096, 0)

    fields = restore_videos.parse_footer_fields(payload)

    assert fields["mode"] == 0x99
    assert fields["mode_label"] not in ("HEAD", "SPOTS")
    assert isinstance(fields["mode_label"], str) and fields["mode_label"]


def test_parse_footer_fields_rejects_a_payload_of_the_wrong_length():
    assert restore_videos.parse_footer_fields(None) is None
    assert restore_videos.parse_footer_fields(b"") is None
    assert restore_videos.parse_footer_fields(b"\x00" * 40) is None
    assert restore_videos.parse_footer_fields(b"\x00" * 42) is None


def test_parse_footer_fields_decodes_the_maximum_u64_and_u32_values():
    payload = _payload(MODE_HEAD, b"\x00" * 24, 0xFFFFFFFFFFFFFFFF,
                       0xFFFFFFFF, 0xFFFFFFFF)

    fields = restore_videos.parse_footer_fields(payload)

    assert fields["orig_size"] == 0xFFFFFFFFFFFFFFFF
    assert fields["zone_size"] == 0xFFFFFFFF
    assert fields["spot_count"] == 0xFFFFFFFF


@pytest.mark.parametrize("extension", [b"mp4", b".mp4", b".m4v"])
def test_parse_footer_keeps_the_extension_byte_for_byte(tmp_path, extension):
    path = tmp_path / "ext.nsm"
    _write_nsm(path, b"\x00" * 8, extension)

    got_extension, footer_len, _payload_bytes, _video_len = \
        restore_videos.parse_footer(str(path))

    assert got_extension == extension.decode("ascii")
    assert footer_len == len(extension) + 50
