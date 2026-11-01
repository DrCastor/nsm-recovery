"""Tests for the entropy-based detection of an oversized encrypted zone.

Two things are checked:

* ``_shannon_entropy`` itself: 8.0 bits/byte for uniform data, 0.0 for a
  constant buffer (and 8.0 for an empty buffer -- the documented "treat it as
  maximally suspicious" choice);
* ``detect_true_enc_header_len``: on a synthetic file made of an
  "encrypted" (pseudo-random) head followed by low-entropy MP4-like
  structure, it must move the boundary away from the default 4096.
"""

import random
import struct

import pytest

import restore_videos


def _noise(n, seed):
    """Deterministic pseudo-random bytes (fixed seed -> reproducible run)."""
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


def _mp4_like_structure(count):
    """Low-entropy, highly repetitive boxes (what follows an encrypted zone)."""
    one = struct.pack(">I", 16) + b"free" + b"\x00" * 8
    assert len(one) == 16
    return one * count


# --------------------------------------------------------------------------
# _shannon_entropy
# --------------------------------------------------------------------------

def test_shannon_entropy_of_all_256_byte_values_is_eight_bits():
    # p == 1/256 for each of the 256 symbols -> exactly 8 bits/byte.
    assert restore_videos._shannon_entropy(bytes(range(256))) == pytest.approx(
        8.0, abs=1e-12)


def test_shannon_entropy_of_a_constant_buffer_is_zero():
    assert restore_videos._shannon_entropy(b"\x00" * 1000) == pytest.approx(
        0.0, abs=1e-12)


def test_shannon_entropy_of_an_empty_buffer_is_eight_bits():
    # Documented behaviour: an empty buffer is reported as maximum entropy
    # (no evidence of structure), never as 0.
    assert restore_videos._shannon_entropy(b"") == pytest.approx(8.0, abs=1e-12)


def test_shannon_entropy_of_two_equiprobable_symbols_is_one_bit():
    assert restore_videos._shannon_entropy(b"ab" * 500) == pytest.approx(
        1.0, abs=1e-12)


def test_shannon_entropy_of_a_90_10_skew_is_about_0_469_bits():
    # -0.9*log2(0.9) - 0.1*log2(0.1) = 0.4689955935892812
    # (cross-checked with an independent computation of the formula.)
    data = b"\x00" * 900 + b"\x01" * 100
    assert restore_videos._shannon_entropy(data) == pytest.approx(
        0.4689955935892812, abs=1e-12)


def test_shannon_entropy_of_pseudo_random_bytes_stays_high_but_below_eight():
    # 4096 draws over 256 symbols are never perfectly uniform: the measured
    # value for this seed is 7.9562, and the test only asserts the band that
    # matters for the threshold (6.0) used by detect_true_enc_header_len.
    data = _noise(4096, 1234)
    entropy = restore_videos._shannon_entropy(data)
    assert 7.5 < entropy < 8.0


def test_shannon_entropy_of_mp4_like_boxes_is_low():
    # Measured 1.4966 bits/byte for this fixture (periodic boxes).
    assert 0.0 < restore_videos._shannon_entropy(_mp4_like_structure(32)) < 2.0


def test_shannon_entropy_is_scale_invariant_for_a_repeated_pattern():
    pattern = b"\x01\x02\x03\x04"
    one = restore_videos._shannon_entropy(pattern)
    many = restore_videos._shannon_entropy(pattern * 1000)
    assert one == pytest.approx(2.0, abs=1e-12)
    assert many == pytest.approx(one, abs=1e-12)


# --------------------------------------------------------------------------
# detect_true_enc_header_len
# --------------------------------------------------------------------------

def test_detect_returns_the_standard_length_when_the_head_is_already_clear(
        tmp_path):
    # Exactly 4096 "encrypted" bytes, then clear structure: the default
    # boundary is already correct.
    data = _noise(4096, 99) + _mp4_like_structure(1024)
    path = tmp_path / "standard.nsm"
    path.write_bytes(data)

    assert restore_videos.detect_true_enc_header_len(str(path), len(data)) == 4096


def test_detect_finds_an_8192_byte_encrypted_zone(tmp_path):
    # 8192 encrypted bytes then structure. Measured: the boundary is
    # recovered exactly (the code rounds the entropy boundary up to the next
    # multiple of 4096 when it is within 512 bytes of it).
    data = _noise(8192, 42) + _mp4_like_structure(1024)
    path = tmp_path / "zone8192.nsm"
    path.write_bytes(data)

    assert restore_videos.detect_true_enc_header_len(str(path), len(data)) == 8192


def test_detect_finds_a_12288_byte_encrypted_zone(tmp_path):
    data = _noise(12288, 99) + _mp4_like_structure(1024)
    path = tmp_path / "zone12288.nsm"
    path.write_bytes(data)

    assert restore_videos.detect_true_enc_header_len(str(path), len(data)) == 12288


def test_detect_reports_a_boundary_close_to_a_non_page_aligned_zone(tmp_path):
    # Empirical tolerance: the refinement step probes 256-byte windows
    # (window // 2) and the final rounding only applies to page-aligned
    # zones, so a 6000-byte zone is underestimated (measured 5832 here).
    # What matters is that the zone is no longer reported as 4096 and that
    # the estimate never overshoots the real boundary.
    data = _noise(6000, 3) + _mp4_like_structure(4096)
    path = tmp_path / "unaligned.nsm"
    path.write_bytes(data)

    detected = restore_videos.detect_true_enc_header_len(str(path), len(data))

    assert 4096 < detected <= 6000
    assert 6000 - detected <= 512


def test_detect_keeps_the_standard_length_when_everything_is_encrypted(tmp_path):
    # No low-entropy transition anywhere: the function must not invent one
    # (the file will be reported as a failure rather than silently rebuilt
    # at the wrong offset).
    data = _noise(200000, 5)
    path = tmp_path / "all-noise.nsm"
    path.write_bytes(data)

    assert restore_videos.detect_true_enc_header_len(str(path), len(data)) == 4096


def test_detect_does_not_look_past_video_len(tmp_path):
    # `video_len` bounds the search: with a video_len equal to the standard
    # length there is nothing to scan, so the default is returned even
    # though the file physically contains a transition at 8192.
    data = _noise(8192, 42) + _mp4_like_structure(1024)
    path = tmp_path / "bounded.nsm"
    path.write_bytes(data)

    assert restore_videos.detect_true_enc_header_len(
        str(path), 4096) == 4096
