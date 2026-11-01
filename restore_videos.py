#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
restore_videos.py
==================

Repair tool for video files (MP4, MKV/WebM, AVI, FLV, ASF, MPEG-PS/TS)
and JPEG images damaged by ransomware that encrypts a zone at the head
of the file (the first 4096 bytes on the reference samples, sometimes
more on other files) and appends a small metadata "footer" at the very
end, containing among other things the original extension.

The tool keeps a sps_pps_profiles/ database of SPS/PPS configurations,
learned locally across runs, and --manifest writes an optional CSV
processing log.

Context / diagnosis (established from real files, encrypted and in
clear):

  - A zone at the head of the file is encrypted: the first 4096 bytes on
    the reference samples, sometimes more on other files (up to ~266 KB
    observed). NO byte is moved, inserted or removed: the rest of the
    file is strictly identical to the original, from the end of the
    encrypted zone onwards. Only the data whose samples fall inside that
    zone is lost (a few frames / a few instants of sound at the start of
    the movie).
  - A 54-byte footer (variable with the length of the extension) is
    appended at the end of the encrypted file. Format (relative to the
    end of the file):
        data[-4:]        == b"HARR"                (end marker)
        data[-49:-45]    == b"HARR"                (start marker)
        data[-50]        == length of the extension (e.g. 4 for ".mp4")
        data[-50-L:-50]  == original extension, e.g. b".mp4"
        data[-45:-4]     == 41 bytes of payload (numbers BE): mode,
                             1 byte (0x15 = HEAD, 0x17 = SPOTS); nonce,
                             24 bytes XChaCha20, unique per file;
                             original size, 8 bytes; zone size, 4 bytes
                             (4096 usually, up to 262144 observed);
                             extra zones, 4 bytes (0 in HEAD mode)
  - The cipher key is derived and kept on the attacker's C2 server,
    behind a payment. Neither the footer nor any recovered byte contains
    it, so decryption is impossible without that server. Each file has
    its own nonce, so nothing learnt on one file decrypts another.
    Recovery is therefore STRUCTURAL (rebuild a valid header around the
    intact payload), not cryptographic.

  Two MP4 layouts have been observed in the test batch:

  CASE A - "moov" (the MP4 index) is placed AFTER "mdat" (data), at the
  very end of the file. In that case the ENTIRE moov box lies after byte
  4096 and is therefore INTACT (nothing to rebuild inside it). It is
  enough to rewrite a valid "ftyp"+"mdat" header for the first 4096
  bytes; any very first samples whose absolute offset (stco/co64 table,
  also intact) falls before byte 4096 will stay unreadable (a few
  fractions of a second at the very start of the video), but the rest of
  the file becomes readable again.

  CASE B - "moov" is placed BEFORE "mdat" (the "faststart" structure).
  The moov box may then overlap the encrypted zone: its very first boxes
  (ftyp, mvhd, tkhd/mdia/hdlr/stsd of the 1st track, etc.) are lost, but
  the sample tables (stss/stsc/stsz/stco) that follow beyond byte 4096
  are, themselves, intact. In that case the script rebuilds the missing
  boxes of the video track:
    - the codec config (avcC for H.264, hvcC for H.265/HEVC: profile/
      level/SPS/PPS, +VPS for HEVC) is recovered by reading directly the
      CLEAR NAL units at the start of the first video sample (H.264 and
      H.265 encoders very often repeat SPS/PPS(/VPS) before every key
      frame). The script first tries an H.264 extraction (NAL types 7/8,
      1-byte NAL header), then, if that fails, an H.265/HEVC extraction
      (NAL types 32/33/34, 2-byte NAL header);
    - width/height are recomputed from the SPS thus recovered (H.264 or
      H.265 SPS parsing depending on the case);
    - the audio track, for its part, is generally entirely intact (its
      "trak" box starts well beyond byte 4096) and is copied as-is;
    - the timing (stts) is not recoverable as-is (its box starts before
      byte 4096): a constant-bitrate stts is generated instead. The
      frame rate used is computed AUTOMATICALLY by dividing the number
      of video frames (intact) by the exact duration of the movie read
      from the mdhd of the audio track (also intact); the result is
      rounded to the nearest standard video frame rate (23.976, 24, 25,
      29.97, 30...) if the difference is tiny. --fps (default 24) is
      only used as a fallback if that computation fails (no usable audio
      track). The final render therefore plays back faithfully at a
      constant rate even if the original recording was variable bitrate.

Behaviour
---------
  - The recovered file is written into the SAME FOLDER as the .nsm, with
    the SAME NAME as the original (the original extension is read from
    the HARR footer; e.g. video.nsm -> video.mp4 next to it).
  - If a .nsm does NOT contain a HARR footer (a file that was only
    RENAMED by the ransomware, without encryption): the real format is
    detected from the leading bytes (magic bytes) and the file is simply
    RENAMED to the right extension, with no reconstruction at all.
    Videos become .mp4 by default (or .mkv/.webm/.avi/.flv if another
    video container is detected); images .jpg, .png, .gif, .bmp, .tiff,
    .webp, .heic, .avif; audio .mp3, .ogg, .flac. With --out-dir, the
    file is moved into that folder; without --keep-nsm the original .nsm
    is consumed (renamed in place), with --keep-nsm it is copied and the
    .nsm is kept. If the format is not recognised: the file is treated
    as a failure (-> _error).
  - With --folder, the ENTIRE TREE is walked recursively.
  - The original .nsm is then MOVED, in both cases, into a folder
    LOCATED AT THE ROOT of the folder passed as argument, REPRODUCING
    the original tree:
      - on SUCCESS -> "_to_delete":
          root/sub/videos/video.nsm -> root/_to_delete/sub/videos/video.nsm
        To be deleted afterwards with its content, once the recovered
        file has been checked.
      - on FAILURE -> "_error":
          root/sub/videos/video.nsm -> root/_error/sub/videos/video.nsm
        To be retried later (new version of the script, --width/--height,
        etc.): it is enough to put the file back in its original place.
    (with --files only: "_to_delete"/"_error" are created next to each
    file.)
  - The --keep-nsm option disables all moving (success AND failure): the
    .nsm files stay at their original location.

Usage
-----
    python3 restore_videos.py --folder "path/to/folder"
    python3 restore_videos.py --files "video1.nsm" "video2.nsm"
        [--out-dir "path/to/output"]       (default: same folder as the .nsm)
        [--fps 24]                          (fallback for CASE B files)
        [--width W --height H]              (last resort, priority/starting
                                              point for auto detection)
        [--no-auto-resolution]               (disables the fast auto detection,
                                              MP4 CASE B -- common resolutions +
                                              already encountered, enabled by
                                              default)
        [--brute-force-resolution]           (last resort only, if the fast
                                              detection fails: expensive
                                              combinatorial sweep, disabled by
                                              default -- see
                                              --auto-resolution-timeout)
        [--resolution-lock]                  (with --width/--height AND
                                              --brute-force-resolution: limits
                                              the combinatorial sweep to THAT
                                              single resolution instead of
                                              trying it first among dozens of
                                              others -- tens of thousands of
                                              attempts then drop to a few
                                              hundred, hence fast; only use it
                                              if the real resolution is known
                                              for certain from another source --
                                              for example a thumbnail of the
                                              same capture)
        [--keep-nsm]                        (move nothing, neither success nor
                                             failure)
        [--manifest "path/to/run.manifest.csv"] (append one CSV row per processed
                                                file: timestamp_utc, source,
                                                status, nsm_location)

The script requires NO reference file: everything is re-derived from the
intact data of each file (standard 'ftyp' box rebuilt, codec and
resolution read from the stream, frame rate computed from the duration of
the intact audio track, etc.).

Dependencies: Python 3 standard library (>=3.8) only. ffmpeg/ffprobe,
when present on the PATH, are used as a DECODING ORACLE to validate a
reconstructed codec configuration (donor files, learned profiles,
automatic detection, MKV and JPEG checks); without them the tool still
works but cannot verify those candidates.
"""

import argparse
import csv
import datetime
import glob
import hashlib
import re
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HARR = b"HARR"
KNOWN_TAGS = [b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'udta',
              b'mvhd', b'trak', b'tkhd', b'mdia', b'mdhd', b'hdlr', b'minf',
              b'vmhd', b'smhd', b'dinf', b'dref', b'stbl', b'stsd', b'stts',
              b'stss', b'stsc', b'stsz', b'stco', b'co64', b'ctts', b'avc1',
              b'avcC', b'mp4a', b'esds', b'hev1', b'hvcC', b'elst', b'edts',
              b'meta', b'pnot']

ENC_HEADER_LEN = 4096  # number of encrypted bytes at the head of each file

# Store of SPS/PPS profiles "learned" across runs (see the dedicated
# section further down, near find_profile_match): by default NEXT TO THE
# SCRIPT, shared between all work folders processed with it.
DEFAULT_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sps_pps_profiles')
PROFILE_STORE_FILENAME = 'profiles.json'

# Columns of the optional run journal (see --manifest and append_manifest
# below): written as a CSV header, once, when the file is created.
MANIFEST_HEADER = ('timestamp_utc', 'source', 'status', 'nsm_location')


# --------------------------------------------------------------------------
# Generic utilities
# --------------------------------------------------------------------------

def log(*a):
    # The default Windows console (cp1252/cp850) cannot encode some
    # characters present in the FILE NAMES quoted by the logs (source
    # profile names, etc.): a plain print then raised UnicodeEncodeError and
    # made the whole script fail in the middle of a reconstruction. We
    # replace the unrepresentable characters instead of interrupting.
    try:
        print(*a, flush=True)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, 'encoding', None) or 'utf-8'
        text = ' '.join(str(x) for x in a)
        print(text.encode(enc, 'replace').decode(enc, 'replace'), flush=True)


# Avoids the same problem for direct print() calls and error output (the
# module is imported by restore_and_reencode.py, so the reconfiguration
# also applies to the latter).
for _std_stream in (sys.stdout, sys.stderr):
    try:
        _std_stream.reconfigure(errors='replace')
    except Exception:
        pass


def append_manifest(manifest_path, source, status, nsm_location=''):
    """Appends ONE row to the run manifest (CSV, UTF-8) and returns True.

    Columns, in order:
      timestamp_utc : current UTC time, formatted 'YYYY-MM-DDTHH:MM:SSZ';
      source        : the source file (the .nsm as given on the command line);
      status        : 'restored', 'renamed' or 'failed';
      nsm_location  : final path of the original .nsm when it was moved,
                      empty string when it was kept in place.

    The header (MANIFEST_HEADER) is written once, when the manifest does not
    exist yet or is empty; the parent folder is created if needed. The csv
    module is used with newline='' and UTF-8 so that quoting and non-ASCII
    paths round-trip. This function never raises: on an OSError, or on a
    path that cannot be encoded (UnicodeError, e.g. an unpaired surrogate),
    a warning is logged and False is returned, so a manifest problem never
    interrupts a recovery run."""
    try:
        parent = os.path.dirname(os.path.abspath(manifest_path))
        os.makedirs(parent, exist_ok=True)
        need_header = (not os.path.exists(manifest_path)
                       or os.path.getsize(manifest_path) == 0)
        with open(manifest_path, 'a', encoding='utf-8', newline='') as fh:
            writer = csv.writer(fh)
            if need_header:
                writer.writerow(MANIFEST_HEADER)
            stamp = datetime.datetime.now(
                datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            writer.writerow((stamp, source, status, nsm_location))
        return True
    except (OSError, UnicodeError) as e:
        log(f"[WARNING] cannot write the manifest {manifest_path} ({e}), "
            f"ignored.")
        return False


def box(tag: bytes, payload: bytes) -> bytes:
    """Builds a simple ISO-BMFF box: [size(4)][tag(4)][payload]."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + tag + payload


def read_u32(b, off):
    return struct.unpack(">I", b[off:off + 4])[0]


# Standard 'ftyp' box (28 bytes, major brand 'mp42') rebuilt from
# scratch: the script needs NO reference file.
DEFAULT_FTYPE = box(b'ftyp', b'mp42' + struct.pack(">I", 0) + b'isommp41mp42')
# Default video timescale for durations rebuilt in CASE B
# (90000: standard value for H.264 MP4s, identical to the one in most
# observed files).
DEFAULT_VIDEO_TIMESCALE = 90000


# --------------------------------------------------------------------------
# Step 1: reading the footer appended by the ransomware
# --------------------------------------------------------------------------

def parse_footer(filepath):
    """Returns (extension, footer_len, payload41, video_len) or raises an
    exception if the footer does not match the expected format."""
    size = os.path.getsize(filepath)
    with open(filepath, 'rb') as fh:
        fh.seek(max(0, size - 256))
        tail = fh.read()
    if tail[-4:] != HARR or tail[-49:-45] != HARR:
        raise ValueError("HARR footer not found / unexpected format")
    ext_len = tail[-50]
    if ext_len <= 0 or ext_len > 32:
        raise ValueError(f"unlikely extension length ({ext_len})")
    extension = tail[-50 - ext_len:-50].decode('ascii', 'replace')
    payload = tail[-45:-4]
    footer_len = ext_len + 50
    video_len = size - footer_len
    return extension, footer_len, payload, video_len


# Encryption modes observed in the footer payload (byte 0):
# HEAD = a single encrypted zone at the head (offset 0, size 'zone_size');
# SPOTS = the head zone PLUS 'spot_count' additional zones of 'zone_size'
# bytes each, spread further in the file (on large files). Values
# reverse-engineered from the locker binary (see the locker
# reverse-engineering notes, not part of this project).
FOOTER_MODE_HEAD = 0x15
FOOTER_MODE_SPOTS = 0x17
FOOTER_MODE_LABELS = {FOOTER_MODE_HEAD: 'HEAD', FOOTER_MODE_SPOTS: 'SPOTS'}


def parse_footer_fields(payload: bytes):
    """Decodes the 41-byte payload returned by parse_footer() into its
    structured fields: encryption mode, nonce, original size, and
    description of the encrypted zone(s). Returns None if the payload does
    not have the expected length (41 bytes) -- should normally never
    happen if parse_footer() succeeded, but stays defensive.

    Layout (established by disassembling the locker, see the analysis
    notes):
      [0]      mode (0x15=HEAD, 0x17=SPOTS, other=unknown)
      [1:25]   nonce (24 bytes, XChaCha20 -- useless without the key)
      [25:33]  original size (u64 BE)
      [33:37]  size of EACH encrypted zone, in bytes (u32 BE)
      [37:41]  number of ADDITIONAL encrypted zones beyond the head zone
               (u32 BE) -- 0 in HEAD mode, generally 4 in SPOTS mode
               (observed on files > ~1 GB)."""
    if payload is None or len(payload) != 41:
        return None
    mode = payload[0]
    nonce = payload[1:25]
    orig_size = struct.unpack(">Q", payload[25:33])[0]
    zone_size = struct.unpack(">I", payload[33:37])[0]
    spot_count = struct.unpack(">I", payload[37:41])[0]
    return {
        'mode': mode,
        'mode_label': FOOTER_MODE_LABELS.get(mode, f"unknown ({mode:#x})"),
        'nonce': nonce,
        'orig_size': orig_size,
        'zone_size': zone_size,
        'spot_count': spot_count,
    }


# --------------------------------------------------------------------------
# Adaptive detection of the real encrypted zone length
# --------------------------------------------------------------------------

def _shannon_entropy(b: bytes) -> float:
    if not b:
        return 8.0
    import collections
    c = collections.Counter(b)
    n = len(b)
    import math as _math
    return -sum((v / n) * _math.log2(v / n) for v in c.values())


def detect_true_enc_header_len(filepath, video_len, standard=ENC_HEADER_LEN,
                                search_cap=8 * 1024 * 1024, step=4096,
                                window=512, threshold=6.0):
    """The vast majority of files only have the `standard` (4096) first
    bytes encrypted -- but some real files have a much larger encrypted
    zone (about 256 KB observed). Detects that larger zone BY ENTROPY
    ANALYSIS: encrypted bytes are almost indistinguishable from random
    noise (Shannon entropy ~7.8-7.95 out of 8), whereas the REAL MP4
    metadata that follows (stsz/stco/stsc tables, repetitive structures)
    has a markedly lower entropy. Starting from `standard`, looks for the
    first point where the entropy of a `window`-byte window falls below
    `threshold` -- then refines that position by binary search (accuracy
    to within a few bytes). Returns `standard` unchanged if nothing of the
    kind is found within the first `search_cap` bytes (standard file, or an
    even larger encrypted zone -- in the latter case undetectable by this
    method, the file will stay in error as before rather than risk a false
    result)."""
    # A single low sample may be an ISOLATED fluctuation inside still
    # encrypted noise (observed in practice on a real file: a 512-byte
    # window at 3.9 bits/byte, surrounded on both sides by normal noise at
    # ~7.1-7.5 -- a mere statistical dip, not a real transition to clear
    # data). We therefore require CONFIRMATION: a second sample,
    # immediately after the first one (contiguous window), also below the
    # threshold, before accepting a point as a real boundary. A real
    # encrypted->clear transition stays low over a zone much wider than a
    # single 512-byte window (verified on the real files where this
    # detection worked correctly), so this confirmation costs nothing on
    # the legitimate cases.
    def _confirmed_low(fh, off):
        fh.seek(off + window)
        confirm = fh.read(window)
        return bool(confirm) and _shannon_entropy(confirm) < threshold

    with open(filepath, 'rb') as fh:
        fh.seek(standard)
        first = fh.read(window)
        if _shannon_entropy(first) < threshold and _confirmed_low(fh, standard):
            return standard  # standard case: already clear from `standard` on

        cap = min(search_cap, max(0, video_len - standard))
        off = 0
        first_low = None
        while off < cap:
            fh.seek(standard + off)
            chunk = fh.read(window)
            if chunk and _shannon_entropy(chunk) < threshold and \
               _confirmed_low(fh, standard + off):
                first_low = standard + off
                break
            off += step
        if first_low is None:
            return standard

        lo, hi = max(standard, first_low - step), first_low
        while hi - lo > 8:
            mid = (lo + hi) // 2
            fh.seek(mid)
            chunk = fh.read(max(64, window // 2))
            if _shannon_entropy(chunk) < threshold:
                hi = mid
            else:
                lo = mid

        # Confirmed by byte-to-byte comparison with an original recovered
        # by the user (a real sample): the REAL boundary ALWAYS falls
        # exactly on a multiple of 4096 (encrypted zone aligned on pages --
        # e.g. 262144 = 64 x 4096), whereas a pure entropy search sometimes
        # underestimates it by a few tens to ~150 bytes (the very end of the
        # last still-encrypted page may happen to have an entropy slightly
        # below the threshold). We therefore round up to the next multiple
        # of 4096 -- but only if the difference is small (<=512 bytes, a
        # wide margin compared to the ~150 bytes observed) so as not to
        # shift the boundary excessively if that hypothesis did not hold on
        # another file.
        rounded = ((hi + 4095) // 4096) * 4096
        if 0 < rounded - hi <= 512:
            return rounded
        return hi


def _mpeg_pack_header_ok(data, off):
    """Validates an MPEG-1/2 pack header starting at `off` (00 00 01 BA).

    The standard mandates MARKER bits set to 1 at fixed positions: an
    accidental 4-byte match inside encrypted noise or inside the packets of
    ANOTHER container (real case: a .wmv whose 3,200-byte packets contained
    00 00 01 BA in small islands) almost always fails here. Also checks
    that the following bytes start a system header (00 00 01 BB) or a PES
    packet (00 00 01 BC-FF)."""
    if off + 17 > len(data) or data[off:off + 4] != MPEG_PACK_START:
        return False
    b = data[off + 4:off + 10]
    if (b[0] >> 6) == 1:                        # MPEG-2: '01' + markers
        if not (b[0] & 0x04) or not (b[0] & 0x01):
            return False
        if not (b[2] & 0x04) or not (b[4] & 0x04):
            return False
        last = data[off + 13]
        if (last >> 6) != 3:                    # '11' + pack_stuffing_length
            return False
        nxt = off + 14 + (last & 0x07)
    elif (b[0] >> 4) == 0b0010:                 # MPEG-1: '0010' + markers
        if not (b[0] & 0x01) or not (b[2] & 0x01) or not (b[4] & 0x01):
            return False
        nxt = off + 12
    else:
        return False
    if nxt + 3 > len(data):
        return False
    return data[nxt:nxt + 3] == b'\x00\x00\x01' and data[nxt + 2] >= 0xbc


def find_mpeg_ps_start_strict(filepath, video_len, enc_header_len,
                               search_cap=8 * 1024 * 1024, min_packs=2):
    """Like find_mpeg_ps_start, but only accepts a pack header that passes
    the marker bit validation (_mpeg_pack_header_ok), and requires
    `min_packs` valid packs in the window. Used for container DETECTION
    (see detect_headerless_encrypted_container): the simple version, which
    is content with the 00 00 01 BA pattern, produced a false positive on
    a file that was not MPEG-PS at all.

    The resynchronisation search of repair_mpeg_ps_case_b keeps, for its
    part, find_mpeg_ps_start: there, the stream is copied as-is and the
    result is anyway checked by the decoder."""
    cap = min(search_cap, max(0, video_len - enc_header_len))
    with open(filepath, 'rb') as fh:
        fh.seek(enc_header_len)
        data = fh.read(cap + 32)
    seen = 0
    first = None
    i = data.find(MPEG_PACK_START)
    while i != -1:
        if _mpeg_pack_header_ok(data, i):
            if first is None:
                first = i
            seen += 1
            if seen >= min_packs:
                return (enc_header_len + first,
                        f"{seen} valid MPEG-PS pack headers (marker bits checked)")
        i = data.find(MPEG_PACK_START, i + 1)
    return None, None


def detect_headerless_encrypted_container(filepath, search_cap=16 * 1024 * 1024,
                                           head_window=4096,
                                           entropy_threshold=7.5):
    """When parse_footer fails (no HARR footer), determines whether the
    file could NEVERTHELESS be a file encrypted by the ransomware whose
    FOOTER was lost or truncated (incomplete file, interruption during a
    transfer, corruption...) -- rather than a file that was simply RENAMED
    (that one is intact, hence clear from byte 0).

    Two cumulative proofs are required before concluding:
    1. the first `head_window` bytes have a very high Shannon entropy
       (>= `entropy_threshold`, almost indistinguishable from random
       noise) -- characteristic of an encrypted zone. A file that was
       simply renamed, for its part, has recognisable magic bytes IN CLEAR
       from byte 0 (much lower entropy): if that is not the case here, we
       let the normal detection (detect_type, on a clear file) handle it,
       this is not that case;
    2. a recognisable video container structure is nevertheless found
       further in the file -- for ISO-BMFF (MP4/MOV), TWO independent tag
       families are required together (moov/trak/mdat on one hand,
       stsz/stco/stbl/stsc/stts on the other) to prevent an isolated
       4-byte match, possible by pure chance in encrypted noise, from
       being taken as proof (same confirmation logic as
       detect_true_enc_header_len).

    Returns (extension, description) if both proofs are met, or None
    otherwise (the file is then still treated as a genuine detection
    failure, as before)."""
    try:
        size = os.path.getsize(filepath)
    except OSError:
        return None
    if size < head_window:
        return None

    with open(filepath, 'rb') as fh:
        head = fh.read(head_window)
    if _shannon_entropy(head) < entropy_threshold:
        return None

    with open(filepath, 'rb') as fh:
        data = fh.read(min(search_cap, size))

    has_mp4_container_tag = any(t in data for t in (b'moov', b'trak', b'mdat'))
    has_mp4_sample_table_tag = any(
        t in data for t in (b'stsz', b'stco', b'stbl', b'stsc', b'stts'))
    if has_mp4_container_tag and has_mp4_sample_table_tag:
        return '.mp4', "ISO-BMFF (tags moov/trak/mdat + tables stsz/stco/stbl/stsc/stts)"

    idx = data.find(b'movi')
    if idx >= 8 and data[idx - 8:idx - 4] == b'LIST':
        return '.avi', "RIFF/AVI (LIST 'movi')"

    flv_off = _flv_find_chain(data, 0, size, min_tags=3)
    if flv_off is not None:
        return '.flv', "Adobe FLV (chain of valid tags)"

    if b'\x1a\x45\xdf\xa3' in data:
        return '.mkv', "Matroska/EBML"

    if find_ts_sync(filepath, size, 0, search_cap=search_cap) is not None:
        return '.ts', "MPEG Transport Stream (0x47 sync confirmed on several packets)"

    ps_off, ps_kind = find_mpeg_ps_start_strict(filepath, size, 0, search_cap=search_cap)
    if ps_off is not None:
        return '.mpg', f"MPEG-PS ({ps_kind})"

    return None


# --------------------------------------------------------------------------
# Step 2: generic scan of ISO-BMFF boxes beyond byte 4096
# --------------------------------------------------------------------------

def scan_boxes(data: bytes, base_off: int, limit_off: int = ENC_HEADER_LEN,
                file_size: int = None):
    """Looks for all occurrences of known MP4 tags in `data`
    (data[i] corresponds to the file at offset base_off+i). Only accepts
    boxes whose size field (4 bytes before the tag) is located at an
    absolute offset >= limit_off (hence in a non-encrypted zone), and whose
    declared size is plausible (<= actual file size, if known)."""
    hits = []
    i = 0
    n = len(data)
    max_size = file_size if file_size is not None else (base_off + n)
    while i < n - 8:
        tagbytes = data[i + 4:i + 8]
        if tagbytes in KNOWN_TAGS:
            abs_off = base_off + i  # position of the size field (4 bytes), the tag follows immediately
            if abs_off >= limit_off:
                size_field = read_u32(data, i)
                if size_field == 1:
                    # real size on 64 bits just after the tag (box
                    # > ~4 GB, typically a very large mdat): the 4-byte
                    # field is only a marker, not the size.
                    if i + 16 <= n:
                        largesize = struct.unpack(">Q", data[i + 8:i + 16])[0]
                        if 16 <= largesize <= max_size:
                            hits.append((abs_off, tagbytes, largesize))
                elif 8 <= size_field <= max_size:
                    hits.append((abs_off, tagbytes, size_field))
        i += 1
    return hits


_BOX_TAG_RE = re.compile(rb'^[\x20-\x7e]{4}$')
# Known CONTAINER boxes: find_moov_and_mdat/validate_moov_box recurse
# into these to check that their content tiles exactly with valid sub-boxes;
# the other tags are accepted as opaque "leaf" boxes (mvhd, tkhd, stts,
# stsz, stco, avcC...).
_MOOV_CONTAINER_TAGS = {b'moov', b'trak', b'mdia', b'minf', b'stbl', b'udta',
                         b'edts', b'mvex', b'dinf', b'meta', b'moof', b'traf'}


def _read_box_header(fh, off, end):
    """Reads the header of an ISO-BMFF box at absolute offset `off` (must
    fit within [off, end)). Returns (tag, header_len, total_size) -- with
    total_size INCLUDING the header, like the ISO-BMFF 'size' field -- or
    None if the header is unreadable/inconsistent at that place."""
    if off + 8 > end:
        return None
    fh.seek(off)
    hdr = fh.read(8)
    if len(hdr) < 8:
        return None
    size_field = read_u32(hdr, 0)
    tag = hdr[4:8]
    if size_field == 1:
        if off + 16 > end:
            return None
        ext = fh.read(8)
        if len(ext) < 8:
            return None
        total_size = struct.unpack(">Q", ext)[0]
        header_len = 16
    elif size_field == 0:
        total_size = end - off
        header_len = 8
    else:
        total_size = size_field
        header_len = 8
    if total_size < header_len or off + total_size > end:
        return None
    return tag, header_len, total_size


def _walk_box_tree(fh, off, end, depth=0, found_tags=None, max_depth=16):
    """Checks that a sequence of ISO-BMFF boxes between `off` and `end`
    (exclusive) tiles EXACTLY with valid boxes: no gap, no overlap, the
    last box ends exactly on `end`, and each tag is a plausible printable
    ASCII sequence. Recurses into the known container boxes
    (_MOOV_CONTAINER_TAGS) to check their content the same way.
    Compressed/encrypted data (noise) NEVER produces such a perfectly
    tiled recursive structure by coincidence -- this is the test used to
    reject a false-positive 'moov' found by a mere signature scan inside
    video data (see validate_moov_box)."""
    if depth > max_depth:
        return False
    pos = off
    saw_any = False
    while pos < end:
        hdr = _read_box_header(fh, pos, end)
        if hdr is None:
            return False
        tag, header_len, total_size = hdr
        if not _BOX_TAG_RE.match(tag):
            return False
        if found_tags is not None:
            found_tags.add(tag)
        if tag in _MOOV_CONTAINER_TAGS and total_size > header_len:
            inner = pos + header_len
            child_end = pos + total_size
            # 'meta' is an ISO FullBox (4 version/flags bytes before the
            # children); the QuickTime variant does not have those 4 bytes.
            starts = (inner + 4, inner) if tag == b'meta' else (inner,)
            for start in starts:
                sub_tags = set() if found_tags is not None else None
                if _walk_box_tree(fh, start, child_end, depth + 1,
                                   sub_tags, max_depth):
                    if found_tags is not None:
                        found_tags.update(sub_tags)
                    break
            else:
                return False
        pos += total_size
        saw_any = True
    return saw_any and pos == end


def validate_moov_box(filepath, moov_off, moov_size, file_size):
    """Structurally checks that a candidate 'moov' box (found by a mere
    signature scan, see scan_boxes) really is a valid moov box -- and not a
    coincidence of the 4 bytes 'moov' inside compressed/encrypted video
    data, with a size field that happens to look plausible (observed in
    practice: an .nsm rebuilt WITHOUT any readable stream at all, whereas
    the script had announced a success in CASE A). Requires that the box
    tile exactly with its children (recursively for the known containers),
    and that it contain at least 'trak' and 'mvhd' -- present in any real
    moov box."""
    if moov_off < 0 or moov_size <= 0 or moov_off + moov_size > file_size:
        return False
    try:
        with open(filepath, 'rb') as fh:
            hdr = _read_box_header(fh, moov_off, file_size)
            if hdr is None or hdr[0] != b'moov':
                return False
            _tag, header_len, total_size = hdr
            if total_size != moov_size:
                return False
            found = set()
            ok = _walk_box_tree(fh, moov_off + header_len,
                                 moov_off + total_size, 0, found)
            return ok and b'trak' in found and b'mvhd' in found
    except (OSError, struct.error):
        return False


def find_moov_and_mdat(filepath, size, enc_header_len=ENC_HEADER_LEN):
    """Locates moov/mdat by scanning the beginning (wide window) then, if
    nothing is found, the end of the file (the 'mdat before moov' layout).
    `enc_header_len`: real length of the encrypted zone for THIS file (see
    detect_true_enc_header_len -- most of the time equal to
    ENC_HEADER_LEN/4096, but not always). Returns a dict with the info
    found.

    A 'moov' candidate is only kept if it passes validate_moov_box: the
    signature scan (scan_boxes) may coincidentally match the 4 bytes
    'moov' + a plausible size inside mdat itself (compressed video data) --
    in which case we keep looking among the OTHER candidates found rather
    than accepting the first one that comes."""
    result = {'moov': None, 'mdat': None, 'head_hits': [], 'tail_hits': []}

    def pick_moov(hits):
        for off, tag, sz in hits:
            if tag == b'moov' and validate_moov_box(filepath, off, sz, size):
                return (off, sz)
        return None

    def pick_mdat(hits):
        for off, tag, sz in hits:
            if tag == b'mdat':
                return (off, sz)
        return None

    HEAD_WINDOW = 64 * 1024 * 1024
    with open(filepath, 'rb') as fh:
        head = fh.read(min(HEAD_WINDOW, size))
    head_hits = scan_boxes(head, 0, limit_off=enc_header_len, file_size=size)
    result['head_hits'] = head_hits
    result['moov'] = pick_moov(head_hits)
    result['mdat'] = pick_mdat(head_hits)

    if result['moov'] is None or result['mdat'] is None:
        TAIL_WINDOW = 32 * 1024 * 1024
        # WARNING: `size` is the size of the video CONTENT (without the HARR
        # footer), but the physical file is longer. It is therefore
        # necessary to (a) read exactly TAIL_WINDOW bytes (and not "up to
        # the end of the physical file"), and (b) use the REAL seek
        # position as the base for the offsets. The former code did
        # tbase = size - len(fh.read()) which, with read() going past
        # `size` because of the footer, shifted ALL the offsets found by
        # the footer length (e.g. -54) -> moov located 54 bytes too early,
        # mdat declared 54 bytes too short and moov truncated by 54 bytes
        # in the rebuilt file (unreadable video).
        tstart = max(0, size - TAIL_WINDOW)
        with open(filepath, 'rb') as fh:
            fh.seek(tstart)
            tail = fh.read(TAIL_WINDOW)
        tbase = tstart
        tail_hits = scan_boxes(tail, tbase, limit_off=enc_header_len, file_size=size)
        result['tail_hits'] = tail_hits
        if result['moov'] is None:
            result['moov'] = pick_moov(tail_hits)
        if result['mdat'] is None:
            result['mdat'] = pick_mdat(tail_hits)

    return result


# --------------------------------------------------------------------------
# Minimal H.264 SPS parsing to recover width/height
# --------------------------------------------------------------------------

class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0  # position in bits

    def u(self, n):
        v = 0
        for _ in range(n):
            byte_i = self.pos >> 3
            bit_i = 7 - (self.pos & 7)
            bit = (self.data[byte_i] >> bit_i) & 1 if byte_i < len(self.data) else 0
            v = (v << 1) | bit
            self.pos += 1
        return v

    def ue(self):
        zeros = 0
        while self.u(1) == 0:
            zeros += 1
            if zeros > 32:
                raise ValueError("invalid exp-golomb")
        if zeros == 0:
            return 0
        return (1 << zeros) - 1 + self.u(zeros)

    def se(self):
        k = self.ue()
        return (-1) ** (k + 1) * ((k + 1) // 2)


def ebsp_to_rbsp(nal: bytes) -> bytes:
    """Removes the emulation-prevention byte (0x03) from an H.264/265 NAL unit."""
    out = bytearray()
    zero_run = 0
    i = 0
    n = len(nal)
    while i < n:
        b = nal[i]
        if zero_run >= 2 and b == 0x03 and i + 1 < n and nal[i + 1] <= 0x03:
            zero_run = 0
            i += 1
            continue
        out.append(b)
        zero_run = zero_run + 1 if b == 0 else 0
        i += 1
    return bytes(out)


def parse_sps_dimensions(sps_nal_no_header: bytes):
    """sps_nal_no_header = bytes of the SPS WITHOUT the NAL header byte (the
    one that contains nal_unit_type). Returns (width, height) or None if
    the parsing fails (non-blocking, purely informative)."""
    try:
        rbsp = ebsp_to_rbsp(sps_nal_no_header)
        br = BitReader(rbsp)
        profile_idc = br.u(8)
        br.u(8)  # constraint flags + reserved
        br.u(8)  # level_idc
        br.ue()  # seq_parameter_set_id
        chroma_format_idc = 1
        if profile_idc in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
            chroma_format_idc = br.ue()
            if chroma_format_idc == 3:
                br.u(1)  # separate_colour_plane_flag
            br.ue()  # bit_depth_luma_minus8
            br.ue()  # bit_depth_chroma_minus8
            br.u(1)  # qpprime_y_zero_transform_bypass_flag
            seq_scaling_matrix_present = br.u(1)
            if seq_scaling_matrix_present:
                count = 8 if chroma_format_idc != 3 else 12
                for _ in range(count):
                    present = br.u(1)
                    if present:
                        # scaling_list: advance without using the value
                        size = 16
                        last_scale, next_scale = 8, 8
                        for _ in range(size):
                            if next_scale != 0:
                                delta = br.se()
                                next_scale = (last_scale + delta + 256) % 256
                            last_scale = next_scale if next_scale != 0 else last_scale
        br.ue()  # log2_max_frame_num_minus4
        pic_order_cnt_type = br.ue()
        if pic_order_cnt_type == 0:
            br.ue()  # log2_max_pic_order_cnt_lsb_minus4
        elif pic_order_cnt_type == 1:
            br.u(1)
            br.se()
            br.se()
            num_ref = br.ue()
            for _ in range(num_ref):
                br.se()
        br.ue()  # max_num_ref_frames
        br.u(1)  # gaps_in_frame_num_value_allowed_flag
        pic_width_in_mbs_minus1 = br.ue()
        pic_height_in_map_units_minus1 = br.ue()
        frame_mbs_only_flag = br.u(1)
        if not frame_mbs_only_flag:
            br.u(1)  # mb_adaptive_frame_field_flag
        br.u(1)  # direct_8x8_inference_flag
        frame_cropping_flag = br.u(1)
        crop_left = crop_right = crop_top = crop_bottom = 0
        if frame_cropping_flag:
            crop_left = br.ue()
            crop_right = br.ue()
            crop_top = br.ue()
            crop_bottom = br.ue()

        width = (pic_width_in_mbs_minus1 + 1) * 16
        height = (2 - frame_mbs_only_flag) * (pic_height_in_map_units_minus1 + 1) * 16

        sub_w, sub_h = 2, 2
        if chroma_format_idc == 0:
            sub_w = sub_h = 0
        elif chroma_format_idc == 3:
            sub_w = 1
            sub_h = 2 - frame_mbs_only_flag
        crop_unit_x = sub_w if sub_w else 1
        crop_unit_y = sub_h * (2 - frame_mbs_only_flag) if sub_h else (2 - frame_mbs_only_flag)
        width -= crop_unit_x * (crop_left + crop_right)
        height -= crop_unit_y * (crop_top + crop_bottom)
        return width, height
    except Exception:
        return None


# --------------------------------------------------------------------------
# Extraction of the NAL units (SPS/PPS) at the start of the first video sample
# --------------------------------------------------------------------------

def extract_sps_pps_from_sample(sample_bytes: bytes, length_size=4, max_nals=12):
    """The 'AVCC' format stores each NAL prefixed by its length (big
    endian, over `length_size` bytes, generally 4). We walk the first NALs
    of the very first sample looking for an SPS (type 7) and a PPS
    (type 8)."""
    sps = pps = None
    pos = 0
    n = len(sample_bytes)
    for _ in range(max_nals):
        if pos + length_size > n:
            break
        nal_len = int.from_bytes(sample_bytes[pos:pos + length_size], 'big')
        nal_start = pos + length_size
        nal_end = nal_start + nal_len
        if nal_len <= 0 or nal_end > n:
            break
        nal = sample_bytes[nal_start:nal_end]
        nal_type = nal[0] & 0x1F
        if nal_type == 7 and sps is None:
            sps = nal
        elif nal_type == 8 and pps is None:
            pps = nal
        if sps is not None and pps is not None:
            break
        pos = nal_end
    return sps, pps


def extract_sei_from_sample(sample_bytes: bytes, length_size=4, max_nals=12):
    """Same principle as extract_sps_pps_from_sample() but recovers the
    first SEI NAL (type 6) instead of SPS/PPS: x264 writes its encoding
    options there in clear (see parse_x264_sei_options()), even when
    SPS/PPS are never repeated in the stream."""
    pos = 0
    n = len(sample_bytes)
    for _ in range(max_nals):
        if pos + length_size > n:
            break
        nal_len = int.from_bytes(sample_bytes[pos:pos + length_size], 'big')
        nal_start = pos + length_size
        nal_end = nal_start + nal_len
        if nal_len <= 0 or nal_end > n:
            break
        nal = sample_bytes[nal_start:nal_end]
        if (nal[0] & 0x1F) == 6:
            return nal[1:]
        pos = nal_end
    return None


def build_avcc(sps: bytes, pps: bytes) -> bytes:
    profile_idc = sps[1]
    compat = sps[2]
    level_idc = sps[3]
    payload = bytes([1, profile_idc, compat, level_idc, 0xFF,
                      0xE1]) + struct.pack(">H", len(sps)) + sps
    payload += bytes([1]) + struct.pack(">H", len(pps)) + pps
    if profile_idc in (100, 110, 122, 144):
        # additional "High profile" fields (chroma format, bit depth...)
        payload += bytes([0xFC | 1, 0xF8 | 1, 0xF8 | 1, 0])
    return box(b'avcC', payload)


def parse_avcc_box(avcc_payload: bytes):
    """Parses the CONTENT of a standard avcC box (AVCDecoderConfiguration
    Record: version, profile, level, then the REAL SPS/PPS prefixed by
    their 2-byte length) and returns (sps, pps) -- the first set of each,
    as-is (with their NAL header byte). Unlike build_fake_avc_sps/pps,
    these are not guessed values: they are the REAL parameters written by
    the original encoder, as recovered from a complete and intact MP4 file
    (see find_first_avcc_in_mp4 / find_avcc_donor_sps_pps)."""
    try:
        pos = 5  # version(1) + profile_idc(1) + compat(1) + level_idc(1) +
        #          reserved(6 bits)+lengthSizeMinusOne(2 bits) (1 byte)
        num_sps = avcc_payload[pos] & 0x1F
        pos += 1
        sps = None
        for _ in range(num_sps):
            ln = int.from_bytes(avcc_payload[pos:pos + 2], 'big')
            pos += 2
            nal = avcc_payload[pos:pos + ln]
            pos += ln
            if sps is None:
                sps = nal
        num_pps = avcc_payload[pos]
        pos += 1
        pps = None
        for _ in range(num_pps):
            ln = int.from_bytes(avcc_payload[pos:pos + 2], 'big')
            pos += 2
            nal = avcc_payload[pos:pos + ln]
            pos += ln
            if pps is None:
                pps = nal
        return sps, pps
    except (IndexError, struct.error):
        return None, None


def find_first_avcc_in_mp4(path):
    """Walks a COMPLETE AND INTACT MP4 file (e.g. another video already
    reconstructed successfully, not an encrypted .nsm) to recover the
    content of the 1st avcC box (REAL H.264 config) it contains, or None
    if not found. Works whatever the position of 'moov' (start or end of
    file). Serves as a 'donor file' of real SPS/PPS for another file
    encrypted by the same ransomware and produced by the same
    encoder/pipeline (see --sps-pps-from and find_avcc_donor_sps_pps)."""
    return find_first_codec_config_in_mp4(path, b'avcC', (b'avc1', b'avc3'))[0]


def find_first_hvcc_in_mp4(path):
    """HEVC equivalent of find_first_avcc_in_mp4: returns
    (content of the 1st hvcC box, compressorname of its hvc1/hev1 sample
    entry). The compressorname is used to spot files REENCODED by
    reencode_fix.py (see REENCODER_MARKERS)."""
    return find_first_codec_config_in_mp4(path, b'hvcC', (b'hvc1', b'hev1'))


def find_first_codec_config_in_mp4(path, config_tag, sample_entry_tags):
    """Common engine of find_first_avcc_in_mp4/find_first_hvcc_in_mp4:
    returns (content of the 1st `config_tag` box found in a sample entry
    `sample_entry_tags`, compressorname of that sample entry), or
    (None, None)."""
    CONTAINER_TAGS = (b'moov', b'trak', b'mdia', b'minf', b'stbl', b'udta', b'edts')

    with open(path, 'rb') as f:
        file_size = os.fstat(f.fileno()).st_size
        compressor = [None]

        def walk(start, end, inside_sample_entry=False):
            pos = start
            while pos + 8 <= end:
                f.seek(pos)
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                box_size = read_u32(hdr, 0)
                tag = hdr[4:8]
                header_len = 8
                if box_size == 1:
                    ext = f.read(8)
                    if len(ext) < 8:
                        break
                    box_size = struct.unpack(">Q", ext)[0]
                    header_len = 16
                elif box_size == 0:
                    box_size = end - pos
                if box_size < header_len or pos + box_size > end:
                    break
                child_start = pos + header_len
                child_end = pos + box_size
                if tag == config_tag:
                    f.seek(child_start)
                    return f.read(child_end - child_start)
                if tag in CONTAINER_TAGS:
                    result = walk(child_start, child_end)
                    if result is not None:
                        return result
                elif tag == b'stsd':
                    # payload: version/flags(4) + entry_count(4), then the
                    # sample entries (e.g. 'avc1') that contain avcC.
                    result = walk(child_start + 8, child_end)
                    if result is not None:
                        return result
                elif tag in sample_entry_tags and not inside_sample_entry:
                    # VisualSampleEntry: 78 fixed bytes before the child
                    # boxes (including avcC) -- same layout as the one
                    # built by repair_case_b/build_avcc above. The
                    # compressorname (32 bytes, 1st byte = length) is at
                    # offset 42 of those 78 bytes.
                    f.seek(child_start + 42)
                    cn = f.read(32)
                    if cn:
                        compressor[0] = cn[1:1 + min(cn[0], 31)].decode('latin-1', 'replace')
                    result = walk(child_start + 78, child_end, inside_sample_entry=True)
                    if result is not None:
                        return result
                pos += box_size
            return None

        return walk(0, file_size), compressor[0]


def find_avcc_donor_sps_pps(donor_paths, frame_nals, sei_nal,
                            frame_nals_confirm=None):
    """Tries, for each 'donor' file (an already complete and intact MP4,
    typically another video from the same encoder already reconstructed
    successfully), to extract its REAL SPS/PPS (avcC box) and to check --
    with the SAME ffmpeg oracle as the automatic detection -- whether it
    cleanly decodes the REAL frame sequence of THIS file
    (`frame_nals`/`sei_nal`). A match here is a much better hint than a
    brute-force search: these are the REAL parameters of a similar
    encoding, not a mere guess -- if the donor really uses the same
    encoding profile (same software/settings), the match is almost certain
    rather than probabilistic. Returns (sps, pps, donor_path) of the first
    conclusive donor, or None.
    `frame_nals_confirm`, if provided, is a longer sequence (several GOPs,
    see _oracle_confirm_window) on which a donor that passed the quick
    window is re-tested before being accepted -- a clean decode over 12
    frames may be a false positive (see ORACLE_QUICK_WINDOW)."""
    if not donor_paths:
        return None
    if shutil.which('ffmpeg') is None:
        log("  [SPS/PPS donor] ffmpeg not found in PATH: check "
            "impossible, donor files ignored.")
        return None
    if not frame_nals:
        log("  [SPS/PPS donor] no frame to test (video samples "
            "unreadable): donor files ignored.")
        return None
    for donor_path in donor_paths:
        try:
            avcc_payload = find_first_avcc_in_mp4(donor_path)
        except OSError as e:
            log(f"  [SPS/PPS donor] {donor_path}: unreadable ({e}), ignored.")
            continue
        if not avcc_payload:
            log(f"  [SPS/PPS donor] {os.path.basename(donor_path)}: no "
                f"avcC box (H.264) found, ignored.")
            continue
        sps, pps = parse_avcc_box(avcc_payload)
        if not sps or not pps:
            log(f"  [SPS/PPS donor] {os.path.basename(donor_path)}: SPS/PPS "
                f"unreadable in avcC, ignored.")
            continue
        dims = parse_sps_dimensions(sps[1:])
        dim_txt = f"{dims[0]}x{dims[1]}" if dims else "unknown resolution"
        ok = _ffmpeg_probe_avc(sps, pps, frame_nals, sei_nal)
        if ok and frame_nals_confirm:
            ok = _ffmpeg_probe_avc(sps, pps, frame_nals_confirm, sei_nal,
                                   timeout=ORACLE_CONFIRM_TIMEOUT)
            verdict = ("clean decode over several GOPs -> USED"
                       if ok else
                       "quick decode OK but confirmation (several GOPs) "
                       "failed, ignored")
        else:
            verdict = ("clean decode of the tested sequence -> USED"
                       if ok else "decode failed, ignored")
        log(f"  [SPS/PPS donor] {os.path.basename(donor_path)} ({dim_txt}): "
            + verdict)
        if ok:
            return sps, pps, donor_path
    return None


# Signatures (compressorname of the sample entry, written by ffmpeg in the
# form "Lavc<version> <encoder>") of files REENCODED to H.265 by
# reencode_fix.py / restore_and_reencode.py: their VPS/SPS/PPS are those of
# the re-encoder, not those of the original encoder -- useless as donors
# or profiles for an original .nsm. These scripts use the ffmpeg of the
# PATH: we therefore ALSO require the libavcodec version of that ffmpeg,
# so as not to discard an original encoded in libx265 by another ffmpeg
# (e.g. "Lavc58.35.100 libx265"). Limitation: after a ffmpeg update, the
# re-encodes made with the old version are no longer recognised.
REENCODER_MARKERS = ('hevc_nvenc', 'libx265')
_local_lavc_version = []


def local_lavc_version():
    """libavcodec version of the ffmpeg in the PATH (e.g. '63.1.101'), or None."""
    if not _local_lavc_version:
        version = None
        try:
            r = subprocess.run(['ffmpeg', '-hide_banner', '-version'],
                               capture_output=True, text=True, timeout=10)
            m = re.search(r'libavcodec\s+(\d+)\.\s*(\d+)\.\s*(\d+)', r.stdout or '')
            if m:
                version = '.'.join(str(int(g)) for g in m.groups())
        except (OSError, subprocess.TimeoutExpired):
            pass
        _local_lavc_version.append(version)
    return _local_lavc_version[0]


def looks_reencoded(compressor_name):
    name = (compressor_name or '').lower()
    if not any(m in name for m in REENCODER_MARKERS):
        return False
    version = local_lavc_version()
    return version is None or f'lavc{version} ' in name


def parse_hvcc_box(hvcc_payload: bytes):
    """Parses the CONTENT of an hvcC box (HEVCDecoderConfigurationRecord)
    and returns (vps, sps, pps) -- the first NAL of each type, as-is
    (with its 2-byte NAL header) -- or (None, None, None)."""
    try:
        num_arrays = hvcc_payload[22]
        pos = 23
        found = {}
        for _ in range(num_arrays):
            nal_type = hvcc_payload[pos] & 0x3F
            num_nalus = int.from_bytes(hvcc_payload[pos + 1:pos + 3], 'big')
            pos += 3
            for _ in range(num_nalus):
                ln = int.from_bytes(hvcc_payload[pos:pos + 2], 'big')
                pos += 2
                nal = hvcc_payload[pos:pos + ln]
                pos += ln
                if len(nal) != ln:
                    raise IndexError
                found.setdefault(nal_type, nal)
        return found.get(32), found.get(33), found.get(34)
    except IndexError:
        return None, None, None


def find_hvcc_donor_vps_sps_pps(donor_paths, oracle_nals):
    """HEVC equivalent of find_avcc_donor_sps_pps: extracts the REAL
    VPS/SPS/PPS (hvcC box) of each donor file and validates it with the
    HEVC ffmpeg oracle (_ffmpeg_probe_hevc) on the REAL frame sequence of
    this file (`oracle_nals`, see extract_hevc_nals_from_sample).
    Returns (vps, sps, pps, donor_path) of the first conclusive donor, or
    None."""
    if not donor_paths:
        return None
    if shutil.which('ffmpeg') is None:
        log("  [HEVC VPS/SPS/PPS donor] ffmpeg not found in PATH: "
            "check impossible, donor files ignored.")
        return None
    if not oracle_nals:
        log("  [HEVC VPS/SPS/PPS donor] no frame to test (video samples "
            "unreadable): donor files ignored.")
        return None
    for donor_path in donor_paths:
        name = os.path.basename(donor_path)
        try:
            hvcc_payload, compressor = find_first_hvcc_in_mp4(donor_path)
        except OSError as e:
            log(f"  [HEVC VPS/SPS/PPS donor] {donor_path}: unreadable ({e}), ignored.")
            continue
        if not hvcc_payload:
            log(f"  [HEVC VPS/SPS/PPS donor] {name}: no hvcC box (H.265) "
                f"found, ignored.")
            continue
        vps, sps, pps = parse_hvcc_box(hvcc_payload)
        sps_info = parse_hevc_sps(sps) if sps else None
        if not (sps and pps and sps_info):
            log(f"  [HEVC VPS/SPS/PPS donor] {name}: VPS/SPS/PPS unreadable "
                f"in hvcC, ignored.")
            continue
        if looks_reencoded(compressor):
            log(f"  [HEVC VPS/SPS/PPS donor] {name}: looks REENCODED "
                f"({compressor}) -- its parameters are those of the re-encoder, "
                f"not of the original encoder: unlikely match.")
        ok = _ffmpeg_probe_hevc(vps, sps, pps, oracle_nals)
        log(f"  [HEVC VPS/SPS/PPS donor] {name} "
            f"({sps_info['width']}x{sps_info['height']}): "
            + ("clean decode of the tested sequence -> USED"
               if ok else "decode failed, ignored"))
        if ok:
            return vps, sps, pps, donor_path
    return None


# --------------------------------------------------------------------------
# SPS/PPS profiles "learned" across runs (cumulative store,
# multi-file, multi-source)
# --------------------------------------------------------------------------
#
# Same principle as the "donor" files (--sps-pps-from) above, but
# AUTOMATIC and CUMULATIVE: each time the script recovers a REAL SPS/PPS
# for a CASE B file (via an explicit --sps-pps-from or via this store
# itself), it records it here with an occurrence counter. On subsequent
# runs, these profiles are tried automatically -- from the MOST frequently
# encountered to the LEAST frequent -- before falling back to the automatic
# search-based detection: many files often come from the same encoder (hence
# the same settings), the right profile is then generally found very
# quickly, with the reliability of a REAL SPS/PPS rather than a guessed
# value.
#
# Deliberately, only REAL SPS/PPS (explicit donor, already known profile,
# or .mp4 file already validated via --seed-profiles) feed this store --
# never the parameters guessed by the automatic detection or by
# --width/--height, which are not guaranteed reliable.
#
# Stored by default next to the script (DEFAULT_PROFILE_DIR, independent of
# the work folder), in a single JSON file `profiles.json`:
#   [{"key": "<sha1 sps+pps>", "sps_hex": "...", "pps_hex": "...",
#     "count": 7, "width": 1920, "height": 1080,
#     "first_seen": "...", "last_seen": "...",
#     "sources": ["fileA.mp4", "fileB.mp4", ...]}, ...]
# HEVC profiles additionally have "codec": "hevc" and "vps_hex"; an entry
# without a "codec" field is an H.264 profile (historical format).


def profile_store_path(profile_dir):
    return os.path.join(profile_dir, PROFILE_STORE_FILENAME)


def load_profile_store(profile_dir):
    path = profile_store_path(profile_dir)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (OSError, ValueError):
        pass
    return []


def save_profile_store(profile_dir, store):
    os.makedirs(profile_dir, exist_ok=True)
    path = profile_store_path(profile_dir)
    tmp_path = path + f'.tmp{os.getpid()}'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def profile_key(sps: bytes, pps: bytes, vps: bytes = None) -> str:
    if vps is not None:
        return hashlib.sha1(b'hevc\x00' + vps + b'\x00' + sps + b'\x00' + pps).hexdigest()
    return hashlib.sha1(sps + b'\x00' + pps).hexdigest()


def profile_codec(entry) -> str:
    return entry.get('codec') or 'avc'


def register_profile(profile_dir, sps: bytes, pps: bytes, source_label,
                      dims=None, max_sources=8, vps: bytes = None):
    """Adds (or updates the counter of) an SPS/PPS profile in the store
    persisted next to the script. Returns (is_new, count). Tolerant to
    errors: an unreadable/corrupt store must never make the current
    reconstruction fail, just restart empty. `vps` provided = HEVC profile
    (VPS/SPS/PPS), otherwise H.264 profile."""
    try:
        store = load_profile_store(profile_dir)
        key = profile_key(sps, pps, vps)
        now = datetime.datetime.now().isoformat(timespec='seconds')
        for entry in store:
            if entry.get('key') == key:
                entry['count'] = int(entry.get('count', 1)) + 1
                entry['last_seen'] = now
                sources = entry.setdefault('sources', [])
                if source_label and source_label not in sources:
                    sources.append(source_label)
                    del sources[:-max_sources]
                save_profile_store(profile_dir, store)
                return False, entry['count']
        entry = {
            'key': key,
            'sps_hex': sps.hex(),
            'pps_hex': pps.hex(),
            'count': 1,
            'first_seen': now,
            'last_seen': now,
            'sources': [source_label] if source_label else [],
        }
        if vps is not None:
            entry['codec'] = 'hevc'
            entry['vps_hex'] = vps.hex()
        if dims:
            entry['width'], entry['height'] = dims
        store.append(entry)
        save_profile_store(profile_dir, store)
        return True, 1
    except Exception as e:
        log(f"  [SPS/PPS profiles] recording impossible ({e}), ignored.")
        return False, 0


def iter_profiles_sorted(profile_dir, codec='avc'):
    """Returns [(sps, pps, entry), ...] for the profiles of the requested
    codec ('avc' or 'hevc' -- the HEVC VPS is in entry['vps_hex']), from
    the MOST to the LEAST frequently encountered profile (tie: most
    recently seen first)."""
    store = [e for e in load_profile_store(profile_dir) if profile_codec(e) == codec]
    store.sort(key=lambda e: (int(e.get('count', 0)), e.get('last_seen', '')),
               reverse=True)
    out = []
    for entry in store:
        try:
            sps = bytes.fromhex(entry['sps_hex'])
            pps = bytes.fromhex(entry['pps_hex'])
        except (KeyError, ValueError):
            continue
        out.append((sps, pps, entry))
    return out


def find_profile_match(profile_dir, frame_nals, sei_nal, max_candidates=None,
                       timeout=4, frame_nals_confirm=None):
    """Tries the SPS/PPS profiles already recorded, from the most to the
    least frequent, with the same multi-frame ffmpeg oracle as
    find_avcc_donor_sps_pps. Returns (sps, pps, entry) of the first
    conclusive profile, or None. As for the donors, `frame_nals_confirm`
    (several GOPs) re-tests every profile that passed the quick window
    before accepting it -- the 12-frame quick window is shorter than one
    GOP on most streams and may accept a foreign profile that only breaks
    beyond it (see ORACLE_QUICK_WINDOW)."""
    if shutil.which('ffmpeg') is None:
        return None
    if not frame_nals:
        return None
    profiles = iter_profiles_sorted(profile_dir)
    if not profiles:
        return None
    if max_candidates:
        profiles = profiles[:max_candidates]
    log(f"  [SPS/PPS profiles] {len(profiles)} known profile(s) in the store "
        f"({profile_dir}), trying from most to least frequent...")
    for i, (sps, pps, entry) in enumerate(profiles, 1):
        dims = parse_sps_dimensions(sps[1:])
        dim_txt = f"{dims[0]}x{dims[1]}" if dims else "unknown resolution"
        ok = _ffmpeg_probe_avc(sps, pps, frame_nals, sei_nal, timeout=timeout)
        if ok and frame_nals_confirm:
            ok = _ffmpeg_probe_avc(sps, pps, frame_nals_confirm, sei_nal,
                                   timeout=ORACLE_CONFIRM_TIMEOUT)
            verdict = ("clean decode over several GOPs -> USED"
                       if ok else
                       "confirmation (several GOPs) failed, next")
        else:
            verdict = ("clean decode -> USED" if ok else "failed, next")
        src_txt = (entry.get('sources') or ['?'])[-1]
        log(f"  [SPS/PPS profiles] #{i}/{len(profiles)} seen {entry.get('count', '?')} "
            f"times (e.g. {src_txt}, {dim_txt}): {verdict}")
        if ok:
            return sps, pps, entry
    return None


def find_hevc_profile_match(profile_dir, oracle_nals, max_candidates=None, timeout=8):
    """HEVC equivalent of find_profile_match: tries the HEVC VPS/SPS/PPS
    profiles already recorded with the HEVC ffmpeg oracle. Returns
    (vps, sps, pps, entry) of the first conclusive profile, or None."""
    if shutil.which('ffmpeg') is None or not oracle_nals:
        return None
    profiles = []
    for sps, pps, entry in iter_profiles_sorted(profile_dir, codec='hevc'):
        try:
            vps = bytes.fromhex(entry['vps_hex']) if entry.get('vps_hex') else None
        except ValueError:
            continue
        profiles.append((vps, sps, pps, entry))
    if not profiles:
        log(f"  [HEVC VPS/SPS/PPS profiles] no HEVC profile in the store ({profile_dir}).")
        return None
    if max_candidates:
        profiles = profiles[:max_candidates]
    log(f"  [HEVC VPS/SPS/PPS profiles] {len(profiles)} known HEVC profile(s) in "
        f"the store ({profile_dir}), trying from most to least frequent...")
    for i, (vps, sps, pps, entry) in enumerate(profiles, 1):
        info = parse_hevc_sps(sps)
        dim_txt = f"{info['width']}x{info['height']}" if info else "unknown resolution"
        ok = _ffmpeg_probe_hevc(vps, sps, pps, oracle_nals, timeout=timeout)
        src_txt = (entry.get('sources') or ['?'])[-1]
        log(f"  [HEVC VPS/SPS/PPS profiles] #{i}/{len(profiles)} seen {entry.get('count', '?')} "
            f"times (e.g. {src_txt}, {dim_txt}): "
            + ("clean decode -> USED" if ok else "failed, next"))
        if ok:
            return vps, sps, pps, entry
    return None


def iter_candidate_video_files(paths):
    exts = ('.mp4', '.m4v', '.mov')
    for p in paths:
        if os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                for fn in filenames:
                    if fn.lower().endswith(exts):
                        yield os.path.join(dirpath, fn)
        elif os.path.isfile(p):
            if p.lower().endswith(exts):
                yield p
        else:
            for m in sorted(glob.glob(p)):
                if os.path.isfile(m) and m.lower().endswith(exts):
                    yield m


def seed_profiles_from_paths(paths, profile_dir):
    """Maintenance mode (--seed-profiles): walks the given files/folders,
    extracts the REAL SPS/PPS (avcC box) of each .mp4/.m4v/.mov found, and
    records it in the profile store -- WITHOUT trying to reconstruct
    anything. Useful to prime the store with already reconstructed/valid
    videos before (re)processing failed .nsm files from the same
    encoder."""
    files = list(iter_candidate_video_files(paths))
    if not files:
        log("No .mp4/.m4v/.mov file found in the paths given to --seed-profiles.")
        return 0, 0, 0
    log(f"Priming the SPS/PPS profile store from {len(files)} file(s) "
        f"(-> {profile_dir})...")
    added, updated, skipped = 0, 0, 0
    for path in files:
        try:
            avcc_payload = find_first_avcc_in_mp4(path)
        except OSError as e:
            log(f"  {os.path.basename(path)}: unreadable ({e}), ignored.")
            skipped += 1
            continue
        if not avcc_payload:
            result = _seed_hevc_profile(path, profile_dir)
            if result == 'added':
                added += 1
            elif result == 'updated':
                updated += 1
            else:
                skipped += 1
            continue
        sps, pps = parse_avcc_box(avcc_payload)
        if not sps or not pps:
            log(f"  {os.path.basename(path)}: SPS/PPS unreadable in avcC, ignored.")
            skipped += 1
            continue
        dims = parse_sps_dimensions(sps[1:])
        is_new, count = register_profile(profile_dir, sps, pps,
                                          os.path.basename(path), dims=dims)
        dim_txt = f"{dims[0]}x{dims[1]}" if dims else "unknown resolution"
        if is_new:
            added += 1
            log(f"  {os.path.basename(path)} ({dim_txt}): new profile.")
        else:
            updated += 1
            log(f"  {os.path.basename(path)} ({dim_txt}): profile already known (seen {count} times).")
    log(f"Priming complete: {added} new profile(s), {updated} already known "
        f"(counter incremented), {skipped} file(s) ignored.")
    return added, updated, skipped


def _seed_hevc_profile(path, profile_dir):
    """HEVC part of seed_profiles_from_paths: returns 'added', 'updated'
    or 'skipped'. Files REENCODED by reencode_fix.py are ignored
    (see REENCODER_MARKERS): their parameters will never match an original
    .nsm and would only slow down every search."""
    name = os.path.basename(path)
    try:
        hvcc_payload, compressor = find_first_hvcc_in_mp4(path)
    except OSError as e:
        log(f"  {name}: unreadable ({e}), ignored.")
        return 'skipped'
    if not hvcc_payload:
        log(f"  {name}: no avcC (H.264) nor hvcC (H.265) box found, ignored.")
        return 'skipped'
    if looks_reencoded(compressor):
        log(f"  {name}: HEVC re-encoded ({compressor}), ignored.")
        return 'skipped'
    vps, sps, pps = parse_hvcc_box(hvcc_payload)
    info = parse_hevc_sps(sps) if sps else None
    if not (sps and pps and info):
        log(f"  {name}: VPS/SPS/PPS unreadable in hvcC, ignored.")
        return 'skipped'
    dims = (info['width'], info['height'])
    is_new, count = register_profile(profile_dir, sps, pps, name, dims=dims, vps=vps)
    if is_new:
        log(f"  {name} ({dims[0]}x{dims[1]}, HEVC): new profile.")
        return 'added'
    log(f"  {name} ({dims[0]}x{dims[1]}, HEVC): profile already known (seen {count} times).")
    return 'updated'


# --------------------------------------------------------------------------
# HEVC / H.265: VPS/SPS/PPS extraction and minimal SPS parsing
# --------------------------------------------------------------------------
#
# Unlike AVC where the NAL header is only one byte, an HEVC NAL unit starts
# with a 2-byte header:
#   forbidden_zero_bit(1) + nal_unit_type(6) + nuh_layer_id(6) + nuh_temporal_id_plus1(3)
# The types we care about: VPS=32, SPS=33, PPS=34.


def extract_vps_sps_pps_from_sample_hevc(sample_bytes: bytes, length_size=4,
                                          max_nals=32):
    """Same principle as extract_sps_pps_from_sample, but for HEVC: the NAL
    units are always prefixed by their length ('HVCC' layout), but the NAL
    type is read differently (2 header bytes, type on 6 bits)."""
    vps = sps = pps = None
    pos = 0
    n = len(sample_bytes)
    for _ in range(max_nals):
        if pos + length_size > n:
            break
        nal_len = int.from_bytes(sample_bytes[pos:pos + length_size], 'big')
        nal_start = pos + length_size
        nal_end = nal_start + nal_len
        if nal_len <= 0 or nal_end > n:
            break
        nal = sample_bytes[nal_start:nal_end]
        if len(nal) >= 2:
            nal_type = (nal[0] >> 1) & 0x3F
            if nal_type == 32 and vps is None:
                vps = nal
            elif nal_type == 33 and sps is None:
                sps = nal
            elif nal_type == 34 and pps is None:
                pps = nal
        if sps is not None and pps is not None:
            break
        pos = nal_end
    return vps, sps, pps


def parse_hevc_sps(sps_nal_with_header: bytes):
    """sps_nal_with_header = complete SPS NAL unit, HEVC header (2 bytes)
    included. Returns a dict with width/height and the fields needed to
    rebuild the 'hvcC' box, or None if parsing fails (non-blocking).

    Trick (as for build_avcc in AVC): the 12 bytes that follow the first
    byte of the SPS (sps_video_parameter_set_id / sps_max_sub_layers
    / sps_temporal_id_nesting on 1 byte) match EXACTLY, bit for
    bit, the general_profile_space/tier/idc + compatibility flags +
    constraint flags + general_level_idc fields expected in the
    HEVCDecoderConfigurationRecord ('hvcC'): they can therefore be copied
    verbatim instead of being re-parsed field by field."""
    try:
        payload = sps_nal_with_header[2:]  # strips the NAL header (2 bytes)
        rbsp = ebsp_to_rbsp(payload)
        if len(rbsp) < 13:
            return None
        b0 = rbsp[0]
        max_sub_layers_minus1 = (b0 >> 1) & 0x7
        general_ptl_bytes = rbsp[1:13]
        general_level_idc = general_ptl_bytes[11]

        br = BitReader(rbsp)
        br.pos = 13 * 8  # skip the initial byte + the 12 profile_tier_level bytes

        sub_profile_present = []
        sub_level_present = []
        for _ in range(max_sub_layers_minus1):
            sub_profile_present.append(br.u(1))
            sub_level_present.append(br.u(1))
        if max_sub_layers_minus1 > 0:
            for _ in range(max_sub_layers_minus1, 8):
                br.u(2)  # reserved_zero_2bits
        for i in range(max_sub_layers_minus1):
            if sub_profile_present[i]:
                br.u(2); br.u(1); br.u(5); br.u(32); br.u(4); br.u(44)
            if sub_level_present[i]:
                br.u(8)

        br.ue()  # sps_seq_parameter_set_id
        chroma_format_idc = br.ue()
        if chroma_format_idc == 3:
            br.u(1)  # separate_colour_plane_flag
        pic_width_in_luma_samples = br.ue()
        pic_height_in_luma_samples = br.ue()
        conf_left = conf_right = conf_top = conf_bottom = 0
        if br.u(1):  # conformance_window_flag
            conf_left = br.ue()
            conf_right = br.ue()
            conf_top = br.ue()
            conf_bottom = br.ue()
        bit_depth_luma_minus8 = br.ue()
        bit_depth_chroma_minus8 = br.ue()

        if chroma_format_idc == 0:
            crop_x, crop_y = 1, 1
        elif chroma_format_idc == 1:
            crop_x, crop_y = 2, 2
        elif chroma_format_idc == 2:
            crop_x, crop_y = 2, 1
        else:
            crop_x, crop_y = 1, 1

        width = pic_width_in_luma_samples - crop_x * (conf_left + conf_right)
        height = pic_height_in_luma_samples - crop_y * (conf_top + conf_bottom)
        if width <= 0 or height <= 0:
            return None

        return {
            'width': width, 'height': height,
            'chroma_format_idc': chroma_format_idc,
            'bit_depth_luma_minus8': bit_depth_luma_minus8,
            'bit_depth_chroma_minus8': bit_depth_chroma_minus8,
            'general_ptl_bytes': bytes(general_ptl_bytes),
            'general_level_idc': general_level_idc,
        }
    except Exception:
        return None


def build_hvcc(vps: bytes, sps: bytes, pps: bytes, sps_info: dict) -> bytes:
    """Builds a minimal but valid 'hvcC' box (HEVCDecoderConfigurationRecord)
    from the VPS/SPS/PPS NAL units recovered in the clear and the
    information extracted from the SPS by parse_hevc_sps()."""
    general_ptl = sps_info['general_ptl_bytes']  # 12 bytes, copied verbatim
    chroma_format_idc = sps_info['chroma_format_idc']
    bd_luma = sps_info['bit_depth_luma_minus8']
    bd_chroma = sps_info['bit_depth_chroma_minus8']

    payload = bytearray()
    payload.append(1)                       # configurationVersion
    payload += general_ptl                  # profile/tier/level (12 bytes)
    payload += struct.pack(">H", 0xF000)    # reserved(4)=1111 + min_spatial_segmentation_idc(12)=0
    payload.append(0xFC)                    # reserved(6)=111111 + parallelismType(2)=0 (unknown)
    payload.append(0xFC | (chroma_format_idc & 0x3))
    payload.append(0xF8 | (bd_luma & 0x7))
    payload.append(0xF8 | (bd_chroma & 0x7))
    payload += struct.pack(">H", 0)         # avgFrameRate = 0 (not specified)
    # constantFrameRate(2)=0 + numTemporalLayers(3)=1 + temporalIdNested(1)=0
    # + lengthSizeMinusOne(2)=3 (NAL units are always prefixed with 4 bytes)
    payload.append((0 << 6) | (1 << 3) | (0 << 2) | 3)

    arrays = []
    if vps is not None:
        arrays.append((32, vps))
    arrays.append((33, sps))
    arrays.append((34, pps))
    payload.append(len(arrays))             # numOfArrays
    for nal_type, nal in arrays:
        payload.append(nal_type & 0x3F)     # array_completeness=0, reserved=0
        payload += struct.pack(">H", 1)     # numNalus
        payload += struct.pack(">H", len(nal))
        payload += nal
    return box(b'hvcC', bytes(payload))


def recover_hevc_config_without_inband_params(fh, first_sample, stsc_raw, stco_raw,
                                               stsz_raw, donor_files, profile_dir,
                                               use_profiles, sample_window=12):
    """CASE B, HEVC stream whose VPS/SPS/PPS are NEVER repeated in the
    stream (they only lived in the original hvcC, lost in the encrypted
    zone). HEVC cascade equivalent to the H.264 one: donor files
    (--sps-pps-from) then learned HEVC profiles, each one validated by
    the HEVC ffmpeg oracle on the first REAL samples of the file.

    Returns (is_hevc, result): is_hevc tells whether the stream was
    recognised as HEVC (in that case the H.264 cascade makes no sense and
    must be skipped); result = None or dict {'codec': 'hevc-donor'|'hevc-profile',
    'vps', 'sps', 'pps', 'sps_info', 'donor_used', 'profile_used'}."""
    oracle_nals = []
    try:
        for (o, s) in resolve_leading_video_sample_offsets(
                stsc_raw, stco_raw, stsz_raw, sample_window):
            fh.seek(o)
            oracle_nals.extend(extract_hevc_nals_from_sample(fh.read(s)))
    except Exception:
        oracle_nals = extract_hevc_nals_from_sample(first_sample)
    if not looks_like_hevc_nals(extract_hevc_nals_from_sample(first_sample)):
        return False, None
    log("  HEVC/H.265 video stream detected, with no VPS/SPS/PPS in the clear: codec "
        "config to be taken from a donor (--sps-pps-from) or from a learned HEVC profile.")

    found = hevc_config_from_donors_or_profiles(oracle_nals, donor_files,
                                                profile_dir, use_profiles)
    if found is None:
        return True, None
    return True, found


def hevc_config_from_donors_or_profiles(oracle_nals, donor_files=None,
                                        profile_dir=None, use_profiles=True):
    """HEVC cascade for a stream whose VPS/SPS/PPS are never repeated in
    the clear (they only lived in the original CodecPrivate / hvcC box,
    lost in the encrypted zone): donor files (--sps-pps-from) then learned
    HEVC profiles, each one validated by the ffmpeg decode oracle
    (_ffmpeg_probe_hevc) on the REAL NAL units of the file
    (`oracle_nals`).

    Shared by CASE B MP4 (recover_hevc_config_without_inband_params) and
    by the Matroska rebuild (.mkv/.webm, see process_mkv_file).

    Returns a dict {'codec': 'hevc-donor'|'hevc-profile', 'vps', 'sps',
    'pps', 'sps_info', 'donor_used', 'profile_used'} or None if neither a
    donor nor a store profile decodes the stream."""
    found = None
    if donor_files:
        r = find_hvcc_donor_vps_sps_pps(donor_files, oracle_nals)
        if r:
            vps, sps, pps, donor_path = r
            found = {'codec': 'hevc-donor', 'vps': vps, 'sps': sps, 'pps': pps,
                     'donor_used': donor_path, 'profile_used': None}
    if found is None and use_profiles:
        r = find_hevc_profile_match(profile_dir, oracle_nals)
        if r:
            vps, sps, pps, entry = r
            found = {'codec': 'hevc-profile', 'vps': vps, 'sps': sps, 'pps': pps,
                     'donor_used': None, 'profile_used': entry}
    if found is None:
        return None
    found['sps_info'] = parse_hevc_sps(found['sps'])
    if not found['sps_info']:
        return None
    return found


def hevc_failure_message(donor_files, profile_dir, use_profiles):
    """CASE B failure message for an HEVC stream with no VPS/SPS/PPS in the clear."""
    donor_note = ""
    if donor_files:
        donor_note = (f"{len(donor_files)} donor file(s) tested "
                      f"(--sps-pps-from), no conclusive match. ")
    profile_note = ""
    if use_profiles:
        n_hevc = len(iter_profiles_sorted(profile_dir, codec='hevc'))
        profile_note = (f"{n_hevc} known HEVC profile(s) in the store ({profile_dir}) "
                        f"tested, no conclusive match. " if n_hevc else
                        f"No HEVC profile in the store ({profile_dir}). ")
    return (donor_note + profile_note +
            "HEVC/H.265 video stream whose VPS/SPS/PPS are never repeated "
            "in the stream: they only lived in the original hvcC box, "
            "lost in the encrypted zone. Automatic detection and "
            "--width/--height only apply to H.264. Re-run with "
            "--sps-pps-from on an ORIGINAL (not re-encoded) HEVC .mp4 from the same "
            "encoder, or prime the store with --seed-profiles on such "
            "files (the outputs re-encoded by reencode_fix.py will not do: "
            "their parameters are those of the re-encoder).")


# --------------------------------------------------------------------------
# Reading "raw" ISO-BMFF boxes from the file (verbatim copy)
# --------------------------------------------------------------------------

def read_raw_box(fh, off):
    fh.seek(off)
    hdr = fh.read(8)
    size = read_u32(hdr, 0)
    tag = hdr[4:8]
    if size == 1:
        largesize = struct.unpack(">Q", fh.read(8))[0]
        fh.seek(off)
        return fh.read(largesize), tag
    fh.seek(off)
    return fh.read(size), tag


def box_header_len(fh, off):
    """Returns the header length (8 or 16 bytes) of an ISO-BMFF box at
    position `off`: 8 for a normal size (4 bytes), 16 if the size field
    equals 1 (real size on 64 bits right after the tag -- box larger
    than ~4 GB, typically a very large mdat)."""
    fh.seek(off)
    size_field = struct.unpack(">I", fh.read(4))[0]
    return 16 if size_field == 1 else 8


def patch_stco_boxes(data: bytes, delta: int) -> bytes:
    """Walks `data` (a self-contained ISO-BMFF box blob, e.g. the
    content of a 'trak' box) and shifts by `delta` bytes every
    value held in the 'stco'/'co64' boxes it contains
    (absolute chunk offsets into 'mdat'). Returns a new blob of
    the SAME LENGTH (only the numeric values change)."""
    buf = bytearray(data)
    i = 0
    n = len(buf)
    while i < n - 8:
        tag = bytes(buf[i + 4:i + 8])
        if tag == b'stco':
            size = struct.unpack(">I", buf[i:i + 4])[0]
            entry_count = struct.unpack(">I", buf[i + 12:i + 16])[0]
            for k in range(entry_count):
                off = i + 16 + 4 * k
                if off + 4 > n:
                    break
                val = struct.unpack(">I", buf[off:off + 4])[0]
                newval = val + delta
                if not (0 <= newval <= 0xFFFFFFFF):
                    raise ValueError("stco shift out of 32-bit range")
                struct.pack_into(">I", buf, off, newval)
            i += max(size, 8)
            continue
        if tag == b'co64':
            size = struct.unpack(">I", buf[i:i + 4])[0]
            entry_count = struct.unpack(">I", buf[i + 12:i + 16])[0]
            for k in range(entry_count):
                off = i + 16 + 8 * k
                if off + 8 > n:
                    break
                val = struct.unpack(">Q", buf[off:off + 8])[0]
                struct.pack_into(">Q", buf, off, val + delta)
            i += max(size, 8)
            continue
        i += 1
    return bytes(buf)


def find_first_box_after(fh, start, end, wanted_tags):
    """Looks, scanning byte by byte between start and end, for the
    first occurrence of one of the `wanted_tags` boxes whose size
    field is itself >= start (unencrypted zone)."""
    fh.seek(start)
    chunk = fh.read(end - start)
    hits = scan_boxes(chunk, start, limit_off=start)
    for off, tag, sz in hits:
        if tag in wanted_tags:
            return off, tag, sz
    return None


# --------------------------------------------------------------------------
# Automatic determination of the video frame rate (CASE B) from the
# REAL duration of the audio track, which is intact
# --------------------------------------------------------------------------
#
# The video timing (stts) is lost (its box sat before byte
# 4096), but we know:
#   - the total number of video frames (stsz entry_count, intact);
#   - the exact duration of the movie in seconds, via the mdhd of the AUDIO
#     track (intact, since its 'trak' box starts well beyond byte
#     4096 and is copied verbatim).
# Dividing one by the other gives the REAL AVERAGE frame rate of the
# file, which is far more reliable than a value guessed at random.

STANDARD_FPS = [23.976, 24.0, 25.0, 29.97, 30.0, 47.952, 48.0, 50.0, 59.94, 60.0]


def parse_mdhd_from_trak(trak_raw: bytes):
    """Looks for the 'mdhd' box inside a complete 'trak' box blob
    (e.g. audio_trak_raw) and returns (timescale, duration), or None
    if not found / unreadable."""
    hits = scan_boxes(trak_raw, 0, limit_off=0, file_size=len(trak_raw))
    for off, tag, sz in hits:
        if tag != b'mdhd':
            continue
        base = off + 8  # after size(4)+tag(4)
        if base >= len(trak_raw):
            continue
        try:
            version = trak_raw[base]
            if version == 1:
                timescale = struct.unpack(">I", trak_raw[base + 20:base + 24])[0]
                duration = struct.unpack(">Q", trak_raw[base + 24:base + 32])[0]
            else:
                timescale = struct.unpack(">I", trak_raw[base + 12:base + 16])[0]
                duration = struct.unpack(">I", trak_raw[base + 16:base + 20])[0]
        except struct.error:
            continue
        if timescale > 0 and duration > 0:
            return timescale, duration
    return None


def _trak_direct_children(trak_bytes: bytes):
    """Walks the DIRECT children of a 'trak' box held in its own buffer
    (box header included, size == len(trak_bytes)). Returns a list of
    (tag, offset, size) or raises ValueError if the buffer is not a
    well-formed, self-contained 'trak' box."""
    if len(trak_bytes) < 8:
        raise ValueError('buffer too short for a box header')
    size = read_u32(trak_bytes, 0)
    if trak_bytes[4:8] != b'trak' or size < 8 or size != len(trak_bytes):
        raise ValueError('not a self-contained trak box')
    children = []
    off = 8
    while off < size:
        if off + 8 > size:
            raise ValueError('truncated child box header')
        child_size = read_u32(trak_bytes, off)
        if child_size < 8 or off + child_size > size:
            raise ValueError('implausible child box size')
        children.append((trak_bytes[off + 4:off + 8], off, child_size))
        off += child_size
    if off != size:
        raise ValueError('children do not tile the trak box')
    return children


def _rewrite_tkhd_duration_box(tkhd_bytes: bytes, new_duration: int) -> bytes:
    """Rewrites the duration field of a 'tkhd' box (version 0: 32-bit at
    payload offset 20, version 1: 64-bit at payload offset 28), leaving the
    rest of the box untouched. Returns the box unchanged if it is too short
    to hold a duration field."""
    if len(tkhd_bytes) < 9:
        return tkhd_bytes
    version = tkhd_bytes[8]
    if version == 1:
        off, width, fmt = 8 + 28, 8, ">Q"
    else:
        off, width, fmt = 8 + 20, 4, ">I"
    if off + width > len(tkhd_bytes):
        return tkhd_bytes
    return tkhd_bytes[:off] + struct.pack(fmt, new_duration) + tkhd_bytes[off + width:]


def strip_track_edit_lists(trak_bytes: bytes, movie_timescale: int) -> bytes:
    """Removes the DIRECT 'edts' child (hence its 'elst') from a 'trak' box
    copied verbatim from a donor file into a freshly rebuilt 'moov'.

    CASE B rebuilds the moov around a synthetic movie timescale (the real
    one was in the original moov, destroyed by the ransomware); the copied
    track's edit list, and its 'tkhd' duration, are still expressed in that
    lost ORIGINAL movie timescale. A conformant player then truncates
    playback at the stale edit list duration even though the media data is
    complete (observed: 14.7s instead of 30s). This drops the edit list and
    rewrites the 'tkhd' duration from the copied track's own 'mdhd'
    (media timescale/duration, untouched) converted to `movie_timescale`.

    A 'trak' with no 'edts' is returned byte-identical (no re-encoding). On
    malformed/garbage input, or when no 'mdhd' can be read, this never
    raises: it falls back to returning the input unchanged, respectively
    to leaving the 'tkhd' duration as it stands."""
    try:
        children = _trak_direct_children(trak_bytes)
    except ValueError:
        return trak_bytes

    if not any(tag == b'edts' for tag, _off, _size in children):
        return trak_bytes

    new_duration = None
    mdhd = parse_mdhd_from_trak(trak_bytes)
    if mdhd:
        media_timescale, media_duration = mdhd
        new_duration = round(media_duration / media_timescale * movie_timescale)

    kept = []
    for tag, off, size in children:
        if tag == b'edts':
            continue
        chunk = trak_bytes[off:off + size]
        if tag == b'tkhd' and new_duration is not None:
            chunk = _rewrite_tkhd_duration_box(chunk, new_duration)
        kept.append(chunk)
    return box(b'trak', b''.join(kept))


def snap_fps(value: float):
    """If `value` is very close to a standard video frame rate (within
    0.5%), returns that standard rate (e.g. 23.976) instead of the raw
    computed value (e.g. 23.9711...), to absorb the small rounding
    inaccuracies of stsz/mdhd."""
    best = min(STANDARD_FPS, key=lambda r: abs(r - value))
    if abs(best - value) <= max(0.03, best * 0.005):
        return best
    return round(value, 3)


def detect_fps_from_audio(audio_trak_raw: bytes, sample_count: int):
    """Returns (fps, description) if the video frame rate could be derived
    from the real duration of the audio track, otherwise None."""
    mdhd = parse_mdhd_from_trak(audio_trak_raw)
    if not mdhd:
        return None
    a_timescale, a_duration = mdhd
    audio_duration_s = a_duration / a_timescale
    if audio_duration_s <= 0 or sample_count <= 0:
        return None
    computed = sample_count / audio_duration_s
    if not (1.0 <= computed <= 240.0):
        # Aberrant audio duration (truncated/missing audio track: mdhd at 0,
        # typical in SPOTS mode when the real audio trak is encrypted):
        # do not derive a frame rate from it -- prefer the SPS VUI or --fps.
        return None
    fps = snap_fps(computed)
    desc = (f"computed from the intact audio track: {sample_count} frames / "
            f"{audio_duration_s:.3f}s of audio (audio mdhd, timescale={a_timescale}) "
            f"= {computed:.4f} fps -> {fps} fps")
    return fps, desc


def _fps_from_sps(sps_with_header):
    """Extracts the frame rate from the VUI of a REAL H.264 SPS (intact
    avcC box, learned profile or donor): timing_info = num_units_in_tick/time_scale,
    rate = time_scale / (2 * num_units_in_tick). Returns a float or None
    if the VUI/timing is absent. Useful when the audio duration is unusable
    (SPOTS mode): the codec config, for its part, is reliable."""
    if not sps_with_header or len(sps_with_header) < 3:
        return None
    try:
        rbsp = ebsp_to_rbsp(sps_with_header[1:])
        br = BitReader(rbsp)
        profile_idc = br.u(8)
        br.u(8)
        br.u(8)
        br.ue()  # seq_parameter_set_id
        if profile_idc in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
            chroma = br.ue()
            if chroma == 3:
                br.u(1)
            br.ue(); br.ue(); br.u(1)
            if br.u(1):  # seq_scaling_matrix_present
                n = 8 if chroma != 3 else 12
                for i in range(n):
                    if br.u(1):
                        size = 16 if i < 6 else 64
                        last = 8
                        nxt = 8
                        for _ in range(size):
                            if nxt != 0:
                                nxt = (last + br.se() + 256) % 256
                            last = nxt if nxt != 0 else last
        br.ue()  # log2_max_frame_num_minus4
        poc = br.ue()
        if poc == 0:
            br.ue()
        elif poc == 1:
            br.u(1); br.se(); br.se()
            for _ in range(br.ue()):
                br.se()
        br.ue()   # max_num_ref_frames
        br.u(1)   # gaps_in_frame_num_value_allowed_flag
        br.ue()   # pic_width_in_mbs_minus1
        br.ue()   # pic_height_in_map_units_minus1
        frame_mbs_only = br.u(1)
        if not frame_mbs_only:
            br.u(1)
        br.u(1)   # direct_8x8_inference_flag
        if br.u(1):  # frame_cropping_flag
            br.ue(); br.ue(); br.ue(); br.ue()
        if not br.u(1):  # vui_parameters_present_flag
            return None
        if br.u(1):  # aspect_ratio_info_present_flag
            if br.u(8) == 255:
                br.u(16); br.u(16)
        if br.u(1):  # overscan_info_present_flag
            br.u(1)
        if br.u(1):  # video_signal_type_present_flag
            br.u(3); br.u(1)
            if br.u(1):
                br.u(8); br.u(8); br.u(8)
        if br.u(1):  # chroma_loc_info_present_flag
            br.ue(); br.ue()
        if not br.u(1):  # timing_info_present_flag
            return None
        num = br.u(32)
        ts = br.u(32)
        br.u(1)  # fixed_frame_rate_flag
        if num <= 0:
            return None
        fps = ts / (2.0 * num)
        if 1.0 <= fps <= 240.0:
            return round(fps, 3)
    except (IndexError, ValueError):
        return None
    return None


def guess_duration_seconds_from_filename(path):
    """Some recording tools (observed on several REAL files) name their
    files with an 'HH.MM.SS.mmm-HH.MM.SS.mmm' suffix (cut boundaries
    start-end, in hours/minutes/seconds/milliseconds since the start of the
    raw capture) just before the extension -- e.g.
    'name_12-00-00-00.00.00.000-00.30.00.000.nsm' (useful duration
    00:30:00.000). Returns the duration in seconds (end - start) if that
    pattern is found and plausible
    (between 1 second and 24h), otherwise None. NAMING HEURISTIC (not a
    container datum) -- see detect_fps_from_filename below for
    the guard that checks it really matches a standard rate
    before relying on it."""
    base = os.path.splitext(os.path.basename(path))[0]
    m = re.search(
        r'(\d{2})\.(\d{2})\.(\d{2})\.(\d{3})-(\d{2})\.(\d{2})\.(\d{2})\.(\d{3})$',
        base)
    if not m:
        return None
    h1, m1, s1, ms1, h2, m2, s2, ms2 = (int(g) for g in m.groups())
    t1 = h1 * 3600 + m1 * 60 + s1 + ms1 / 1000.0
    t2 = h2 * 3600 + m2 * 60 + s2 + ms2 / 1000.0
    duration = t2 - t1
    if duration <= 1.0 or duration > 24 * 3600:
        return None
    return duration


def detect_fps_from_filename(path, sample_count):
    """Like detect_fps_from_audio above, but from the duration
    GUESSED from the file NAME (see
    guess_duration_seconds_from_filename) -- fallback used only
    when no audio track is available to compute a real
    rate (single video track, see repair_case_b_single_video_track).
    Returns (fps, description) ONLY if the resulting rate matches
    a standard video rate (within 0.5%, see snap_fps): otherwise the
    file name pattern probably does not encode a duration
    (false positive, or simply another recording tool) and we
    return None rather than imposing an implausible rate -- --fps
    then remains the only fallback."""
    duration = guess_duration_seconds_from_filename(path)
    if duration is None or sample_count <= 0:
        return None
    raw_fps = sample_count / duration
    snapped = snap_fps(raw_fps)
    if snapped not in STANDARD_FPS:
        return None
    return snapped, (f"derived from the file name ('start-end' pattern detected, "
                      f"useful duration = {duration:.3f}s): {sample_count} frames / "
                      f"{duration:.3f}s = {raw_fps:.4f} fps -> {snapped} fps -- "
                      f"HEURISTIC (not a container datum, derived from the file "
                      f"name), to be checked in a video player")


# --------------------------------------------------------------------------
# CASE A: intact moov, placed after mdat (or at least after byte 4096)
# --------------------------------------------------------------------------

def repair_case_a(filepath, out_path, video_len, moov_off, moov_size,
                   ftyp: bytes, progress=None, head_len=ENC_HEADER_LEN):
    """Rewrites only the first `head_len` bytes (ftyp + mdat header)
    and copies everything else verbatim up to moov_off+moov_size.
    `head_len` must match the REAL size of the encrypted zone for
    this file (zone_size field of the footer if available, otherwise
    detection by entropy, otherwise the standard value 4096) -- using
    the constant ENC_HEADER_LEN instead would be incorrect on files
    whose encrypted zone exceeds 4096 bytes (rebuild leaving
    still encrypted bytes in the output)."""
    mdat_body_len = moov_off - len(ftyp)
    if mdat_body_len <= 0:
        raise ValueError("unexpected layout (moov before the end of ftyp?)")

    # The "body" of mdat starts just after new_header (at offset
    # len(new_header), <= head_len) and not necessarily at head_len: the
    # declared size of mdat must be recomputed accordingly once
    # new_header is assembled.
    def _mdat_header_for(body_len):
        if body_len < (1 << 32) - 1:
            return struct.pack(">I", body_len + 8) + b'mdat'
        return struct.pack(">I", 1) + b'mdat' + struct.pack(">Q", body_len + 16)

    new_header = ftyp + _mdat_header_for(mdat_body_len)
    mdat_true_body_len = moov_off - len(new_header)
    new_header = ftyp + _mdat_header_for(mdat_true_body_len)
    padding = head_len - len(new_header)
    if padding < 0:
        raise ValueError(f"rebuilt header (ftyp+mdat) > {head_len} bytes, case not handled")
    new_header += b'\x00' * padding

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(new_header)
        src.seek(head_len)
        remaining = (moov_off + moov_size) - head_len
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)
    return True


# --------------------------------------------------------------------------
# CASE B, variant "stsc/stsz also lost": only the stco table of the
# video track survived
# --------------------------------------------------------------------------
#
# Normally, when the video codec config (stsd/avcC) is lost, its
# sample tables stsc/stsz/stco (which follow stsd in stbl)
# survive anyway -- they are large (proportional to the
# number of samples) and therefore extend well beyond byte
# 4096. But if stsc (chunk -> sample count mapping) is itself
# very large -- frequent for a real-time capture with an
# irregular chunk split -- its OWN tag can still fall
# in the encrypted zone, also causing the loss of stsz (which follows
# just after). In that case only stco (the last of the three, often
# the latest in the file) remains visible.
#
# stsc/stsz can nevertheless be REBUILT in a very frequent case: a
# real-time capture usually interleaves audio and video by writing
# EACH sample as a separate chunk (1 sample = 1 chunk). By
# merging the chunk offsets of the video track (stco, recovered) with
# those of THE OTHER intact track (usually the audio, whose stco is
# itself fully reliable), we know the split position of EACH
# sample in mdat, video or audio alike, whatever the
# interleaving: the size of a video sample is then simply
# the distance to the next split (video or audio). The result
# is checked (plausible sizes) before being used.


def parse_stco_offsets(stco_raw: bytes):
    """Returns the list of chunk offsets (integers, file order)
    of an already read 'stco' OR 'co64' box (raw bytes, with header)."""
    entry_count = struct.unpack(">I", stco_raw[12:16])[0]
    offsets = []
    if stco_raw[4:8] == b'co64':
        for k in range(entry_count):
            base = 16 + 8 * k
            if base + 8 > len(stco_raw):
                break
            offsets.append(struct.unpack(">Q", stco_raw[base:base + 8])[0])
        return offsets
    for k in range(entry_count):
        base = 16 + 4 * k
        if base + 4 > len(stco_raw):
            break
        offsets.append(struct.unpack(">I", stco_raw[base:base + 4])[0])
    return offsets


def derive_synthetic_stsc_stsz(video_stco_raw: bytes, other_stco_raw: bytes,
                                mdat_data_end: int):
    """Rebuilds synthetic (but STRUCTURALLY valid, directly usable as if
    they had been recovered) 'stsc'/'stsz' boxes for the video track,
    assuming 1 sample per chunk -- see the section above. Returns
    (stsc_raw, stsz_raw), or None if the assumption produces aberrant
    sizes (video chunk and next chunk identical, negative/huge
    size...)."""
    video_offsets = parse_stco_offsets(video_stco_raw)
    other_offsets = parse_stco_offsets(other_stco_raw) if other_stco_raw else []
    if not video_offsets:
        return None
    merged = sorted(set(video_offsets) | set(other_offsets))
    if len(merged) != len(video_offsets) + len(other_offsets):
        return None  # offset collision between the two tracks: give up
    pos_index = {off: i for i, off in enumerate(merged)}
    sizes = []
    for off in video_offsets:
        i = pos_index[off]
        nxt = merged[i + 1] if i + 1 < len(merged) else mdat_data_end
        size = nxt - off
        if size <= 0 or size > 64 * 1024 * 1024:
            return None  # invalid assumption for this file: give up
        sizes.append(size)

    sample_count = len(sizes)
    stsz_body = (b'\x00' * 4 + struct.pack(">I", 0) + struct.pack(">I", sample_count) +
                 b''.join(struct.pack(">I", s) for s in sizes))
    stsz_raw = box(b'stsz', stsz_body)

    stsc_body = b'\x00' * 4 + struct.pack(">I", 1) + struct.pack(">III", 1, 1, 1)
    stsc_raw = box(b'stsc', stsc_body)
    return stsc_raw, stsz_raw


def derive_synthetic_stsc(video_stco_raw: bytes, video_stsz_raw: bytes,
                           other_stco_raw, mdat_data_end: int):
    """Rebuilds a REAL 'stsc' box (not a mere "1 sample per chunk"
    assumption) for the video track, from its OWN 'stco'/'co64' (chunk
    offsets, intact) and 'stsz' (size of each sample, intact) -- useful
    when only the 'stsc' tag itself falls into the encrypted zone (stco
    and stsz, larger, usually survive). Nothing is assumed about the
    number of samples per chunk: the REAL sizes (stsz) are accumulated
    in order until EXACTLY reaching the boundary of the next chunk (the
    next offset found in stco/co64, video track or neighbouring track
    merged -- since mdat interleaves both tracks continuously). If at a
    single place the accumulation does not land exactly on a boundary,
    the assumption (contiguous chunks, no extra bytes between two
    samples) is invalidated -- we return None rather than produce a
    wrong file."""
    video_offsets = parse_stco_offsets(video_stco_raw)
    other_offsets = parse_stco_offsets(other_stco_raw) if other_stco_raw else []
    if not video_offsets:
        return None
    merged = sorted(set(video_offsets) | set(other_offsets))
    pos_index = {off: i for i, off in enumerate(merged)}

    stsz_p = video_stsz_raw[8:]
    sample_size = struct.unpack(">I", stsz_p[4:8])[0]
    sample_count = struct.unpack(">I", stsz_p[8:12])[0]
    if sample_count == 0:
        return None
    if sample_size != 0:
        sizes = [sample_size] * sample_count
    else:
        if len(stsz_p) < 12 + 4 * sample_count:
            return None
        sizes = list(struct.unpack(">%dI" % sample_count, stsz_p[12:12 + 4 * sample_count]))

    sample_idx = 0
    samples_per_chunk = []
    for off in video_offsets:
        i = pos_index[off]
        nxt = merged[i + 1] if i + 1 < len(merged) else mdat_data_end
        target_len = nxt - off
        if target_len <= 0:
            return None
        cum = 0
        count = 0
        while sample_idx < sample_count and cum < target_len:
            cum += sizes[sample_idx]
            sample_idx += 1
            count += 1
        if cum != target_len or count == 0:
            return None  # invalid assumption (non-contiguous chunks): give up
        samples_per_chunk.append(count)
    if sample_idx != sample_count:
        return None  # not all samples are distributed exactly

    entries = []
    for idx, spc in enumerate(samples_per_chunk):
        chunk_num = idx + 1
        if entries and entries[-1][1] == spc:
            continue  # same sample count/chunk as the previous entry: the
            # preceding stsc range already covers this chunk implicitly
        entries.append([chunk_num, spc, 1])
    stsc_body = (b'\x00' * 4 + struct.pack(">I", len(entries)) +
                 b''.join(struct.pack(">III", fc, spc, sdi) for fc, spc, sdi in entries))
    return box(b'stsc', stsc_body)


def derive_video_tables_from_audio_gaps(fh, audio_stco_raw, audio_stsc_raw,
                                          audio_stsz_raw, mdat_body_start,
                                          mdat_data_end, au_grouping=False,
                                          codec_hint=None):
    """Last resort when the THREE video sample tables
    (stco/stsc/stsz) are lost (none of them is even visible to serve
    as a starting point, unlike derive_synthetic_stsc(_stsz)
    above which need at least the video stco). Rebuilds stco,
    stsc AND stsz for the video EXACTLY (not a "1 sample per
    chunk" assumption) from the only "gaps" left in mdat by the REAL
    audio bytes (audio stco/stsc/stsz, entirely intact):

      1) Computes the byte ranges REALLY occupied by the audio
         in mdat, chunk by chunk, summing the real sample
         sizes (stsz) assigned to each audio chunk by the
         REAL audio stsc (not an assumed 1 sample/chunk: the
         real split, whatever it is).
      2) Everything that remains in [mdat_body_start, mdat_data_end) and is
         covered by NONE of these audio ranges forms "gaps"
         -- necessarily video (mdat only has 2 tracks).
      3) Each gap = one video chunk. It is walked as a sequence
         of AVCC samples (4-byte big-endian length + data):
         if that read lands exactly on the end of the gap, we get in
         passing the exact number of samples of the chunk AND the
         exact size of each one. If a single gap does not land exactly (or if the
         audio ranges overlap, a sign that the assumption "mdat contains
         only audio+video, two tracks" is false for this
         file), we give up (None) rather than produce a wrong
         file.

    Returns (stco_raw, stsc_raw, stsz_raw), or None.

    `au_grouping=True` rebuilds the video samples by grouping the
    NAL units into ACCESS UNITS (frames) instead of treating each NAL as a
    sample: to be used when each sample may contain
    several NAL units (SEI/SPS/PPS/IDR) and/or a chunk may contain
    several samples (extreme case)."""
    audio_offsets = parse_stco_offsets(audio_stco_raw)
    if not audio_offsets:
        return None

    entry_count = struct.unpack(">I", audio_stsc_raw[12:16])[0]
    stsc_entries = []
    for k in range(entry_count):
        base = 16 + 12 * k
        if base + 12 > len(audio_stsc_raw):
            return None
        stsc_entries.append(struct.unpack(">III", audio_stsc_raw[base:base + 12]))
    if not stsc_entries:
        return None

    total_chunks = len(audio_offsets)
    samples_per_chunk_list = [0] * total_chunks
    for i, (first_chunk, spc, _sdi) in enumerate(stsc_entries):
        end_chunk = (stsc_entries[i + 1][0] - 1) if i + 1 < len(stsc_entries) else total_chunks
        for c in range(first_chunk, end_chunk + 1):
            if 1 <= c <= total_chunks:
                samples_per_chunk_list[c - 1] = spc
    if any(spc <= 0 for spc in samples_per_chunk_list):
        return None

    stsz_p = audio_stsz_raw[8:]
    a_sample_size = struct.unpack(">I", stsz_p[4:8])[0]
    a_sample_count = struct.unpack(">I", stsz_p[8:12])[0]
    if a_sample_size != 0:
        a_sizes = [a_sample_size] * a_sample_count
    else:
        if len(stsz_p) < 12 + 4 * a_sample_count:
            return None
        a_sizes = list(struct.unpack(">%dI" % a_sample_count, stsz_p[12:12 + 4 * a_sample_count]))

    sample_idx = 0
    audio_ranges = []
    for c in range(total_chunks):
        spc = samples_per_chunk_list[c]
        start = audio_offsets[c]
        length = 0
        for _ in range(spc):
            if sample_idx >= a_sample_count:
                return None
            length += a_sizes[sample_idx]
            sample_idx += 1
        if length <= 0:
            return None
        audio_ranges.append((start, start + length))
    if sample_idx != a_sample_count:
        return None

    audio_ranges.sort()
    for i in range(1, len(audio_ranges)):
        if audio_ranges[i][0] < audio_ranges[i - 1][1]:
            return None  # unexpected audio/audio overlap: give up

    gaps = []
    cursor = mdat_body_start
    for (s, e) in audio_ranges:
        if s > cursor:
            gaps.append((cursor, s))
        cursor = max(cursor, e)
    if cursor < mdat_data_end:
        gaps.append((cursor, mdat_data_end))
    gaps = [g for g in gaps if g[1] > g[0]]
    if not gaps:
        return None

    video_chunk_offsets = []
    video_samples_per_chunk = []
    video_sample_sizes = []
    fallback_chunks = 0
    au_codec = None
    for (gs, ge) in gaps:
        if au_grouping:
            # Groups the NAL units of the video region into ACCESS UNITS
            # (frames): one H.264/HEVC sample may contain several
            # NAL units (SEI + SPS + PPS + IDR) and one chunk may contain
            # several samples -- the NAL-by-NAL split (historical
            # mode) would break frames.
            if ge - gs > 128 * 1024 * 1024:
                # Huge video region (non-interleaved muxing): we avoid
                # loading it in memory, even if it means keeping it as a single
                # sample (very rare case, real files interleave
                # audio and video).
                video_chunk_offsets.append(gs)
                video_samples_per_chunk.append(1)
                video_sample_sizes.append(ge - gs)
                continue
            fh.seek(gs)
            data = fh.read(ge - gs)
            if au_codec is None:
                # `codec_hint` (taken from the real intact avcC/hvcC box of
                # the moov, when it survived) takes precedence over
                # content-based detection, unreliable on a stream that does not repeat
                # its parameter NAL units in the clear.
                au_codec = codec_hint or _detect_avcc_codec(data)
            au_sizes = (_split_avcc_region_into_aus(data, au_codec)
                        if au_codec else None)
            chunk_off = gs
            if not au_sizes and au_codec:
                # Exact split failed: the gap boundary is
                # slightly off (a few bytes of margin) or the gap ends
                # with a small remainder. We resynchronise on a
                # head offset, otherwise we settle for the longest
                # splittable prefix (the trailing remainder stays unused).
                resync = _split_avcc_region_into_aus_resync(data, au_codec)
                if resync:
                    chunk_off, au_sizes = gs + resync[0], resync[1]
                else:
                    au_sizes = _split_avcc_region_into_aus_prefix(data, au_codec)
            if not au_sizes:
                # MPEG-4 Part 2 (mp4v): each VOP = one sample.
                au_sizes = _split_mpeg4_region_into_samples(data)
            if not au_sizes:
                au_sizes = [ge - gs]
            video_chunk_offsets.append(chunk_off)
            video_samples_per_chunk.append(len(au_sizes))
            video_sample_sizes.extend(au_sizes)
            continue
        pos = gs
        count = 0
        chunk_sizes = []
        desynced = False
        while pos < ge:
            if pos + 4 > ge:
                desynced = True
                break
            fh.seek(pos)
            len_bytes = fh.read(4)
            if len(len_bytes) != 4:
                desynced = True
                break
            nal_len = struct.unpack(">I", len_bytes)[0]
            sample_len = nal_len + 4
            if nal_len <= 0 or pos + sample_len > ge:
                desynced = True
                break
            chunk_sizes.append(sample_len)
            pos += sample_len
            count += 1
        if desynced or pos != ge or count == 0:
            # This particular gap cannot be split NAL by NAL (see
            # comment above the loop): EXACT fallback (not an
            # assumption) into 1 single sample covering the whole gap --
            # the bytes and the chunk boundary stay identical,
            # only the sample split on the container side changes
            # for that gap.
            chunk_sizes = [ge - gs]
            count = 1
            fallback_chunks += 1
        video_chunk_offsets.append(gs)
        video_samples_per_chunk.append(count)
        video_sample_sizes.extend(chunk_sizes)

    if fallback_chunks:
        log(f"     ({fallback_chunks}/{len(gaps)} video chunk(s) grouped into 1 "
            f"single sample -- a few NAL units could not be split "
            f"individually in this/these chunk(s), probably an SPS/PPS "
            f"re-insertion before a keyframe; local frame-rate "
            f"micro-anomaly possible on those few frames only.)")

    return _build_video_tables(video_chunk_offsets, video_samples_per_chunk,
                               video_sample_sizes)


def _build_video_tables(video_chunk_offsets, video_samples_per_chunk,
                        video_sample_sizes):
    """Assembles the stco(/co64), stsc and stsz boxes from the determined
    video chunks and sample sizes (from the audio gaps, or from the mdat
    content). Returns (stco_raw, stsc_raw, stsz_raw), or None if
    no chunk."""
    if not video_chunk_offsets or not video_sample_sizes:
        return None
    if max(video_chunk_offsets) > 0xFFFFFFFF:
        stco_raw = box(b'co64', b'\x00' * 4 +
                       struct.pack(">I", len(video_chunk_offsets)) +
                       b''.join(struct.pack(">Q", o) for o in video_chunk_offsets))
    else:
        stco_raw = box(b'stco', b'\x00' * 4 +
                       struct.pack(">I", len(video_chunk_offsets)) +
                       b''.join(struct.pack(">I", o) for o in video_chunk_offsets))

    stsz_raw = box(b'stsz', b'\x00' * 4 + struct.pack(">I", 0) +
                   struct.pack(">I", len(video_sample_sizes)) +
                   b''.join(struct.pack(">I", s) for s in video_sample_sizes))

    entries = []
    for idx, spc in enumerate(video_samples_per_chunk):
        chunk_num = idx + 1
        if entries and entries[-1][1] == spc:
            continue
        entries.append([chunk_num, spc, 1])
    stsc_raw = box(b'stsc', b'\x00' * 4 + struct.pack(">I", len(entries)) +
                   b''.join(struct.pack(">III", fc, spc, sdi)
                            for fc, spc, sdi in entries))
    return stco_raw, stsc_raw, stsz_raw


# Maximum plausible size of a video NAL (a 1080p I frame stays well
# below). Beyond that, the "length" read is not a real NAL: it is the start
# of a non-video zone (interleaved audio chunk, SPOTS encrypted zone...). Acts
# as a guard in the reading of AVCC lengths.
_MAX_NAL_BYTES = 16 * 1024 * 1024


def _stsz_box_plausible(stsz_raw):
    """A valid stsz either has a non-zero fixed sample size, or
    a non-zero sample count. An stsz with 0 entry AND size 0 is
    invalid (surviving tag alone, encrypted data)."""
    if not stsz_raw or len(stsz_raw) < 20 or stsz_raw[4:8] != b'stsz':
        return False
    sample_size = struct.unpack(">I", stsz_raw[12:16])[0]
    count = struct.unpack(">I", stsz_raw[16:20])[0]
    return sample_size > 0 or count > 0


def _first_sample_looks_avcc(fh, stsz_raw, stco_raw):
    """Checks that the 1st sample designated by the candidate tables
    (stsz+stco) reads as the start of an AVCC/HEVC stream (NAL units
    prefixed by their length). Used to tell REAL video tables from
    misleading ones (those of another track, e.g. audio) that survive in
    SPOTS mode when the video ones fall into the encrypted zone."""
    try:
        ss = struct.unpack(">I", stsz_raw[12:16])[0]
        cnt = struct.unpack(">I", stsz_raw[16:20])[0]
        if ss == 0:
            if cnt == 0:
                return False
            ss = struct.unpack(">I", stsz_raw[20:24])[0]
        off = struct.unpack(">I", stco_raw[16:20])[0]
        fh.seek(off)
        data = fh.read(min(ss, 64 * 1024))
    except (struct.error, OSError):
        return False
    pos = 0
    nals = 0
    while pos + 4 <= len(data) and nals < 8:
        ln = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
        if ln <= 0 or ln > _MAX_NAL_BYTES or pos + 4 + ln > len(data):
            break
        b0 = data[pos + 4]
        if not ((b0 & 0x1F) in (1, 2, 3, 4, 5, 6, 7, 8, 9)
                or b0 in (0x40, 0x42, 0x44, 0x4E)):
            return False
        nals += 1
        pos += 4 + ln
    return nals >= 2


def _first_sample_looks_mpeg4(fh, stsz_raw, stco_raw):
    """Checks that the 1st sample designated by the candidate tables
    starts with an MPEG-4 Part 2 visual start code (00 00 01 B0..BF),
    a sign of valid video tables for an mp4v stream."""
    try:
        ss = struct.unpack(">I", stsz_raw[12:16])[0]
        cnt = struct.unpack(">I", stsz_raw[16:20])[0]
        if ss == 0:
            if cnt == 0:
                return False
            ss = struct.unpack(">I", stsz_raw[20:24])[0]
        off = struct.unpack(">I", stco_raw[16:20])[0]
        fh.seek(off)
        data = fh.read(min(ss, 4096))
    except (struct.error, OSError):
        return False
    return re.search(rb'\x00\x00\x01[\xb0-\xbf]', data) is not None


def _has_valid_intact_avcc(fh, by_tag):
    """Tells whether an avcC box FOUND in the clear zone is really
    usable (parsable SPS/PPS + readable resolution). Rules out
    false positives of a mere signature scan inside encrypted
    data (noise): a fortuitous 'avcC' must not prevent the
    rebuild of the tables/config from the content."""
    for off, _sz in by_tag.get(b'avcC', [])[:4]:
        try:
            box = read_raw_box(fh, off)[0]
            sps, pps = parse_avcc_box(box[8:])
        except (OSError, struct.error, IndexError):
            continue
        if sps and pps and parse_sps_dimensions(sps[1:]):
            return True
    return False


def _find_avcc_run_start(fh, base, end, search=64 * 1024, max_skips=1 << 20):
    """Looks, within [base, base+search), for the 1st offset from which a
    long run of AVCC NAL units reads. Returns (absolute_offset, n_NAL), or
    (None, 0). Used to recover the real start of a video stream in mdat
    when the container tables are unusable (SPOTS mode).
    `max_skips` bounds the number of positions tested: without it, on a
    long non-video zone (audio chunk, encrypted zone), EVERY byte of the
    search window was tested (several million), which could
    take hours; at most ~1 MB of bytes are tested, largely enough
    to find the stream resuming after a gap."""
    span = min(search + 1024, max(0, end - base))
    if span < 16:
        return None, 0
    fh.seek(base)
    buf = fh.read(span)
    best_n = 0
    best_off = None
    limit = min(max(0, len(buf) - 8), max_skips)
    for skip in range(0, limit):
        pos = skip
        nnals = 0
        while pos + 4 <= len(buf):
            ln = (buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]
            if ln <= 0 or ln > _MAX_NAL_BYTES or pos + 4 + ln > len(buf):
                break
            nnals += 1
            pos += 4 + ln
        if nnals > best_n:
            best_n = nnals
            best_off = base + skip
        if best_n >= 200:
            break
    if best_n >= 8:
        return best_off, best_n
    return None, 0


def _find_avcc_start_in_buf(buf, i0, max_scan):
    """Looks in `buf`, from index `i0`, for the 1st index j where a
    run of AVCC NAL units reads (>= 8 NAL units). Returns j or None.
    Everything happens in `buf` (no disk read), for a single sequential
    read of the file."""
    n = len(buf)
    limit = min(n - 4, i0 + max_scan)
    j = i0
    while j < limit:
        pos = j
        nnals = 0
        while pos + 4 <= n:
            ln = (buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]
            if ln <= 0 or ln > _MAX_NAL_BYTES or pos + 4 + ln > n:
                break
            nnals += 1
            pos += 4 + ln
        if nnals >= 8:
            return j
        j += 1
    return None


def _split_avcc_stream(fh, start, end, codec, window=8 * 1024 * 1024,
                       max_resync=1024 * 1024):
    """Walks [start, end) as a continuous AVCC/HEVC stream, reading the
    file ONCE ONLY (through successive windows), groups the NAL units into
    ACCESS UNITS, and RESYNCHRONISES after each break (SPOTS encrypted
    zone, interleaved audio chunk...) INSIDE the current buffer. Returns
    (absolute_offsets, sizes) of the access units.

    Key optimisation: a first version re-read a large window at
    EACH break; with breaks every few tens of KB
    (interleaved audio), that re-read tens of GB and took
    hours. Here every byte of the file is read only once."""
    au_offsets = []
    au_sizes = []
    au_start = start
    au_has_vcl = False
    pending = None
    pos = start
    consumed = start
    while pos < end:
        fh.seek(pos)
        buf = fh.read(min(window, end - pos))
        n = len(buf)
        if n < 4:
            break
        i = 0
        while True:
            if i + 4 > n:
                consumed = pos + n
                break
            noff = pos + i
            ln = (buf[i] << 24) | (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3]
            if ln <= 0 or ln > _MAX_NAL_BYTES or noff + 4 + ln > end:
                # break: resynchronise INSIDE the buffer (no re-read)
                if au_has_vcl and consumed > au_start:
                    au_offsets.append(au_start)
                    au_sizes.append(consumed - au_start)
                au_has_vcl = False
                pending = None
                j = _find_avcc_start_in_buf(buf, i + 1, max_resync)
                if j is None:
                    # No resumption point within the `max_resync` bytes
                    # scanned: skip that whole range at once rather
                    # than advance by 1 byte and rescan it entirely on
                    # the next turn (otherwise O(n^2) over a long non
                    # recoverable zone -- blocked for hours on large
                    # SPOTS files without ever crashing or progressing).
                    consumed = pos + min(n, i + 1 + max_resync)
                    break
                i = j
                au_start = pos + j
                consumed = pos + j
                continue
            if i + 4 + ln > n:
                consumed = noff  # NAL straddling the boundary: resume at noff
                break
            nal = buf[i + 4:i + 4 + ln]
            if _is_vcl_nal(nal, codec):
                if au_has_vcl and _nal_starts_new_access_unit(nal, codec):
                    ns = pending if pending is not None else noff
                    if ns > au_start:
                        au_offsets.append(au_start)
                        au_sizes.append(ns - au_start)
                    au_start = ns
                    consumed = ns
                    au_has_vcl = False
                au_has_vcl = True
                pending = None
            else:
                if au_has_vcl and pending is None:
                    pending = noff
            consumed = noff + 4 + ln
            i += 4 + ln
        pos = consumed if consumed > pos else pos + (n if n else 1)
    if au_has_vcl and consumed > au_start:
        au_offsets.append(au_start)
        au_sizes.append(consumed - au_start)
    return au_offsets, au_sizes


def _recover_video_tables_from_content(fh, mdat_body, mdat_end,
                                       max_scan=64 * 1024, max_resync=1024 * 1024):
    """When the video sample tables of the container are
    unusable (typically part of them fell into the encrypted zone in
    SPOTS mode), rebuilds those tables DIRECTLY from the content of
    mdat: finds the start of the AVCC stream, walks it with resynchronisation
    (SPOTS/audio), groups into access units. Returns
    (codec, stco_raw, stsc_raw, stsz_raw), or None."""
    off, n_nals = _find_avcc_run_start(fh, mdat_body, mdat_end, search=max_scan)
    if off:
        fh.seek(off)
        probe = fh.read(4 * 1024 * 1024)
        codec = _detect_avcc_codec(probe)
        if codec is not None:
            au_offs, au_sizes = _split_avcc_stream(fh, off, mdat_end, codec,
                                                   max_resync=max_resync)
            if len(au_sizes) >= 2:
                tables = _build_video_tables(au_offs, [1] * len(au_offs), au_sizes)
                if tables:
                    return (codec,) + tables
    # No AVCC: try MPEG-4 Part 2 (start-code stream, each VOP
    # 00 00 01 B6 = one sample; a possible VOL/sequence header
    # 00 00 01 B3 preceding it is attached to the sample).
    res = _recover_mpeg4_tables_from_content(fh, mdat_body, mdat_end)
    if res:
        offs, sizes = res
        tables = _build_video_tables(offs, [1] * len(offs), sizes)
        if tables:
            return ('mpeg4',) + tables
    return None


def _recover_mpeg4_tables_from_content(fh, mdat_body, mdat_end):
    """Rebuilds the sample tables of an MPEG-4 Part 2 (mp4v) stream
    from the CONTENT of mdat: each VOP (start code 00 00 01 B6) is a
    sample; a VOL/sequence header (00 00 01 B3/B0/B1) preceding it
    is attached to the sample. Returns (offsets, sizes) or None.
    Assumes a CONTIGUOUS video stream (checked by construction)."""
    fh.seek(mdat_body)
    head = fh.read(65536)
    m = re.search(rb'\x00\x00\x01[\xb0-\xbf]', head)
    if not m:
        return None
    start = mdat_body + m.start()
    boundaries = [start]
    pending_vol = None
    prev_tail = b''
    pos = start
    window = 8 * 1024 * 1024
    while pos < mdat_end:
        fh.seek(pos)
        chunk = fh.read(min(window, mdat_end - pos))
        if not chunk:
            break
        buf = prev_tail + chunk
        base = pos - len(prev_tail)
        i = 0
        n = len(buf)
        while i + 4 <= n:
            if buf[i] == 0 and buf[i + 1] == 0 and buf[i + 2] == 1:
                code = buf[i + 3]
                abs_pos = base + i
                if 0xB0 <= code <= 0xB1 or code == 0xB3:
                    pending_vol = abs_pos
                elif code == 0xB6:
                    boundaries.append(pending_vol if pending_vol is not None
                                      else abs_pos)
                    pending_vol = None
                i += 4
            else:
                i += 1
        prev_tail = buf[-3:]
        pos += len(chunk)
    boundaries = sorted(set(b for b in boundaries if b >= start))
    if len(boundaries) < 2:
        return None
    offs = boundaries
    sizes = [offs[i + 1] - offs[i] for i in range(len(offs) - 1)]
    sizes.append(mdat_end - offs[-1])
    return offs, sizes


def _intact_mpeg4_config(fh, by_tag, audio_trak_off):
    """Looks in the moov (clear zone) for an `mp4v` sample entry
    (MPEG-4 Part 2) whose `esds` box (codec config, with the real VOL)
    is intact. Returns (esds_box_bytes, width, height) or None. Allows
    recovering an mp4v with its REAL config (instead of resynthesising it)."""
    for soff, _ssz in [e for e in by_tag.get(b'stsd', []) if e[0] < audio_trak_off]:
        try:
            sbox = read_raw_box(fh, soff)[0]
        except OSError:
            continue
        if len(sbox) < 36 or sbox[20:24] != b'mp4v':
            continue
        width = struct.unpack(">H", sbox[48:50])[0]
        height = struct.unpack(">H", sbox[50:52])[0]
        cands = [e for e in by_tag.get(b'esds', []) if soff < e[0] < audio_trak_off]
        if not cands:
            continue
        try:
            esds_box = read_raw_box(fh, cands[0][0])[0]
        except OSError:
            continue
        return esds_box, width, height
    return None


def _avcc_region_parses_exactly(fh, start, end):
    """Checks that [start, end) reads EXACTLY as a run
    of video samples prefixed by their length (4 bytes big-endian,
    AVC/H.264 format as well as HEVC/H.265), with no gap or overshoot:
    every length must land exactly on the end of the zone. Returns True/False
    (empty region = True). This is the key test that discriminates a real
    start of video sample from a randomly picked byte (a random
    32-bit length has very little chance of fitting in the zone)."""
    if start > end:
        return False
    pos = start
    buf = b''
    base = start
    while pos < end:
        if pos + 4 > end:
            return False
        if not (base <= pos and pos + 4 <= base + len(buf)):
            fh.seek(pos)
            buf = fh.read(min(1024 * 1024, end - pos))
            base = pos
            if len(buf) < 4:
                return False
        rel = pos - base
        n = (buf[rel] << 24) | (buf[rel + 1] << 16) | (buf[rel + 2] << 8) | buf[rel + 3]
        if n <= 0 or pos + 4 + n > end:
            return False
        pos += 4 + n
    return pos == end


def _detect_avcc_codec(data):
    """Guesses the codec (H.264 'avc' or H.265 'hevc') of a video region
    made of samples prefixed by their length, from the parameter NAL units
    present in the clear (H.264 SPS type 7; HEVC VPS/SPS types
    32/33). Returns 'avc', 'hevc' or None."""
    n = len(data)
    # The video regions computed by complement of the audio ranges may
    # start a few bytes before/after a real NAL boundary (see
    # _split_avcc_region_into_aus_resync). We therefore try several head
    # offsets and keep the one that decodes the MOST consistent NAL units: a
    # wrong offset only reads a few fake NAL units before losing sync,
    # the right one reads hundreds/thousands.
    best = None  # (n_nals, codec)
    for skip in range(0, 33):
        if skip + 8 > n:
            break
        pos = skip
        n_nals = 0
        has_avc_sps = False
        has_hevc_param = False
        avc_vcl = 0
        while pos + 4 <= n:
            ln = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
            if ln <= 0 or ln > _MAX_NAL_BYTES or pos + 4 + ln > n:
                break
            b0 = data[pos + 4]
            if (b0 & 0x1F) == 7:              # H.264 SPS (never HEVC)
                has_avc_sps = True
            # H.264 slice NAL unit (types 1-5): b0 is ALWAYS odd (the
            # type is 1..5, nal_ref_idc does not touch bit 0). In single-layer
            # HEVC, b0 = (type<<1) -> ALWAYS EVEN. An odd b0 with
            # a type within 1..5 therefore cannot be single-layer HEVC ->
            # strong hint of AVC even WITHOUT an SPS in the clear (encrypted avcC, SPOTS).
            if (b0 & 0x1F) in (1, 2, 3, 4, 5) and (b0 & 1):
                avc_vcl += 1
            # HEVC parameter NAL unit: b0 exactly 0x40/0x42/0x44 (VPS/SPS/PPS,
            # nuh_layer_id=0) and temporal_id_plus1 (3 low bits of b1) != 0.
            if b0 in (0x40, 0x42, 0x44) and pos + 5 < n and (data[pos + 5] & 0x07) != 0:
                has_hevc_param = True
            n_nals += 1
            pos += 4 + ln
        codec = None
        if has_avc_sps or avc_vcl >= 3:
            codec = 'avc'
        elif has_hevc_param:
            codec = 'hevc'
        if codec is not None:
            if best is None or n_nals > best[0]:
                best = (n_nals, codec)
            if n_nals >= 100:                # clean alignment: no need to insist
                return codec
    return best[1] if best else None


def _nal_starts_new_access_unit(nal, codec):
    """Tells whether the NAL unit `nal` starts a new access unit (frame):
    - H.264: VCL NAL unit (1-5) whose first_mb_in_slice (ue(v), the very
      first field of the RBSP) is 0, i.e. whose 1st bit is 1;
    - H.265: VCL NAL unit (<= 31) whose first_slice_segment_in_pic_flag
      (1st bit of the slice segment header) is 1.
    Non-VCL NAL units (SEI/SPS/PPS/AUD...) never open an access unit: they
    attach to the frame that follows."""
    if not nal:
        return False
    if codec == 'avc':
        if (nal[0] & 0x1F) in (1, 2, 3, 4, 5):
            rbsp = ebsp_to_rbsp(nal[1:])
            return bool(rbsp) and (rbsp[0] & 0x80) != 0
        return False
    if codec == 'hevc':
        if len(nal) >= 3 and ((nal[0] >> 1) & 0x3F) <= 31:
            return (nal[2] & 0x80) != 0
    return False


def _is_vcl_nal(nal, codec):
    if not nal:
        return False
    if codec == 'avc':
        return (nal[0] & 0x1F) in (1, 2, 3, 4, 5)
    if codec == 'hevc':
        return len(nal) >= 2 and ((nal[0] >> 1) & 0x3F) <= 31
    return False


def _split_avcc_region_into_aus(data, codec):
    """`data` = a video region (run of AVCC samples prefixed by
    their 4-byte length). Groups the NAL units into access units and
    returns the list of sizes in bytes of each access unit, or None
    if the region is not a consistent AVCC run / codec unknown.

    An access unit = possible non-VCL NAL units (SEI/SPS/PPS/AUD...) followed
    by the VCL NAL units of one same frame. A new VCL NAL unit carrying the
    "first slice" flag opens a frame; the non-VCL NAL units preceding it
    (and following the last slice of the previous frame) belong to
    it, hence the tracking of `pending`."""
    if codec not in ('avc', 'hevc'):
        return None
    nals = []
    pos = 0
    n = len(data)
    while pos < n:
        if pos + 4 > n:
            return None
        ln = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
        if ln <= 0 or pos + 4 + ln > n:
            return None
        nals.append((pos, data[pos + 4:pos + 4 + ln]))
        pos += 4 + ln
    if not nals:
        return None

    sizes = []
    au_start = 0
    au_has_vcl = False
    pending = None  # 1st non-VCL NAL unit after the last slice of the current AU
    for (off, nal) in nals:
        if _is_vcl_nal(nal, codec):
            if au_has_vcl and _nal_starts_new_access_unit(nal, codec):
                new_start = pending if pending is not None else off
                sizes.append(new_start - au_start)
                au_start = new_start
                au_has_vcl = False
            au_has_vcl = True
            pending = None
        else:
            if au_has_vcl and pending is None:
                pending = off
    sizes.append(n - au_start)
    if any(s <= 0 for s in sizes):
        return None
    return sizes


def _split_mpeg4_region_into_samples(data):
    """`data` = an MPEG-4 Part 2 video region (run of start codes). Each
    VOP (00 00 01 B6) is a sample; a VOL/sequence header
    (00 00 01 B0/B1/B3) preceding it is attached to the sample. Returns
    the list of sample sizes, or None if no VOP is found."""
    n = len(data)
    m = re.search(rb'\x00\x00\x01[\xb0-\xbf]', data)
    if not m:
        return None
    start = m.start()
    boundaries = [start]
    pending = None
    i = start
    while i + 4 <= n:
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            code = data[i + 3]
            if 0xB0 <= code <= 0xB1 or code == 0xB3:
                pending = i
            elif code == 0xB6:
                boundaries.append(pending if pending is not None else i)
                pending = None
            i += 4
        else:
            i += 1
    boundaries = sorted(set(b for b in boundaries if b >= start))
    if len(boundaries) < 2:
        return None
    sizes = [boundaries[i + 1] - boundaries[i] for i in range(len(boundaries) - 1)]
    sizes.append(n - boundaries[-1])
    if any(s <= 0 for s in sizes):
        return None
    return sizes


def _split_avcc_region_into_aus_resync(data, codec, max_resync=32):
    """Retries the access-unit split, skipping up to
    `max_resync` head bytes: the boundary of a video "gap" (computed
    by complement of the audio ranges) may be slightly off by
    a few bytes. Returns (offset, sizes) of the first offset that splits
    EXACTLY up to the end of `data`, or None."""
    limit = min(max_resync, max(0, len(data) - 8))
    for skip in range(0, limit + 1):
        sizes = _split_avcc_region_into_aus(data[skip:], codec)
        if sizes:
            return skip, sizes
    return None


def _split_avcc_region_into_aus_prefix(data, codec, min_frac=0.9):
    """Last fallback: splits the longest PREFIX of `data` that reads
    as a consistent AVCC NAL run (the trailing remainder -- a few
    bytes -- is ignored). Returns the access-unit sizes, or None if
    even the prefix covers less than `min_frac` of the region."""
    n = len(data)
    pos = 0
    while pos + 4 <= n:
        ln = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
        if ln <= 0 or pos + 4 + ln > n:
            break
        pos += 4 + ln
    if pos < n * min_frac:
        return None
    return _split_avcc_region_into_aus(data[:pos], codec)


def derive_audio_stsc_by_video_avcc(fh, audio_stco_raw, audio_stsz_raw,
                                    mdat_body_start, mdat_data_end):
    """Extreme case: the whole VIDEO track (trak +
    stco/stsc/stsz) fell into the encrypted zone, and for the AUDIO track
    only `stco` and `stsz` remain -- even its `stsc` is lost.
    Without the audio `stsc`, it is impossible to know how many samples each
    audio chunk contains, hence impossible to compute the audio ranges in
    mdat and, by difference, the video samples.

    We rebuild that audio `stsc` with the help of the AVCC SPLIT of the
    video: mdat alternates video chunks (samples prefixed by their
    4-byte length) and audio chunks. We walk the audio chunks
    in order; for each one, we look for the SMALLEST number
    of samples (real sizes read from the real `stsz`) such that the
    remainder up to the next audio chunk reads EXACTLY as a run
    of AVCC samples (or is empty). The AVCC split is very
    constraining, so that resumption point is in practice unique; we
    take the smallest one to avoid landing, further down the video, on
    a sample boundary that would match by chance. At the end, the
    sum of the consumed samples must equal EXACTLY the total of
    `stsz` (and any remainder after the last audio chunk must
    read as AVCC): otherwise we give up rather than produce a wrong file.

    Only applies to a video with samples prefixed by their length
    (AVC/HEVC) -- not MPEG-4 Part 2. Returns the raw content of a valid
    'stsc' box (bytes), or None."""
    audio_offsets = parse_stco_offsets(audio_stco_raw)
    if not audio_offsets:
        return None

    stsz_p = audio_stsz_raw[8:]
    if len(stsz_p) < 12:
        return None
    a_sample_size = struct.unpack(">I", stsz_p[4:8])[0]
    a_sample_count = struct.unpack(">I", stsz_p[8:12])[0]
    if a_sample_count == 0:
        return None
    if a_sample_size != 0:
        a_sizes = [a_sample_size] * a_sample_count
    else:
        if len(stsz_p) < 12 + 4 * a_sample_count:
            return None
        a_sizes = list(struct.unpack(">%dI" % a_sample_count,
                                     stsz_p[12:12 + 4 * a_sample_count]))

    prev = None
    for off in audio_offsets:
        if off < mdat_body_start or off >= mdat_data_end:
            return None
        if prev is not None and off < prev:
            return None  # unordered audio chunks: assumption defeated
        prev = off

    total_chunks = len(audio_offsets)
    samples_per_chunk = []
    sample_idx = 0
    cursor = mdat_body_start
    for c in range(total_chunks):
        start = audio_offsets[c]
        next_off = (audio_offsets[c + 1] if c + 1 < total_chunks
                    else mdat_data_end)
        if start < cursor or next_off < start:
            return None
        # Possible video BEFORE this audio chunk (mostly useful at the very
        # beginning, before the first audio chunk).
        if start > cursor and not _avcc_region_parses_exactly(fh, cursor, start):
            return None

        chosen_k = None
        cum = 0
        k = 0
        while sample_idx + k < a_sample_count:
            k += 1
            cum += a_sizes[sample_idx + k - 1]
            end = start + cum
            if end > next_off:
                break
            if end == next_off or _avcc_region_parses_exactly(fh, end, next_off):
                chosen_k = k
                break
        if chosen_k is None:
            return None
        samples_per_chunk.append(chosen_k)
        sample_idx += chosen_k
        cursor = next_off

    if sample_idx != a_sample_count:
        return None
    if cursor < mdat_data_end and not _avcc_region_parses_exactly(
            fh, cursor, mdat_data_end):
        return None

    entries = []
    for i, spc in enumerate(samples_per_chunk):
        if entries and entries[-1][1] == spc:
            continue
        entries.append((i + 1, spc, 1))
    stsc_body = (b'\x00' * 4 + struct.pack(">I", len(entries)) +
                 b''.join(struct.pack(">III", fc, spc, sdi)
                          for fc, spc, sdi in entries))
    return box(b'stsc', stsc_body)


# --------------------------------------------------------------------------
# CASE B, variant "reversed track order": the video track, not the
# audio track, is the one whose header survived
# --------------------------------------------------------------------------
#
# The normal CASE B algorithm assumes the video track is ALWAYS listed
# first in moov (the most common convention): its own
# 'trak' box then falls into the encrypted zone (lost), while the audio
# track, listed second, is entirely visible/intact and copied
# verbatim. Some recording software reverse that order
# (audio first): in that case it is the VIDEO track that ends up
# visible/intact (with a REAL avcC/hvcC config, far better than a
# guessed rebuild), and it is the AUDIO track whose header is
# lost. Since audio never repeats its config (esds/mp4a) in the
# stream itself (unlike the video track where an SPS/PPS can sometimes
# be repeated), that audio config is unrecoverable: the output
# file is then VIDEO ONLY (without sound), but 100% reliable on the
# image side since nothing is guessed.


def repair_case_b_video_track_intact(filepath, out_path, mdat_off, mdat_size,
                                       video_trak_off, video_trak_size,
                                       fps_fallback, progress=None):
    with open(filepath, 'rb') as fh:
        video_trak_raw, _ = read_raw_box(fh, video_trak_off)

    local_hits = scan_boxes(video_trak_raw, 0, limit_off=0, file_size=len(video_trak_raw))

    def find_local(tag):
        return next(((o, t, s) for (o, t, s) in local_hits if t == tag), None)

    width = height = None
    avcc_hit = find_local(b'avcC')
    if avcc_hit:
        o, t, s = avcc_hit
        sps, pps = parse_avcc_box(video_trak_raw[o:o + s][8:])
        if sps:
            dims = parse_sps_dimensions(sps[1:])
            if dims:
                width, height = dims

    if width is None or height is None:
        # last resort (HEVC, or unreadable avcC): tkhd, always
        # present and always REAL here since the track is intact.
        tkhd_hit = find_local(b'tkhd')
        if tkhd_hit:
            o, t, s = tkhd_hit
            tkhd_raw = video_trak_raw[o:o + s]
            try:
                width = struct.unpack(">I", tkhd_raw[-8:-4])[0] >> 16
                height = struct.unpack(">I", tkhd_raw[-4:])[0] >> 16
            except struct.error:
                pass
    if not (width and height):
        raise ValueError("intact video track found, but its resolution cannot "
                          "be read (tkhd/avcC unreadable)")

    sample_count = 0
    stsz_hit = find_local(b'stsz')
    if stsz_hit:
        o, t, s = stsz_hit
        stsz_raw = video_trak_raw[o:o + s]
        if len(stsz_raw) >= 20:
            sample_count = struct.unpack(">I", stsz_raw[16:20])[0]

    mdhd_info = parse_mdhd_from_trak(video_trak_raw)
    if mdhd_info:
        v_timescale, v_duration = mdhd_info
    else:
        v_timescale, v_duration = DEFAULT_VIDEO_TIMESCALE, 0

    # The copied trak keeps its edts/elst edit list and tkhd duration
    # expressed in the ORIGINAL (lost) movie timescale: drop/rewrite them
    # for the new mvhd, whose timescale is v_timescale here.
    video_trak_raw = strip_track_edit_lists(video_trak_raw, v_timescale)

    fps_used = fps_fallback
    fps_source = f"default / supplied via --fps ({fps_fallback} fps)"
    if v_duration > 0 and sample_count > 0:
        fps_used = snap_fps(sample_count / (v_duration / v_timescale))
        fps_source = (f"computed from the REAL mdhd of the intact video track: "
                       f"{sample_count} frames / {v_duration / v_timescale:.3f}s "
                       f"(timescale={v_timescale}) -> {fps_used} fps")

    mvhd = box(b'mvhd', b'\x00' * 4 + b'\x00' * 8 +
               struct.pack(">I", v_timescale) + struct.pack(">I", v_duration) +
               struct.pack(">I", 0x00010000) + struct.pack(">H", 0x0100) + b'\x00\x00' +
               b'\x00' * 8 +
               struct.pack(">iiiiiiiii", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               b'\x00' * 24 + struct.pack(">I", 2))

    ftyp = DEFAULT_FTYPE

    def assemble_moov(video_trak_bytes):
        return box(b'moov', mvhd + video_trak_bytes)

    with open(filepath, 'rb') as fh_mdat_hdr:
        mdat_header_len = box_header_len(fh_mdat_hdr, mdat_off)
    moov_draft = assemble_moov(video_trak_raw)
    new_mdat_body_start = len(ftyp) + len(moov_draft) + mdat_header_len
    old_mdat_body_start = mdat_off + mdat_header_len
    delta = new_mdat_body_start - old_mdat_body_start
    video_trak_patched = patch_stco_boxes(video_trak_raw, delta)
    moov = assemble_moov(video_trak_patched)
    assert len(moov) == len(moov_draft), "internal inconsistency (intact video track)"

    header = ftyp + moov
    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(header)
        src.seek(mdat_off)
        remaining = mdat_size
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)

    return True, {
        'width': width, 'height': height, 'sample_count': sample_count,
        'fps_fallback': fps_used, 'fps_source': fps_source,
        'codec': 'avc-video-track-intact',
        'x264_opts': None, 'detect_info': None, 'donor_used': None,
        'profile_used': None,
    }


# --------------------------------------------------------------------------
# CASE B, "SINGLE video track" variant (no audio in the source):
# no 'trak' is ever found intact (the file's single 'trak' falls,
# like its descriptors, entirely inside the encrypted zone), only the
# large video sample tables survive.
# --------------------------------------------------------------------------

def repair_case_b_single_video_track(filepath, out_path, video_len, mdat_off,
                                      mdat_size, by_tag, fps_fallback,
                                      progress=None, width_override=None,
                                      height_override=None, auto_resolution=True,
                                      auto_resolution_timeout=90,
                                      brute_force_resolution=False,
                                      resolution_lock=False,
                                      sps_pps_donor_files=None, profile_dir=None,
                                      use_profiles=True, learn_profiles=True):
    """CASE B without any intact 'trak' at all: file with a SINGLE video
    track (no audio in the original source), whose 'trak' itself -- like
    its tkhd/mdia/hdlr/stsd/avcC/mdhd/stts/stss/ctts -- falls entirely
    inside the first 4096 encrypted bytes; only its large sample tables
    (stsc/stsz/stco), too big to fit there, survive in the clear. Reuses
    exactly the same SPS/PPS recovery cascade as repair_case_b (donor
    --sps-pps-from -> learned profiles -> automatic detection ->
    manual --width/--height). Without an audio track, the frame rate
    cannot be computed from an audio duration: only the --fps value
    supplied on the command line is used, that being the sole
    source of the frame rate (default 24 fps)."""
    if profile_dir is None:
        profile_dir = DEFAULT_PROFILE_DIR
    with open(filepath, 'rb') as fh:
        stsc_all = by_tag.get(b'stsc', [])
        stsz_all = by_tag.get(b'stsz', [])
        stco_all = sorted(by_tag.get(b'stco', []) + by_tag.get(b'co64', []),
                           key=lambda e: e[0])
        stss = by_tag[b'stss'][0] if by_tag.get(b'stss') else None

        stsc_raw = stsz_raw = stco_raw = None
        tables_derived = False
        tables_derived_by_audio_avcc = False
        if stsc_all and stsz_all and stco_all:
            stsz_raw, _ = read_raw_box(fh, stsz_all[0][0])
            stco_raw, _ = read_raw_box(fh, stco_all[0][0])
            stsc_raw, _ = read_raw_box(fh, stsc_all[0][0])
        elif stco_all and not stsc_all and not stsz_all:
            # stco visible, stsc/stsz lost: "1 sample = 1 chunk"
            # assumption (no other track to merge the offsets with
            # here -- single track).
            stco_raw, _ = read_raw_box(fh, stco_all[0][0])
            derived = derive_synthetic_stsc_stsz(stco_raw, None, mdat_off + mdat_size)
            if derived:
                stsc_raw, stsz_raw = derived
                tables_derived = True
        elif stco_all and stsz_all and not stsc_all:
            # stco AND stsz visible, only stsc missing: EXACT derivation
            # (not an assumption) from the real sizes/offsets.
            stco_raw, _ = read_raw_box(fh, stco_all[0][0])
            stsz_raw, _ = read_raw_box(fh, stsz_all[0][0])
            derived_stsc = derive_synthetic_stsc(stco_raw, stsz_raw, None,
                                                  mdat_off + mdat_size)
            if derived_stsc:
                stsc_raw = derived_stsc
                tables_derived = True
            else:
                # These stsz/stco do NOT describe a contiguous track: they
                # actually belong to the AUDIO track (whose stsc is lost
                # too), the VIDEO being interleaved in mdat (see
                # extreme case). We first rebuild the audio stsc using
                # the video AVCC split, then derive the
                # VIDEO tables from the "holes" left by the audio.
                mdat_body = mdat_off + box_header_len(fh, mdat_off)
                log("     surviving stsz/stco are NOT contiguous: they belong to "
                    "the AUDIO track (stsc lost), the video being interleaved "
                    "in mdat -- rebuilding the audio stsc from the "
                    "video AVCC split, then deriving the "
                    "VIDEO tables from the audio 'holes'...")
                audio_stsc_recovered = derive_audio_stsc_by_video_avcc(
                    fh, stco_raw, stsz_raw, mdat_body, mdat_off + mdat_size)
                if audio_stsc_recovered:
                    derived = derive_video_tables_from_audio_gaps(
                        fh, stco_raw, audio_stsc_recovered, stsz_raw,
                        mdat_body, mdat_off + mdat_size, au_grouping=True)
                    if derived:
                        stco_raw, stsc_raw, stsz_raw = derived
                        tables_derived = True
                        tables_derived_by_audio_avcc = True

        if not (stsc_raw and stsz_raw and stco_raw):
            raise ValueError(
                "video sample tables not found: neither a single video "
                "track (non-contiguous stsz/stco), nor a reconstruction "
                "from the audio track (audio stsc lost, AVCC interleaving "
                "unresolved) succeeded")

        stss_box = None
        if stss:
            stss_box, _ = read_raw_box(fh, stss[0])

        sample_size = struct.unpack(">I", stsz_raw[12:16])[0]
        if sample_size == 0:
            first_sample_size = struct.unpack(">I", stsz_raw[20:24])[0]
        else:
            first_sample_size = sample_size
        if stco_raw[4:8] == b'co64':
            first_chunk_offset = struct.unpack(">Q", stco_raw[16:24])[0]
        else:
            first_chunk_offset = struct.unpack(">I", stco_raw[16:20])[0]
        fh.seek(first_chunk_offset)
        first_sample = fh.read(min(first_sample_size, 4 * 1024 * 1024))

        codec = None
        width = height = None
        config_box = None
        sample_entry_tag = None

        sps, pps = extract_sps_pps_from_sample(first_sample)
        if sps and pps:
            dims = parse_sps_dimensions(sps[1:])
            if dims:
                width, height = dims
                config_box = build_avcc(sps, pps)
                sample_entry_tag = b'avc1'
                codec = 'avc'

        vps = hevc_sps = hevc_pps = None
        if codec is None:
            vps, hevc_sps, hevc_pps = extract_vps_sps_pps_from_sample_hevc(first_sample)
            if hevc_sps and hevc_pps:
                sps_info = parse_hevc_sps(hevc_sps)
                if sps_info:
                    width, height = sps_info['width'], sps_info['height']
                    config_box = build_hvcc(vps, hevc_sps, hevc_pps, sps_info)
                    sample_entry_tag = b'hev1'
                    codec = 'hevc'

        x264_opts = None
        detect_info = None
        auto_attempted = False
        donor_used = None
        profile_used = None
        donor_sps = donor_pps = None
        profile_sps = profile_pps = None
        hevc_stream = False
        mpeg4_stream = False
        if codec is None:
            mpeg4_stream, mpeg4_result = recover_mpeg4_part2_config(
                fh, first_sample, stsc_raw, stco_raw, stsz_raw,
                width_hint=width_override, height_hint=height_override,
                auto_resolution=auto_resolution,
                max_seconds=auto_resolution_timeout, profile_dir=profile_dir)
            if mpeg4_result:
                width, height = mpeg4_result['width'], mpeg4_result['height']
                config_box = build_esds_mpeg4(mpeg4_result['dsi'])
                sample_entry_tag = b'mp4v'
                codec = 'mpeg4-generic-auto'
                detect_info = mpeg4_result
        if codec is None and not mpeg4_stream:
            sei_payload = extract_sei_from_sample(first_sample)
            x264_opts = parse_x264_sei_options(sei_payload) if sei_payload else {}

            ORACLE_SAMPLE_WINDOW = ORACLE_QUICK_WINDOW
            oracle_nals = []
            frame_nals_confirm = None
            if auto_resolution or sps_pps_donor_files or use_profiles:
                oracle_nals = _collect_leading_video_nals(
                    fh, stsc_raw, stco_raw, stsz_raw, ORACLE_SAMPLE_WINDOW,
                    first_sample)
                oracle_nals_confirm = _collect_leading_video_nals(
                    fh, stsc_raw, stco_raw, stsz_raw,
                    _oracle_confirm_window(x264_opts), first_sample)
                frame_nals_confirm = [nal for (t, nal) in oracle_nals_confirm
                                      if t in (5, 1)]

            sei_nal_for_oracle = next((nal for (t, nal) in oracle_nals if t == 6), None)
            frame_nals_for_oracle = [nal for (t, nal) in oracle_nals if t in (5, 1)]

            hevc_stream, hevc_result = recover_hevc_config_without_inband_params(
                fh, first_sample, stsc_raw, stco_raw, stsz_raw,
                sps_pps_donor_files, profile_dir, use_profiles)
            if hevc_result:
                vps, hevc_sps, hevc_pps = hevc_result['vps'], hevc_result['sps'], hevc_result['pps']
                sps_info = hevc_result['sps_info']
                width, height = sps_info['width'], sps_info['height']
                config_box = build_hvcc(vps, hevc_sps, hevc_pps, sps_info)
                sample_entry_tag = b'hvc1'
                codec = hevc_result['codec']
                donor_used = hevc_result['donor_used']
                profile_used = hevc_result['profile_used']

            if sps_pps_donor_files and not hevc_stream:
                donor_result = find_avcc_donor_sps_pps(
                    sps_pps_donor_files, frame_nals_for_oracle, sei_nal_for_oracle,
                    frame_nals_confirm=frame_nals_confirm)
                if donor_result:
                    donor_sps, donor_pps, donor_path = donor_result
                    dims = parse_sps_dimensions(donor_sps[1:])
                    if dims:
                        width, height = dims
                        config_box = build_avcc(donor_sps, donor_pps)
                        sample_entry_tag = b'avc1'
                        codec = 'avc-donor'
                        donor_used = donor_path

            if codec is None and use_profiles and not hevc_stream:
                profile_result = find_profile_match(
                    profile_dir, frame_nals_for_oracle, sei_nal_for_oracle,
                    frame_nals_confirm=frame_nals_confirm)
                if profile_result:
                    profile_sps, profile_pps, profile_entry = profile_result
                    dims = parse_sps_dimensions(profile_sps[1:])
                    if dims:
                        width, height = dims
                        config_box = build_avcc(profile_sps, profile_pps)
                        sample_entry_tag = b'avc1'
                        codec = 'avc-profile'
                        profile_used = profile_entry

            if codec is None and auto_resolution and not hevc_stream:
                auto_attempted = True
                detect_info = auto_detect_avc_generic_params(
                    oracle_nals, x264_opts,
                    width_hint=width_override, height_hint=height_override,
                    max_seconds=auto_resolution_timeout,
                    profile_dir=profile_dir,
                    brute_force=brute_force_resolution,
                    resolution_lock=resolution_lock)
                if detect_info:
                    fake_sps = build_fake_avc_sps(
                        detect_info['width'], detect_info['height'],
                        log2_max_frame_num=detect_info['log2_max_frame_num'],
                        log2_max_poc_lsb=detect_info['log2_max_poc_lsb'],
                        max_num_ref_frames=detect_info['max_num_ref_frames'],
                        poc_type=detect_info['poc_type'])
                    fake_pps = build_fake_avc_pps(x264_opts, qp_minus26=detect_info['pic_init_qp_minus26'])
                    width, height = detect_info['width'], detect_info['height']
                    config_box = build_avcc(fake_sps, fake_pps)
                    sample_entry_tag = b'avc1'
                    codec = 'avc-generic-auto'
                    if frame_nals_confirm and not _ffmpeg_probe_avc(
                            fake_sps, fake_pps, frame_nals_confirm,
                            sei_nal_for_oracle, timeout=ORACLE_CONFIRM_TIMEOUT):
                        log("  [auto-detection resolution] WARNING: the config "
                            "found does NOT confirm across several GOPs (risk "
                            "of corrupted blocks at every keyframe) -- check "
                            "playback in a video player before deleting "
                            "the .nsm.")

            if codec is None and width_override and height_override and not hevc_stream:
                # Reuses the REAL values already read from the x264 SEI
                # (ref/bframes/b_pyramid -> log2_max_frame_num/poc_lsb and
                # pic_order_cnt_type through x264's formulas; ref=N in
                # the clear) when available, rather
                # than build_fake_avc_sps generic defaults: only the
                # resolution then remains an assumption.
                manual_f, manual_p = _x264_default_f_p(x264_opts)
                manual_ref = (_x264_num_ref_frames(x264_opts)
                              or _x264_ref_hint(x264_opts) or 2)
                fake_sps = build_fake_avc_sps(
                    width_override, height_override,
                    log2_max_frame_num=manual_f, log2_max_poc_lsb=manual_p,
                    max_num_ref_frames=manual_ref,
                    poc_type=_x264_poc_type(x264_opts))
                fake_pps = build_fake_avc_pps(
                    x264_opts, qp_minus26=_x264_init_qp_guesses(x264_opts)[0])
                width, height = width_override, height_override
                config_box = build_avcc(fake_sps, fake_pps)
                sample_entry_tag = b'avc1'
                codec = 'avc-generic'

            if learn_profiles and codec == 'avc-donor':
                register_profile(profile_dir, donor_sps, donor_pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec == 'avc-profile':
                register_profile(profile_dir, profile_sps, profile_pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec in ('hevc-donor', 'hevc-profile'):
                register_profile(profile_dir, hevc_sps, hevc_pps,
                                  os.path.basename(out_path), dims=(width, height), vps=vps)
            elif learn_profiles and codec == 'avc':
                # Most frequent case -- REAL SPS/PPS read directly from the
                # stream (repeated before the IDR, no search needed) --
                # but so far never recorded: restore_and_reencode.py
                # then deletes this decoded file (replaced by the re-encoded
                # HEVC result), erasing these REAL parameters for good.
                # Real case observed: several HEVC files already recovered
                # successfully (so their original VPS/SPS/PPS were
                # indeed readable at that time), yet 0 HEVC
                # profile learned over the whole corpus -- so the next
                # file from the same source, this one WITHOUT VPS/SPS/PPS
                # in the clear, no longer finds any donor or profile (total
                # failure, even with automatic detection: it only covers H.264).
                register_profile(profile_dir, sps, pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec == 'hevc':
                register_profile(profile_dir, hevc_sps, hevc_pps,
                                  os.path.basename(out_path), dims=(width, height), vps=vps)

        udta_raw = None
        udta_hit = by_tag[b'udta'][0] if by_tag.get(b'udta') else None
        if udta_hit:
            udta_raw, _ = read_raw_box(fh, udta_hit[0])

        sample_count = struct.unpack(">I", stsz_raw[16:20])[0]

    if not (codec and width and height and config_box):
        if mpeg4_stream:
            return False, mpeg4_failure_message(auto_resolution)
        if hevc_stream:
            return False, hevc_failure_message(sps_pps_donor_files, profile_dir, use_profiles)
        ffmpeg_missing = shutil.which('ffmpeg') is None
        donor_note = ""
        if sps_pps_donor_files:
            donor_note = (f"{len(sps_pps_donor_files)} donor file(s) "
                           f"tested (--sps-pps-from) without a conclusive match. ")
        profile_note = ""
        if use_profiles:
            n_known_profiles = len(iter_profiles_sorted(profile_dir))
            if n_known_profiles:
                profile_note = (f"{n_known_profiles} known SPS/PPS profile(s) in the "
                                 f"database ({profile_dir}) tested without a "
                                 f"conclusive match. ")
        if not auto_resolution:
            detect_note = "Automatic detection disabled (--no-auto-resolution). "
        elif ffmpeg_missing:
            detect_note = ("ffmpeg is not installed (or not in PATH): automatic "
                            "resolution detection could not be "
                            "attempted -- install ffmpeg to enable it. ")
        elif auto_attempted:
            detect_note = ("Automatic resolution detection was attempted "
                            "(via ffmpeg) without finding a conclusive combination -- "
                            "the original resolution may not be among those "
                            "tested, or other stream parameters differ too much "
                            "from the original. ")
        else:
            detect_note = ""
        return False, (donor_note + profile_note + "VPS/SPS/PPS not found (or unusable) in the "
                        "first sample, tried as both AVC/H.264 and "
                        "HEVC/H.265 (single video track, no audio track in this "
                        "file): cannot rebuild the video codec "
                        "config (the stream may not include the parameters "
                        "in the clear in every keyframe -- common when x264/x265 "
                        "muxes directly to MP4 without --repeat-headers). " +
                        detect_note +
                        "Retry with --width/--height to force a precise "
                        "resolution (EXPERIMENTAL attempt), or "
                        "--brute-force-resolution for a wider sweep -- "
                        "not guaranteed to decode correctly, resolution to be "
                        "checked in a video player.")

    # ---- video frame rate: no audio track in this file -> first attempt
    #      the duration deduced from the FILE NAME (pattern 'start-end',
    #      see detect_fps_from_filename -- heuristic, checked against
    #      the standard frame rates before being used), then --fps as
    #      the very last fallback ----
    fps_used = fps_fallback
    fps_source = (f"default / supplied via --fps ({fps_fallback} fps) -- "
                  f"no audio track in this file to compute a real "
                  f"frame rate")
    detected_from_name = detect_fps_from_filename(filepath, sample_count)
    if detected_from_name:
        fps_used, fps_source = detected_from_name

    timescale = DEFAULT_VIDEO_TIMESCALE
    duration_track = int(sample_count / fps_used * timescale)

    tkhd = box(b'tkhd', bytes([0, 0, 0, 7]) + b'\x00' * 8 +
               struct.pack(">I", 1) + b'\x00' * 4 +
               struct.pack(">I", duration_track) + b'\x00' * 8 +
               struct.pack(">h", 0) + struct.pack(">h", 0) +
               struct.pack(">h", 0) + b'\x00\x00' +
               struct.pack(">iiiiiiiii", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               struct.pack(">H", width) + b'\x00\x00' +
               struct.pack(">H", height) + b'\x00\x00')

    mdhd = box(b'mdhd', b'\x00' * 4 + b'\x00' * 8 +
               struct.pack(">I", timescale) + struct.pack(">I", duration_track) +
               b'\x55\xc4' + b'\x00\x00')

    hdlr = box(b'hdlr', b'\x00' * 4 + b'\x00' * 4 + b'vide' + b'\x00' * 12 + b'VideoHandler\x00')

    vmhd = box(b'vmhd', bytes([0, 0, 0, 1]) + b'\x00' * 8)
    url_ = box(b'url ', bytes([0, 0, 0, 1]))
    dref = box(b'dref', b'\x00' * 4 + struct.pack(">I", 1) + url_)
    dinf = box(b'dinf', dref)

    stsd_entry_payload = (b'\x00' * 6 + struct.pack(">H", 1) +
                           b'\x00' * 16 +
                           struct.pack(">H", width) + struct.pack(">H", height) +
                           struct.pack(">I", 0x00480000) + struct.pack(">I", 0x00480000) +
                           b'\x00' * 4 + struct.pack(">H", 1) +
                           b'\x00' * 32 +
                           struct.pack(">H", 24) + struct.pack(">h", -1) +
                           config_box)
    visual_sample_entry = box(sample_entry_tag, stsd_entry_payload)
    stsd = box(b'stsd', b'\x00' * 4 + struct.pack(">I", 1) + visual_sample_entry)

    stts_body = b'\x00' * 4 + struct.pack(">I", 1) + struct.pack(">II", sample_count,
                                                                    max(1, int(timescale // fps_used)))
    stts = box(b'stts', stts_body)

    mvhd = box(b'mvhd', b'\x00' * 4 + b'\x00' * 8 +
               struct.pack(">I", timescale) + struct.pack(">I", duration_track) +
               struct.pack(">I", 0x00010000) + struct.pack(">H", 0x0100) + b'\x00\x00' +
               b'\x00' * 8 +
               struct.pack(">iiiiiiiii", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               b'\x00' * 24 + struct.pack(">I", 2))

    ftyp = DEFAULT_FTYPE

    def assemble_moov(stco_for_video):
        stbl_children = stsd + stts + stsc_raw + stsz_raw + stco_for_video
        if stss_box:
            stbl_children += stss_box
        stbl = box(b'stbl', stbl_children)
        minf = box(b'minf', vmhd + dinf + stbl)
        mdia = box(b'mdia', mdhd + hdlr + minf)
        video_trak = box(b'trak', tkhd + mdia)
        moov_children = mvhd + video_trak
        if udta_raw:
            moov_children += udta_raw
        return box(b'moov', moov_children)

    with open(filepath, 'rb') as fh_mdat_hdr:
        mdat_header_len = box_header_len(fh_mdat_hdr, mdat_off)
    moov_draft = assemble_moov(stco_raw)
    new_mdat_body_start = len(ftyp) + len(moov_draft) + mdat_header_len
    old_mdat_body_start = mdat_off + mdat_header_len
    delta = new_mdat_body_start - old_mdat_body_start
    log_msg = f"  (sample offset shift applied: {delta:+d} bytes)"

    stco_patched = patch_stco_boxes(stco_raw, delta)
    moov = assemble_moov(stco_patched)
    assert len(moov) == len(moov_draft), "internal inconsistency: fixing the offsets changed the size of moov"
    print(log_msg)

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(ftyp)
        dst.write(moov)
        src.seek(mdat_off)
        remaining = mdat_size
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)

    return True, {
        'width': width, 'height': height, 'sample_count': sample_count,
        'fps_fallback': fps_used, 'fps_source': fps_source, 'codec': codec,
        'x264_opts': x264_opts, 'detect_info': detect_info, 'donor_used': donor_used,
        'profile_used': profile_used, 'tables_derived': tables_derived,
        'tables_derived_by_audio_avcc': tables_derived_by_audio_avcc,
        'no_audio_track': True,
    }


# --------------------------------------------------------------------------
# CASE B: moov overlaps the encrypted zone -> partial reconstruction
# --------------------------------------------------------------------------

def repair_case_b(filepath, out_path, video_len, mdat_off, mdat_size,
                   fps_fallback, progress=None, width_override=None,
                   height_override=None, auto_resolution=True,
                   auto_resolution_timeout=90, brute_force_resolution=False,
                   resolution_lock=False,
                   sps_pps_donor_files=None,
                   profile_dir=None, use_profiles=True, learn_profiles=True,
                   enc_header_len=ENC_HEADER_LEN):
    if profile_dir is None:
        profile_dir = DEFAULT_PROFILE_DIR
    with open(filepath, 'rb') as fh:
        # 1) locate, in the intact zone [enc_header_len .. mdat_off),
        #    the audio track (complete trak) and the video track tables
        # (enlarged window: on a very long recording, everything
        # before mdat -- video tables + complete audio trak -- can
        # exceed a few MB by far)
        HEAD_SCAN_CAP = 512 * 1024 * 1024
        head = fh.read(min(mdat_off, HEAD_SCAN_CAP))
        hits = scan_boxes(head, 0, limit_off=enc_header_len, file_size=video_len)

        by_tag = {}
        for off, tag, sz in hits:
            by_tag.setdefault(tag, []).append((off, sz))

        if b'trak' not in by_tag:
            if by_tag.get(b'stsz') and (by_tag.get(b'stco') or by_tag.get(b'co64')):
                log("  no intact 'trak' track found: likely a file with a "
                    "SINGLE video track (no audio in the original source) -- "
                    "attempting reconstruction without an audio track.")
                return repair_case_b_single_video_track(
                    filepath, out_path, video_len, mdat_off, mdat_size, by_tag,
                    fps_fallback, progress=progress,
                    width_override=width_override, height_override=height_override,
                    auto_resolution=auto_resolution,
                    auto_resolution_timeout=auto_resolution_timeout,
                    brute_force_resolution=brute_force_resolution,
                    resolution_lock=resolution_lock,
                    sps_pps_donor_files=sps_pps_donor_files,
                    profile_dir=profile_dir, use_profiles=use_profiles,
                    learn_profiles=learn_profiles)
            raise ValueError("no intact 'trak' track found (unsupported structure)")
        audio_trak_off, audio_trak_size = by_tag[b'trak'][0]

        # Reversed track order (see repair_case_b_video_track_intact
        # above): is the first VISIBLE trak in fact the video one
        # (sample entry avc1/avc3/hev1/hvc1 found inside)?
        VIDEO_CODEC_TAGS = (b'avc1', b'avc3', b'hev1', b'hvc1')
        video_tags_inside_first_trak = [
            (o, t, s) for (o, t, s) in hits
            if t in VIDEO_CODEC_TAGS and audio_trak_off <= o < audio_trak_off + audio_trak_size]
        if video_tags_inside_first_trak:
            return repair_case_b_video_track_intact(
                filepath, out_path, mdat_off, mdat_size,
                audio_trak_off, audio_trak_size, fps_fallback, progress=progress)

        def first(tag):
            return by_tag[tag][0] if tag in by_tag and by_tag[tag] else None

        stss = first(b'stss')
        stsc_all = by_tag.get(b'stsc', [])
        stsz_all = by_tag.get(b'stsz', [])
        # 'co64' (64-bit chunk offsets) is used instead of
        # 'stco' as soon as the file exceeds ~4 GB -- very frequent on
        # very long recordings; both are searched for.
        stco_all = sorted(by_tag.get(b'stco', []) + by_tag.get(b'co64', []),
                           key=lambda e: e[0])
        # The (lost) video track tables appear BEFORE the
        # first intact 'trak' (which is the next track, usually
        # the audio one).
        def before_trak(entries):
            return [e for e in entries if e[0] < audio_trak_off]

        stsc_list = before_trak(stsc_all)
        stsz_list = before_trak(stsz_all)
        stco_list = before_trak(stco_all)

        stsc_raw = stsz_raw = stco_raw = None
        tables_derived = False
        tables_derived_from_gaps = False
        if stsc_list and stsz_list and stco_list:
            stsc_off, stsc_size = stsc_list[0]
            stsz_off, stsz_size = stsz_list[0]
            stco_off, stco_size = stco_list[0]
            stsz_raw, _ = read_raw_box(fh, stsz_off)
            stco_raw, _ = read_raw_box(fh, stco_off)
            stsc_raw, _ = read_raw_box(fh, stsc_off)
        elif stco_list and not stsc_list and not stsz_list:
            # video track stco visible, but stsc/stsz lost (their
            # own tag falls into the encrypted zone): attempt at
            # reconstruction via the other intact track (see
            # derive_synthetic_stsc_stsz above).
            stco_off, stco_size = stco_list[0]
            stco_raw, _ = read_raw_box(fh, stco_off)
            other_stco_candidates = [e for e in stco_all if e[0] >= audio_trak_off]
            if other_stco_candidates:
                other_stco_off, _ = other_stco_candidates[0]
                other_stco_raw, _ = read_raw_box(fh, other_stco_off)
                derived = derive_synthetic_stsc_stsz(
                    stco_raw, other_stco_raw, mdat_off + mdat_size)
                if derived:
                    stsc_raw, stsz_raw = derived
                    tables_derived = True
        elif stco_list and stsz_list and not stsc_list:
            # stco AND stsz of the video track visible, only the 'stsc'
            # tag itself falls into the encrypted zone: EXACT
            # derivation (not an assumption) via derive_synthetic_stsc
            # above, from the real sizes (stsz) and the real
            # chunk offsets (stco/co64).
            stco_off, stco_size = stco_list[0]
            stco_raw, _ = read_raw_box(fh, stco_off)
            stsz_off, stsz_size = stsz_list[0]
            stsz_raw, _ = read_raw_box(fh, stsz_off)
            other_stco_candidates = [e for e in stco_all if e[0] >= audio_trak_off]
            other_stco_raw = None
            if other_stco_candidates:
                other_stco_off, _ = other_stco_candidates[0]
                other_stco_raw, _ = read_raw_box(fh, other_stco_off)
            derived_stsc = derive_synthetic_stsc(
                stco_raw, stsz_raw, other_stco_raw, mdat_off + mdat_size)
            if derived_stsc:
                stsc_raw = derived_stsc
                tables_derived = True
        elif not (stsc_raw and stsz_raw and stco_raw):
            # None of the three video tables is visible, OR only part
            # of them is (real case: stco/ctts/stss survive but stsz
            # -- and often stts -- fall into the encrypted head zone,
            # when that zone only covers the very start of moov). In all
            # cases where at least one of the three is missing, last resort,
            # only possible if the audio track itself is intact -- see
            # derive_video_tables_from_audio_gaps above.
            other_stco_candidates = [e for e in stco_all if e[0] >= audio_trak_off]
            other_stsc_candidates = [e for e in stsc_all if e[0] >= audio_trak_off]
            other_stsz_candidates = [e for e in stsz_all if e[0] >= audio_trak_off]
            if other_stco_candidates and other_stsc_candidates and other_stsz_candidates:
                a_stco_raw, _ = read_raw_box(fh, other_stco_candidates[0][0])
                a_stsc_raw, _ = read_raw_box(fh, other_stsc_candidates[0][0])
                a_stsz_raw, _ = read_raw_box(fh, other_stsz_candidates[0][0])
                mdat_header_len = box_header_len(fh, mdat_off)
                # Codec hint from the REAL config boxes of the
                # moov when they survived (avcC -> H.264, hvcC -> HEVC):
                # content-based detection is unreliable on a stream that does
                # not repeat its parameter NALs, and above all an H.264 slice
                # NAL can be mistaken for a HEVC VPS (see
                # _detect_avcc_codec).
                codec_hint = ('avc' if by_tag.get(b'avcC')
                              else 'hevc' if by_tag.get(b'hvcC') else None)
                # au_grouping=True: groups NALs into ACCESS UNITS
                # (frames) -- essential when a frame is coded in
                # several slices (common: ~12 slices/frame here), without
                # which each slice would be counted as a frame (hence an
                # absurd frame rate, e.g. 323 fps instead of 25).
                derived_from_gaps = derive_video_tables_from_audio_gaps(
                    fh, a_stco_raw, a_stsc_raw, a_stsz_raw,
                    mdat_off + mdat_header_len, mdat_off + mdat_size,
                    au_grouping=True, codec_hint=codec_hint)
                if derived_from_gaps:
                    stco_raw, stsc_raw, stsz_raw = derived_from_gaps
                    tables_derived = True
                    tables_derived_from_gaps = True

        # Validation of the retained video tables: an stsz without any entry
        # (or without a size) is invalid -- typical of an stsz whose tag
        # fell into the encrypted zone (SPOTS mode), while misleading
        # tags (stsc/stco of another track, stsz with 0 entry) survive.
        # We do not trust them and rebuild the tables from the CONTENT.
        # In SPOTS mode (head zone > 4096), the container tables are
        # often misleading (the visible "1st trak" is not necessarily
        # the audio one, stsz boxes with 0 entry survive...): we do not
        # trust them and ALWAYS rebuild the tables from the mdat content,
        # as soon as no intact codec config (avcC/hvcC) is available.
        if (enc_header_len > ENC_HEADER_LEN
                or not (stsc_raw and stsz_raw and stco_raw)
                or not _stsz_box_plausible(stsz_raw)
                or not (_first_sample_looks_avcc(fh, stsz_raw, stco_raw)
                        or _first_sample_looks_mpeg4(fh, stsz_raw, stco_raw))):
            if (not _has_valid_intact_avcc(fh, by_tag)
                    and not by_tag.get(b'hvcC')):
                log("     unusable video tables in the container (likely "
                    "SPOTS mode): reconstructing from the CONTENT of mdat "
                    "(AVCC stream, resynchronisation of the encrypted zones)...")
                content = _recover_video_tables_from_content(
                    fh, mdat_off + box_header_len(fh, mdat_off),
                    mdat_off + mdat_size)
                if content:
                    _c_codec, stco_raw, stsc_raw, stsz_raw = content
                    tables_derived = True

        if not (stsc_raw and stsz_raw and stco_raw):
            raise ValueError("video sample tables not found before the next track")
        stss_box = None
        if stss and stss[0] < audio_trak_off:
            stss_box, _ = read_raw_box(fh, stss[0])

        # 2) read the very first video sample to extract
        #    SPS/PPS (codec config) directly from the real data
        sample_size = struct.unpack(">I", stsz_raw[12:16])[0]
        if sample_size == 0:
            # fixed size not used: each sample has its own
            # size, stored in the table that follows (first entry)
            first_sample_size = struct.unpack(">I", stsz_raw[20:24])[0]
        else:
            first_sample_size = sample_size
        if stco_raw[4:8] == b'co64':
            first_chunk_offset = struct.unpack(">Q", stco_raw[16:24])[0]
        else:
            first_chunk_offset = struct.unpack(">I", stco_raw[16:20])[0]
        fh.seek(first_chunk_offset)
        first_sample = fh.read(min(first_sample_size, 4 * 1024 * 1024))

        # AVC/H.264 is tried first (SPS/PPS type 7/8, 1-byte NAL
        # header), then, if that yields nothing usable, HEVC/H.265 (VPS
        #/SPS/PPS type 32/33/34, 2-byte NAL header). The two NAL type
        # families do not overlap, so no ambiguity is possible.
        codec = None
        width = height = None
        config_box = None
        sample_entry_tag = None

        # 0) Video codec config (avcC box) SURVIVING in the clear in the
        # moov: when the encrypted head zone (4096 bytes) only covers
        # the very start of moov, the avcC box (stsd -> avc1 -> avcC) can
        # remain entirely intact in the clear zone. It is then the REAL
        # SPS/PPS of the original encoder: we use it DIRECTLY, without
        # going through the video stream (which, on such muxes, often does
        # not repeat the parameters before keyframes), the donors, the
        # learned profiles or automatic detection -- no guessing.
        sps = pps = None
        vps = hevc_sps = hevc_pps = None
        intact_avcc = by_tag.get(b'avcC')
        if intact_avcc:
            try:
                avcc_box, _ = read_raw_box(fh, intact_avcc[0][0])
                sps_i, pps_i = parse_avcc_box(avcc_box[8:])
            except (OSError, struct.error, IndexError):
                sps_i = pps_i = None
            if sps_i and pps_i:
                dims = parse_sps_dimensions(sps_i[1:])
                if dims:
                    sps, pps = sps_i, pps_i
                    width, height = dims
                    config_box = build_avcc(sps, pps)
                    sample_entry_tag = b'avc1'
                    codec = 'avc'
                    log("     video codec config (avcC) found INTACT in "
                        "the moov: used directly (real SPS/PPS, no "
                        "guessing).")

        if codec is None:
            sps, pps = extract_sps_pps_from_sample(first_sample)
            if sps and pps:
                dims = parse_sps_dimensions(sps[1:])
                if dims:
                    width, height = dims
                    config_box = build_avcc(sps, pps)
                    sample_entry_tag = b'avc1'
                    codec = 'avc'

        if codec is None:
            vps, hevc_sps, hevc_pps = extract_vps_sps_pps_from_sample_hevc(first_sample)
            if hevc_sps and hevc_pps:
                sps_info = parse_hevc_sps(hevc_sps)
                if sps_info:
                    width, height = sps_info['width'], sps_info['height']
                    config_box = build_hvcc(vps, hevc_sps, hevc_pps, sps_info)
                    sample_entry_tag = b'hev1'
                    codec = 'hevc'

        # Learning of the REAL SPS/PPS read directly (intact avcC/hvcC
        # box, or parameter NALs repeated in the stream): to be recorded
        # HERE, because the learning block further below is nested in
        # "if codec is None and not mpeg4_stream" and therefore only runs
        # for the donor/profile/detection cases -- never when the codec is
        # already determined as above (it was a hole: these real
        # parameters never fed the database).
        if learn_profiles and codec == 'avc':
            register_profile(profile_dir, sps, pps,
                              os.path.basename(out_path), dims=(width, height))
        elif learn_profiles and codec == 'hevc':
            register_profile(profile_dir, hevc_sps, hevc_pps,
                              os.path.basename(out_path), dims=(width, height),
                              vps=vps)

        # 2bis) last resort: neither SPS/PPS (H.264) nor VPS/SPS/PPS (HEVC)
        # ever repeated in the stream (common when x264/x265 mux
        # directly to MP4, without --repeat-headers: the codec config then
        # lives ONLY in the original avcC/hvcC, lost with the rest of
        # the encrypted zone). If --width/--height are supplied, we
        # synthesise a best-effort H.264 SPS/PPS, refined with the real
        # x264 settings read in the clear from the SEI of the first sample
        # when present (cabac/weightp/weightb/8x8dct/
        # constrained_intra) -- EXPERIMENTAL, not guaranteed to decode
        # correctly (frame_num/poc bit-depths and QP remain guessed).
        x264_opts = None
        detect_info = None
        auto_attempted = False
        donor_used = None
        profile_used = None
        hevc_stream = False
        mpeg4_stream = False
        if codec is None:
            # MPEG-4 Part 2 whose REAL config (esds, with the VOL) survived
            # in the clear zone: we use it as is rather than
            # re-synthesising it (exact resolution and VOL).
            m4 = _intact_mpeg4_config(fh, by_tag, audio_trak_off)
            if m4:
                esds_box, mw, mh = m4
                width, height = mw, mh
                config_box = esds_box
                sample_entry_tag = b'mp4v'
                codec = 'mpeg4-intact'
                log("     MPEG-4 Part 2 config (esds) found INTACT in the "
                    "moov: used directly (%dx%d)." % (mw, mh))
        if codec is None:
            mpeg4_stream, mpeg4_result = recover_mpeg4_part2_config(
                fh, first_sample, stsc_raw, stco_raw, stsz_raw,
                width_hint=width_override, height_hint=height_override,
                auto_resolution=auto_resolution,
                max_seconds=auto_resolution_timeout, profile_dir=profile_dir)
            if mpeg4_result:
                width, height = mpeg4_result['width'], mpeg4_result['height']
                config_box = build_esds_mpeg4(mpeg4_result['dsi'])
                sample_entry_tag = b'mp4v'
                codec = 'mpeg4-generic-auto'
                detect_info = mpeg4_result
        if codec is None and not mpeg4_stream:
            sei_payload = extract_sei_from_sample(first_sample)
            x264_opts = parse_x264_sei_options(sei_payload) if sei_payload else {}

            # We fetch several leading video samples (not
            # only the 1st) so that the verification oracle can
            # test the decoding of a small I+P/B sequence, not
            # only of the isolated IDR frame -- far more reliable, whether
            # for a donor file or for automatic
            # detection (see find_avcc_donor_sps_pps /
            # auto_detect_avc_generic_params).
            ORACLE_SAMPLE_WINDOW = ORACLE_QUICK_WINDOW
            oracle_nals = []
            frame_nals_confirm = None
            if auto_resolution or sps_pps_donor_files or use_profiles:
                oracle_nals = _collect_leading_video_nals(
                    fh, stsc_raw, stco_raw, stsz_raw, ORACLE_SAMPLE_WINDOW,
                    first_sample)
                oracle_nals_confirm = _collect_leading_video_nals(
                    fh, stsc_raw, stco_raw, stsz_raw,
                    _oracle_confirm_window(x264_opts), first_sample)
                frame_nals_confirm = [nal for (t, nal) in oracle_nals_confirm
                                      if t in (5, 1)]

            sei_nal_for_oracle = next((nal for (t, nal) in oracle_nals if t == 6), None)
            frame_nals_for_oracle = [nal for (t, nal) in oracle_nals if t in (5, 1)]

            # 0) HEVC stream: dedicated HEVC cascade (donors then HEVC
            # profiles); the H.264 cascade below is then skipped.
            hevc_stream, hevc_result = recover_hevc_config_without_inband_params(
                fh, first_sample, stsc_raw, stco_raw, stsz_raw,
                sps_pps_donor_files, profile_dir, use_profiles)
            if hevc_result:
                vps, hevc_sps, hevc_pps = hevc_result['vps'], hevc_result['sps'], hevc_result['pps']
                sps_info = hevc_result['sps_info']
                width, height = sps_info['width'], sps_info['height']
                config_box = build_hvcc(vps, hevc_sps, hevc_pps, sps_info)
                sample_entry_tag = b'hvc1'
                codec = hevc_result['codec']
                donor_used = hevc_result['donor_used']
                profile_used = hevc_result['profile_used']

            # 1) donor files (--sps-pps-from): PRIORITY over everything
            # else -- these are REAL SPS/PPS (taken from another
            # file of the same source/encoder already rebuilt successfully,
            # explicitly supplied by the user), not values
            # guessed by search.
            if sps_pps_donor_files and not hevc_stream:
                donor_result = find_avcc_donor_sps_pps(
                    sps_pps_donor_files, frame_nals_for_oracle, sei_nal_for_oracle,
                    frame_nals_confirm=frame_nals_confirm)
                if donor_result:
                    donor_sps, donor_pps, donor_path = donor_result
                    dims = parse_sps_dimensions(donor_sps[1:])
                    if dims:
                        width, height = dims
                        config_box = build_avcc(donor_sps, donor_pps)
                        sample_entry_tag = b'avc1'
                        codec = 'avc-donor'
                        donor_used = donor_path

            # 1bis) otherwise, SPS/PPS profiles already learned automatically
            # during previous runs (see --seed-profiles above):
            # also REAL SPS/PPS, tested from the most to the least often
            # encountered -- very effective when several files
            # come from the same source/encoder.
            if codec is None and use_profiles and not hevc_stream:
                profile_result = find_profile_match(
                    profile_dir, frame_nals_for_oracle, sei_nal_for_oracle,
                    frame_nals_confirm=frame_nals_confirm)
                if profile_result:
                    profile_sps, profile_pps, profile_entry = profile_result
                    dims = parse_sps_dimensions(profile_sps[1:])
                    if dims:
                        width, height = dims
                        config_box = build_avcc(profile_sps, profile_pps)
                        sample_entry_tag = b'avc1'
                        codec = 'avc-profile'
                        profile_used = profile_entry

            # 2) otherwise, automatic detection (search/guess) --
            # H.264 only for now.
            if codec is None and auto_resolution and not hevc_stream:
                auto_attempted = True
                detect_info = auto_detect_avc_generic_params(
                    oracle_nals, x264_opts,
                    width_hint=width_override, height_hint=height_override,
                    max_seconds=auto_resolution_timeout,
                    profile_dir=profile_dir,
                    brute_force=brute_force_resolution,
                    resolution_lock=resolution_lock)
                if detect_info:
                    fake_sps = build_fake_avc_sps(
                        detect_info['width'], detect_info['height'],
                        log2_max_frame_num=detect_info['log2_max_frame_num'],
                        log2_max_poc_lsb=detect_info['log2_max_poc_lsb'],
                        max_num_ref_frames=detect_info['max_num_ref_frames'],
                        poc_type=detect_info['poc_type'])
                    fake_pps = build_fake_avc_pps(x264_opts, qp_minus26=detect_info['pic_init_qp_minus26'])
                    width, height = detect_info['width'], detect_info['height']
                    config_box = build_avcc(fake_sps, fake_pps)
                    sample_entry_tag = b'avc1'
                    codec = 'avc-generic-auto'
                    if frame_nals_confirm and not _ffmpeg_probe_avc(
                            fake_sps, fake_pps, frame_nals_confirm,
                            sei_nal_for_oracle, timeout=ORACLE_CONFIRM_TIMEOUT):
                        log("  [auto-detection resolution] WARNING: the config "
                            "found does NOT confirm across several GOPs (risk "
                            "of corrupted blocks at every keyframe) -- check "
                            "playback in a video player before deleting "
                            "the .nsm.")

            # 3) as a very last resort, generic manual --width/--height
            # (H.264 SPS/PPS: irrelevant on an HEVC stream).
            if codec is None and width_override and height_override and not hevc_stream:
                # Reuses the REAL values already read from the x264 SEI
                # (ref/bframes/b_pyramid -> log2_max_frame_num/poc_lsb and
                # pic_order_cnt_type through x264's formulas; ref=N in
                # the clear) when available, rather
                # than build_fake_avc_sps generic defaults: only the
                # resolution then remains an assumption.
                manual_f, manual_p = _x264_default_f_p(x264_opts)
                manual_ref = (_x264_num_ref_frames(x264_opts)
                              or _x264_ref_hint(x264_opts) or 2)
                fake_sps = build_fake_avc_sps(
                    width_override, height_override,
                    log2_max_frame_num=manual_f, log2_max_poc_lsb=manual_p,
                    max_num_ref_frames=manual_ref,
                    poc_type=_x264_poc_type(x264_opts))
                fake_pps = build_fake_avc_pps(
                    x264_opts, qp_minus26=_x264_init_qp_guesses(x264_opts)[0])
                width, height = width_override, height_override
                config_box = build_avcc(fake_sps, fake_pps)
                sample_entry_tag = b'avc1'
                codec = 'avc-generic'

            # Learning: only the REAL SPS/PPS (explicit donor,
            # already known profile -- both validated by the multi-frame
            # ffmpeg oracle --, or read directly from the stream in the clear)
            # feed the profile database -- never the parameters guessed
            # by automatic detection/--width/--height, not guaranteed
            # to be reliable.
            if learn_profiles and codec == 'avc-donor':
                register_profile(profile_dir, donor_sps, donor_pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec == 'avc-profile':
                register_profile(profile_dir, profile_sps, profile_pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec in ('hevc-donor', 'hevc-profile'):
                register_profile(profile_dir, hevc_sps, hevc_pps,
                                  os.path.basename(out_path), dims=(width, height), vps=vps)
            elif learn_profiles and codec == 'avc':
                # Most frequent case -- REAL SPS/PPS read directly from the
                # stream (repeated before the IDR, no search needed) --
                # but so far never recorded: restore_and_reencode.py
                # then deletes this decoded file (replaced by the re-encoded
                # HEVC result), erasing these REAL parameters for good.
                # Real case observed: several HEVC files already recovered
                # successfully (so their original VPS/SPS/PPS were
                # indeed readable at that time), yet 0 HEVC
                # profile learned over the whole corpus -- so the next
                # file from the same source, this one WITHOUT VPS/SPS/PPS
                # in the clear, no longer finds any donor or profile (total
                # failure, even with automatic detection: it only covers H.264).
                register_profile(profile_dir, sps, pps,
                                  os.path.basename(out_path), dims=(width, height))
            elif learn_profiles and codec == 'hevc':
                register_profile(profile_dir, hevc_sps, hevc_pps,
                                  os.path.basename(out_path), dims=(width, height), vps=vps)

        # 3) audio track: verbatim copy of the entire trak box
        audio_trak_raw, _ = read_raw_box(fh, audio_trak_off)
        # The copied trak keeps its edts/elst edit list and tkhd duration
        # expressed in the ORIGINAL (lost) movie timescale: drop/rewrite them
        # for the synthetic DEFAULT_VIDEO_TIMESCALE used by the mvhd below.
        audio_trak_raw = strip_track_edit_lists(audio_trak_raw, DEFAULT_VIDEO_TIMESCALE)

        # 4) udta (optional), if it is intact
        udta_raw = None
        udta_hit = first(b'udta')
        if udta_hit and udta_hit[0] > audio_trak_off:
            udta_raw, _ = read_raw_box(fh, udta_hit[0])

        sample_count = struct.unpack(">I", stsz_raw[16:20])[0]

    if not (codec and width and height and config_box):
        if mpeg4_stream:
            return False, mpeg4_failure_message(auto_resolution)
        if hevc_stream:
            return False, hevc_failure_message(sps_pps_donor_files, profile_dir, use_profiles)
        ffmpeg_missing = shutil.which('ffmpeg') is None
        donor_note = ""
        if sps_pps_donor_files:
            donor_note = (f"{len(sps_pps_donor_files)} donor file(s) "
                           f"tested (--sps-pps-from) without a conclusive match. ")
        profile_note = ""
        if use_profiles:
            n_known_profiles = len(iter_profiles_sorted(profile_dir))
            if n_known_profiles:
                profile_note = (f"{n_known_profiles} known SPS/PPS profile(s) in the "
                                 f"database ({profile_dir}) tested without a "
                                 f"conclusive match. ")
        if not auto_resolution:
            detect_note = "Automatic detection disabled (--no-auto-resolution). "
        elif ffmpeg_missing:
            detect_note = ("ffmpeg is not installed (or not in PATH): automatic "
                            "resolution detection could not be "
                            "attempted -- install ffmpeg to enable it. ")
        elif auto_attempted:
            detect_note = ("Automatic resolution detection was attempted "
                            "(via ffmpeg) without finding a conclusive combination -- "
                            "the original resolution may not be among those "
                            "tested, or other stream parameters differ too much "
                            "from the original. ")
        else:
            detect_note = ""
        return False, (donor_note + profile_note + "VPS/SPS/PPS not found (or unusable) in the "
                        "first sample, tried as both AVC/H.264 and "
                        "HEVC/H.265: cannot rebuild the video "
                        "codec config (the stream may not include the "
                        "parameters in the clear in every keyframe -- common "
                        "when x264/x265 muxes directly to MP4 without "
                        "--repeat-headers). " + detect_note +
                        "Retry with --width/--height to force a precise "
                        "resolution (EXPERIMENTAL attempt with a "
                        "generic H.264 SPS/PPS, refined with the x264 settings "
                        "from the SEI if present) -- not guaranteed to decode "
                        "correctly, resolution to be checked in a video "
                        "player.")

    # ---- video frame rate: first the VUI of the REAL SPS (reliable, especially
    #      when the audio track is unusable -- SPOTS case), otherwise the
    #      duration of the intact audio track, otherwise --fps (default 24 fps) ----
    fps_used = fps_fallback
    fps_source = f"default / supplied via --fps ({fps_fallback} fps), audio duration unusable"
    # The duration of the intact AUDIO track is the reference when it is
    # usable (it is the real duration of the file). The VUI of the SPS is
    # used ONLY AS A FALLBACK: its frame rate may not match if the SPS
    # comes from a learned PROFILE / a donor (another file from the same
    # encoder but a different frame rate -- real case: a 29 fps profile
    # applied to a 25 fps file, video ~14 % too short), and it is
    # essential in SPOTS mode where the audio track is unusable.
    detected = detect_fps_from_audio(audio_trak_raw, sample_count)
    if detected is None:
        _config_sps = (sps if codec == 'avc' else
                       profile_sps if codec == 'avc-profile' else
                       donor_sps if codec == 'avc-donor' else None)
        if _config_sps:
            _vfps = _fps_from_sps(_config_sps)
            if _vfps:
                detected = (_vfps, f"read from the VUI of the SPS (fallback: audio "
                                   f"duration unusable): {_vfps} fps")
    if detected:
        fps_used, fps_source = detected

    # ---- box construction ----
    timescale = DEFAULT_VIDEO_TIMESCALE
    duration_track = int(sample_count / fps_used * timescale)

    tkhd = box(b'tkhd', bytes([0, 0, 0, 7]) + b'\x00' * 8 +
               struct.pack(">I", 1) + b'\x00' * 4 +
               struct.pack(">I", duration_track) + b'\x00' * 8 +
               struct.pack(">h", 0) + struct.pack(">h", 0) +
               struct.pack(">h", 0) + b'\x00\x00' +
               struct.pack(">iiiiiiiii", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               struct.pack(">H", width) + b'\x00\x00' +
               struct.pack(">H", height) + b'\x00\x00')

    mdhd = box(b'mdhd', b'\x00' * 4 + b'\x00' * 8 +
               struct.pack(">I", timescale) + struct.pack(">I", duration_track) +
               b'\x55\xc4' + b'\x00\x00')

    hdlr = box(b'hdlr', b'\x00' * 4 + b'\x00' * 4 + b'vide' + b'\x00' * 12 + b'VideoHandler\x00')

    vmhd = box(b'vmhd', bytes([0, 0, 0, 1]) + b'\x00' * 8)
    url_ = box(b'url ', bytes([0, 0, 0, 1]))
    dref = box(b'dref', b'\x00' * 4 + struct.pack(">I", 1) + url_)
    dinf = box(b'dinf', dref)

    stsd_entry_payload = (b'\x00' * 6 + struct.pack(">H", 1) +
                           b'\x00' * 16 +
                           struct.pack(">H", width) + struct.pack(">H", height) +
                           struct.pack(">I", 0x00480000) + struct.pack(">I", 0x00480000) +
                           b'\x00' * 4 + struct.pack(">H", 1) +
                           b'\x00' * 32 +
                           struct.pack(">H", 24) + struct.pack(">h", -1) +
                           config_box)
    visual_sample_entry = box(sample_entry_tag, stsd_entry_payload)
    stsd = box(b'stsd', b'\x00' * 4 + struct.pack(">I", 1) + visual_sample_entry)

    stts_body = b'\x00' * 4 + struct.pack(">I", 1) + struct.pack(">II", sample_count,
                                                                    max(1, int(timescale // fps_used)))
    stts = box(b'stts', stts_body)

    mvhd = box(b'mvhd', b'\x00' * 4 + b'\x00' * 8 +
               struct.pack(">I", timescale) + struct.pack(">I", duration_track) +
               struct.pack(">I", 0x00010000) + struct.pack(">H", 0x0100) + b'\x00\x00' +
               b'\x00' * 8 +
               struct.pack(">iiiiiiiii", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               b'\x00' * 24 + struct.pack(">I", 3))

    ftyp = DEFAULT_FTYPE

    def assemble_moov(stco_for_video, audio_trak_bytes):
        stbl_children = stsd + stts + stsc_raw + stsz_raw + stco_for_video
        if stss_box:
            stbl_children += stss_box
        stbl = box(b'stbl', stbl_children)
        minf = box(b'minf', vmhd + dinf + stbl)
        mdia = box(b'mdia', mdhd + hdlr + minf)
        video_trak = box(b'trak', tkhd + mdia)
        moov_children = mvhd + video_trak + audio_trak_bytes
        if udta_raw:
            moov_children += udta_raw
        return box(b'moov', moov_children)

    # 1st pass: "blank" assembly (stco offsets not patched) to
    # know the exact length of the new moov -> this determines by
    # how much the chunk offsets must be shifted (the
    # ftyp+moov bytes no longer have the same length as the old original
    # header, whereas mdat itself is never moved).
    with open(filepath, 'rb') as fh_mdat_hdr:
        mdat_header_len = box_header_len(fh_mdat_hdr, mdat_off)
    moov_draft = assemble_moov(stco_raw, audio_trak_raw)
    new_mdat_body_start = len(ftyp) + len(moov_draft) + mdat_header_len
    old_mdat_body_start = mdat_off + mdat_header_len
    delta = new_mdat_body_start - old_mdat_body_start
    log_msg = f"  (sample offset shift applied: {delta:+d} bytes)"

    stco_patched = patch_stco_boxes(stco_raw, delta)
    audio_trak_patched = audio_trak_raw
    audio_dropped = False
    try:
        audio_trak_patched = patch_stco_boxes(audio_trak_raw, delta)
    except ValueError as e:
        # The AUDIO track chunk offsets are unusable (absurd value
        # -- typically a table that fell into the encrypted zone).
        # Rather than abandoning the WHOLE file while the video itself
        # is validated (codec config verified by decoding), we rebuild
        # VIDEO ONLY, as the AVI path already does for the same reason.
        # WARNING: when the video tables were ADDITIONALLY DERIVED from
        # the chunk offsets, they relied on this unusable audio track
        # -- the result is then verified by decoding further
        # down, and discarded if it does not play.
        log(f"  [WARNING] audio track dropped: its chunk offset "
            f"table is unusable ({e}). VIDEO-ONLY reconstruction.")
        audio_trak_patched = b''
        audio_dropped = True
        moov_draft = assemble_moov(stco_raw, b'')
        delta = (len(ftyp) + len(moov_draft) + mdat_header_len
                 - old_mdat_body_start)
        stco_patched = patch_stco_boxes(stco_raw, delta)
        log_msg = (f"  (sample offset shift applied: "
                   f"{delta:+d} bytes, video only)")
    moov = assemble_moov(stco_patched, audio_trak_patched)
    assert len(moov) == len(moov_draft), "internal inconsistency: fixing the offsets changed the size of moov"
    print(log_msg)

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(ftyp)
        dst.write(moov)
        src.seek(mdat_off)
        remaining = mdat_size
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)

    if audio_dropped:
        # The audio track was dropped: if the video tables had additionally
        # been DERIVED (stsc/stsz lost), they were derived relying on
        # this track's offsets -- which are precisely the ones we just
        # declared unusable. The only reliable judge is the decoder:
        # a file that does not play is not kept.
        dec_ok, dec_msg = _probe_decodable(out_path)
        if dec_ok is False:
            try:
                os.remove(out_path)
            except OSError:
                pass
            return False, (f"unusable audio track AND derived video "
                           f"tables: the video-only file does not play "
                           f"({dec_msg}) -- file not kept.")

    return True, {
        'width': width, 'height': height, 'sample_count': sample_count,
        'fps_fallback': fps_used, 'fps_source': fps_source, 'codec': codec,
        'x264_opts': x264_opts, 'detect_info': detect_info, 'donor_used': donor_used,
        'profile_used': profile_used, 'tables_derived': tables_derived,
        'tables_derived_from_gaps': tables_derived_from_gaps,
    }


# ==========================================================================
# MATROSKA / EBML SECTION (.mkv, .webm)
# ==========================================================================
#
# Same ransomware, same principle (first 4096 bytes encrypted + HARR
# footer at the end), but a completely different container: Matroska (EBML)
# instead of MP4 (ISO-BMFF). Diagnosis established on a real sample:
#
#   - There is NO absolute offset table to fix (unlike MP4's
#     stco/co64): a Matroska Cluster is self-contained, so it is enough
#     to locate the first intact Cluster and copy the rest of the
#     file as is behind a new synthetic header (EBML+Segment+Info+Tracks).
#     Much simpler than MP4 CASE B reconstruction.
#   - On the other hand, "Tracks" (the equivalent of moov: CodecID, CodecPrivate
#     i.e. the codec config, dimensions...) is often tiny and fits
#     ENTIRELY in the first 4096 encrypted bytes -> lost. We still try,
#     as a precaution, a signature scan for Tracks beyond
#     byte 4096 (rare but some files have a large SeekHead that
#     pushes Tracks further away); failing that, we "sniff" the codec config
#     directly from the first frames of each track, EXACTLY
#     as for MP4 CASE B:
#       - Audio: AC3/DTS/MP3 are self-describing (sync word + fixed
#         header in every frame), hence recoverable WITHOUT CodecPrivate.
#       - H.264/H.265 video: if the encoder repeats SPS/PPS(/VPS) in the clear
#         before keyframes (common), they are recovered the same way as for
#         MP4 CASE B. If they are NEVER repeated in the stream (common
#         with x264 without --repeat-headers), they are lost for good: we
#         then offer, only if the user supplies --width/--height,
#         a synthetic "generic" SPS/PPS (x264 default settings:
#         High profile, CABAC, 4:2:0 8-bit) -- AT BEST, experimental, the
#         video may not decode correctly if the original encoder
#         was not using those exact settings.
#   - The split MUST be aligned on a Cluster containing a
#     REAL keyframe (IDR) for the video track: gluing to the first simply
#     readable Cluster, even with the right codec config, produces a stream
#     that starts in the middle of a GOP (P/B frames referencing absent
#     frames) and does not decode.
#
# The script NEVER MODIFIES the original .nsm/.mkv files.

def read_ebml_vint(data, pos, keep_marker=False):
    """Reads a variable-size EBML integer starting at `pos`. Returns
    (value, length_in_bytes), or None if unreadable. `keep_marker=True`
    keeps the marker bit (used for element IDs)."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first == 0:
        return None
    length = 1
    mask = 0x80
    while mask and not (first & mask):
        mask >>= 1
        length += 1
    if length > 8 or pos + length > len(data):
        return None
    if keep_marker:
        value = 0
        for i in range(length):
            value = (value << 8) | data[pos + i]
    else:
        value = first & (mask - 1)
        for i in range(1, length):
            value = (value << 8) | data[pos + i]
    return value, length


def read_ebml_element(data, pos):
    """Reads the header (ID + size) of an EBML element at `pos`."""
    idr = read_ebml_vint(data, pos, keep_marker=True)
    if not idr:
        return None
    eid, idlen = idr
    szr = read_ebml_vint(data, pos + idlen, keep_marker=False)
    if not szr:
        return None
    size, szlen = szr
    all_ones = (1 << (7 * szlen)) - 1
    unknown = (size == all_ones)
    content_start = pos + idlen + szlen
    return {'id': eid, 'id_len': idlen, 'size': size, 'size_len': szlen,
            'unknown': unknown, 'content_start': content_start}


def iter_ebml_children(data, start, limit):
    """Walks the child elements between [start, limit). Stops
    cleanly at `limit`, or at the first unreadable element / element of
    unknown size (Clusters/Segments of unknown size are rare but
    do exist; we do not descend into them more finely here, which is enough for
    the sniffing)."""
    pos = start
    while pos < limit:
        hdr = read_ebml_element(data, pos)
        if not hdr:
            break
        yield hdr
        if hdr['unknown']:
            break
        pos = hdr['content_start'] + hdr['size']


def ebml_size_bytes(value, length=None):
    """Encodes `value` as an EBML size (vint), on `length` bytes when
    specified, otherwise on the minimum required."""
    if length is None:
        length = 1
        while value > (1 << (7 * length)) - 2:
            length += 1
    if value > (1 << (7 * length)) - 1:
        raise ValueError("value too large for the requested vint length")
    marker = 0x80 >> (length - 1)
    out = bytearray(length)
    v = value
    for i in range(length - 1, -1, -1):
        out[i] = v & 0xFF
        v >>= 8
    out[0] |= marker
    return bytes(out)


def ebml_elem(id_bytes, payload):
    return id_bytes + ebml_size_bytes(len(payload)) + payload


def ebml_uint(value, length=None):
    if value == 0:
        return b'\x00' * (length or 1)
    if length is None:
        length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, 'big')


def ebml_float(value):
    return struct.pack('>d', float(value))


def ebml_str(s):
    return s.encode('ascii', 'replace')


TRACK_NUMBER_ID = b'\xd7'
TRACK_UID_ID = b'\x73\xc5'
TRACK_TYPE_ID = b'\x83'
CODEC_ID_ID = b'\x86'
CODEC_PRIVATE_ID = b'\x63\xa2'
VIDEO_TRACK_ID = b'\xe0'
AUDIO_TRACK_ID = b'\xe1'
PIXEL_WIDTH_ID = b'\xb0'
PIXEL_HEIGHT_ID = b'\xba'
SAMPLING_FREQ_ID = b'\xb5'
CHANNELS_ID = b'\x9f'
TRACK_ENTRY_ID = b'\xae'
TRACKS_ID_B = b'\x16\x54\xae\x6b'
INFO_ID_B = b'\x15\x49\xa9\x66'
TIMECODESCALE_ID = b'\x2a\xd7\xb1'
MUXING_APP_ID = b'\x4d\x80'
WRITING_APP_ID = b'\x57\x41'
EBML_HEADER_ID = b'\x1a\x45\xdf\xa3'
SEGMENT_ID_B = b'\x18\x53\x80\x67'
DOCTYPE_ID = b'\x42\x82'
DOCTYPE_VERSION_ID = b'\x42\x87'
DOCTYPE_READ_VERSION_ID = b'\x42\x85'
EBML_VERSION_ID = b'\x42\x86'
EBML_READ_VERSION_ID = b'\x42\xf7'
EBML_MAX_ID_LENGTH_ID = b'\x42\xf2'
EBML_MAX_SIZE_LENGTH_ID = b'\x42\xf3'

CLUSTER_ID = 0x1F43B675
SIMPLEBLOCK_ID = 0xA3
BLOCKGROUP_ID = 0xA0
BLOCK_ID = 0xA1
MKV_TRACKS_ID_RAW = 0x1654AE6B


def build_ebml_header():
    body = (ebml_elem(EBML_VERSION_ID, ebml_uint(1)) +
            ebml_elem(EBML_READ_VERSION_ID, ebml_uint(1)) +
            ebml_elem(EBML_MAX_ID_LENGTH_ID, ebml_uint(4)) +
            ebml_elem(EBML_MAX_SIZE_LENGTH_ID, ebml_uint(8)) +
            ebml_elem(DOCTYPE_ID, ebml_str("matroska")) +
            ebml_elem(DOCTYPE_VERSION_ID, ebml_uint(4)) +
            ebml_elem(DOCTYPE_READ_VERSION_ID, ebml_uint(2)))
    return ebml_elem(EBML_HEADER_ID, body)


def build_mkv_info(timecode_scale=1000000):
    body = (ebml_elem(TIMECODESCALE_ID, ebml_uint(timecode_scale)) +
            ebml_elem(MUXING_APP_ID, ebml_str("restore_videos.py")) +
            ebml_elem(WRITING_APP_ID, ebml_str("restore_videos.py")))
    return ebml_elem(INFO_ID_B, body)


def build_mkv_track_entry(track_number, track_type, codec_id, codec_private=None,
                           width=None, height=None, sampling_freq=None, channels=None):
    body = (ebml_elem(TRACK_NUMBER_ID, ebml_uint(track_number)) +
            ebml_elem(TRACK_UID_ID, ebml_uint(track_number)) +
            ebml_elem(TRACK_TYPE_ID, ebml_uint(track_type)) +
            ebml_elem(CODEC_ID_ID, ebml_str(codec_id)))
    if codec_private is not None:
        body += ebml_elem(CODEC_PRIVATE_ID, codec_private)
    if track_type == 1:
        video_body = (ebml_elem(PIXEL_WIDTH_ID, ebml_uint(width)) +
                      ebml_elem(PIXEL_HEIGHT_ID, ebml_uint(height)))
        body += ebml_elem(VIDEO_TRACK_ID, video_body)
    elif track_type == 2:
        audio_body = (ebml_elem(SAMPLING_FREQ_ID, ebml_float(sampling_freq)) +
                      ebml_elem(CHANNELS_ID, ebml_uint(channels)))
        body += ebml_elem(AUDIO_TRACK_ID, audio_body)
    return ebml_elem(TRACK_ENTRY_ID, body)


def build_mkv_tracks(track_entries):
    return ebml_elem(TRACKS_ID_B, b''.join(track_entries))


def build_avcc_payload(sps: bytes, pps: bytes) -> bytes:
    """Same content as build_avcc() but WITHOUT the ISO-BMFF box wrapper
    (size+tag): this is the format expected by CodecPrivate in Matroska."""
    profile_idc = sps[1]; compat = sps[2]; level_idc = sps[3]
    payload = bytes([1, profile_idc, compat, level_idc, 0xFF,
                      0xE1]) + struct.pack(">H", len(sps)) + sps
    payload += bytes([1]) + struct.pack(">H", len(pps)) + pps
    if profile_idc in (100, 110, 122, 144):
        payload += bytes([0xFC | 1, 0xF8 | 1, 0xF8 | 1, 0])
    return payload


def build_hvcc_payload(vps, sps, pps, sps_info) -> bytes:
    """Equivalent of build_hvcc() without the ISO-BMFF box wrapper."""
    boxed = build_hvcc(vps, sps, pps, sps_info)
    return boxed[8:]  # strips size(4)+tag(4)


# ---------------------------------------------------------- SPS/PPS "at best"
# Used ONLY when the original SPS/PPS is definitively unrecoverable
# (never repeated in the stream) AND the user supplies --width/--height.
# x264 default settings (High profile / CABAC / 4:2:0 8-bit), very
# widespread but NOT guaranteed identical to the original encoder: the video
# may not decode correctly if the real settings differed
# (entropy mode, number of reference frames, etc. -- these parameters are
# not in the file name, nor recoverable without the real SPS/PPS).

class BitWriter:
    def __init__(self):
        self.bits = []

    def u(self, value, n):
        for i in range(n - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def ue(self, value):
        value = value + 1
        nbits = value.bit_length()
        self.u(0, nbits - 1)
        self.u(value, nbits)

    def se(self, value):
        code = (-2 * value) if value <= 0 else (2 * value - 1)
        self.ue(code)

    def rbsp_trailing(self):
        self.bits.append(1)
        while len(self.bits) % 8 != 0:
            self.bits.append(0)

    def to_bytes(self):
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            byte = 0
            for b in self.bits[i:i + 8]:
                byte = (byte << 1) | b
            out.append(byte)
        return bytes(out)


def rbsp_to_ebsp(rbsp: bytes) -> bytes:
    """Inverse of ebsp_to_rbsp(): reinserts the emulation-prevention
    bytes (0x03) wherever 2 consecutive zeros would be followed by a byte <=3."""
    out = bytearray()
    zero_run = 0
    for b in rbsp:
        if zero_run >= 2 and b <= 0x03:
            out.append(0x03)
            zero_run = 0
        out.append(b)
        zero_run = zero_run + 1 if b == 0 else 0
    return bytes(out)


def build_fake_avc_sps(width, height, profile_idc=100, level_idc=41,
                        log2_max_frame_num=8, log2_max_poc_lsb=8,
                        max_num_ref_frames=2, poc_type=0):
    # poc_type: 0 (explicit POC in every slice header, on
    # log2_max_poc_lsb bits) or 2 (POC derived from frame_num, NO POC field
    # in the header) -- x264 uses 2 as soon as bframes=0 (and not interlaced).
    # A wrong poc_type shifts the parsing of ALL slice headers.
    bw = BitWriter()
    bw.u(profile_idc, 8)
    bw.u(0, 8)
    bw.u(level_idc, 8)
    bw.ue(0)
    high_profiles = (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135)
    if profile_idc in high_profiles:
        bw.ue(1); bw.ue(0); bw.ue(0); bw.u(0, 1); bw.u(0, 1)
    bw.ue(log2_max_frame_num - 4)
    bw.ue(poc_type)
    if poc_type == 0:
        bw.ue(log2_max_poc_lsb - 4)
    bw.ue(max_num_ref_frames)
    bw.u(0, 1)
    mb_w = (width + 15) // 16
    mb_h = (height + 15) // 16
    bw.ue(mb_w - 1)
    bw.ue(mb_h - 1)
    bw.u(1, 1)
    bw.u(1, 1)
    crop_needed = (mb_w * 16 != width) or (mb_h * 16 != height)
    bw.u(1 if crop_needed else 0, 1)
    if crop_needed:
        crop_x, crop_y = 2, 2
        crop_right = (mb_w * 16 - width) // crop_x
        crop_bottom = (mb_h * 16 - height) // crop_y
        bw.ue(0); bw.ue(crop_right); bw.ue(0); bw.ue(crop_bottom)
    bw.u(0, 1)
    bw.rbsp_trailing()
    ebsp = rbsp_to_ebsp(bw.to_bytes())
    return bytes([0x67]) + ebsp


def parse_x264_sei_options(sei_payload: bytes):
    """Parses the 'user data unregistered' SEI message that x264 inserts in
    the clear before the first keyframe (e.g. "x264 - core 161 ... - options:
    cabac=1 ref=1 ... 8x8dct=1 ..."). Returns a {option: value} dict on a
    best-effort basis ({} if the SEI is not recognisable). Used
    ONLY to refine the 'at best' codec config of
    build_fake_avc_pps() when the original SPS/PPS is definitively
    lost (never repeated in the stream) -- never replaces a real
    SPS/PPS recovered in the clear."""
    if not sei_payload:
        return {}
    try:
        text = sei_payload.decode('latin-1', 'replace')
    except Exception:
        return {}
    marker = 'options:'
    idx = text.find(marker)
    if idx < 0:
        return {}
    opts_str = text[idx + len(marker):]
    result = {}
    for tok in opts_str.split():
        if '=' in tok:
            k, _, v = tok.partition('=')
            k = k.strip()
            v = v.strip()
            if k:
                result[k] = v
    return result


def build_fake_avc_pps(x264_opts=None, qp_minus26=0):
    """'At best' PPS (see build_fake_avc_sps above). If x264_opts is
    supplied (dict from parse_x264_sei_options(), read from the x264 SEI in
    the clear at the start of the first sample), a few fields are adjusted
    from the REAL encoder settings (cabac, weightp, weightb,
    8x8dct, constrained_intra) instead of keeping generic
    values: the synthesised config then matches the real stream far more
    closely. Remains EXPERIMENTAL (rebuilt SPS/PPS, not the originals):
    frame_num/poc bit depths and QP are still guessed, so decoding is not
    guaranteed pixel-perfect."""
    o = x264_opts or {}
    cabac = o.get('cabac', '1') != '0'
    weightp = o.get('weightp', '0') not in ('0', '')
    weightb = o.get('weightb', '0') not in ('0', '')
    dct8x8 = o.get('8x8dct', '0') not in ('0', '')
    constrained_intra = o.get('constrained_intra', '0') not in ('0', '')
    # x264 writes num_ref_idx_l0_default_active = ref ('ref' option) and only
    # signals deviations from that value in the slice header: a wrong
    # default makes the ref_idx of every P frame misparse.
    try:
        ref_l0 = max(1, min(32, int(o.get('ref', '1'))))
    except ValueError:
        ref_l0 = 1
    # SEI chroma_qp_offset = the final value written into the PPS by x264
    # (psy-rd already applied); does not break decoding if wrong, but
    # shifts the colours.
    try:
        chroma_qp = max(-12, min(12, int(o.get('chroma_qp_offset', '0'))))
    except ValueError:
        chroma_qp = 0
    bw = BitWriter()
    bw.ue(0)                          # pic_parameter_set_id
    bw.ue(0)                          # seq_parameter_set_id
    bw.u(1 if cabac else 0, 1)        # entropy_coding_mode_flag
    bw.u(0, 1)                        # bottom_field_pic_order_in_frame_present_flag
    bw.ue(0)                          # num_slice_groups_minus1
    bw.ue(ref_l0 - 1)                 # num_ref_idx_l0_default_active_minus1
    bw.ue(0)                          # num_ref_idx_l1_default_active_minus1
    bw.u(1 if weightp else 0, 1)      # weighted_pred_flag
    bw.u(2 if weightb else 0, 2)      # weighted_bipred_idc (x264: 2=implicit)
    bw.se(qp_minus26)                 # pic_init_qp_minus26 (guessed/detected)
    bw.se(0)                          # pic_init_qs_minus26
    bw.se(chroma_qp)                  # chroma_qp_index_offset
    bw.u(1, 1)                        # deblocking_filter_control_present_flag
    bw.u(1 if constrained_intra else 0, 1)  # constrained_intra_pred_flag
    bw.u(0, 1)                        # redundant_pic_cnt_present_flag
    bw.u(1 if dct8x8 else 0, 1)       # transform_8x8_mode_flag
    bw.u(0, 1)                        # pic_scaling_matrix_present_flag
    bw.se(chroma_qp)                  # second_chroma_qp_index_offset
    bw.rbsp_trailing()
    ebsp = rbsp_to_ebsp(bw.to_bytes())
    return bytes([0x68]) + ebsp


def extract_nals_from_sample(sample_bytes: bytes, length_size=4, max_nals=30):
    """Splits an AVCC sample (length prefix, no start code)
    into a list of raw NAL units WITH their header byte: [(type, nal), ...].
    Used to recover the SEI and the first IDR frame verbatim for
    automatic resolution detection (see auto_detect_avc_generic_params)."""
    out = []
    pos = 0
    n = len(sample_bytes)
    for _ in range(max_nals):
        if pos + length_size > n:
            break
        nal_len = int.from_bytes(sample_bytes[pos:pos + length_size], 'big')
        nal_start = pos + length_size
        nal_end = nal_start + nal_len
        if nal_len <= 0 or nal_end > n:
            break
        nal = sample_bytes[nal_start:nal_end]
        if nal:
            out.append((nal[0] & 0x1F, nal))
        pos = nal_end
    return out


def extract_hevc_nals_from_sample(sample_bytes: bytes, length_size=4, max_nals=30):
    """HEVC equivalent of extract_nals_from_sample: [(HEVC type, nal), ...]
    with the type read from the 2-byte NAL header ((b0 >> 1) & 0x3F)."""
    return [((nal[0] >> 1) & 0x3F, nal)
            for (_t, nal) in extract_nals_from_sample(sample_bytes, length_size, max_nals)
            if len(nal) >= 2]


# Valid HEVC NAL types (H.265 table 7-1): VCL 0-9 and IRAP 16-21,
# then VPS/SPS/PPS/AUD/EOS/EOB/FD/SEI 32-40. The others are reserved or
# unspecified.
HEVC_VALID_NAL_TYPES = set(range(0, 10)) | set(range(16, 22)) | set(range(32, 41))


def looks_like_hevc_nals(hevc_nals) -> bool:
    """Tells whether NALs (split by extract_hevc_nals_from_sample)
    form a plausible HEVC stream: consistent HEVC headers
    (forbidden_zero_bit=0, nuh_layer_id=0, nuh_temporal_id_plus1>=1, valid
    type) on ALL NALs, and at least one IRAP frame (IDR/CRA/BLA,
    types 16-21). An H.264 stream read this way fails very quickly: its slices
    (0x65, 0x41, 0x21, 0x01...) yield a reserved type or a
    non-zero nuh_layer_id."""
    if not hevc_nals:
        return False
    for t, nal in hevc_nals:
        if nal[0] & 0x80 or t not in HEVC_VALID_NAL_TYPES:
            return False
        layer_id = ((nal[0] & 0x01) << 5) | (nal[1] >> 3)
        if layer_id != 0 or (nal[1] & 0x07) == 0:
            return False
    return any(16 <= t <= 21 for t, _ in hevc_nals)


def resolve_leading_video_sample_offsets(stsc_raw, stco_raw, stsz_raw, count):
    """Computes the ABSOLUTE offsets (in the file) and sizes of the first
    `count` video samples, taking CHUNKING into account
    (stsc/stco) -- essential as soon as the video track is interleaved
    with the audio track (a common case in MP4): the samples are then
    NOT contiguous in bytes, and a plain sequential read from
    the 1st chunk would read garbage past it (verified
    empirically). Used to recover several frames (not just the
    1st) for a more reliable automatic detection oracle."""
    def payload(raw):
        return raw[8:]

    stsc_p = payload(stsc_raw)
    stsc_entry_count = struct.unpack(">I", stsc_p[4:8])[0]
    stsc_entries = []
    off = 8
    for _ in range(stsc_entry_count):
        first_chunk, spc, sdi = struct.unpack(">III", stsc_p[off:off + 12])
        stsc_entries.append((first_chunk, spc, sdi))
        off += 12

    stco_p = payload(stco_raw)
    stco_entry_count = struct.unpack(">I", stco_p[4:8])[0]
    if stco_raw[4:8] == b'co64':
        chunk_offsets = list(struct.unpack(">%dQ" % stco_entry_count,
                                            stco_p[8:8 + 8 * stco_entry_count]))
    else:
        chunk_offsets = list(struct.unpack(">%dI" % stco_entry_count,
                                            stco_p[8:8 + 4 * stco_entry_count]))

    stsz_p = payload(stsz_raw)
    sample_size = struct.unpack(">I", stsz_p[4:8])[0]
    sample_count = struct.unpack(">I", stsz_p[8:12])[0]
    n = min(count, sample_count)
    if sample_size == 0:
        sizes = list(struct.unpack(">%dI" % n, stsz_p[12:12 + 4 * n]))
    else:
        sizes = [sample_size] * n

    spc_for_chunk = {}
    for idx, (first_chunk, spc, sdi) in enumerate(stsc_entries):
        next_first_chunk = (stsc_entries[idx + 1][0] if idx + 1 < len(stsc_entries)
                             else stco_entry_count + 1)
        for c in range(first_chunk, next_first_chunk):
            spc_for_chunk[c] = spc

    offsets = []
    sample_idx = 0
    chunk_num = 1
    while sample_idx < n and chunk_num <= stco_entry_count:
        spc = spc_for_chunk.get(chunk_num, 0)
        pos = chunk_offsets[chunk_num - 1]
        for _ in range(spc):
            if sample_idx >= n:
                break
            sz = sizes[sample_idx]
            offsets.append((pos, sz))
            pos += sz
            sample_idx += 1
        chunk_num += 1
    return offsets


def _ffmpeg_probe_avc(sps: bytes, pps: bytes, frame_nals, sei_nal=None, timeout=4):
    """Checks, via ffmpeg (must be installed and in the PATH), whether the REAL
    frame sequence of the file (the initial IDR followed by several
    P/B frames, in `frame_nals`) decodes WITHOUT ERROR with this candidate
    SPS/PPS pair. Testing SEVERAL frames (not just the IDR) is
    important: a wrong log2_max_frame_num/poc_lsb/max_num_ref_frames
    can, by coincidence, let the header of the single IDR frame
    parse without error while it is wrong, and then break all the
    P/B frames that follow (observed empirically). A "clean" decode
    (return code 0, empty stderr in -v error mode) over the whole sequence
    is therefore a far better clue than a test on the IDR alone, but still
    does not guarantee pixel-perfect rendering beyond the few
    frames tested."""
    SC = b'\x00\x00\x00\x01'
    parts = [SC + sps, SC + pps]
    if sei_nal:
        parts.append(SC + sei_nal)
    for nal in frame_nals:
        parts.append(SC + nal)
    data = b''.join(parts)
    fd, path = tempfile.mkstemp(suffix='.h264')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        try:
            r = subprocess.run(
                ['ffmpeg', '-v', 'error', '-f', 'h264', '-i', path, '-f', 'null', '-'],
                capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return r.returncode == 0 and not (r.stderr or b'').strip()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# Frame windows to VALIDATE an SPS/PPS candidate by ffmpeg decoding.
# The "quick" window (12 frames, historical behaviour) serves as a first
# filter to scan many candidates fast; but it is SHORTER
# than a GOP on most streams (keyint 50 to 250), so an
# SPS/PPS from ANOTHER encoder can decode it cleanly by coincidence and
# then break the whole file. Real case: a profile learned from a different
# encoder (first GOPs of a 1280x720 x264 stream) was accepted by the
# 12-frame window; the reconstruction then produced 7244 ffmpeg errors
# and lost 527 of the 34671 frames (corrupted blocks at every key
# frame, ~every 1.7 s), whereas the config derived from the SEI decoded the
# whole file without a single error. So we CONFIRM every candidate accepted
# by the quick window (donor, learned profile, auto detection) on a
# window covering several GOPs, calibrated on the real keyint (x264 SEI).
ORACLE_QUICK_WINDOW = 12
ORACLE_CONFIRM_TIMEOUT = 30


def _oracle_confirm_window(x264_opts):
    """Number of leading frames to decode in order to CONFIRM an SPS/PPS candidate
    accepted by the quick window (see ORACLE_QUICK_WINDOW): covers
    several GOPs starting from the real keyint read from the x264 SEI -- a wrong
    log2_max_frame_num / max_num_ref_frames often only shows up after
    a few key frames. Floor 150 (already covers the unknown-keyint case),
    ceiling 300 (bounds the cost of the confirmation decode)."""
    keyint = _x264_int_opt(x264_opts, 'keyint', 0) if x264_opts else 0
    n = max(150, keyint * 4) if keyint else 150
    return min(n, 300)


def _collect_leading_video_nals(fh, stsc_raw, stco_raw, stsz_raw, count,
                                first_sample):
    """Raw NALs (SPS/PPS/SEI/frames) of the first `count` video
    samples, in order. Falls back to the single 1st sample if the read
    fails (same behaviour as the historical call sites)."""
    try:
        out = []
        for (o, s) in resolve_leading_video_sample_offsets(
                stsc_raw, stco_raw, stsz_raw, count):
            fh.seek(o)
            out.extend(extract_nals_from_sample(fh.read(s)))
        return out
    except Exception:
        return extract_nals_from_sample(first_sample)


def _ffmpeg_probe_hevc(vps, sps, pps, oracle_nals, timeout=8):
    """HEVC equivalent of _ffmpeg_probe_avc: candidate VPS/SPS/PPS followed
    by the REAL NAL sequence of the file (`oracle_nals`, SEI and frames
    in order, see extract_hevc_nals_from_sample), decoded by ffmpeg
    as a raw HEVC stream. Clean = return code 0, empty stderr (-v error) AND
    at least one decoded frame per frame in the stream. As in H.264, a
    wrong SPS often lets the key frame decode on its own but breaks the
    following frames ("Could not find ref with POC ..."), hence the test on
    several frames. Wider timeout than in H.264: HEVC frames from such
    captures (3200x1600 and above) are heavy to decode."""
    SC = b'\x00\x00\x00\x01'
    body = [nal for (t, nal) in oracle_nals if t not in (32, 33, 34)]
    # a frame may hold several slices: we count the VCL NALs whose
    # first_slice_segment_in_pic_flag (1st bit after the header) is 1
    n_frames = sum(1 for (t, nal) in oracle_nals
                   if t < 32 and len(nal) > 2 and nal[2] & 0x80)
    if not n_frames:
        return False
    parts = [SC + nal for nal in (vps, sps, pps) if nal] + [SC + nal for nal in body]
    fd, path = tempfile.mkstemp(suffix='.hevc')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(b''.join(parts))
        try:
            r = subprocess.run(
                ['ffmpeg', '-v', 'error', '-f', 'hevc', '-i', path,
                 '-f', 'framemd5', '-'],
                capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return False
        if r.returncode != 0 or (r.stderr or b'').strip():
            return False
        decoded = sum(1 for line in (r.stdout or b'').splitlines()
                      if line and not line.startswith(b'#'))
        return decoded >= n_frames
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# Common resolutions tried by automatic detection, in a reasonable priority
# order (16:9 first, from the most common to the rarest for
# streaming video). 1920x1080 is placed first: it is by
# far the most widespread resolution for this kind of content.
COMMON_VIDEO_RESOLUTIONS = [
    (1920, 1080), (1280, 720), (960, 540), (1280, 960), (1024, 768),
    (854, 480), (1024, 576), (800, 450), (640, 480), (640, 360),
    (720, 480), (720, 404), (576, 324), (480, 270),
    (2560, 1440), (3840, 2160),
]


def profile_dims_by_frequency(profile_dir):
    """Returns the (width, height) pairs ALREADY SEEN in the SPS/PPS
    profile store (--seed-profiles / automatic learning over successive
    reconstructions), sorted from most to least frequent (sum of the
    counters of the profiles sharing that resolution). Used to
    prioritize automatic resolution detection on the formats actually
    used in the corpus rather than on a generic list of common
    resolutions."""
    counts = {}
    for entry in load_profile_store(profile_dir):
        if profile_codec(entry) != 'avc':
            continue
        w = entry.get('width')
        h = entry.get('height')
        if not (w and h):
            continue
        try:
            key = (int(w), int(h))
        except (TypeError, ValueError):
            continue
        counts[key] = counts.get(key, 0) + int(entry.get('count', 1) or 1)
    return [dims for dims, _ in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]


def _x264_ref_hint(x264_opts):
    """Returns max_num_ref_frames as ACTUALLY used by
    the encoder (read in the clear from the x264 SEI -- 'ref=N'), if available.
    To be tested FIRST (see auto_detect_avc_generic_params) rather than
    guessing that value blindly."""
    try:
        return int(x264_opts.get('ref'))
    except (TypeError, ValueError, AttributeError):
        return None


def _x264_int_opt(x264_opts, key, default):
    try:
        return int((x264_opts or {}).get(key, default))
    except (ValueError, TypeError):
        return default


def _x264_poc_type(x264_opts):
    """pic_order_cnt_type as chosen by x264 (encoder/set.c): 0 if there
    are B-frames or interlacing, 2 otherwise. Without an x264 SEI (unknown
    options), 0 -- the most common case outside x264."""
    if not x264_opts or 'bframes' not in x264_opts:
        return 0
    if _x264_int_opt(x264_opts, 'bframes', 0) > 0:
        return 0
    if _x264_int_opt(x264_opts, 'interlaced', 0) > 0:
        return 0
    return 2


def _x264_sps_guesses(x264_opts, default_keyint=250):
    """(log2_max_frame_num, log2_max_pic_order_cnt_lsb) pairs to try,
    from most to least likely, based on the options read from the x264 SEI.

    1) Formula of recent x264 (encoder/set.c): frame_num is sized
       on the number of reference frames (ref, B-frame
       reordering, pyramid), NOT on keyint -- often only 4 bits;
       the POC on the maximum delta between frames (bframes, pyramid).
    2) Old formula (old x264) based on keyint_max, kept as
       a fallback.
    These are only starting points: the wide pass explores around them."""
    o = x264_opts or {}
    bframes = _x264_int_opt(o, 'bframes', 0)
    pyramid = 1 if _x264_int_opt(o, 'b_pyramid', 0) and bframes > 1 else 0
    ref = _x264_int_opt(o, 'ref', 1)
    reorder = (2 if pyramid else 1) if bframes else 0
    num_ref = min(16, max(ref, 1 + reorder, 4 if pyramid else 1))
    max_frame_num = num_ref * (pyramid + 1) + 1
    f_new = 4
    while (1 << f_new) <= max_frame_num:
        f_new += 1
    max_delta_poc = (bframes + 2) * (pyramid + 1) * 2
    p_new = 4
    while (1 << p_new) <= max_delta_poc * 2:
        p_new += 1

    keyint = _x264_int_opt(o, 'keyint', default_keyint)
    f_old = 4
    while (1 << f_old) <= keyint:
        f_old += 1
    p_old = 4
    while (1 << p_old) <= keyint * 2:
        p_old += 1
    return list(dict.fromkeys([(f_new, p_new), (f_old, p_old)]))


def _x264_num_ref_frames(x264_opts):
    """max_num_ref_frames as written into the SPS by x264 (encoder/set.c):
    at least 'ref', and enough for B-frame reordering and the
    pyramid. None without an x264 SEI."""
    o = x264_opts or {}
    if 'ref' not in o:
        return None
    bframes = _x264_int_opt(o, 'bframes', 0)
    pyramid = 1 if _x264_int_opt(o, 'b_pyramid', 0) and bframes > 1 else 0
    reorder = (2 if pyramid else 1) if bframes else 0
    return min(16, max(_x264_int_opt(o, 'ref', 1), 1 + reorder, 4 if pyramid else 1))


def _x264_init_qp_guesses(x264_opts):
    """pic_init_qp_minus26 values to try, based on the rate-control mode
    read from the SEI. x264 writes the crf value (integer part) in CRF and
    the qp value in CQP; in ABR/CBR/2-pass it is not deducible
    (scan from 0 to -12). With
    CABAC, a wrong initial QP corrupts the context initialisation and
    the whole frame decodes wrongly (real case: crf=22, only -4
    works); with CAVLC it has no effect on decoding."""
    o = x264_opts or {}
    rc = o.get('rc', '')
    vals = []
    try:
        if rc == 'crf' and 'crf' in o:
            crf = float(o['crf'])
            vals = [int(crf) - 26, int(round(crf)) - 26]
        elif rc == 'cqp' and 'qp' in o:
            vals = [int(float(o['qp'])) - 26]
        elif rc in ('abr', 'cbr', '2pass'):
            # The value written into the PPS is not deducible from the SEI (real
            # case: rc=2pass, only -6 works): 0 first, then a scan.
            vals = [0] + list(range(-1, -13, -1))
    except ValueError:
        vals = []
    vals = [max(-26, min(25, v)) for v in vals]
    return list(dict.fromkeys(vals)) if vals else [0]


def _ffmpeg_concealed_mbs(sps, pps, idr_nals, sei_nal=None, timeout=8):
    """Decodes the single IDR frame (its slices, in `idr_nals`) with this
    SPS/PPS and returns the number of macroblocks ffmpeg had to CONCEAL
    (message 'concealing N DC ...'), i.e. those of the grid that the
    slices did not cover; 0 if no message, None on failure."""
    SC = b'\x00\x00\x00\x01'
    data = (SC + sps + SC + pps + (SC + sei_nal if sei_nal else b'')
            + b''.join(SC + n for n in idr_nals))
    fd, path = tempfile.mkstemp(suffix='.h264')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        try:
            r = subprocess.run(
                ['ffmpeg', '-v', 'info', '-threads', '1', '-f', 'h264', '-i', path,
                 '-f', 'null', '-'], capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return None
        m = re.search(rb'concealing (\d+) DC', r.stderr or b'')
        return int(m.group(1)) if m else 0
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _x264_default_f_p(x264_opts, default_keyint=250):
    """Most likely (log2_max_frame_num, log2_max_poc_lsb) pair (see
    _x264_sps_guesses)."""
    return _x264_sps_guesses(x264_opts, default_keyint)[0]


def _avc_geometry_scan(frame_nals, sei_nal, x264_opts, fp_guesses, poc_type,
                       ref, qp_guesses, max_seconds, tall_rows=136, max_mb_w=240):
    """Recovers width AND height without a resolution list (see the call
    in auto_detect_avc_generic_params). Returns (width, height,
    log2_max_frame_num, log2_max_poc_lsb, pic_init_qp_minus26, trials) or
    None."""
    t0 = time.time()
    tests = 0
    idr_nals = []
    for nal in frame_nals:
        if (nal[0] & 0x1F) != 5:
            break
        idr_nals.append(nal)
    if not idr_nals:
        return None
    for qp in qp_guesses:
        pps = build_fake_avc_pps(x264_opts, qp_minus26=qp)
        for (f, p) in fp_guesses:
            def sps_for(w, h):
                return build_fake_avc_sps(w, h, log2_max_frame_num=f,
                                          log2_max_poc_lsb=p,
                                          max_num_ref_frames=ref,
                                          poc_type=poc_type)
            widths = []
            for mb_w in range(8, max_mb_w + 1):
                if time.time() - t0 > max_seconds:
                    log(f"  [auto-detection resolution] geometric scan: "
                        f"time budget ({max_seconds}s) reached after "
                        f"{tests} trials, giving up.")
                    return None
                tests += 1
                if _ffmpeg_probe_avc(sps_for(mb_w * 16, tall_rows * 16), pps,
                                     frame_nals, sei_nal):
                    widths.append(mb_w)
            for mb_w in widths[:4]:
                n = _ffmpeg_concealed_mbs(sps_for(mb_w * 16, tall_rows * 16), pps,
                                          idr_nals, sei_nal)
                real = mb_w * tall_rows - (n or 0)
                # n == 0: the frame is at least as tall as the grid
                if not n or real <= 0 or real % mb_w:
                    continue
                w, h = mb_w * 16, (real // mb_w) * 16
                if h == 1088:
                    h = 1080  # standard 1080p crop (68 rows)
                tests += 1
                if _ffmpeg_probe_avc(sps_for(w, h), pps, frame_nals, sei_nal):
                    return w, h, f, p, qp, tests
    return None


def auto_detect_avc_generic_params(nals, x264_opts, width_hint=None,
                                     height_hint=None, max_seconds=90,
                                     profile_dir=None, brute_force=False,
                                     resolution_lock=False, extra_fp_guesses=None,
                                     auto_extend_budget=1):
    """Attempts to recover AUTOMATICALLY (width, height,
    log2_max_frame_num, log2_max_pic_order_cnt_lsb, max_num_ref_frames,
    pic_init_qp_minus26) when the original SPS/PPS is lost (never
    repeated in the stream), by generating candidates and checking via
    ffmpeg whether the REAL frame sequence (IDR + several P/B, in
    `nals` -- see resolve_leading_video_sample_offsets +
    extract_nals_from_sample) decodes cleanly with each of them (see
    _ffmpeg_probe_avc). Testing several frames (not just the IDR) is
    important: a wrong parameter can, by coincidence, let
    the header of the single IDR frame parse without error while it is
    wrong, and then break all the P/B frames that follow (observed
    empirically). EXPERIMENTAL: a clean decode over the few
    frames tested is a strong clue, not an absolute proof beyond them.
    Returns a dict {'width', 'height', 'log2_max_frame_num',
    'log2_max_poc_lsb', 'max_num_ref_frames', 'pic_init_qp_minus26',
    'tested', 'elapsed'}, or None if nothing conclusive was found within
    the allotted time budget (or if ffmpeg is not available, or
    if no IDR NAL was found).

    resolution_lock=True (requires width_hint/height_hint): the
    resolution is no longer a merely PRIORITY candidate among the full
    list (common + already encountered), it becomes the ONLY
    resolution tested -- in the quick pass as well as in the wide pass.
    Useful when width_hint/height_hint are known with certainty (for
    example via a source external to the file): the wide pass then drops
    from tens of thousands of trials (all resolutions x all
    parameters) to a few hundred (a single resolution x all
    parameters), hence well within the default time
    budget.

    auto_extend_budget (default 1): number of automatic extensions of the
    budget, granted to the quick pass as well as to the geometric scan when
    `max_seconds` is reached. One extension targets 480 s (or 4x the requested
    budget if that is larger), capped at 900 s: a file
    declared unrecoverable at 90 s can therefore be recovered without intervention
    (real case: 656x480 found at ~285 s)."""
    if shutil.which('ffmpeg') is None:
        log("  [auto-detection resolution] ffmpeg not found in the PATH: "
            "automatic detection disabled (install ffmpeg, or specify "
            "--width/--height manually).")
        return None
    sei_nal = next((nal for (t, nal) in nals if t == 6), None)
    frame_nals = [nal for (t, nal) in nals if t in (5, 1)]
    if not frame_nals or (frame_nals[0][0] & 0x1F) != 5:
        log("  [auto-detection resolution] no IDR frame found in the "
            "first samples: automatic detection impossible.")
        return None

    candidates = list(COMMON_VIDEO_RESOLUTIONS)
    if profile_dir:
        profile_dims = profile_dims_by_frequency(profile_dir)
        if profile_dims:
            common_set = set(COMMON_VIDEO_RESOLUTIONS)
            profile_set = set(profile_dims)
            # already seen in the store -> first, in their real
            # frequency order (whether they are already in the generic
            # list or not); the rest of the generic list follows,
            # in its original order.
            candidates = profile_dims + [c for c in candidates if c not in profile_set]
            new_ones = [d for d in profile_dims if d not in common_set]
            if new_ones:
                log(f"  [auto-detection resolution] {len(new_ones)} "
                    f"resolution(s) from the profile store (already "
                    f"encountered in other files) added and "
                    f"tested in priority: " +
                    ', '.join(f'{w}x{h}' for w, h in new_ones[:12]) +
                    ('...' if len(new_ones) > 12 else ''))
    if width_hint and height_hint:
        pair = (width_hint, height_hint)
        if pair in candidates:
            candidates.remove(pair)
        candidates.insert(0, pair)

    if resolution_lock:
        if not (width_hint and height_hint):
            log("  [auto-detection resolution] --resolution-lock ignored: "
                "--width/--height were not supplied (nothing to lock).")
        else:
            candidates = [(width_hint, height_hint)]
            log(f"  [auto-detection resolution] --resolution-lock active: "
                f"scan limited to {width_hint}x{height_hint} only "
                f"(the other candidate resolutions will not be tested).")

    fp_guesses = _x264_sps_guesses(x264_opts)
    if extra_fp_guesses:
        # Additional pairs to try AFTER those derived from the x264 SEI
        # (see MKV_UNKNOWN_ENCODER_FP_GUESSES): used by containers
        # whose header is in the encrypted zone and which have NO x264 SEI
        # in the clear, hence whose encoder is unknown. The historical order is
        # preserved, so no previously winning candidate changes rank.
        fp_guesses = list(dict.fromkeys(list(fp_guesses) + list(extra_fp_guesses)))
    def_f, def_p = fp_guesses[0]
    poc_type = _x264_poc_type(x264_opts)
    ref_hint = _x264_ref_hint(x264_opts)
    qp_guesses = _x264_init_qp_guesses(x264_opts)
    x264_num_ref = _x264_num_ref_frames(x264_opts)

    t0 = time.time()
    tested = 0

    # Time budget, with AUTOMATIC EXTENSION: the quick pass may
    # exceed the requested budget without that meaning the resolution is
    # unrecoverable (real case: a 656x480 file that needed ~285 s while
    # the default budget is 90 s -- it had been declared unrecoverable
    # at 90 s). So we consume `auto_extend_budget` extensions (one by
    # default: target 480 s, ceiling 900 s) instead of giving up.
    budget = float(max_seconds)
    extensions_left = max(0, int(auto_extend_budget))

    def budget_used():
        """True if the current budget is exceeded AND no extension
        is available."""
        nonlocal budget, extensions_left
        if time.time() - t0 <= budget:
            return False
        if extensions_left <= 0:
            return True
        extensions_left -= 1
        old = budget
        # Target: at least 480 s (the real 656x480 case needed ~370 s of
        # detection), at most 900 s so as not to overspend on a file whose
        # starting budget is already large.
        budget = min(max(budget * 4.0, 480.0), 900.0)
        log(f"  [auto-detection resolution] budget of {old:.0f}s reached "
            f"after {tested} trials: AUTOMATIC EXTENSION up to "
            f"{budget:.0f}s ({extensions_left} extension(s) left).")
        return False

    def try_one(w, h, f, p, ref, qp):
        nonlocal tested
        tested += 1
        sps = build_fake_avc_sps(w, h, log2_max_frame_num=f, log2_max_poc_lsb=p,
                                  max_num_ref_frames=ref, poc_type=poc_type)
        pps = build_fake_avc_pps(x264_opts, qp_minus26=qp)
        return _ffmpeg_probe_avc(sps, pps, frame_nals, sei_nal)

    def make_result(w, h, f, p, ref, qp):
        return {'width': w, 'height': h, 'log2_max_frame_num': f,
                'log2_max_poc_lsb': p, 'poc_type': poc_type,
                'max_num_ref_frames': ref,
                'pic_init_qp_minus26': qp, 'tested': tested,
                'elapsed': time.time() - t0}

    ref_note = f", ref={ref_hint} (read from the x264 SEI)" if ref_hint else ""
    poc_note = (f"pic_order_cnt_type=2 (bframes=0: no POC in the slices)"
                if poc_type == 2 else f"pic_order_cnt_type=0")
    log(f"  [auto-detection resolution] searching among {len(candidates)} "
        f"common resolutions (ffmpeg as decoding oracle on "
        f"{len(frame_nals)} frames) -- settings guessed from the x264 SEI: "
        f"{poc_note}, (log2_max_frame_num, log2_max_poc_lsb) among "
        f"{fp_guesses}, pic_init_qp_minus26 among {qp_guesses}"
        f"{ref_note}...")

    # Quick pass: settings derived from the x264 SEI on each candidate
    # resolution. When the SEI gives the number of references, we limit ourselves to
    # the value written by x264 into the SPS (and to 'ref' itself); otherwise,
    # a few common values.
    if ref_hint:
        ref_candidates_fast = list(dict.fromkeys(
            [r for r in (x264_num_ref, ref_hint) if r]))
    else:
        ref_candidates_fast = [1, 2, 3, 4, 6]
    fast_combos = [(f, p, ref, qp) for qp in qp_guesses for (f, p) in fp_guesses
                   for ref in ref_candidates_fast]
    fast_pass_exhausted = True
    for (w, h) in candidates:
        if budget_used():
            fast_pass_exhausted = False
            break
        for (f, p, ref, qp) in fast_combos:
            if budget_used():
                fast_pass_exhausted = False
                break
            if try_one(w, h, f, p, ref, qp):
                hint_note = " -- read from the x264 SEI" if ref == ref_hint else ""
                log(f"  [auto-detection resolution] found: {w}x{h} "
                    f"(log2_max_frame_num={f}, log2_max_poc_lsb={p}, "
                    f"pic_order_cnt_type={poc_type}, ref={ref}{hint_note}, "
                    f"pic_init_qp_minus26={qp}, {tested} trials, "
                    f"{time.time()-t0:.1f}s)")
                return make_result(w, h, f, p, ref, qp)
        else:
            continue
        break

    # Geometric pass: the resolution is in no list (real case:
    # vertical 416x720 video named "720P_..."). With the right settings,
    # only the REAL width (in macroblocks) decodes cleanly, including
    # inside a grid taller than the frame: intra prediction and the
    # entropy contexts depend on the left/top neighbours, hence on the
    # width. The height is then read from the IDR alone: ffmpeg conceals the
    # grid macroblocks that the slice does not cover, and the concealed
    # count directly gives the number of real rows. Dedicated time
    # budget (the quick pass may have consumed its own).
    if fast_pass_exhausted and (w_found := _avc_geometry_scan(
            frame_nals, sei_nal, x264_opts, fp_guesses, poc_type,
            ref_candidates_fast[0], qp_guesses, budget)):
        w, h, f, p, qp, n_tests = w_found
        tested += n_tests
        log(f"  [auto-detection resolution] found by geometric scan: "
            f"{w}x{h} (log2_max_frame_num={f}, log2_max_poc_lsb={p}, "
            f"pic_order_cnt_type={poc_type}, ref={ref_candidates_fast[0]}, "
            f"pic_init_qp_minus26={qp}, {tested} trials, "
            f"{time.time()-t0:.1f}s)")
        return make_result(w, h, f, p, ref_candidates_fast[0], qp)

    if not fast_pass_exhausted:
        log(f"  [auto-detection resolution] time budget ({budget:.0f}s, "
            f"extensions included) reached during the quick pass, after "
            f"{tested} trials -- giving up (rerun with "
            f"--auto-resolution-timeout higher to go further).")
        return None

    if not brute_force:
        log(f"  [auto-detection resolution] no conclusive candidate among "
            f"the {tested} trials of the quick pass (default settings "
            f"only) in {time.time()-t0:.1f}s. The wide pass (combinatorial "
            f"scan, far more expensive and not guaranteed to succeed) "
            f"was NOT attempted -- rerun with --brute-force-resolution "
            f"(and possibly a high --auto-resolution-timeout) to "
            f"try it explicitly.")
        return None

    # Wide pass (optional, --brute-force-resolution): scan of
    # log2_max_frame_num / log2_max_poc_lsb (around the guessed
    # starting point) / max_num_ref_frames / initial QP, within the
    # remaining time budget. When the REAL max_num_ref_frames is known (ref_hint, read
    # in the clear from the x264 SEI), it is no longer scanned at all (cost per
    # resolution divided by ~8): this makes it possible to cover ALL
    # candidate resolutions rather than only the 3 most likely,
    # useful when the right resolution is not among those already seen
    # in the profile store. Without ref_hint (non-x264 stream, or unreadable
    # SEI), we fall back to the previous compromise (3 resolutions, ref
    # scanned from 1 to 8) to stay within a reasonable time budget.
    if ref_hint:
        # reliable ref_hint (real SEI) -> the frame_num/POC starting points,
        # computed from the SAME x264 options, are too:
        # margin tightened to +/-1 rather than +/-3 (49x cheaper), so as to
        # be able to cover ALL candidate resolutions within the
        # time budget instead of stopping halfway.
        margin = 1
        ref_candidates_large = [ref_hint]
        large_pass_candidates = candidates
    else:
        margin = 3
        ref_candidates_large = list(range(1, 9))
        large_pass_candidates = candidates[:3]
    # around EACH starting point (recent and old x264 formula)
    f_range = sorted({v for (f0, _) in fp_guesses
                      for v in range(max(4, f0 - margin), min(16, f0 + margin) + 1)})
    if poc_type == 2:
        p_range = [def_p]  # irrelevant: no POC field in the slices
    else:
        p_range = sorted({v for (_, p0) in fp_guesses
                          for v in range(max(4, p0 - margin), min(16, p0 + margin) + 1)})
    log(f"  [auto-detection resolution] wide pass: {len(large_pass_candidates)} "
        f"resolution(s) x {len(f_range)}x{len(p_range)} combinations "
        f"frame_num/poc_lsb x {len(ref_candidates_large)} value(s) of "
        f"max_num_ref_frames" +
        (f" (ref={ref_hint}, known -- not scanned)" if ref_hint else " (guessed, scanned)") +
        f" x 17 QP...")
    for (w, h) in large_pass_candidates:
        for f in f_range:
            for p in p_range:
                for ref in ref_candidates_large:
                    for qp in range(-8, 9):
                        if time.time() - t0 > max_seconds:
                            log(f"  [auto-detection resolution] time "
                                f"budget ({max_seconds}s) reached after "
                                f"{tested} trials, giving up.")
                            return None
                        if try_one(w, h, f, p, ref, qp):
                            log(f"  [auto-detection resolution] found: "
                                f"{w}x{h} log2_max_frame_num={f} "
                                f"log2_max_poc_lsb={p} max_num_ref_frames="
                                f"{ref} pic_init_qp_minus26={qp} "
                                f"({tested} trials, {time.time()-t0:.1f}s)")
                            return make_result(w, h, f, p, ref, qp)

    log(f"  [auto-detection resolution] no conclusive candidate among "
        f"{tested} trials in {time.time()-t0:.1f}s (on {len(frame_nals)} "
        f"frames tested each time): the real resolution is "
        f"probably not in the tested list, or other parameters of the "
        f"stream differ from the original. The file may only be "
        f"recoverable at the keyframe (IDR) level, not frame by "
        f"frame.")
    return None


# --------------------------------------------------------------------------
# MPEG-4 Part 2 ('mp4v': Xvid, DivX, mpeg4 from libavcodec) -- CASE B
# --------------------------------------------------------------------------
# The samples are raw VOPs (start codes 00 00 01 B3/B6); the
# config (VOL: width, height, time base, coding flags) lives
# only in the original esds, lost with the rest of the encrypted moov. We
# resynthesise it and ffmpeg serves as the oracle, as for H.264.

_MPEG4_VISUAL_START_CODES = (b'\x00\x00\x01\xb0', b'\x00\x00\x01\xb3',
                              b'\x00\x00\x01\xb6')
_MPEG4_TIME_RES_PREFERRED = [25, 30, 24, 15, 12, 10, 20, 50, 60, 100, 1000,
                              25000, 30000, 24000, 15000, 12500, 10000,
                              12000, 50000, 60000]
# (interlaced, mpeg_quant, quarter_sample, resync_disable, vo_ver_id,
#  vo_type, vol_control_parameters): libavcodec default settings
# first (simple profile, then advanced simple), then common variants.
_MPEG4_VOL_VARIANTS = [
    (0, 0, 0, 1, 1, 1, 0), (0, 0, 0, 1, 5, 17, 0), (0, 0, 1, 1, 5, 17, 0),
    (0, 0, 0, 0, 1, 1, 0), (1, 0, 0, 1, 1, 1, 0), (1, 0, 0, 1, 5, 17, 0),
    (0, 1, 0, 1, 1, 1, 0), (0, 1, 0, 1, 5, 17, 0), (0, 0, 0, 1, 1, 1, 1),
    (0, 0, 0, 1, 5, 17, 1), (0, 0, 0, 0, 5, 17, 0), (1, 1, 0, 1, 5, 17, 0),
]


def looks_like_mpeg4_part2(sample: bytes) -> bool:
    """First video sample that starts with an MPEG-4
    Part 2 start code (and contains a VOP) -- and whose first 4 bytes are not
    simply the length of an AVC NAL (a chain of lengths that lands
    exactly on the end of the sample)."""
    if sample[:4] not in _MPEG4_VISUAL_START_CODES:
        return False
    if sample.find(b'\x00\x00\x01\xb6', 0, 65536) < 0:
        return False
    pos = 0
    while pos + 4 <= len(sample):
        n = int.from_bytes(sample[pos:pos + 4], 'big')
        if n == 0 or pos + 4 + n > len(sample):
            return True
        pos += 4 + n
    return pos != len(sample)


def _mpeg4_time_bits_candidates(sample: bytes):
    """Number of bits of the vop_time_increment field, read from the header of
    the first VOP: an intra VOP at the start of a file has a null increment, so
    the zeros before the marker bit give its width. The other coherent
    values (marker bit at 1 after N bits) follow, in ascending order."""
    i = sample.find(b'\x00\x00\x01\xb6')
    if i < 0:
        return []
    bits = ''.join(f'{b:08b}' for b in sample[i + 4:i + 4 + 12])
    pos = 2
    while pos < len(bits) and bits[pos] == '1':
        pos += 1
    pos += 1
    if pos >= len(bits) or bits[pos] != '1':
        return []
    pos += 1
    cands = [n for n in range(1, 17) if pos + n < len(bits) and bits[pos + n] == '1']
    first_one = bits.find('1', pos)
    if first_one - pos >= 1 and (first_one - pos) in cands:
        cands.remove(first_one - pos)
        cands.insert(0, first_one - pos)
    return cands


def _mpeg4_time_res_for_bits(nbits: int) -> int:
    for r in _MPEG4_TIME_RES_PREFERRED:
        if max(1, (r - 1).bit_length()) == nbits:
            return r
    return (1 << (nbits - 1)) + 1


def build_mpeg4_vol(width, height, time_res, interlaced=0, mpeg_quant=0,
                     quarter_sample=0, resync_disable=1, ver_id=1, vo_type=1,
                     control_params=0):
    """Video Object Layer (ISO 14496-2 6.2.3), as written by the mpeg4
    encoder of libavcodec, start code 00 00 01 20 included."""
    bw = BitWriter()
    bw.u(0x120, 32)
    bw.u(0, 1)                      # random_accessible_vol
    bw.u(vo_type, 8)
    bw.u(1, 1); bw.u(ver_id, 4); bw.u(1, 3)   # is_object_layer_identifier
    bw.u(1, 4)                      # aspect_ratio_info: square
    if control_params:
        bw.u(1, 1); bw.u(1, 2); bw.u(1, 1); bw.u(0, 1)
    else:
        bw.u(0, 1)
    bw.u(0, 2); bw.u(1, 1)          # rectangular shape, marker
    bw.u(time_res, 16); bw.u(1, 1); bw.u(0, 1); bw.u(1, 1)
    bw.u(width, 13); bw.u(1, 1); bw.u(height, 13); bw.u(1, 1)
    bw.u(interlaced, 1)
    bw.u(1, 1)                      # obmc_disable
    bw.u(0, 1 if ver_id == 1 else 2)   # sprite_enable
    bw.u(0, 1)                      # not_8_bit
    bw.u(mpeg_quant, 1)
    if mpeg_quant:
        bw.u(0, 1); bw.u(0, 1)      # default matrices
    if ver_id != 1:
        bw.u(quarter_sample, 1)
    bw.u(1, 1)                      # complexity_estimation_disable
    bw.u(resync_disable, 1)
    bw.u(0, 1)                      # data_partitioning
    if ver_id != 1:
        bw.u(0, 1); bw.u(0, 1)      # newpred, reduced_resolution_vop
    bw.u(0, 1)                      # scalability
    bw.bits.append(0)               # stuffing: 0 then ones up to the byte
    while len(bw.bits) % 8:
        bw.bits.append(1)
    return bw.to_bytes()


def build_mpeg4_decoder_config(vol: bytes) -> bytes:
    """Visual Object Sequence + Visual Object + Video Object + VOL, as
    expected in DecoderSpecificInfo of the esds."""
    return (b'\x00\x00\x01\xb0\xf5' + b'\x00\x00\x01\xb5\x09' +
            b'\x00\x00\x01\x00' + vol)


def build_esds_mpeg4(dsi: bytes) -> bytes:
    def desc(tag, payload):
        n = len(payload)
        return bytes([tag, 0x80 | ((n >> 21) & 0x7f), 0x80 | ((n >> 14) & 0x7f),
                      0x80 | ((n >> 7) & 0x7f), n & 0x7f]) + payload
    dcd = desc(4, bytes([0x20, 0x11]) + b'\x00\x00\x00' + struct.pack(">II", 0, 0)
               + desc(5, dsi))
    es = desc(3, struct.pack(">HB", 1, 0) + dcd + desc(6, b'\x02'))
    return box(b'esds', b'\x00\x00\x00\x00' + es)


def _ffmpeg_probe_mpeg4(dsi: bytes, samples: bytes, timeout=20):
    """True if the file's samples decode WITHOUT ANY error
    (return code 0, empty stderr in -v error) with this candidate config."""
    fd, path = tempfile.mkstemp(suffix='.m4v')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(dsi + samples)
        try:
            r = subprocess.run(
                ['ffmpeg', '-v', 'error', '-f', 'm4v', '-i', path, '-f', 'null', '-'],
                capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return r.returncode == 0 and not (r.stderr or b'').strip()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def recover_mpeg4_part2_config(fh, first_sample, stsc_raw, stco_raw, stsz_raw,
                                width_hint=None, height_hint=None,
                                auto_resolution=True, max_seconds=90,
                                profile_dir=None, sample_window=12):
    """CASE B, MPEG-4 Part 2 stream whose VOL (original esds) is lost.
    Returns (is_mpeg4, result): is_mpeg4 says that the stream was recognised
    (the H.264 cascade is then skipped); result = None or dict {'width',
    'height', 'time_res', 'time_bits', 'variant', 'dsi', 'tested',
    'elapsed'}."""
    if not looks_like_mpeg4_part2(first_sample):
        return False, None
    log("  MPEG-4 Part 2 video stream (mp4v: Xvid/DivX/libavcodec) detected, "
        "without its config (VOL): resynthesis, ffmpeg as decoding oracle.")
    if not auto_resolution:
        log("  automatic detection disabled (--no-auto-resolution).")
        return True, None
    if shutil.which('ffmpeg') is None:
        log("  ffmpeg not found in the PATH: detection impossible.")
        return True, None

    try:
        stream = b''
        for (o, s) in resolve_leading_video_sample_offsets(
                stsc_raw, stco_raw, stsz_raw, sample_window):
            fh.seek(o)
            stream += fh.read(s)
    except Exception:
        stream = first_sample
    if not stream:
        stream = first_sample

    time_bits = _mpeg4_time_bits_candidates(first_sample) or [5, 15, 10, 4, 6, 3, 8, 16]
    candidates = list(COMMON_VIDEO_RESOLUTIONS)
    if profile_dir:
        profile_dims = profile_dims_by_frequency(profile_dir)
        if profile_dims:
            profile_set = set(profile_dims)
            candidates = profile_dims + [c for c in candidates if c not in profile_set]
    if width_hint and height_hint:
        pair = (width_hint, height_hint)
        if pair in candidates:
            candidates.remove(pair)
        candidates.insert(0, pair)

    t0 = time.time()
    tested = 0
    log(f"  [auto-detection MPEG-4] {len(candidates)} candidate resolutions, "
        f"likely vop_time_increment_bits: {time_bits[:4]}...")
    for vi, variant in enumerate(_MPEG4_VOL_VARIANTS):
        interlaced, mpeg_quant, quarter, resync_dis, ver_id, vo_type, ctrl = variant
        nbits_list = time_bits if vi == 0 else time_bits[:1]
        for (w, h) in candidates:
            for nbits in nbits_list:
                if time.time() - t0 > max_seconds:
                    log(f"  [auto-detection MPEG-4] time budget ({max_seconds}s) "
                        f"reached after {tested} trials, giving up.")
                    return True, None
                res = _mpeg4_time_res_for_bits(nbits)
                dsi = build_mpeg4_decoder_config(build_mpeg4_vol(
                    w, h, res, interlaced, mpeg_quant, quarter, resync_dis,
                    ver_id, vo_type, ctrl))
                tested += 1
                if _ffmpeg_probe_mpeg4(dsi, stream):
                    log(f"  [auto-detection MPEG-4] found: {w}x{h} "
                        f"(vop_time_increment_bits={nbits}, VOL variant #{vi}, "
                        f"{tested} trials, {time.time()-t0:.1f}s)")
                    return True, {'width': w, 'height': h, 'time_res': res,
                                  'time_bits': nbits, 'variant': vi, 'dsi': dsi,
                                  'tested': tested, 'elapsed': time.time() - t0}
    log(f"  [auto-detection MPEG-4] no conclusive candidate among {tested} "
        f"trials in {time.time()-t0:.1f}s.")
    return True, None


def mpeg4_failure_message(auto_resolution):
    return ("MPEG-4 Part 2 (mp4v) video stream whose config (VOL) was in "
            "the original esds, lost in the encrypted zone. " +
            ("No tested resolution/flag combination decodes cleanly "
             "the first frames: the resolution may not be among "
             "those tested (try --width/--height). "
             if auto_resolution else "Automatic detection disabled. ") +
            "Neither donors (--sps-pps-from) nor the profile store "
            "apply to this codec.")


# ------------------------------------------------------------- Audio sniffing
# AC3/DTS/MP3 are self-describing (sync word + fixed header repeated in
# every frame): unlike AAC/Opus/Vorbis/FLAC (which need a lost
# CodecPrivate), they are detected and configured WITHOUT any info
# from the original container.

def sniff_ac3(frame: bytes):
    if len(frame) < 8 or frame[0] != 0x0B or frame[1] != 0x77:
        return None
    fscod = (frame[4] >> 6) & 0x3
    rates = {0: 48000, 1: 44100, 2: 32000}
    sr = rates.get(fscod)
    if sr is None:
        return None
    acmod = frame[6] >> 5
    ch_table = {0: 2, 1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 4, 7: 5}
    ch = ch_table.get(acmod, 6)
    return {'codec_id': 'A_AC3', 'sampling_freq': sr, 'channels': ch}


def sniff_dts(frame: bytes):
    if len(frame) < 12 or frame[0:4] != b'\x7f\xfe\x80\x01':
        return None
    br = BitReader(frame[4:])
    br.u(1); br.u(5); br.u(1); br.u(7); br.u(14)
    amode = br.u(6)
    sfreq = br.u(4)
    sfreq_table = {1: 8000, 2: 16000, 3: 32000, 6: 11025, 7: 22050, 8: 44100,
                   11: 12000, 12: 24000, 13: 48000, 14: 96000, 15: 192000}
    amode_ch = {0: 1, 1: 2, 2: 2, 3: 2, 4: 2, 5: 3, 6: 3, 7: 4, 8: 4, 9: 5}
    sr = sfreq_table.get(sfreq, 48000)
    ch = amode_ch.get(amode, 6)
    return {'codec_id': 'A_DTS', 'sampling_freq': sr, 'channels': ch}


def sniff_mp3(frame: bytes):
    if len(frame) < 4 or frame[0] != 0xFF or (frame[1] & 0xE0) != 0xE0:
        return None
    version_bits = (frame[1] >> 3) & 0x3
    layer_bits = (frame[1] >> 1) & 0x3
    if layer_bits != 0x1:
        return None
    sr_bits = (frame[2] >> 2) & 0x3
    sr_table = {
        0x3: {0: 44100, 1: 48000, 2: 32000},
        0x2: {0: 22050, 1: 24000, 2: 16000},
        0x0: {0: 11025, 1: 12000, 2: 8000},
    }.get(version_bits)
    if not sr_table or sr_bits not in sr_table:
        return None
    sr = sr_table[sr_bits]
    channel_mode = (frame[3] >> 6) & 0x3
    ch = 1 if channel_mode == 3 else 2
    return {'codec_id': 'A_MPEG/L3', 'sampling_freq': sr, 'channels': ch}


AUDIO_SNIFFERS = [sniff_ac3, sniff_dts, sniff_mp3]


# -------------------------------------------------------------- Blocks / Cluster

def parse_mkv_block(block_data):
    """Splits a Block/SimpleBlock into (track_number, [frames]). Handles
    'fixed-size' lacing (the only one commonly used for modern audio/video);
    Xiph/EBML lacing is rare here and simply ignored (empty list) rather than
    mis-decoded."""
    tn = read_ebml_vint(block_data, 0, keep_marker=False)
    if not tn:
        return None
    track_num, tnlen = tn
    if tnlen + 3 > len(block_data):
        return None
    flags = block_data[tnlen + 2]
    lacing = (flags >> 1) & 0x3
    payload = block_data[tnlen + 3:]
    if lacing == 0:
        return track_num, [payload]
    if lacing == 2 and len(payload) >= 1:
        nframes = payload[0] + 1
        rest = payload[1:]
        if nframes <= 0 or len(rest) % nframes:
            return track_num, [payload]
        fsize = len(rest) // nframes
        return track_num, [rest[i * fsize:(i + 1) * fsize] for i in range(nframes)]
    return track_num, []


def iter_mkv_cluster_blocks(data, cluster_start, cluster_limit):
    for ch in iter_ebml_children(data, cluster_start, cluster_limit):
        block_data = None
        if ch['id'] == SIMPLEBLOCK_ID:
            block_data = data[ch['content_start']: ch['content_start'] + ch['size']]
        elif ch['id'] == BLOCKGROUP_ID:
            sub_limit = ch['content_start'] + ch['size']
            for sub in iter_ebml_children(data, ch['content_start'], sub_limit):
                if sub['id'] == BLOCK_ID:
                    block_data = data[sub['content_start']: sub['content_start'] + sub['size']]
                    break
        if block_data:
            parsed = parse_mkv_block(block_data)
            if parsed:
                yield parsed


def find_first_mkv_cluster(filepath, video_len, enc_header_len=ENC_HEADER_LEN,
                            scan_window=64 * 1024 * 1024):
    """Signature scan for the first credible Cluster (0x1F43B675) at an offset
    >= enc_header_len (unencrypted zone)."""
    with open(filepath, 'rb') as fh:
        data = fh.read(min(scan_window, video_len))
    n = len(data)
    i = enc_header_len if enc_header_len < n else n
    target = bytes([0x1F, 0x43, 0xB6, 0x75])
    while i < n - 8:
        if data[i:i + 4] == target:
            hdr = read_ebml_element(data, i)
            if hdr and (hdr['unknown'] or hdr['content_start'] + hdr['size'] <= video_len):
                return i
        i += 1
    return None


# Plausibility bounds for an H.264 SPS/PPS "found in the clear" in a Matroska
# stream (see sniff_mkv_video_avc). A real H.264 SPS is a few tens of bytes
# (at worst a few hundred with a quantisation matrix), a PPS a few tens:
# beyond that it is necessarily a false positive. Real case: a read with the
# WRONG length prefix produced a 41 667-byte "SPS", decoded into an absurd
# 2x96 resolution, and the file was reported as rebuilt although no image
# decoded (the .mkv produced contained no readable stream).
AVC_SPS_MAX_BYTES = 512
AVC_PPS_MAX_BYTES = 256


def _plausible_avc_sps(sps):
    """Minimal guard on an H.264 SPS "found in the clear": plausible size and
    dimensions. Does NOT enter the syntax (that is ffmpeg decoding's job, see
    _ffmpeg_probe_avc): only coarse false positives produced by a bad read of
    the stream are discarded."""
    if not sps or len(sps) > AVC_SPS_MAX_BYTES:
        return False
    dims = parse_sps_dimensions(sps[1:])
    if not dims:
        return False
    w, h = dims
    return 16 <= w <= 8192 and 16 <= h <= 8192 and w % 2 == 0 and h % 2 == 0


def sniff_mkv_video_avc(frames):
    """Looks for an H.264 SPS/PPS in the clear in the first frames.

    A SINGLE length-prefix hypothesis is used: the one that
    detect_mkv_video_length_size() validates on those same frames (>= 90% of
    the frames decode exactly). Trying several lengths (4 THEN 2) made NALs
    of type 7/8 appear purely by chance with the wrong hypothesis: on the real
    case that motivated this fix, reading with 2 bytes yielded ghost "SPS"/"PPS",
    hence an invalid avcC, and the file was reported as rebuilt although no
    image decoded. The pair found must additionally pass _plausible_avc_sps()."""
    length_size = detect_mkv_video_length_size(frames)
    if length_size is None:
        return None, None, None
    for frame in frames:
        pos = 0; n = len(frame)
        sps = pps = None
        while pos + length_size <= n:
            nal_len = int.from_bytes(frame[pos:pos + length_size], 'big')
            ns, ne = pos + length_size, pos + length_size + nal_len
            if nal_len <= 0 or ne > n:
                break
            t = frame[ns] & 0x1F
            if t == 7 and sps is None:
                sps = frame[ns:ne]
            elif t == 8 and pps is None:
                pps = frame[ns:ne]
            if sps and pps:
                if _plausible_avc_sps(sps) and len(pps) <= AVC_PPS_MAX_BYTES:
                    return sps, pps, length_size
                sps = pps = None  # implausible pair: keep going
            pos = ne
    return None, None, None


def _plausible_hevc_sps(sps):
    """HEVC equivalent of _plausible_avc_sps (see sniff_mkv_video_hevc)."""
    if not sps or len(sps) > 4096:
        return False
    info = parse_hevc_sps(sps)
    if not info:
        return False
    w, h = info.get('width'), info.get('height')
    return bool(w and h and 16 <= w <= 8192 and 16 <= h <= 8192)


def sniff_mkv_video_hevc(frames):
    """HEVC equivalent of sniff_mkv_video_avc: a single length-prefix
    hypothesis (the one validated by detect_mkv_video_length_size) and a
    plausibility guard on the SPS."""
    length_size = detect_mkv_video_length_size(frames)
    if length_size is None:
        return None, None, None, None
    for frame in frames:
        pos = 0; n = len(frame)
        vps = sps = pps = None
        while pos + length_size <= n:
            nal_len = int.from_bytes(frame[pos:pos + length_size], 'big')
            ns, ne = pos + length_size, pos + length_size + nal_len
            if nal_len <= 0 or ne > n:
                break
            t = (frame[ns] >> 1) & 0x3F
            if t == 32 and vps is None:
                vps = frame[ns:ne]
            elif t == 33 and sps is None:
                sps = frame[ns:ne]
            elif t == 34 and pps is None:
                pps = frame[ns:ne]
            if sps and pps:
                if _plausible_hevc_sps(sps) and len(pps) <= 1024:
                    return vps, sps, pps, length_size
                vps = sps = pps = None  # implausible pair: keep going
            pos = ne
    return None, None, None, None


def detect_mkv_video_length_size(frames):
    """Even without a visible SPS/PPS, checks whether `frames` look like
    length-prefixed H.264/H.265 (4 or 2 bytes), if only to be able to
    recognise keyframes later (NAL type 5 or 19/20/21)."""
    for length_size in (4, 2):
        ok = total = 0
        for frame in frames[:30]:
            pos = 0; n = len(frame)
            valid = True; local_count = 0
            while pos + length_size <= n:
                nal_len = int.from_bytes(frame[pos:pos + length_size], 'big')
                ne = pos + length_size + nal_len
                if nal_len <= 0 or ne > n:
                    valid = False
                    break
                pos = ne
                local_count += 1
            total += 1
            if valid and pos == n and local_count >= 1:
                ok += 1
        if total and ok / total > 0.9:
            return length_size
    return None


def scan_mkv_tracks_from_clusters(filepath, first_cluster_off, video_len,
                                   scan_bytes=12 * 1024 * 1024, max_clusters=60):
    with open(filepath, 'rb') as fh:
        fh.seek(first_cluster_off)
        data = fh.read(min(scan_bytes, video_len - first_cluster_off))
    pos = 0; n = len(data)
    frames_by_track = {}
    n_clusters = 0
    while pos < n - 8 and n_clusters < max_clusters:
        hdr = read_ebml_element(data, pos)
        if not hdr or hdr['id'] != CLUSTER_ID:
            break
        n_clusters += 1
        cstart = hdr['content_start']
        cend = cstart + hdr['size'] if not hdr['unknown'] else n
        for track_num, frames in iter_mkv_cluster_blocks(data, cstart, min(cend, n)):
            frames_by_track.setdefault(track_num, []).extend(frames)
        pos = cend
    return frames_by_track


def identify_mkv_tracks(frames_by_track):
    """For each sniffed track: tries audio (AC3/DTS/MP3), then video
    (H.264 then H.265, with or without SPS/PPS found)."""
    results = []
    for track_num, frames in sorted(frames_by_track.items()):
        if not frames:
            continue
        audio_hit = None
        for sniff in AUDIO_SNIFFERS:
            sample = [f for f in frames[:8] if len(f) > 8]
            votes = [sniff(f) for f in sample]
            votes = [v for v in votes if v]
            if sample and len(votes) >= min(3, len(sample)):
                audio_hit = votes[0]
                break
        if audio_hit:
            results.append({'track_number': track_num, 'kind': 'audio', **audio_hit})
            continue

        sps, pps, ls = sniff_mkv_video_avc(frames[:60])
        if sps and pps:
            results.append({'track_number': track_num, 'kind': 'video', 'codec': 'avc',
                             'sps': sps, 'pps': pps, 'length_size': ls,
                             'frames': frames})
            continue
        vps, sps, pps, ls = sniff_mkv_video_hevc(frames[:60])
        if sps and pps:
            results.append({'track_number': track_num, 'kind': 'video', 'codec': 'hevc',
                             'vps': vps, 'sps': sps, 'pps': pps, 'length_size': ls,
                             'frames': frames})
            continue

        ls = detect_mkv_video_length_size(frames)
        if ls:
            results.append({'track_number': track_num, 'kind': 'video_no_config',
                             'length_size': ls, 'frames': frames})
        else:
            results.append({'track_number': track_num, 'kind': 'unknown'})
    return results


def find_first_mkv_video_keyframe_cluster(filepath, first_cluster_off, video_len,
                                           video_track_number, codec, length_size,
                                           scan_bytes=96 * 1024 * 1024, max_clusters=4000):
    """Returns the absolute offset of the Cluster holding the first REAL
    keyframe (H.264 IDR type 5, or H.265 IDR/CRA type 19/20/21) of the
    identified video track. Essential: splicing on a Cluster that holds only
    the middle of a GOP (P/B frames without their reference frames) would not
    decode, even with the right codec config."""
    with open(filepath, 'rb') as fh:
        fh.seek(first_cluster_off)
        data = fh.read(min(scan_bytes, video_len - first_cluster_off))
    n = len(data)
    pos = 0
    n_clusters = 0
    while pos < n - 8 and n_clusters < max_clusters:
        hdr = read_ebml_element(data, pos)
        if not hdr or hdr['id'] != CLUSTER_ID:
            break
        cluster_abs_off = first_cluster_off + pos
        cstart = hdr['content_start']
        cend = cstart + hdr['size'] if not hdr['unknown'] else n
        for track_num, frames in iter_mkv_cluster_blocks(data, cstart, min(cend, n)):
            if track_num != video_track_number:
                continue
            for frame in frames:
                p = 0; fn = len(frame)
                while p + length_size <= fn:
                    nal_len = int.from_bytes(frame[p:p + length_size], 'big')
                    ns, ne = p + length_size, p + length_size + nal_len
                    if nal_len <= 0 or ne > fn:
                        break
                    if codec == 'avc':
                        is_kf = (frame[ns] & 0x1F) == 5
                    else:
                        is_kf = ((frame[ns] >> 1) & 0x3F) in (19, 20, 21)
                    if is_kf:
                        return cluster_abs_off
                    p = ne
        pos = cend
        n_clusters += 1
    return None


def repair_mkv(filepath, out_path, video_len, first_cluster_off, tracks, progress=None):
    """tracks: list of dicts already fully determined by the caller
    (see process_mkv_file), each with at least track_number, kind
    ('video'|'audio') and the codec_id/codec_private/width/height/
    sampling_freq/channels fields needed."""
    entries = []
    for t in tracks:
        if t['kind'] == 'video':
            entries.append(build_mkv_track_entry(t['track_number'], 1, t['codec_id'],
                                                   codec_private=t.get('codec_private'),
                                                   width=t['width'], height=t['height']))
        elif t['kind'] == 'audio':
            entries.append(build_mkv_track_entry(t['track_number'], 2, t['codec_id'],
                                                   codec_private=t.get('codec_private'),
                                                   sampling_freq=t['sampling_freq'],
                                                   channels=t['channels']))
    tracks_elem = build_mkv_tracks(entries)
    info_elem = build_mkv_info()
    ebml_hdr = build_ebml_header()

    tail_len = video_len - first_cluster_off
    segment_payload_len = len(info_elem) + len(tracks_elem) + tail_len
    segment_hdr = SEGMENT_ID_B + ebml_size_bytes(segment_payload_len, length=8)

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(ebml_hdr)
        dst.write(segment_hdr)
        dst.write(info_elem)
        dst.write(tracks_elem)
        src.seek(first_cluster_off)
        remaining = tail_len
        copied = 0
        while remaining > 0:
            chunk = src.read(min(CHUNK, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
            copied += len(chunk)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)
    return True


# Pairs (log2_max_frame_num, log2_max_pic_order_cnt_lsb) tried IN ADDITION
# to the two derived from the x264 SEI, for Matroska video tracks whose
# configuration is in the encrypted zone AND which have no x264 SEI in the
# clear (unknown encoder, then: the x264 formulas do not apply).
# Real case: a captured 1080p stream whose only correct combination was
# (8, 8) -- absent from both x264 formulas, which made the
# reconstruction fail. All these candidates are verified by ffmpeg decoding
# (see auto_detect_avc_generic_params), none is accepted blindly.
MKV_UNKNOWN_ENCODER_FP_GUESSES = [
    (8, 8), (4, 8), (8, 4), (16, 16), (8, 16), (16, 8),
]


def _mkv_track_nals(track, max_nals=16):
    """NALs ((type, nal)) of the first VIDEO frames of an identified Matroska
    track, starting at the FIRST keyframe: the decoding oracle (see
    _ffmpeg_probe_avc and auto_detect_avc_generic_params) requires a sequence
    that starts on an IDR. Used both to check an SPS/PPS read in the clear and
    to feed the automatic detection."""
    length_size = track.get('length_size') or 4
    out = []
    for frame in (track.get('frames') or []):
        nals = extract_nals_from_sample(frame, length_size, 16)
        if not out and not any(t == 5 for (t, _) in nals):
            continue                     # wait for the first keyframe
        out.extend(nals)
        if len(out) >= max_nals:
            break
    return out[:max_nals]


def _mkv_looks_hevc(track):
    """True if the first frames of the track look like HEVC
    (see looks_like_hevc_nals): avoids launching the H.264 automatic
    detection -- and producing a false success -- on an H.265 stream whose
    configuration (hvcC/CodecPrivate) is in the encrypted zone."""
    length_size = track.get('length_size') or 4
    nals = []
    for frame in (track.get('frames') or [])[:12]:
        nals.extend(extract_hevc_nals_from_sample(frame, length_size, 16))
    return looks_like_hevc_nals(nals)


def _mkv_hevc_oracle_nals(track, max_frames=24):
    """HEVC NALs ((HEVC type, nal)) of the first frames of the track, starting
    at the FIRST random access picture (IRAP: 19/20/21): that is what the
    _ffmpeg_probe_hevc oracle expects, since it counts pictures there and
    requires that ALL of them decode (see hevc_config_from_donors_or_profiles).

    RASL NALs (types 8/9) are discarded when the sequence starts on a CRA
    picture (21): in an open GOP these are the leading pictures whose
    references precede the splice point -- no decoder can restore them (ffmpeg
    drops them cleanly, but they then do not count as decoded, which would
    make the oracle fail wrongly)."""
    length_size = track.get('length_size') or 4
    out = []
    started = False
    skip_rasl = False
    for frame in (track.get('frames') or [])[:max_frames]:
        nals = extract_hevc_nals_from_sample(frame, length_size, 16)
        if not started:
            rap = [t for (t, _) in nals if 16 <= t <= 21]
            if not rap:
                continue                     # wait for the first keyframe
            started = True
            skip_rasl = 21 in rap and 19 not in rap and 20 not in rap
        if skip_rasl:
            nals = [(t, nal) for (t, nal) in nals if t not in (8, 9)]
        out.extend(nals)
    return out


def _mkv_video_config_is_real(track):
    """Checks by ffmpeg DECODING that an SPS/PPS 'found in the clear' really
    describes the first frames of the stream. sniff_mkv_video_avc only checks
    coarse plausibility (size, dimensions); this oracle closes the last gap:
    a plausible but WRONG pair otherwise produced a .mkv reported as rebuilt
    in which no image decoded. Without ffmpeg in the PATH, returns True: a
    file is not degraded for lack of a tool."""
    if shutil.which('ffmpeg') is None:
        return True
    nals = _mkv_track_nals(track)
    frame_nals = [nal for (t, nal) in nals if t in (5, 1)]
    if not frame_nals:
        return True
    sei_nal = next((nal for (t, nal) in nals if t == 6), None)
    return _ffmpeg_probe_avc(track['sps'], track['pps'], frame_nals, sei_nal)


def process_mkv_file(path, out_dir, video_len, width_override=None, height_override=None,
                     auto_resolution=True, auto_resolution_timeout=90,
                     brute_force_resolution=False, resolution_lock=False,
                     sps_pps_donor_files=None, profile_dir=None, use_profiles=True):
    """Full orchestration for a .mkv/.webm file. Returns (ok,
    message_or_details).

    The codec configuration of the video track comes, in order:
      1. from the SPS/PPS found in the clear, but ONLY if the ffmpeg decoding
         oracle confirms it (see _mkv_video_config_is_real);
      2. from the automatic detection of H.264 parameters (the same machinery
         checked by decoding as MP4 CASE B: see
         auto_detect_avc_generic_params) when the original configuration is
         in the encrypted zone;
      3. from the explicit --width/--height fallback (EXPERIMENTAL).
    Without cases 1 or 2, an explicit failure is preferred to a file reported
    as rebuilt but unreadable."""
    first_cluster_off = find_first_mkv_cluster(path, video_len)
    if first_cluster_off is None:
        return False, ("no readable Matroska Cluster found beyond the "
                        "encrypted zone: structure not recognised for this file.")
    log(f"  first readable Cluster found at offset {first_cluster_off}")

    frames_by_track = scan_mkv_tracks_from_clusters(path, first_cluster_off, video_len)
    identified = identify_mkv_tracks(frames_by_track)
    if not identified:
        return False, "no track detected in the first Clusters."

    tracks = []
    splice_off = first_cluster_off
    any_video = False
    for t in identified:
        tn = t['track_number']
        if t['kind'] == 'audio':
            log(f"  track {tn}: audio {t['codec_id']} detected automatically "
                f"({t['sampling_freq']} Hz, {t['channels']} channels)")
            tracks.append({'track_number': tn, 'kind': 'audio', 'codec_id': t['codec_id'],
                            'sampling_freq': t['sampling_freq'], 'channels': t['channels']})
        elif t['kind'] in ('video', 'video_no_config'):
            # Codec: the one from sniffing when it succeeded, otherwise deduced
            # from the NAL structure. To be determined BEFORE the keyframe
            # search, whose rule differs H.264 (NAL 5) / H.265 (NAL 19/20/21) --
            # without which an H.265 stream without VPS/SPS/PPS in the clear
            # never had a recognised keyframe and was rejected outright.
            codec = t.get('codec')
            if codec is None:
                codec = 'hevc' if _mkv_looks_hevc(t) else 'avc'
            # 1) Position of the first REAL keyframe: essential in
            #    all cases (splicing in the middle of a GOP would not
            #    decode, even with the right codec configuration).
            kf_off = find_first_mkv_video_keyframe_cluster(
                path, first_cluster_off, video_len, tn, codec, t['length_size'])
            if kf_off is None:
                log(f"  track {tn}: [WARNING] no keyframe (IDR) "
                    f"found in the scan window -> track ignored "
                    f"(the stream could not start cleanly)")
                continue

            # 2) Codec configuration: the one read in the clear if it exists AND
            #    if the oracle confirms it, otherwise reconstruction below.
            codec_id = codec_private = None
            width = height = None
            if t['kind'] == 'video' and codec == 'avc':
                if _mkv_video_config_is_real(t):
                    dims = parse_sps_dimensions(t['sps'][1:])
                    if dims:
                        width, height = dims
                        codec_id = 'V_MPEG4/ISO/AVC'
                        codec_private = build_avcc_payload(t['sps'], t['pps'])
                        log(f"  track {tn}: avc video detected automatically "
                            f"(SPS/PPS found in the clear AND ffmpeg decoding of "
                            f"the first frames verified), resolution "
                            f"{width}x{height}")
                if codec_private is None:
                    log(f"  track {tn}: SPS/PPS found in the clear REJECTED by "
                        f"the decoding oracle (false positive: these parameters do "
                        f"not describe the real stream) -> configuration "
                        f"rebuilt below")
            elif t['kind'] == 'video':
                sps_info = parse_hevc_sps(t['sps'])
                dims = (sps_info['width'], sps_info['height']) if sps_info else None
                if dims:
                    width, height = dims
                    codec_id = 'V_MPEGH/ISO/HEVC'
                    codec_private = build_hvcc_payload(t.get('vps'), t['sps'],
                                                       t['pps'], sps_info)
                    log(f"  track {tn}: hevc video detected automatically "
                        f"(VPS/SPS/PPS found in the clear), resolution "
                        f"{width}x{height}")
                else:
                    log(f"  track {tn}: HEVC SPS found but unreadable -> track ignored")
                    continue

            if codec_private is None and codec == 'hevc':
                # 3a) HEVC/H.265 stream whose config was in the
                #     CodecPrivate (encrypted zone) and is never repeated:
                #     reuse from a --sps-pps-from donor or from a learned
                #     HEVC profile, each candidate being validated by the
                #     ffmpeg decoding oracle -- same cascade as MP4
                #     CASE B, see hevc_config_from_donors_or_profiles.
                oracle_nals = _mkv_hevc_oracle_nals(t)
                found = None
                if oracle_nals and looks_like_hevc_nals(oracle_nals):
                    log(f"  track {tn}: HEVC/H.265 stream without VPS/SPS/PPS in "
                        f"the clear -> codec config to be reused from a donor "
                        f"(--sps-pps-from) or from a learned HEVC profile.")
                    found = hevc_config_from_donors_or_profiles(
                        oracle_nals, sps_pps_donor_files, profile_dir, use_profiles)
                if found is None:
                    log(f"  track {tn}: no HEVC configuration found "
                        f"(neither a --sps-pps-from donor nor a learned HEVC "
                        f"profile recognised by the decoding oracle) -> track ignored")
                    continue
                sps_info = found['sps_info']
                width, height = sps_info['width'], sps_info['height']
                codec_id = 'V_MPEGH/ISO/HEVC'
                codec_private = build_hvcc_payload(found.get('vps'), found['sps'],
                                                   found['pps'], sps_info)
                log(f"  track {tn}: HEVC configuration reused "
                    + ("from a donor file (--sps-pps-from)"
                       if found['codec'] == 'hevc-donor'
                       else "from a learned HEVC profile")
                    + f" and verified by decoding: {width}x{height}")

            if codec_private is None:
                # 3b) Automatic H.264 detection (candidates verified by
                #     ffmpeg decoding of the first frames), then fallback to
                #     --width/--height.
                nals = _mkv_track_nals(t)
                sei_nal = next((nal for (nt, nal) in nals if nt == 6), None)
                x264_opts = parse_x264_sei_options(sei_nal) if sei_nal else {}
                cfg = None
                if auto_resolution and nals:
                    cfg = auto_detect_avc_generic_params(
                        nals, x264_opts, width_hint=width_override,
                        height_hint=height_override,
                        max_seconds=auto_resolution_timeout,
                        profile_dir=profile_dir,
                        brute_force=brute_force_resolution,
                        resolution_lock=resolution_lock,
                        extra_fp_guesses=(None if x264_opts
                                          else MKV_UNKNOWN_ENCODER_FP_GUESSES))
                if cfg:
                    width, height = cfg['width'], cfg['height']
                    sps = build_fake_avc_sps(width, height,
                                             log2_max_frame_num=cfg['log2_max_frame_num'],
                                             log2_max_poc_lsb=cfg['log2_max_poc_lsb'],
                                             max_num_ref_frames=cfg['max_num_ref_frames'],
                                             poc_type=cfg['poc_type'])
                    pps = build_fake_avc_pps(x264_opts,
                                             qp_minus26=cfg['pic_init_qp_minus26'])
                    codec_id = 'V_MPEG4/ISO/AVC'
                    codec_private = build_avcc_payload(sps, pps)
                    log(f"  track {tn}: codec configuration rebuilt by "
                        f"automatic detection (verified by decoding): "
                        f"{width}x{height}")
                elif width_override and height_override:
                    log(f"  track {tn}: H.264 video detected but SPS/PPS never "
                        f"repeated in the stream -> codec config IMPOSSIBLE to read; "
                        f"synthesis of a 'best effort' SPS/PPS for {width_override}x"
                        f"{height_override} (EXPERIMENTAL, x264 default "
                        f"settings assumed -- may not decode if the original "
                        f"encoder used other settings)")
                    sps = build_fake_avc_sps(width_override, height_override)
                    pps = build_fake_avc_pps()
                    width, height = width_override, height_override
                    codec_id = 'V_MPEG4/ISO/AVC'
                    codec_private = build_avcc_payload(sps, pps)
                else:
                    log(f"  track {tn}: video detected but SPS/PPS never "
                        f"repeated in the stream -> resolution/profile lost. "
                        f"Track ignored (re-run with --width/--height for an "
                        f"EXPERIMENTAL attempt, not guaranteed -- automatic "
                        f"detection, for its part, requires ffmpeg in the PATH).")
                    continue

            if kf_off > splice_off:
                splice_off = kf_off
            any_video = True
            tracks.append({'track_number': tn, 'kind': 'video', 'codec_id': codec_id,
                           'codec_private': codec_private, 'width': width, 'height': height})
        else:
            log(f"  track {tn}: unrecognised type (neither self-describing "
                f"audio nor H.264/H.265 video) -> track ignored")

    if not tracks:
        return False, "no usable track (no recognised audio, no video with codec config)."

    if not any_video:
        log("  [INFO] no recoverable video track: the rebuilt file "
            "will be audio only.")

    return True, {'splice_off': splice_off, 'tracks': tracks}


# --------------------------------------------------------------------------
# Files simply renamed to .nsm (not encrypted, no HARR footer)
# --------------------------------------------------------------------------
#
# Some .nsm files are NOT encrypted by the ransomware: they have neither the
# encrypted zone at the head, nor the HARR footer. They are plain files
# (video, image, audio) that were renamed to .nsm. For them it is enough to
# detect the real format (magic bytes) and rename the file to the right
# extension, with no reconstruction at all. Videos are by default renamed
# to .mp4 (unless another container is detected, e.g. .mkv/.webm); images
# according to their format (jpg, png, ...).

def detect_type(filepath):
    """Detect the real format of a file (video, image or audio) from its
    magic bytes. Returns (category, extension), or (None, None) if the
    format is not recognised. The first value is 'video', 'image' or
    'audio'."""
    with open(filepath, 'rb') as fh:
        head = fh.read(256)
    n = len(head)
    if n < 12:
        return None, None

    # ---- Images ----
    if head[:3] == b'\xff\xd8\xff':
        return 'image', '.jpg'
    if head[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image', '.png'
    if head[:4] == b'GIF8':
        return 'image', '.gif'
    if head[:2] == b'BM':
        return 'image', '.bmp'
    if head[:4] in (b'II*\x00', b'MM\x00*'):
        return 'image', '.tiff'
    if head[:4] == b'RIFF' and head[8:12] == b'WEBP':
        return 'image', '.webp'

    # ---- Audio ----
    if head[:3] == b'ID3':
        return 'audio', '.mp3'
    if head[:4] == b'OggS':
        return 'audio', '.ogg'
    if head[:4] == b'fLaC':
        return 'audio', '.flac'

    # ---- Video ----
    if head[:4] == b'RIFF' and head[8:12] == b'AVI ':
        return 'video', '.avi'
    if head[:3] == b'FLV':
        return 'video', '.flv'
    if head[:4] == b'\x1a\x45\xdf\xa3':
        # EBML / Matroska: WebM or MKV depending on the DocType
        if b'webm' in head:
            return 'video', '.webm'
        return 'video', '.mkv'
    if head[4:8] == b'ftyp':
        # ISO-BMFF: MP4/MOV (video) or HEIC/AVIF (image) depending on the brand
        brand = head[8:12]
        if brand in (b'heic', b'heix', b'heim', b'heis', b'hevc', b'hevx',
                      b'mif1', b'msf1'):
            return 'image', '.heic'
        if brand in (b'avif', b'avis'):
            return 'image', '.avif'
        return 'video', '.mp4'
    if head[:16] == b'\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c':
        # ASF (Advanced Systems Format, .wmv/.wma container): identified
        # by this fixed GUID (Header Object) at the very start of the file.
        # Encountered here only for files that were SIMPLY RENAMED
        # (no HARR footer, intact file) -- no reconstruction
        # needed, just finding the right extension back. All corpus files
        # in this case are video: extension .wmv.
        return 'video', '.wmv'
    if _looks_like_mpeg_ts(filepath):
        # MPEG Transport Stream (.ts/.m2ts) simply renamed (intact
        # file, no HARR footer): see _looks_like_mpeg_ts for the
        # check (0x47 sync byte confirmed on several consecutive
        # 188-byte packets, not a single isolated byte).
        return 'video', '.ts'
    return None, None


def _looks_like_mpeg_ts(filepath, min_packets=8):
    """Check that a file is a valid MPEG Transport Stream: unlike a single
    0x47 byte (which can appear purely by chance anywhere in a file), a REAL
    TS stream has a 0x47 sync byte at the start of EVERY 188-byte packet,
    repeatedly from the start of the file. Here we require confirmation over
    `min_packets` consecutive packets before concluding -- avoids any false
    positive."""
    try:
        with open(filepath, 'rb') as fh:
            chunk = fh.read(TS_PACKET_SIZE * min_packets)
    except OSError:
        return False
    if len(chunk) < TS_PACKET_SIZE * min_packets:
        return False
    return all(chunk[i * TS_PACKET_SIZE] == TS_SYNC_BYTE
               for i in range(min_packets))


def unique_dest(out_path):
    """Return `out_path` if it is available, otherwise a free path obtained
    by adding a _1, _2, ... suffix (e.g. video.jpg -> video_1.jpg)."""
    if not os.path.exists(out_path):
        return out_path
    stem, ext = os.path.splitext(out_path)
    i = 1
    while os.path.exists(f"{stem}_{i}{ext}"):
        i += 1
    return f"{stem}_{i}{ext}"


def handle_simple_rename(path, out_dir, keep_nsm=False):
    """The file is NOT encrypted by the ransomware (no HARR footer): it was
    simply renamed to .nsm. Its real format is detected and the file is
    renamed to the right extension.

    - Without --keep-nsm: the .nsm is RENAMED (moved) to its real extension
      (the original .nsm no longer exists, so there is nothing left to move).
    - With --keep-nsm: the .nsm is COPIED to its real extension and the
      original .nsm is kept.

    Returns (True, 'renamed') on success, or (False, 'failed') on failure
    (unrecognised format / error)."""
    kind, ext = detect_type(path)
    if kind is None:
        log("  [FAILED] real format not recognised (no known video, image "
            "or audio format): cannot determine the right extension.")
        return False, 'failed'
    stem = os.path.splitext(os.path.basename(path))[0]
    out_path = unique_dest(os.path.join(out_dir, stem + ext))
    log(f"  real format detected: {kind} ({ext})")
    log(f"  -> rename: {os.path.basename(path)}  =>  "
        f"{os.path.basename(out_path)}")
    try:
        if keep_nsm:
            shutil.copy2(path, out_path)
            log(f"  -> copy done (--keep-nsm, original .nsm kept): "
                f"{out_path}")
        else:
            shutil.move(path, out_path)
            log(f"  -> file renamed: {out_path}")
        return True, 'renamed'
    except Exception as e:
        log(f"  [FAILED] rename failed: {e}")
        return False, 'failed'



# ==========================================================================
# SECTION AVI / RIFF (.avi)
# ==========================================================================
#
# Same ransomware (first 4096 bytes encrypted + footer), but a totally
# different container: RIFF ('RIFF' + size + 'AVI ' instead of
# ISO-BMFF). The RIFF/hdrl header (avih + one strl per track, which
# hold codec/resolution/audio format -- the AVI equivalent of
# moov) falls entirely inside the encrypted zone on the files
# observed, but the LIST 'movi' (raw audio/video data, interleaved
# chunk by chunk) that follows it is located directly by its signature
# ('LIST' + size + 'movi') without relying on a fixed 4096-byte
# split. As for mdat in MP4, no byte of 'movi' is modified:
# only a new header (hdrl + idx1) is rebuilt around it.
#
# Unlike the H.264 SPS/PPS (never guaranteed to repeat), the
# codec observed on the real sample files is MPEG-4
# Part 2 (Xvid/DivX/FMP4...): this format writes its video_object_layer()
# -- which holds width/height AND the EXACT frame rate -- IN THE CLEAR at
# the start of EVERY video sequence (like an H.264 SPS, but with
# marker_bit set to 1 throughout the syntax: checked one by one, at the
# slightest mismatch the bit-by-bit parsing is considered wrong and
# abandoned rather than returning an aberrant value). Video
# reconstruction is therefore RELIABLE (real values, not guessed). AUDIO
# configuration ('strf'/WAVEFORMATEX), for its part, never repeats in the
# stream (like 'esds'/'mp4a' in MP4): if an audio track is detected in
# 'movi', it is reported but DROPPED (same limits, same choice as
# 'avc-video-track-intact' on the MP4 side) rather than guessing an
# audio format at random.


def find_riff_movi(filepath, video_len):
    """Locate the LIST 'movi' of an AVI/RIFF file encrypted by the
    ransomware: look directly for the signature ('LIST' + LE size
    + 'movi') in the intact zone (from ENC_HEADER_LEN), without
    assuming it starts exactly at 4096 (the real files observed
    do, but nothing guarantees it in general -- a search margin is
    therefore used). Returns a dict, or None if not found:
    {'movi_list_off'
    (position of the 'LIST' tag), 'movi_data_off' (position just after the
    'movi' fourcc, start of the very first chunk), 'movi_list_size'
    (declared size of the LIST, 'movi' fourcc included)}"""
    SEARCH_CAP = 16 * 1024 * 1024
    with open(filepath, 'rb') as fh:
        fh.seek(ENC_HEADER_LEN)
        window = fh.read(min(SEARCH_CAP, max(0, video_len - ENC_HEADER_LEN)))
    idx = window.find(b'movi')
    while idx != -1:
        if idx >= 8 and window[idx - 8:idx - 4] == b'LIST':
            size = struct.unpack('<I', window[idx - 4:idx])[0]
            return {
                'movi_list_off': ENC_HEADER_LEN + idx - 8,
                'movi_data_off': ENC_HEADER_LEN + idx + 4,
                'movi_list_size': size,
            }
        idx = window.find(b'movi', idx + 1)
    return None


def scan_avi_movi(filepath, movi_data_off, movi_data_end):
    """Walk the whole LIST 'movi' of an AVI file (consecutive chunks:
    4-byte FourCC + 4-byte LE size + data, padded to an even size with a
    filler byte when needed), reading only the chunk HEADERS (8 bytes),
    never the data -- fast even on a 'movi' of several hundred MB.
    Returns a dict {tag: [(relative_offset, size), ...]}; the relative
    offset is counted from the very first data byte of 'movi' (standard
    convention of the 'idx1' index, independent of the position of the
    LIST in the rebuilt final file -- no shift to apply, unlike the
    absolute 'stco' offsets in MP4)."""
    by_tag = {}
    BUF = 64 * 1024 * 1024
    with open(filepath, 'rb') as fh:
        buf = b''
        buf_start = movi_data_off
        pos = movi_data_off
        while pos < movi_data_end:
            need = pos - buf_start
            if need + 8 > len(buf):
                fh.seek(pos)
                new_data = fh.read(BUF)
                if not new_data:
                    break
                buf = new_data
                buf_start = pos
                need = 0
            if need + 8 > len(buf):
                break
            tag = buf[need:need + 4]
            size = struct.unpack('<I', buf[need + 4:need + 8])[0]
            rel_off = pos - movi_data_off
            by_tag.setdefault(tag, []).append((rel_off, size))
            pos += 8 + size + (size % 2)
    return by_tag


def find_mpeg4_vol_start(data):
    """Look for the MPEG-4 Part 2 'video_object_layer_start_code'
    (00 00 01 20-2F, Xvid/DivX/FMP4...) in `data`, return the offset
    just after that 4-byte code (start of the VOL body to parse bit by
    bit), or None if absent."""
    pos = 0
    while True:
        i = data.find(b'\x00\x00\x01', pos)
        if i == -1 or i + 3 >= len(data):
            return None
        code = data[i + 3]
        if 0x20 <= code <= 0x2F:
            return i + 4
        pos = i + 1


def parse_mpeg4_vol_wh(data):
    """Parse an MPEG-4 Part 2 video_object_layer() directly from the REAL
    stream (not a guess -- values written in the clear by the encoder),
    to extract width/height AND the EXACT frame rate from it when
    fixed_vop_rate is active (rate = vop_time_increment_resolution /
    fixed_vop_time_increment, straight from the stream). Every marker_bit
    (value always 1 in a valid stream, placed at regular intervals by the
    standard as an alignment guard) is checked: at the slightest mismatch
    the bit-by-bit parsing is considered wrong and None is returned rather
    than an aberrant value. Only the standard rectangular form
    (video_object_layer_shape == 0, by far the most common) is handled;
    returns None otherwise. Returns a dict
    {'width', 'height', 'fps', 'vop_time_increment_resolution',
    'fixed_vop_time_increment'} or None."""
    start = find_mpeg4_vol_start(data)
    if start is None:
        return None
    br = BitReader(data)
    br.pos = start * 8

    def marker():
        return br.u(1) == 1

    try:
        br.u(1)  # random_accessible_vol
        br.u(8)  # video_object_type_indication
        is_obj_layer_id = br.u(1)
        verid = 1
        if is_obj_layer_id:
            verid = br.u(4)
            br.u(3)  # video_object_layer_priority
        aspect_ratio_info = br.u(4)
        if aspect_ratio_info == 0xF:
            br.u(8)
            br.u(8)
        vol_control_parameters = br.u(1)
        if vol_control_parameters:
            br.u(2)  # chroma_format
            br.u(1)  # low_delay
            vbv = br.u(1)
            if vbv:
                br.u(15)
                if not marker():
                    return None
                br.u(15)
                if not marker():
                    return None
                br.u(15)
                if not marker():
                    return None
                br.u(3)
                br.u(11)
                if not marker():
                    return None
                br.u(15)
                if not marker():
                    return None
        shape = br.u(2)
        if shape == 3 and is_obj_layer_id and verid != 1:
            br.u(4)  # video_object_layer_shape_extension
        if not marker():
            return None
        vtir = br.u(16)  # vop_time_increment_resolution
        if vtir <= 0:
            return None
        if not marker():
            return None
        fixed_vop_rate = br.u(1)
        fixed_vop_time_increment = None
        if fixed_vop_rate:
            nbits = max(1, (vtir - 1).bit_length())
            fixed_vop_time_increment = br.u(nbits)
        if shape != 0:
            return None  # non-rectangular shape: not handled (very rare)
        if not marker():
            return None
        width = br.u(13)
        if not marker():
            return None
        height = br.u(13)
        if not marker():
            return None
    except Exception:
        return None
    if width <= 0 or height <= 0 or width > 16384 or height > 16384:
        return None
    fps = None
    if fixed_vop_time_increment and fixed_vop_time_increment > 0:
        fps = vtir / fixed_vop_time_increment
    return {'width': width, 'height': height, 'fps': fps,
            'vop_time_increment_resolution': vtir,
            'fixed_vop_time_increment': fixed_vop_time_increment}


def riff_chunk(tag4: bytes, payload: bytes) -> bytes:
    """Encode a RIFF chunk (4-byte tag + 4-byte LE size + data), padded
    to an even size with a filler byte when needed (standard RIFF rule)."""
    out = tag4 + struct.pack('<I', len(payload)) + payload
    if len(payload) % 2:
        out += b'\x00'
    return out


def riff_list(kind4: bytes, children_bytes: bytes) -> bytes:
    return riff_chunk(b'LIST', kind4 + children_bytes)


def build_avih(micro_sec_per_frame, total_frames, width, height, num_streams,
               suggested_buffer_size=0, max_bytes_per_sec=0):
    """AVIMAINHEADER (56 bytes)."""
    AVIF_HASINDEX = 0x00000010
    return struct.pack('<14I',
                        micro_sec_per_frame, max_bytes_per_sec, 0, AVIF_HASINDEX,
                        total_frames, 0, num_streams, suggested_buffer_size,
                        width, height, 0, 0, 0, 0)


def build_strh_video(fourcc, scale, rate, length, width, height,
                      suggested_buffer_size=0):
    """AVISTREAMHEADER (56 bytes) for a video track."""
    return (b'vids' + fourcc +
            struct.pack('<I', 0) +               # dwFlags
            struct.pack('<HH', 0, 0) +            # wPriority, wLanguage
            struct.pack('<I', 0) +                # dwInitialFrames
            struct.pack('<I', scale) +
            struct.pack('<I', rate) +
            struct.pack('<I', 0) +                # dwStart
            struct.pack('<I', length) +
            struct.pack('<I', suggested_buffer_size) +
            struct.pack('<i', -1) +               # dwQuality
            struct.pack('<I', 0) +                # dwSampleSize (0 = variable)
            struct.pack('<hhhh', 0, 0, width, height))  # rcFrame


def build_bitmapinfoheader(width, height, fourcc):
    """BITMAPINFOHEADER (40 bytes), used as 'strf' for a compressed
    video track."""
    return struct.pack('<IiiHHIIiiII',
                        40, width, height, 1, 0,
                        struct.unpack('<I', fourcc)[0],
                        max(1, width * height * 3),
                        0, 0, 0, 0)


def build_avi_hdrl(width, height, video_fourcc, total_video_frames,
                    fps_num, fps_den):
    micro_sec_per_frame = round(1000000 * fps_den / fps_num) if fps_num else 0
    avih = riff_chunk(b'avih', build_avih(micro_sec_per_frame, total_video_frames,
                                           width, height, 1))
    strh = riff_chunk(b'strh', build_strh_video(video_fourcc, fps_den, fps_num,
                                                 total_video_frames, width, height))
    strf = riff_chunk(b'strf', build_bitmapinfoheader(width, height, video_fourcc))
    strl = riff_list(b'strl', strh + strf)
    return riff_list(b'hdrl', avih + strl)


def build_idx1(video_tag, chunks):
    """AVIOLDINDEX ('idx1'): 16 bytes per entry (ckid + dwFlags +
    dwChunkOffset + dwChunkLength). All entries are marked "key frame"
    (AVIIF_KEYFRAME) for lack of a reliable way to tell key frames from
    the others without decoding the stream -- permissive choice, good
    enough for basic playback/seek."""
    AVIIF_KEYFRAME = 0x00000010
    entries = bytearray()
    for rel_off, size in chunks:
        entries += video_tag + struct.pack('<III', AVIIF_KEYFRAME, rel_off, size)
    return riff_chunk(b'idx1', bytes(entries))


def repair_avi_case_b(filepath, out_path, video_len, movi_info, progress=None):
    """Rebuild an AVI file whose RIFF/hdrl header is lost (encrypted
    zone) but whose LIST 'movi' (already located in `movi_info`, see
    find_riff_movi) is intact. See the section header for the general
    strategy."""
    movi_data_off = movi_info['movi_data_off']
    movi_list_size = movi_info['movi_list_size']
    movi_data_end = min(movi_data_off + max(0, movi_list_size - 4), video_len)

    log("  full walk of the LIST 'movi' to identify the streams "
        "(video/audio) and their chunks...")
    by_tag = scan_avi_movi(filepath, movi_data_off, movi_data_end)

    video_candidates = [t for t in by_tag if len(t) == 4 and t[2:4] in (b'dc', b'db')]
    if not video_candidates:
        raise ValueError("no video stream (chunk 'NNdc'/'NNdb') identified in 'movi'")
    video_tag = max(video_candidates, key=lambda t: len(by_tag[t]))
    video_chunks = by_tag[video_tag]
    if not video_chunks:
        raise ValueError("video stream identified but no usable chunk")

    first_rel_off, first_size = video_chunks[0]
    with open(filepath, 'rb') as fh:
        fh.seek(movi_data_off + first_rel_off + 8)
        first_sample = fh.read(min(first_size, 4 * 1024 * 1024))

    vol_info = parse_mpeg4_vol_wh(first_sample)
    if not vol_info:
        raise ValueError(
            "video codec not recognised or unreadable MPEG-4 VOL in the "
            "first sample (only MPEG-4 Part 2 / Xvid / DivX / FMP4 is "
            "currently handled for AVI files)")

    width, height = vol_info['width'], vol_info['height']
    fps = vol_info['fps']
    if fps:
        fps_num = vol_info['vop_time_increment_resolution']
        fps_den = vol_info['fixed_vop_time_increment']
        fps_source = (f"EXACT frame rate read from the MPEG-4 stream (VOL, in the clear): "
                       f"vop_time_increment_resolution={fps_num} / "
                       f"fixed_vop_time_increment={fps_den} = {fps:.4f} fps")
    else:
        fps_num, fps_den = 25, 1
        fps_source = ("video frame rate not fixed in the stream (fixed_vop_rate=0) -- "
                       "fallback to 25 fps by default, to check in a video player")

    total_video_frames = len(video_chunks)
    video_fourcc = b'FMP4'

    log(f"  codec/resolution/frame rate recovered DIRECTLY from the video stream "
        f"(MPEG-4 Part 2 VOL, in the clear, stream '{video_tag.decode(errors='replace')}') "
        f": {width}x{height}, {total_video_frames} frames")
    log(f"     ({fps_source})")

    audio_dropped = False
    audio_candidates = [t for t in by_tag if len(t) == 4 and t[2:4] == b'wb']
    if audio_candidates:
        audio_tag = max(audio_candidates, key=lambda t: len(by_tag[t]))
        audio_dropped = True
        log(f"     [WARNING] audio track detected (stream "
            f"'{audio_tag.decode(errors='replace')}', {len(by_tag[audio_tag])} "
            f"chunks) but its exact format (sample rate, mono/stereo, codec) "
            f"was in the encrypted 'strf' header and never repeats in the "
            f"clear in the stream (unlike the video SPS/PPS): "
            f"NOT RECOVERABLE reliably. Audio track DROPPED -- "
            f"file rebuilt VIDEO ONLY (without sound), same limit as "
            f"the equivalent MP4 case (intact video track / audio "
            f"config not found).")

    hdrl = build_avi_hdrl(width, height, video_fourcc, total_video_frames,
                           fps_num, fps_den)
    idx1 = build_idx1(video_tag, video_chunks)

    riff_body_len = 4 + len(hdrl) + 8 + movi_list_size + len(idx1)

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        dst.write(b'RIFF')
        dst.write(struct.pack('<I', riff_body_len))
        dst.write(b'AVI ')
        dst.write(hdrl)
        dst.write(b'LIST')
        dst.write(struct.pack('<I', movi_list_size))
        dst.write(b'movi')
        src.seek(movi_data_off)
        remaining = max(0, movi_list_size - 4)
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)
        dst.write(idx1)

    return True, {
        'width': width, 'height': height, 'sample_count': total_video_frames,
        'fps_fallback': round(fps, 4) if fps else fps_num / fps_den,
        'fps_source': fps_source, 'codec': 'mpeg4-avi-real',
        'video_tag': video_tag.decode(errors='replace'),
        'audio_dropped': audio_dropped,
    }




# ==========================================================================
# SECTION FLV (.flv)
# ==========================================================================
#
# Same ransomware (encrypted zone at the head + HARR footer), Adobe
# FLV container this time. An FLV file is a LINEAR SEQUENCE of tags: a
# fixed 9-byte header ('FLV' + version + audio/video flags +
# DataOffset), then a 4-byte 'PreviousTagSize0' (usually 0),
# then consecutive tags of the form:
#
#   [type (1) | DataSize (3, big-endian) | timestamp (3) |
#    timestamp_extended (1) | StreamID (3, = 0) |
#    data (DataSize) | PreviousTagSize (4)]
#
# where PreviousTagSize equals EXACTLY 11 + DataSize. It is a strong
# constraint (32 bits) used as a check: a fake tag has very little
# chance of satisfying it by accident, whereas a bare type byte
# 8/9/18 (audio/video/script) is frequent in any stream. The first
# ENTIRELY intact tag is thus found just after the encrypted zone,
# with no reference file at all.
#
# The script re-reads the tags as they are (no byte of the audio/video
# data is modified) and only rewrites IN FRONT of them a valid FLV
# header (9 bytes + PreviousTagSize0), with the audio/video flags
# deduced from the tag types actually encountered. Unlike
# MP4/AVI, NO codec reconstruction is needed on the FLV side: each
# tag carries its own type and, for audio as for video, its
# configuration in its first data byte. The audio track is
# therefore NOT dropped here (it is intact beyond the zone).
#
# The first tag (often an 'onMetaData' script carrying duration/bitrate,
# not essential for playback) may fall partly inside the encrypted
# zone: we therefore start at the first entirely valid tag.
#
# Known limit (common to SPOTS mode): if the ransomware encrypted
# ADDITIONAL zones in the middle of the file, they break the tag
# chain. The script then tries to resynchronise on the next chain and
# resumes the copy from there (the tags whose bytes fell inside
# the zone are lost), rather than inserting random bytes that the
# FLV demultiplexer would misinterpret.

FLV_TAG_HEADER_LEN = 11          # bytes before the tag data
FLV_TAG_TYPES = (8, 9, 18)       # 8=audio, 9=video, 18=script (onMetaData)
FLV_TAG_AUDIO = 8
FLV_TAG_VIDEO = 9


def _flv_parse_tag(data, rel, base, end):
    """Parse the header of an FLV tag at offset `rel` in `data` (which
    represents the file from the ABSOLUTE offset `base`), and check its
    consistency: known type, zero StreamID, and above all PreviousTagSize ==
    11 + DataSize. Returns a dict {'type', 'size', 'timestamp', 'total'}
    or None if this is not a valid FLV tag."""
    abs_pos = base + rel
    if rel < 0 or abs_pos + FLV_TAG_HEADER_LEN > end:
        return None
    if rel + FLV_TAG_HEADER_LEN > len(data):
        return None
    t = data[rel]
    if t not in FLV_TAG_TYPES:
        return None
    ds = (data[rel + 1] << 16) | (data[rel + 2] << 8) | data[rel + 3]
    if ds <= 0:
        return None
    total = FLV_TAG_HEADER_LEN + ds + 4
    if abs_pos + total > end or rel + total > len(data):
        return None
    ts = ((data[rel + 4] << 16) | (data[rel + 5] << 8) | data[rel + 6]) | \
         (data[rel + 7] << 24)
    sid = (data[rel + 8] << 16) | (data[rel + 9] << 8) | data[rel + 10]
    if sid != 0:
        return None
    prev = int.from_bytes(data[rel + 11 + ds:rel + 15 + ds], 'big')
    if prev != FLV_TAG_HEADER_LEN + ds:
        return None
    return {'type': t, 'size': ds, 'timestamp': ts, 'total': total}


def _flv_validate_chain(data, base, end, rel, min_tags=3, min_ts=None):
    """Check that from offset `rel` in `data`, `min_tags` valid FLV tags
    follow one another with increasing timestamps (the first one having to be
    >= `min_ts` when provided). Returns the ABSOLUTE offset of the first tag
    if the chain is valid, otherwise None."""
    pos = rel
    last_ts = None
    for i in range(min_tags):
        tag = _flv_parse_tag(data, pos, base, end)
        if tag is None:
            return None
        if i == 0 and min_ts is not None and tag['timestamp'] < min_ts:
            return None
        if last_ts is not None and tag['timestamp'] < last_ts:
            return None
        last_ts = tag['timestamp']
        pos += tag['total']
    return base + rel


def _flv_find_chain(data, base, end, min_tags=3, min_ts=None):
    """Scan `data` byte by byte for the first tag of a valid FLV chain of
    `min_tags` consecutive tags. Returns the ABSOLUTE offset of that first
    tag, or None."""
    n = len(data)
    limit = n - 15
    i = 0
    while i <= limit:
        if data[i] in FLV_TAG_TYPES:
            found = _flv_validate_chain(data, base, end, i, min_tags, min_ts)
            if found is not None:
                return found
        i += 1
    return None


class _FlvTagReader:
    """Sequential buffered reader for the tags of an FLV file: reads the
    file in large blocks (32 MB) and reloads a block only when the current
    tag overflows the buffer, which avoids one disk access per tag on
    multi-GB files (hundreds of thousands of tags)."""

    READ = 32 * 1024 * 1024

    def __init__(self, fh, pos, end):
        self.fh = fh
        self.pos = pos
        self.end = end
        self.buf = b''
        self.base = pos
        self._reload()

    def _reload(self, size=None):
        self.fh.seek(self.pos)
        self.buf = self.fh.read(size or self.READ)
        self.base = self.pos

    def _ensure(self, n):
        rel = self.pos - self.base
        if rel < 0 or rel + n > len(self.buf):
            self._reload(n if n > self.READ else None)
            rel = self.pos - self.base
        return rel >= 0 and rel + n <= len(self.buf)

    def parse(self):
        if self.pos + FLV_TAG_HEADER_LEN + 4 > self.end:
            return None
        if not self._ensure(FLV_TAG_HEADER_LEN):
            return None
        rel = self.pos - self.base
        b = self.buf
        t = b[rel]
        if t not in FLV_TAG_TYPES:
            return None
        ds = (b[rel + 1] << 16) | (b[rel + 2] << 8) | b[rel + 3]
        if ds <= 0:
            return None
        total = FLV_TAG_HEADER_LEN + ds + 4
        if not self._ensure(total):
            return None
        rel = self.pos - self.base
        b = self.buf
        ts = ((b[rel + 4] << 16) | (b[rel + 5] << 8) | b[rel + 6]) | \
             (b[rel + 7] << 24)
        sid = (b[rel + 8] << 16) | (b[rel + 9] << 8) | b[rel + 10]
        if sid != 0:
            return None
        prev = int.from_bytes(b[rel + 11 + ds:rel + 15 + ds], 'big')
        if prev != FLV_TAG_HEADER_LEN + ds:
            return None
        return {'type': t, 'size': ds, 'timestamp': ts, 'total': total}

    def tag_view(self, total):
        rel = self.pos - self.base
        return memoryview(self.buf)[rel:rel + total]

    def read_region(self, maxlen):
        """Re-read the buffer from `self.pos` (at most `maxlen` bytes) and
        return the data, for a resynchronisation search."""
        self.fh.seek(self.pos)
        self.buf = self.fh.read(maxlen)
        self.base = self.pos
        return self.buf

    def seek(self, pos):
        self.pos = pos
        self._reload()


def repair_flv_case_b(filepath, out_path, video_len, enc_header_len, progress=None):
    """Rebuild an FLV file whose header (and very first tag, 'onMetaData')
    fell into the encrypted zone, but whose audio/video tag chain beyond it is
    intact. See the section header for the strategy. Returns (True, extra) or
    raises an exception if no valid tag chain is found."""
    scan_start = max(0, min(enc_header_len, video_len))
    SEARCH_CAP = 16 * 1024 * 1024
    with open(filepath, 'rb') as src:
        src.seek(scan_start)
        region = src.read(min(SEARCH_CAP, max(0, video_len - scan_start)))

    # A chain of 3 tags is more than enough to rule out any false positive
    # (the PreviousTagSize check is already very discriminating); we fall
    # back to 2 then 1 tag only for very short files.
    first = _flv_find_chain(region, scan_start, video_len, min_tags=3)
    if first is None:
        first = _flv_find_chain(region, scan_start, video_len, min_tags=2)
    if first is None:
        first = _flv_find_chain(region, scan_start, video_len, min_tags=1)
    if first is None:
        raise ValueError(
            "no valid FLV tag chain (consistent type / DataSize / timestamp / "
            "PreviousTagSize) found in the intact zone: FLV structure "
            "not recognised for this file")
    del region
    log(f"  first intact FLV tag at offset {first} "
        f"(encrypted zone at the head: {enc_header_len} bytes)")

    has_audio = False
    has_video = False
    video_codec_id = None
    codec_config_seen = False
    tag_count = 0
    skipped = 0
    last_ts = None
    RESYNC_CAP = max(16 * 1024 * 1024, enc_header_len * 4)

    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        # Provisional FLV header (flags at 0: recomputed at the end of the
        # walk, once the tag types actually encountered are known)
        # followed by PreviousTagSize0 = 0.
        dst.write(b'FLV\x01\x00' + struct.pack('>I', 9) + b'\x00\x00\x00\x00')
        reader = _FlvTagReader(src, first, video_len)
        while reader.pos + FLV_TAG_HEADER_LEN + 4 <= video_len:
            tag = reader.parse()
            if tag is None:
                # Chain break: typically an ADDITIONAL encrypted zone
                # (SPOTS mode). Look for the next valid tag
                # beyond it and resume the copy from there.
                data = reader.read_region(min(RESYNC_CAP, video_len - reader.pos))
                nxt = _flv_find_chain(data, reader.pos, video_len,
                                      min_tags=2, min_ts=last_ts)
                if nxt is None:
                    nxt = _flv_find_chain(data, reader.pos, video_len,
                                          min_tags=1, min_ts=last_ts)
                if nxt is None:
                    break
                skipped += nxt - reader.pos
                log(f"     [SPECIAL] tag chain interrupted at offset "
                    f"{reader.pos}: resuming on the next tag at offset "
                    f"{nxt} ({nxt - reader.pos} unrecognised byte(s) skipped, "
                    f"typically an additional encrypted zone in "
                    f"SPOTS mode)")
                reader.seek(nxt)
                continue
            if tag['type'] == FLV_TAG_AUDIO:
                has_audio = True
            elif tag['type'] == FLV_TAG_VIDEO:
                vid = reader.tag_view(tag['total'])
                # 1st data byte: 4 FrameType bits (high) + 4
                # CodecID bits (low).
                cid = vid[11] & 0x0F
                if video_codec_id is None:
                    video_codec_id = cid
                # For AVC (7) / HEVC (12), a tag whose 2nd data byte
                # equals 0 is the sequence header tag
                # (AVCDecoderConfigurationRecord / HEVCDecoderConfiguration-
                # Record): IT carries the SPS/PPS. If it lies in the
                # encrypted zone (typically the very first video tag, the
                # config being written only ONCE in FLV), that config is lost.
                if cid in (7, 12) and tag['size'] >= 2 and vid[12] == 0:
                    codec_config_seen = True
                has_video = True
            last_ts = tag['timestamp']
            dst.write(reader.tag_view(tag['total']))
            reader.pos += tag['total']
            tag_count += 1
            if progress and tag_count % 20000 == 0:
                progress(reader.pos)

        if tag_count == 0:
            raise ValueError(
                "valid FLV tag chain detected but no tag could "
                "be read")
        flags = (0x01 if has_video else 0x00) | (0x04 if has_audio else 0x00)
        dst.seek(0)
        dst.write(b'FLV\x01' + bytes([flags]) + struct.pack('>I', 9))

    return True, {
        'codec': 'flv-tags-real',
        'has_audio': has_audio,
        'has_video': has_video,
        'video_codec_id': video_codec_id,
        'codec_config_seen': codec_config_seen,
        'tag_count': tag_count,
        'skipped_bytes': skipped,
        'first_tag_off': first,
    }


# ==========================================================================
# SECTION MPEG-PS (.mpg / .mpeg)
# ==========================================================================
#
# Same ransomware (encrypted header + footer), but a stream ENTIRELY
# DIFFERENT from the previous containers: an MPEG-1/2 Program Stream (PS)
# has NO external index table comparable to moov (MP4) or hdrl
# (AVI) -- it is a "self-synchronising" stream where every unit (pack,
# system header, audio/video PES packet) starts with a 4-byte
# START CODE 00 00 01 XX in the clear, unique by construction of the stream
# (unlike H.264 which needs emulation-prevention bytes,
# the MPEG-1/2 syntax guarantees such a pattern can only appear
# as a real start code). An MPEG-PS reader/demultiplexer therefore
# resynchronises automatically on the first valid start code encountered,
# without needing to know the exact position of the start of the stream.
#
# Strategy: locate, after the encrypted zone, the first usable pack header
# (00 00 01 BA) -- or failing that a video stream start code
# (sequence header 00 00 01 B3 or video PES 00 00 01 E0-EF) -- then
# copy the whole stream as is from that point down to the end of the
# payload. The few tens/hundreds of bytes BEFORE that
# point (leftover encrypted zone or unrecognised structure) are
# lost, but this is strictly analogous to losing the
# ftyp/moov header in MP4 CASE B: no consequence on the readability of the
# following stream. Bonus: unlike the H.264/SPS, the MPEG-1/2
# sequence header (00 00 01 B3) holds width/height/frame rate IN THE CLEAR
# (not entropy-coded) -- as soon as it is found, the real
# resolution/frame rate is known with certainty, without needing auto-detection
# or profiles.

MPEG_PACK_START = b'\x00\x00\x01\xba'
MPEG_SEQUENCE_HEADER_START = b'\x00\x00\x01\xb3'
MPEG_SYSTEM_HEADER_START = b'\x00\x00\x01\xbb'


def find_mpeg_ps_start(filepath, video_len, enc_header_len,
                        search_cap=8 * 1024 * 1024):
    """Search from `enc_header_len` for the first usable MPEG-PS
    synchronisation point: preferably a pack header (00 00 01 BA),
    otherwise a video sequence header (00 00 01 B3) or the start of a
    video PES packet (00 00 01 E0-EF). Returns
    (absolute_offset, description), or (None, None) if nothing is found
    within the first `search_cap` bytes after `enc_header_len`."""
    cap = min(search_cap, max(0, video_len - enc_header_len))
    with open(filepath, 'rb') as fh:
        fh.seek(enc_header_len)
        data = fh.read(cap)

    idx = data.find(MPEG_PACK_START)
    if idx != -1:
        return enc_header_len + idx, 'pack header (00 00 01 BA)'

    idx = data.find(MPEG_SEQUENCE_HEADER_START)
    if idx != -1:
        return enc_header_len + idx, 'video sequence header (00 00 01 B3)'

    m = re.search(rb'\x00\x00\x01[\xe0-\xef]', data)
    if m:
        return enc_header_len + m.start(), 'video PES packet (00 00 01 E0-EF)'

    return None, None


_MPEG_FRAMERATE_TABLE = {
    1: 23.976, 2: 24.0, 3: 25.0, 4: 29.97, 5: 30.0,
    6: 50.0, 7: 59.94, 8: 60.0,
}


def parse_mpeg_sequence_header_wh(data):
    """Extract width/height/frame rate IN THE CLEAR from the first
    MPEG-1/2 sequence header (00 00 01 B3) found in `data` --
    those fields are NOT entropy-coded (unlike the H.264 SPS),
    they are directly readable bit by bit right after the start code.
    Returns a dict, or None if no sequence header is found /
    unreadable."""
    idx = data.find(MPEG_SEQUENCE_HEADER_START)
    if idx == -1:
        return None
    chunk = data[idx + 4:idx + 12]
    if len(chunk) < 7:
        return None
    width = (chunk[0] << 4) | (chunk[1] >> 4)
    height = ((chunk[1] & 0x0f) << 8) | chunk[2]
    framerate_code = chunk[3] & 0x0f
    if width <= 0 or height <= 0:
        return None
    fps = _MPEG_FRAMERATE_TABLE.get(framerate_code)
    return {'width': width, 'height': height, 'fps': fps,
            'framerate_code': framerate_code}


def repair_mpeg_ps_case_b(filepath, out_path, video_len, enc_header_len,
                           progress=None):
    """Rebuild an MPEG-1/2 Program Stream file (.mpg/.mpeg) whose very
    start of stream is lost (encrypted zone) by resynchronising on the
    first usable start code and then copying the whole stream as is down
    to the end of the payload. See the section header for the general
    strategy."""
    start_off, start_kind = find_mpeg_ps_start(filepath, video_len, enc_header_len)
    if start_off is None:
        raise ValueError(
            "no MPEG-PS start code (pack header / sequence header / video "
            "PES) found in the intact zone: structure not recognised for "
            "this file")

    lost_bytes = start_off - enc_header_len
    log(f"  MPEG-PS resynchronisation: first usable {start_kind} found at "
        f"offset {start_off}"
        + (f" ({lost_bytes} unusable byte(s) right after the encrypted "
           f"zone, ignored)" if lost_bytes else ""))

    with open(filepath, 'rb') as fh:
        fh.seek(start_off)
        sample = fh.read(min(4 * 1024 * 1024, video_len - start_off))
    seq_info = parse_mpeg_sequence_header_wh(sample)
    if seq_info:
        fps_txt = (f"{seq_info['fps']:.3f} fps (code {seq_info['framerate_code']})"
                   if seq_info['fps'] else
                   f"frame rate code {seq_info['framerate_code']} non-standard")
        log(f"     resolution/frame rate recovered DIRECTLY from the MPEG "
            f"sequence header (in the clear): {seq_info['width']}x{seq_info['height']}, {fps_txt}")
    else:
        log("     [WARNING] no video sequence header (00 00 01 B3) found in "
            "the first MB after the resynchronisation point -- "
            "resolution/frame rate not verified, but the stream will be "
            "copied as is (an MPEG-PS reader resynchronises on the "
            "following start codes anyway).")

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        src.seek(start_off)
        remaining = video_len - start_off
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)

    return True, {
        'start_off': start_off, 'start_kind': start_kind,
        'lost_bytes': lost_bytes,
        'width': seq_info['width'] if seq_info else None,
        'height': seq_info['height'] if seq_info else None,
        'fps': seq_info['fps'] if seq_info else None,
    }




# ==========================================================================
# SECTION MPEG-TS (.ts / .m2ts / .mts) -- and the fallback for mislabelled
# .mkv/.webm files whose REAL content is a raw TS stream
# ==========================================================================
#
# Found on a real sample: some files named ".mkv" are NOT Matroska/EBML
# at all -- they are raw MPEG-2 Transport Streams (fixed 188-byte
# packets, each starting with the 0x47 sync byte), simply named with the
# wrong extension by the capture/download tool. That is why no Matroska
# Cluster (0x1F43B675) is ever found in those files: the format was
# never Matroska.
#
# Like an MPEG-PS stream (see previous section), a TS stream is
# self-synchronising and needs NO external index table to be read: PAT
# (Program Association Table, PID 0) and PMT (Program Map Table) are
# repeated periodically in the clear all along the stream (not only at
# the start) so that a decoder can "join" the stream at any time --
# exactly the situation of a file whose very start is lost in the
# encrypted zone. Strategy: resynchronise on the first valid 0x47 packet
# (confirmed over several tens of consecutive packets to avoid a false
# positive), then copy the whole stream as is from that point.
#
# Start-point refinement (verified on a real sample, declared .mp4 by
# the footer but real content in TS, ~2h09, header corrupted over
# ~258 KB + 3 corrupted blocks at ~25/50/75 %): the 1st 0x47 alignment
# can fall in the MIDDLE of a truncated PES packet (the encrypted-zone
# boundary cuts the PES right in the middle). A stream that starts with
# those orphan fragments references SPS/PPS that were never declared:
# the ffmpeg demultiplexer fails ("non-existing PPS referenced" /
# "no frame!"), the MP4 remux does not pass its verification and the
# file stayed in error. find_ts_first_keyframe then looks for the first
# CLEAN key frame (video PES starting with SPS+PPS+IDR, as produced by a
# standard encoder that repeats SPS/PPS before each IDR) just after the
# alignment, and the copy starts HERE: the codec config is present from
# the first byte, the remux extracts it cleanly, and only the orphan
# fragments preceding the key frame (undecodable anyway) are skipped.

TS_PACKET_SIZE = 188
TS_SYNC_BYTE = 0x47

TS_STREAM_TYPE_NAMES = {
    0x01: 'MPEG-1 video', 0x02: 'MPEG-2 video',
    0x03: 'MPEG-1 audio', 0x04: 'MPEG-2 audio',
    0x06: 'private data (private PES)',
    0x0f: 'AAC audio (ADTS)', 0x11: 'AAC audio (LATM)',
    0x1b: 'H.264/AVC video', 0x24: 'H.265/HEVC video',
    0x15: 'metadata (PES)', 0x81: 'AC-3 audio',
}


def find_ts_sync(filepath, video_len, search_start, search_cap=8 * 1024 * 1024,
                  min_consecutive_packets=64):
    """Look from `search_start` for a valid TS packet alignment: a 0x47
    byte that repeats every 188 bytes over at least `min_consecutive_packets`
    consecutive packets (prevents a lone 0x47 byte, which can appear by
    chance, from being taken for a real synchronisation point). Returns the
    absolute offset found, or None."""
    cap = min(search_cap, max(0, video_len - search_start))
    with open(filepath, 'rb') as fh:
        fh.seek(search_start)
        data = fh.read(cap)

    need = TS_PACKET_SIZE * min_consecutive_packets
    limit = len(data) - need
    for off in range(0, max(0, limit)):
        if data[off] != TS_SYNC_BYTE:
            continue
        window = data[off:off + need]
        if all(window[i] == TS_SYNC_BYTE for i in range(0, len(window), TS_PACKET_SIZE)):
            return search_start + off
    return None


def _ts_packet_fields(pkt):
    pusi = (pkt[1] >> 6) & 1
    pid = ((pkt[1] & 0x1f) << 8) | pkt[2]
    afc = (pkt[3] >> 4) & 3
    payload_start = 4
    if afc in (2, 3):
        af_len = pkt[4]
        payload_start = 5 + af_len
    payload = pkt[payload_start:] if afc in (1, 3) else b''
    return pusi, pid, payload


def parse_ts_pat_pmt(filepath, sync_off, video_len, search_cap=4 * 1024 * 1024):
    """Walk the TS packets from `sync_off` to find the PAT (PID 0) then
    the PMT it designates, and identify the elementary streams (PID +
    stream type). Returns
    {'pmt_pid', 'pcr_pid', 'streams': [{'pid', 'stream_type'}, ...]}
    or None if not found within `search_cap` bytes."""
    cap = min(search_cap, max(0, video_len - sync_off))
    with open(filepath, 'rb') as fh:
        fh.seek(sync_off)
        data = fh.read(cap)
    n = len(data) - (len(data) % TS_PACKET_SIZE)

    pmt_pid = None
    for off in range(0, n, TS_PACKET_SIZE):
        pkt = data[off:off + TS_PACKET_SIZE]
        if pkt[0] != TS_SYNC_BYTE:
            continue
        pusi, pid, payload = _ts_packet_fields(pkt)
        if pid == 0 and pusi and payload:
            pointer = payload[0]
            sec = payload[1 + pointer:]
            if len(sec) < 8:
                continue
            section_length = ((sec[1] & 0x0f) << 8) | sec[2]
            prog_data = sec[8:3 + section_length - 4]
            for i in range(0, len(prog_data) - 3, 4):
                program_number = (prog_data[i] << 8) | prog_data[i + 1]
                pid_field = ((prog_data[i + 2] & 0x1f) << 8) | prog_data[i + 3]
                if program_number != 0:
                    pmt_pid = pid_field
                    break
            if pmt_pid:
                break
    if pmt_pid is None:
        return None

    for off in range(0, n, TS_PACKET_SIZE):
        pkt = data[off:off + TS_PACKET_SIZE]
        if pkt[0] != TS_SYNC_BYTE:
            continue
        pusi, pid, payload = _ts_packet_fields(pkt)
        if pid == pmt_pid and pusi and payload:
            pointer = payload[0]
            sec = payload[1 + pointer:]
            if len(sec) < 12:
                continue
            section_length = ((sec[1] & 0x0f) << 8) | sec[2]
            pcr_pid = ((sec[8] & 0x1f) << 8) | sec[9]
            program_info_length = ((sec[10] & 0x0f) << 8) | sec[11]
            idx = 12 + program_info_length
            end = 3 + section_length - 4
            streams = []
            while idx + 5 <= end and idx + 5 <= len(sec):
                stream_type = sec[idx]
                elem_pid = ((sec[idx + 1] & 0x1f) << 8) | sec[idx + 2]
                es_info_length = ((sec[idx + 3] & 0x0f) << 8) | sec[idx + 4]
                streams.append({'stream_type': stream_type, 'pid': elem_pid})
                idx += 5 + es_info_length
            return {'pmt_pid': pmt_pid, 'pcr_pid': pcr_pid, 'streams': streams}
    return None


def extract_ts_es_sample(filepath, sync_off, video_len, pid, max_bytes=2 * 1024 * 1024,
                          search_cap=8 * 1024 * 1024):
    """Reassemble the payload bytes (PES) of a given PID, from the first
    PUSI=1 packet encountered (start of a PES packet), until the next PES
    packet starts or `max_bytes` is reached. Returns the raw bytes (PES
    header included) or b'' if nothing is found."""
    cap = min(search_cap, max(0, video_len - sync_off))
    with open(filepath, 'rb') as fh:
        fh.seek(sync_off)
        data = fh.read(cap)
    n = len(data) - (len(data) % TS_PACKET_SIZE)
    out = bytearray()
    started = False
    for off in range(0, n, TS_PACKET_SIZE):
        pkt = data[off:off + TS_PACKET_SIZE]
        if pkt[0] != TS_SYNC_BYTE:
            continue
        pusi, pid_here, payload = _ts_packet_fields(pkt)
        if pid_here != pid:
            continue
        if pusi:
            if started:
                break
            started = True
        if started:
            out.extend(payload)
            if len(out) >= max_bytes:
                break
    return bytes(out)


def _pes_payload(data):
    """Strip the PES header (00 00 01 + stream_id + length + flags +
    PES_header_data_length) from a buffer starting with a PES packet;
    returns the ES bytes that follow (or `data` as is if the PES header
    is not recognised)."""
    if len(data) < 9 or data[0:3] != b'\x00\x00\x01':
        return data
    pes_header_data_length = data[8]
    return data[9 + pes_header_data_length:]


def _find_annexb_nal(data, nal_type, max_scan=2 * 1024 * 1024):
    """Find the first Annex-B NAL (start code 00 00 01 or 00 00 00 01) of
    the requested type in `data`. Returns the NAL bytes WITHOUT the
    header byte (ready for parse_sps_dimensions), or None."""
    limit = min(len(data), max_scan)
    i = 0
    while i < limit - 4:
        start = None
        if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
            start = i + 3
        elif data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 0 and \
                i + 3 < limit and data[i + 3] == 1:
            start = i + 4
        if start is None:
            i += 1
            continue
        if start >= limit:
            break
        nal_byte = data[start]
        if (nal_byte & 0x1f) == nal_type:
            j = start + 1
            end = limit
            while j < limit - 2:
                if data[j] == 0 and data[j + 1] == 0 and data[j + 2] in (0, 1):
                    end = j
                    break
                j += 1
            return data[start + 1:end]
        i = start
    return None


def _pes_nal_positions(buf, max_scan=65536, max_nals=8):
    """Walk the start of an H.264 video PES payload (Annex-B) and
    return the list (offset, NAL type) of the first `max_nals` NAL
    units, in order, within the first `max_scan` bytes (both start
    codes 00 00 01 and 00 00 00 01 are recognised)."""
    out = []
    i = 0
    L = min(len(buf), max_scan)
    while i + 4 <= L and len(out) < max_nals:
        if buf[i] == 0 and buf[i + 1] == 0 and buf[i + 2] == 1:
            out.append((i + 3, buf[i + 3] & 0x1f))
            i += 4
        elif i + 5 <= L and buf[i] == 0 and buf[i + 1] == 0 and \
                buf[i + 2] == 0 and buf[i + 3] == 1:
            out.append((i + 4, buf[i + 4] & 0x1f))
            i += 5
        else:
            i += 1
    return out


def _pes_starts_with_clean_keyframe(buf, max_scan=65536, max_nals=8):
    """Signature of a "clean" key frame at the very start of an H.264
    video PES: an SPS (NAL 7) followed by a PPS (NAL 8) followed by an
    IDR (NAL 5), in that order, among the first NAL units (other NALs --
    SEI for example -- may be interleaved). This is exactly what a
    standard encoder that repeats SPS/PPS before each IDR produces: a
    PES that starts this way is decodable from its first byte, whereas a
    PES that begins in the middle of a picture (orphan fragment of a
    truncated PES) references parameters that were never declared."""
    pos = {}
    for off, nal_type in _pes_nal_positions(buf, max_scan, max_nals):
        if nal_type not in pos:
            pos[nal_type] = off
    return 7 in pos and 8 in pos and 5 in pos and \
        pos[7] < pos[8] < pos[5]


def find_ts_first_keyframe(filepath, sync_off, video_len,
                           search_cap=16 * 1024 * 1024,
                           max_pes_bytes=256 * 1024):
    """From `sync_off` (a valid TS packet alignment), look for the FIRST
    video PUSI packet whose PES starts with the signature of a clean key
    frame (SPS+PPS+IDR, see _pes_starts_with_clean_keyframe).

    Why: the 0x47 alignment found by find_ts_sync can fall in the middle
    of a truncated PES packet (the encrypted-zone boundary, or a
    corrupted block, cuts the PES right in the middle). Copying from that
    raw alignment makes the stream start with orphan fragments that
    reference SPS/PPS which were never declared: the ffmpeg demultiplexer
    then reports "non-existing PPS referenced" / "no frame!" and the
    following MP4 remux does not pass its verification, the file being
    left in error. Starting at the first clean key frame, on the other
    hand, guarantees the presence of the codec configuration at the very
    start of the stream: the remux extracts it cleanly and the first
    pictures decode without error. The only loss is the few tens/thousands
    of bytes of orphan fragments that preceded the key frame -- which
    were not decodable anyway (verified on a real sample: start refined
    to 60 KB past the 1st alignment, 2h09 MP4 remux valid end to end).

    Returns {'off': absolute offset of the TS packet (188-byte aligned),
    'pid': video PID, 'sps': SPS bytes without the header byte (or
    None)} if a clean key frame is found within the first `search_cap`
    bytes, otherwise None (the caller then falls back on the standard
    behaviour: start on the raw alignment)."""
    cap = min(search_cap, max(0, video_len - sync_off))
    if cap <= 0:
        return None
    with open(filepath, 'rb') as fh:
        fh.seek(sync_off)
        data = fh.read(cap)
    n = len(data) - (len(data) % TS_PACKET_SIZE)
    i = 0
    while i < n:
        pkt = data[i:i + TS_PACKET_SIZE]
        if pkt[0] != TS_SYNC_BYTE:
            # Desynchronisation (corrupted block): find the next valid
            # packet boundary and resume the search -- like a
            # demultiplexer that "joins" the stream.
            i += 1
            while i < n and data[i] != TS_SYNC_BYTE:
                i += 1
            continue
        pusi, pid, payload = _ts_packet_fields(pkt)
        if pusi and len(payload) >= 9 and payload[:3] == b'\x00\x00\x01':
            # PES of any stream_id: the SPS+PPS+IDR NAL signature below
            # acts as the filter. Do NOT restrict to the "video"
            # 0xC0-0xDF range of the standard -- observed on a real
            # sample, the DVR multiplexer uses "non-standard" stream_id
            # values (video in 0xE0, which is the audio range of the
            # standard, and ADTS audio in 0xC0): the NAL signature is the
            # only reliable criterion, audio cannot produce it by chance
            # (verified: an audio PES from that same stream returns a
            # single bogus NAL of type 3 and is correctly rejected). The
            # START of the payload is reassembled by following the
            # continuation packets of the same PID (a PES is often split
            # over several 188-byte TS packets).
            parts = [payload]
            total = len(payload)
            j = i + TS_PACKET_SIZE
            while total < max_pes_bytes and j + TS_PACKET_SIZE <= n:
                nxt = data[j:j + TS_PACKET_SIZE]
                if nxt[0] != TS_SYNC_BYTE:
                    break
                pusi2, pid2, payload2 = _ts_packet_fields(nxt)
                if pusi2 or pid2 != pid or not payload2:
                    break
                parts.append(payload2)
                total += len(payload2)
                j += TS_PACKET_SIZE
            buf = b''.join(parts)
            if _pes_starts_with_clean_keyframe(buf):
                sps = _find_annexb_nal(buf, 7)
                return {'off': sync_off + i, 'pid': pid, 'sps': sps}
        i += TS_PACKET_SIZE
    return None


def repair_ts_case_b(filepath, out_path, video_len, enc_header_len,
                      progress=None):
    """Rebuild an MPEG Transport Stream (.ts) whose very start is lost
    (encrypted zone) by resynchronising on the first valid TS packet
    alignment and then copying the whole stream as is down to the end of
    the payload. See the section header for the general strategy.

    Refinement (verified on a real sample: declared .mp4 by the footer
    but real content in TS, ~2h09, header corrupted over ~258 KB
    + 3 corrupted blocks at ~25 %/50 %/75 % down the stream): the 1st
    0x47 alignment can fall in the MIDDLE of a truncated PES packet. The
    first clean key frame (video PES starting with SPS+PPS+IDR) is then
    looked for just after the alignment and the copy is started from
    HERE rather than from the raw alignment: the codec configuration is
    present from the first byte of the rebuilt stream, the MP4 remux
    extracts it cleanly (instead of failing with "non-existing PPS
    referenced"), and the first pictures decode without error -- only
    the orphan fragments that preceded the key frame (not decodable
    anyway) are skipped. If no clean key frame is found in the analysed
    window, we fall back on the raw alignment (original behaviour)."""
    sync_off = find_ts_sync(filepath, video_len, enc_header_len)
    if sync_off is None:
        raise ValueError(
            "no TS packet alignment (0x47 every 188 bytes, confirmed over "
            "several tens of consecutive packets) found in the intact "
            "zone: structure not recognised for this file")

    lost_bytes = sync_off - enc_header_len
    log(f"  TS resynchronisation: valid packet alignment found at "
        f"offset {sync_off}"
        + (f" ({lost_bytes} unusable byte(s) right after the encrypted "
           f"zone, ignored)" if lost_bytes else ""))

    # --- Refined start point: first clean key frame (SPS+PPS+IDR)
    kf = find_ts_first_keyframe(filepath, sync_off, video_len)
    if kf is not None:
        start_off = kf['off']
        log(f"  [SPECIAL] refined start point: first clean key frame "
            f"(video PES starting with SPS+PPS+IDR) at offset "
            f"{start_off} -- the 1st 0x47 alignment ({sync_off}) fell "
            f"in the middle of a truncated PES packet; the "
            f"{start_off - sync_off} bytes of orphan fragments before "
            f"the key frame were not decodable anyway: starting from the "
            f"key frame guarantees that the codec config is present from "
            f"the start of the stream (clean MP4 remux, without "
            f"'non-existing PPS' errors).")
    else:
        start_off = sync_off
        log("  [INFO] no clean key frame (SPS+PPS+IDR) located in "
            "the analysed window: starting on the 1st valid packet "
            "alignment (standard behaviour).")

    pat_pmt = parse_ts_pat_pmt(filepath, sync_off, video_len)
    video_pid = None
    width = height = None
    if pat_pmt:
        kinds = []
        for s in pat_pmt['streams']:
            name = TS_STREAM_TYPE_NAMES.get(s['stream_type'], f"type {s['stream_type']:#04x}")
            kinds.append(f"PID {s['pid']} ({name})")
            if s['stream_type'] in (0x1b, 0x24) and video_pid is None:
                video_pid = s['pid']
        log(f"  PAT/PMT recovered IN THE CLEAR (repeated periodically in "
            f"the stream, as the TS standard requires): {', '.join(kinds)}")
    else:
        log("  [WARNING] PAT/PMT not found in the analysed window "
            "(malformed or absent -- already observed on a real "
            "sample) -- stream copied as is, but track identification "
            "could not be confirmed "
            "(a TS reader may still find them further down in "
            "the stream).")
        if kf is not None and kf.get('pid') is not None:
            video_pid = kf['pid']
            log(f"     video PID inferred from the key frame packet "
                f"located: {video_pid}")

    if video_pid is not None:
        try:
            # If the key frame has already been located, its SPS is
            # already extracted (faster and more reliable: it comes from
            # a COMPLETE PES, unlike a reassembly that may cut in the
            # middle of a PES).
            sps = kf.get('sps') if kf else None
            if sps is None:
                es = extract_ts_es_sample(filepath, sync_off, video_len,
                                          video_pid)
                sps = _find_annexb_nal(_pes_payload(es), 7)
            if sps:
                wh = parse_sps_dimensions(sps)
                if wh:
                    width, height = wh
                    log(f"     resolution recovered DIRECTLY from the H.264 "
                        f"SPS in the clear (PID {video_pid}): {width}x{height}")
        except Exception:
            pass  # purely informational, must never make the rebuild fail

    CHUNK = 32 * 1024 * 1024
    with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
        src.seek(start_off)
        remaining = video_len - start_off
        copied = 0
        while remaining > 0:
            n = src.read(min(CHUNK, remaining))
            if not n:
                break
            dst.write(n)
            remaining -= len(n)
            copied += len(n)
            if progress and copied % (256 * 1024 * 1024) < CHUNK:
                progress(copied)

    return True, {
        'sync_off': sync_off, 'start_off': start_off,
        'clean_start': kf is not None,
        'lost_bytes': lost_bytes,
        'width': width, 'height': height,
        'streams': pat_pmt['streams'] if pat_pmt else None,
    }


def remux_ts_reconstructed(ts_path, timeout=600, verify_seconds=8):
    """Does it rebuild a .ts that is REALLY readable? Observed empirically
    (real case from our test batch): a .ts obtained by a simple byte copy
    from a resynchronisation point (see repair_ts_case_b)
    contains a perfectly valid H.264 stream -- identical SPS/PPS
    correctly repeated before each IDR, verified NAL by NAL -- and
    decodes WITHOUT A SINGLE ERROR once extracted into a raw elementary
    stream (`ffmpeg -c copy file.h264`). Yet the MPEG-TS DEMULTIPLEXER
    of ffmpeg fails to decode it IN PLACE (`ffmpeg -i file.ts`),
    with "non-existing PPS X referenced" errors repeating over
    the whole file: the structure of the TS packets themselves (continuity,
    PES) around the resynchronisation point seems to unsettle its
    internal demultiplexing state, even though the video bytes are intact.

    Reliable workaround (verified on a real sample, ~21 minutes, clean
    decode confirmed from start to finish
    afterwards): REMUX the .ts (stream copy, `-c copy`, no
    re-encode so no loss and no significant CPU cost) into a
    fresh MP4 container. The H.264/AAC stream is bit-for-bit identical;
    only the container changes, and the new container itself does decode
    normally.

    Replaces ts_path with an .mp4 of the same name if the remux AND the
    verification (error-free decode of the first `verify_seconds`
    seconds, on the new file) both succeed; the
    original .ts is then deleted. Returns the final path used
    (.mp4 if remux+verification OK, .ts unchanged otherwise) and a message
    (None if everything went well, otherwise the reason for falling back on
    the .ts). Never raises: a failed remux is only a fallback,
    not a failure of the rebuild itself (the .ts remains the
    result, as produced before this step)."""
    if shutil.which('ffmpeg') is None:
        return ts_path, ("ffmpeg not found in PATH: MP4 remux "
                          "impossible, .ts kept as is (may not "
                          "decode correctly with some players -- "
                          "see the note in the README)")
    mp4_path = os.path.splitext(ts_path)[0] + '.mp4'
    try:
        proc = subprocess.run(
            ['ffmpeg', '-y', '-v', 'error', '-i', ts_path,
             '-c', 'copy', '-movflags', '+faststart', mp4_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=timeout)
    except Exception as e:
        return ts_path, f"MP4 remux impossible ({e}): .ts kept as is"
    if proc.returncode != 0 or not os.path.exists(mp4_path):
        err = proc.stderr.decode('utf-8', 'replace').strip().splitlines()
        err_tail = ' | '.join(err[-3:]) if err else f"return code {proc.returncode}"
        return ts_path, f"MP4 remux failed ({err_tail}): .ts kept as is"

    try:
        verify = subprocess.run(
            ['ffmpeg', '-v', 'error', '-i', mp4_path, '-t', str(verify_seconds),
             '-f', 'null', '-'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        verify_lines = verify.stderr.decode('utf-8', 'replace').strip().splitlines()
    except Exception as e:
        verify_lines = [f"verification failed ({e})"]

    # "non monotonically increasing dts" is a muxing warning
    # (DTS order for the -f null write, unrelated to
    # frame-by-frame decoding) observed even on SAFE remuxes
    # confirmed readable end to end (verified on a real sample): it is
    # ignored here. On the other hand any error
    # actually affecting decoding (slice header, PPS/SPS,
    # invalid data, lost frames) makes the verification fail.
    BENIGN_SUBSTRINGS = ('non monotonically increasing dts',)
    real_errors = [ln for ln in verify_lines
                   if ln.strip() and not any(b in ln for b in BENIGN_SUBSTRINGS)]

    if real_errors:
        # The remux produced a file, but decoding still reports
        # real errors: this MP4 is NOT trusted, the original .ts is
        # kept (already produced by repair_ts_case_b)
        # and the remux attempt is deleted.
        try:
            os.remove(mp4_path)
        except OSError:
            pass
        return ts_path, (f"MP4 remux produced but decode verification "
                          f"still in error ({real_errors[0]!r}): .ts "
                          f"kept as is")

    try:
        os.remove(ts_path)
    except OSError:
        pass
    return mp4_path, None


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

# ------------------------------------------------------------ ASF (WMV/WMA)
# An ASF file starts with the Header object (a 30-byte header) which
# contains a series of objects (File Properties, one Stream Properties
# per track, Header Extension, Codec List, ...), then the Data object
# (FIXED-size packets) and finally, optionally, one or more index objects.
# No absolute offset is stored anywhere (the indexes reference packet
# NUMBERS): the header can therefore be replaced by a header of a
# different size without touching the rest of the file.
#
# When the ASF header extends past the encrypted zone (real case: 5265-byte
# header, 4096-byte zone), the objects essential to decoding are often
# intact -- in particular the Stream Properties, which carry the complete
# codec config (BITMAPINFOHEADER + WMV3/VC-1 private data, WAVEFORMATEX
# + WMA private data). Only the Header object header itself, File Properties
# and Header Extension (placed first) are lost; all of them can be recomputed:
#   - File Properties: File ID copied from the Data object, packet count and
#     size read from the Data object, duration from the Simple Index (or the
#     last packet send time), preroll from the 1st packet, bitrate from
#     Stream Bitrate Properties;
#   - Header Extension: empty object (mandatory per the standard, its content
#     -- languages, extended metadata -- is not needed for playback).

def _asf_guid(s):
    """Text GUID -> 16 bytes in ASF order (first 3 fields in
    little-endian, like uuid.UUID(s).bytes_le)."""
    h = s.replace('-', '')
    b = bytes.fromhex(h)
    return b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:]


ASF_HEADER = _asf_guid('75B22630-668E-11CF-A6D9-00AA0062CE6C')
ASF_DATA = _asf_guid('75B22636-668E-11CF-A6D9-00AA0062CE6C')
ASF_FILE_PROPERTIES = _asf_guid('8CABDCA1-A947-11CF-8EE4-00C00C205365')
ASF_STREAM_PROPERTIES = _asf_guid('B7DC0791-A9B7-11CF-8EE6-00C00C205365')
ASF_HEADER_EXTENSION = _asf_guid('5FBF03B5-A92E-11CF-8EE3-00C00C205365')
ASF_RESERVED_1 = _asf_guid('ABD3D211-A9BA-11CF-8EE6-00C00C205365')
ASF_STREAM_BITRATE = _asf_guid('7BF875CE-468D-11D1-8D82-006097C9A2B2')
ASF_SIMPLE_INDEX = _asf_guid('33000890-E5B1-11CF-89F4-00A0C90349CB')
ASF_VIDEO_MEDIA = _asf_guid('BC19EFC0-5B4D-11CF-A8FD-00805F5C442B')
ASF_AUDIO_MEDIA = _asf_guid('F8699E40-5B4D-11CF-A8FD-00805F5C442B')
# Top-level header objects recognised for chaining
ASF_HEADER_CHILDREN = {_asf_guid(s) for s in (
    '8CABDCA1-A947-11CF-8EE4-00C00C205365',  # File Properties
    'B7DC0791-A9B7-11CF-8EE6-00C00C205365',  # Stream Properties
    '5FBF03B5-A92E-11CF-8EE3-00C00C205365',  # Header Extension
    '86D15240-311D-11D0-A3A4-00A0C90348F6',  # Codec List
    '1EFB1A30-0B62-11D0-A39B-00A0C90348F6',  # Script Command
    'F487CD01-A951-11CF-8EE6-00C00C205365',  # Marker
    'D6FD9EBA-7AB2-11D0-A3A4-00A0C90348F6',  # Bitrate Mutual Exclusion
    '75B22635-668E-11CF-A6D9-00AA0062CE6C',  # Error Correction
    '75B22633-668E-11CF-A6D9-00AA0062CE6C',  # Content Description
    'D2D0A440-E307-11D2-97F0-00A0C95EA850',  # Extended Content Description
    '2211B3FA-BD23-11D2-B4B7-00A0C955FC6E',  # Content Branding
    '7BF875CE-468D-11D1-8D82-006097C9A2B2',  # Stream Bitrate Properties
    '2211B3FB-BD23-11D2-B4B7-00A0C955FC6E',  # Content Encryption
    '298AE614-2622-4C17-B935-DAE07EE9289C',  # Extended Content Encryption
    '2211B3FC-BD23-11D2-B4B7-00A0C955FC6E',  # Digital Signature
    '1806D474-CADF-4509-A4BA-9AABCB96AAE8',  # Padding
)}


def _asf_first_presentation_ms(packet):
    """Presentation time (ms) of the 1st media object of the 1st data
    packet -- by ASF construction, equal to the file preroll. None if the
    packet cannot be parsed."""
    try:
        pos = 0
        if packet[0] & 0x80:                     # Error Correction present
            pos += 1 + (packet[0] & 0x0F)
        ltf, prop = packet[pos], packet[pos + 1]
        pos += 2
        size_of = lambda code: (0, 1, 2, 4)[code & 3]
        pos += size_of(ltf >> 5) + size_of(ltf >> 1) + size_of(ltf >> 3)
        pos += 6                                 # send time + duration
        if ltf & 1:                              # several payloads
            pos += 1
        pos += 1                                 # stream number
        pos += size_of(prop >> 4)                # media object number
        off_len = size_of(prop >> 2)
        offset_field = packet[pos:pos + off_len]
        pos += off_len
        rep_len_size = size_of(prop)
        rep_len = int.from_bytes(packet[pos:pos + rep_len_size], 'little')
        pos += rep_len_size
        if rep_len >= 8:
            return struct.unpack('<I', packet[pos + 4:pos + 8])[0]
        if rep_len == 1 and off_len:             # compressed payload
            return int.from_bytes(offset_field, 'little')
    except (IndexError, struct.error):
        return None
    return None


def _asf_stream_summary(obj):
    """Readable summary of a Stream Properties object (type, codec,
    dimensions/rate); None if it cannot be parsed."""
    try:
        stype = obj[24:40]
        tsd = obj[78:]
        if stype == ASF_VIDEO_MEDIA:
            w, h = struct.unpack('<II', tsd[0:8])
            fourcc = tsd[11 + 16:11 + 20].decode('ascii', 'replace')
            return {'kind': 'video', 'width': w, 'height': h, 'codec': fourcc}
        if stype == ASF_AUDIO_MEDIA:
            tag, ch, rate = struct.unpack('<HHI', tsd[0:8])
            return {'kind': 'audio', 'codec': f"0x{tag:04X}", 'channels': ch,
                    'sample_rate': rate}
        return {'kind': 'other'}
    except struct.error:
        return None


def repair_asf_case_b(filepath, out_path, video_len, enc_header_len):
    """Rebuild an ASF file (.wmv/.wma/.asf) whose header is lost,
    provided the header objects located AFTER the encrypted zone still
    contain the Stream Properties (see the section header).
    Returns (True, infos) or (False, failure message)."""
    with open(filepath, 'rb') as fh:
        head = fh.read(min(video_len, 4 * 1024 * 1024))

    dpos = head.find(ASF_DATA, enc_header_len)
    if dpos < 0:
        return False, ("ASF Data object not found in the intact zone (within "
                       "the first 4 MB): the ASF header probably fits "
                       "entirely inside the encrypted zone, with the codec "
                       "config -- not reconstructible without a reference "
                       "file.")
    if dpos + 50 > len(head):
        return False, "truncated ASF Data object"
    data_size = struct.unpack('<Q', head[dpos + 16:dpos + 24])[0]
    file_id = head[dpos + 24:dpos + 40]
    n_packets = struct.unpack('<Q', head[dpos + 40:dpos + 48])[0]
    if not n_packets or data_size < 50 or (data_size - 50) % n_packets:
        return False, (f"inconsistent ASF Data object (size {data_size}, "
                       f"{n_packets} packets): packet size not "
                       f"deductible.")
    packet_size = (data_size - 50) // n_packets
    if dpos + data_size > video_len:
        return False, (f"ASF Data object ({data_size} bytes from "
                       f"{dpos}) goes past the end of the data ({video_len}).")

    # First intact header object: the first known GUID, after the encrypted
    # zone, from which the object chain (GUID + size) lands
    # EXACTLY on the Data object -- a byte of the truncated object that
    # happens to look like a GUID does not pass this check.
    candidates = sorted(m.start() for g in ASF_HEADER_CHILDREN
                        for m in re.finditer(re.escape(g), head[:dpos])
                        if m.start() >= enc_header_len)
    first = None
    for cand in candidates:
        pos = cand
        while pos < dpos and head[pos:pos + 16] in ASF_HEADER_CHILDREN:
            size = struct.unpack('<Q', head[pos + 16:pos + 24])[0]
            if size < 24:
                break
            pos += size
        if pos == dpos:
            first = cand
            break
    if first is None:
        return False, ("no chain of intact ASF header objects leading "
                       "to the Data object was found after the encrypted "
                       "zone.")

    objects = []
    pos = first
    while pos < dpos:
        size = struct.unpack('<Q', head[pos + 16:pos + 24])[0]
        objects.append(head[pos:pos + size])
        pos += size
    streams = [_asf_stream_summary(o) for o in objects
               if o[:16] == ASF_STREAM_PROPERTIES]
    if not streams:
        return False, ("ASF Stream Properties lost (inside the encrypted "
                       "zone): track codec config not "
                       "reconstructible without a reference file.")
    have_fp = any(o[:16] == ASF_FILE_PROPERTIES for o in objects)
    have_hx = any(o[:16] == ASF_HEADER_EXTENSION for o in objects)

    # Duration: Simple Index (interval x number of entries) if present just
    # after the Data object, otherwise send time + duration of the last packet.
    with open(filepath, 'rb') as fh:
        fh.seek(dpos + data_size)
        trailer = fh.read(min(64, video_len - dpos - data_size))
        fh.seek(dpos + 50 + (n_packets - 1) * packet_size)
        last_packet = fh.read(packet_size)
    play_100ns = None
    duration_source = None
    if trailer[:16] == ASF_SIMPLE_INDEX and len(trailer) >= 56:
        interval = struct.unpack('<Q', trailer[40:48])[0]
        count = struct.unpack('<I', trailer[52:56])[0]
        if interval and count:
            play_100ns = interval * count
            duration_source = "Simple Index"
    first_packet = head[dpos + 50:dpos + 50 + packet_size]
    preroll = _asf_first_presentation_ms(first_packet)
    if preroll is None or preroll > 60000:
        preroll = 3000
    if play_100ns is not None:
        # the Simple Index is indexed in PRESENTATION time, preroll
        # included: the played duration is what is left once the preroll
        # is removed (verified: 1561 one-second entries for 1555 s of media
        # with a 5 s preroll)
        play_100ns = max(0, play_100ns - preroll * 10000)
    if play_100ns is None:
        try:
            p = 1 + (last_packet[0] & 0x0F) if last_packet[0] & 0x80 else 0
            ltf = last_packet[p]
            size_of = lambda code: (0, 1, 2, 4)[code & 3]
            p += 2 + size_of(ltf >> 5) + size_of(ltf >> 1) + size_of(ltf >> 3)
            send_ms, dur_ms = struct.unpack('<IH', last_packet[p:p + 6])
            play_100ns = max(0, send_ms + dur_ms - preroll) * 10000
            duration_source = "last packet send time"
        except (IndexError, struct.error):
            play_100ns = 0
            duration_source = "unknown"

    bitrate = 0
    for o in objects:
        if o[:16] == ASF_STREAM_BITRATE:
            n = struct.unpack('<H', o[24:26])[0]
            for k in range(n):
                bitrate += struct.unpack('<I', o[26 + 6 * k + 2:26 + 6 * k + 6])[0]
    if not bitrate and play_100ns:
        bitrate = int(data_size * 8 / (play_100ns / 1e7))

    new_objects = []
    if not have_fp:
        play = play_100ns + preroll * 10000
        creation = int((time.time() + 11644473600) * 1e7)  # FILETIME
        new_objects.append(
            ASF_FILE_PROPERTIES + struct.pack('<Q', 104) + file_id
            + struct.pack('<QQQQQQ', 0, creation, n_packets, play, play, preroll)
            + struct.pack('<IIII', 0x2, packet_size, packet_size, bitrate))
    if not have_hx:
        new_objects.append(ASF_HEADER_EXTENSION + struct.pack('<Q', 46)
                           + ASF_RESERVED_1 + struct.pack('<HI', 6, 0))
    new_objects.extend(objects)
    body_len = sum(len(o) for o in new_objects)
    header = (ASF_HEADER + struct.pack('<QI', 30 + body_len, len(new_objects))
              + b'\x01\x02')
    total = len(header) + body_len + (video_len - dpos)
    if not have_fp:
        fp = new_objects[0]
        new_objects[0] = fp[:40] + struct.pack('<Q', total) + fp[48:]

    with open(filepath, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        for o in new_objects:
            fo.write(o)
        fi.seek(dpos)
        remaining = video_len - dpos
        while remaining:
            buf = fi.read(min(remaining, 8 * 1024 * 1024))
            if not buf:
                break
            fo.write(buf)
            remaining -= len(buf)

    return True, {
        'header_len_orig': dpos,
        'kept_from': first,
        'kept_objects': len(objects),
        'rebuilt': [n for n, missing in (('File Properties', not have_fp),
                                         ('Header Extension', not have_hx)) if missing],
        'streams': streams,
        'packets': n_packets,
        'packet_size': packet_size,
        'duration_s': play_100ns / 1e7,
        'duration_source': duration_source,
        'preroll_ms': preroll,
    }


# --------------------------------------------------------------------------
# SECTION JPEG IMAGE (.jpg / .jpeg)
# --------------------------------------------------------------------------
#
# The .jpg files in _error folders are not videos: they are photos
# whose header is LONG (EXIF with thumbnail + IPTC + ICC profile, often
# more than 4 KB). The leading encrypted zone (4096 bytes) then only
# destroys the START of that header: the SOI, the start of the EXIF and the
# thumbnail it contains. The quantisation tables, the SOF (dimensions), the
# Huffman tables and the SOS of the MAIN IMAGE remain intact in the
# clear, along with the whole of its entropy stream down to the final EOI.
# Gluing an SOI back in front of the start of that header chain
# is therefore enough -- verified by decoding -- to recover the original image.
#
# Measured on the corpus: most of the _error images (84 %) fall in this
# case. The others have their header entirely
# inside the encrypted zone (dimensions AND tables lost): explicit failure,
# no heuristic is attempted (nothing would allow decoding).
JPEG_SOF_MARKERS = (0xC0, 0xC1, 0xC2)   # baseline, extended, progressive
JPEG_MAX_DIM = 20000
JPEG_SCAN_BYTES = 256 * 1024


def _jpeg_markers(head, start, limit=None):
    """JPEG structure markers encountered in `head` from
    `start`, as [(offset, marker, length), ...].

    The walk advances by the declared length when it is consistent and by
    a single byte otherwise: the intact zone often starts in the MIDDLE of a
    segment payload (the EXIF thumbnail), where phantom 0xFFxx sequences
    appear -- this fallback allows resynchronising on the
    real main-image chain."""
    out = []
    i = start
    n = len(head) if limit is None else min(limit, len(head))
    while i < n - 4:
        if head[i] == 0xFF and head[i + 1] not in (0x00, 0xFF) \
                and not (0xD0 <= head[i + 1] <= 0xD9):
            ln = int.from_bytes(head[i + 2:i + 4], 'big')
            if 2 <= ln <= 65535 and i + 2 + ln <= n:
                out.append((i, head[i + 1], ln))
                i += 2 + ln
                continue
        i += 1
    return out


def _jpeg_strict_chain(head, start, limit=None):
    """Markers reached from `start` following ONLY the declared lengths
    (no byte-by-byte scan). Returns [(offset, marker),
    ...] down to the SOS, or None as soon as the chain is no longer consistent.

    Used to establish that a quantisation table, an SOF and an SOS really
    form CONTIGUOUS SEGMENTS of one and the same image."""
    out = []
    i = start
    n = len(head) if limit is None else min(limit, len(head))
    while i < n - 4:
        if head[i] != 0xFF:
            return None
        m = head[i + 1]
        if m == 0xD9:                       # EOI
            out.append((i, m))
            return out
        if m == 0x00 or m == 0xFF or 0xD0 <= m <= 0xD8:
            return None
        ln = int.from_bytes(head[i + 2:i + 4], 'big')
        if ln < 2 or i + 2 + ln > n:
            return None
        out.append((i, m))
        if m == 0xDA:                       # SOS: end of the header
            return out
        i += 2 + ln
    return None


def _jpeg_decode_check(path, width, height, timeout=120):
    """Verify by DECODING that the rebuilt JPEG reads and really has the
    size announced by its own SOF. ffmpeg if available, otherwise Pillow;
    without any decoder, we accept while reporting it (same policy as the
    other containers). Returns (ok, message)."""
    if shutil.which('ffmpeg'):
        try:
            r = subprocess.run(['ffmpeg', '-v', 'error', '-i', path,
                                '-f', 'null', '-'],
                               capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"ffmpeg decoding impossible ({e})"
        err = (r.stderr or b'').decode('latin1', 'replace').strip()
        if r.returncode != 0 or err:
            return False, "ffmpeg rejected it: " + (err.splitlines()[0][:160]
                                                    if err else f"code {r.returncode}")
        try:
            p = subprocess.run(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
                                '-show_entries', 'stream=width,height',
                                '-of', 'csv=p=0', path],
                               capture_output=True, text=True, timeout=60)
            got = p.stdout.strip().replace(' ', '')
            if got and got != f"{width},{height}":
                return False, (f"decoded size {got} != {width},{height} "
                               f"announced by the SOF")
        except (subprocess.TimeoutExpired, OSError):
            pass
        return True, 'clean ffmpeg decoding'
    try:
        from PIL import Image
        with Image.open(path) as im:
            im.load()
            if im.size != (width, height):
                return False, (f"Pillow: {im.size[0]}x{im.size[1]} != "
                               f"{width}x{height} announced by the SOF")
        return True, 'clean Pillow decoding'
    except ImportError:
        return True, ("no decoder available (neither ffmpeg nor Pillow): "
                      "SOF/DQT/DHT/SOS + EOI structure verified, decoding "
                      "not tested")
    except Exception as e:
        return False, f"Pillow: {type(e).__name__}: {e}"


def repair_jpeg_image(filepath, out_path, video_len, enc_header_len=ENC_HEADER_LEN,
                      scan_bytes=JPEG_SCAN_BYTES):
    """Rebuild a JPEG image whose header is only PARTIALLY
    inside the leading encrypted zone (see the section above).

    Steps: final EOI present -> largest SOF in the clear (the main
    image; smaller SOFs are the previews/thumbnails nested
    in EXIF/IPTC) -> quantisation and Huffman tables + SOS in the clear
    -> write `SOI + [DQT ... end of the useful part]` -> VERIFICATION
    by decoding (never a false success: a candidate that does not decode
    is rejected and the file is reported as failed).

    Returns (True, details) or (False, message)."""
    with open(filepath, 'rb') as fh:
        head = fh.read(min(video_len, scan_bytes))
        fh.seek(max(0, video_len - 64))
        tail = fh.read()

    if b'\xff\xd9' not in tail:
        return False, ("no EOI (FFD9) at the end of the useful part: entropy "
                       "stream truncated, nothing to rebuild.")

    markers = _jpeg_markers(head, enc_header_len, len(head))
    sofs = []
    for (off, m, ln) in markers:
        if m in JPEG_SOF_MARKERS and ln > 8 and off + 9 <= len(head):
            prec = head[off + 4]
            h = int.from_bytes(head[off + 5:off + 7], 'big')
            w = int.from_bytes(head[off + 7:off + 9], 'big')
            if prec in (8, 12) and 16 <= w <= JPEG_MAX_DIM and 16 <= h <= JPEG_MAX_DIM:
                sofs.append((off, w, h, prec))
    if not sofs:
        return False, ("no SOF (dimensions) in the intact zone: the image "
                       "header is entirely inside the encrypted zone -- "
                       "tables and dimensions lost, recovery impossible "
                       "without the key.")
    sof_off, width, height, prec = max(sofs, key=lambda s: s[1] * s[2])

    sos_list = [off for (off, m, _) in markers if m == 0xDA and off > sof_off]
    if not sos_list:
        return False, ("SOF found but no SOS in the intact zone: start of the "
                       "entropy stream lost, decoding impossible.")
    sos_off = sos_list[0]
    if not any(m == 0xC4 for (off, m, _) in markers if enc_header_len < off < sos_off):
        return False, ("SOF and SOS found but the Huffman tables (DHT) "
                       "are inside the encrypted zone: decoding impossible "
                       "(no standard table is assumed).")

    # Chain start: the closest quantisation table upstream,
    # PROVIDED the segment chain it opens really contains THAT
    # SOF and THAT SOS (chain verified segment by segment). This is what
    # guarantees that the tables of ANOTHER image are not glued back on: a
    # decode done with the wrong quantisation tables produces
    # no error at all, only a wrong image -- verification by
    # decoding alone would therefore not catch it.
    dqt_offsets = [off for (off, m, _) in markers if m == 0xDB and off < sof_off]
    starts = []
    for off in reversed(dqt_offsets):
        chain = _jpeg_strict_chain(head, off, len(head))
        if chain and sof_off in (o for (o, _) in chain) \
                and sos_off in (o for (o, _) in chain):
            starts.append(off)
            if len(starts) >= 4:
                break
    if not starts:
        # No usable quantisation table upstream: last
        # resort, the SOF itself (decoding will tell whether something is
        # missing).
        chain = _jpeg_strict_chain(head, sof_off, len(head))
        if chain and sos_off in (o for (o, _) in chain):
            starts.append(sof_off)
    if not starts:
        return False, ("inconsistent JPEG header in the intact zone: no "
                       "continuous chain of segments links a quantisation "
                       "table, the SOF and the SOS found -- "
                       "reconstruction refused rather than produced at "
                       "random.")

    last_msg = 'no candidate tested'
    for start in starts:
        with open(filepath, 'rb') as src, open(out_path, 'wb') as dst:
            src.seek(start)
            dst.write(b'\xff\xd8')               # SOI glued back
            remaining = video_len - start
            while remaining > 0:
                chunk = src.read(min(4 * 1024 * 1024, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)
        ok, msg = _jpeg_decode_check(out_path, width, height)
        if ok:
            return True, {
                'width': width, 'height': height, 'precision': prec,
                'sof_off': sof_off, 'sos_off': sos_off,
                'chain_from': start, 'start_offset': start,
                'verified': msg,
                'size': os.path.getsize(out_path),
            }
        last_msg = msg
        try:
            os.remove(out_path)                  # rejected candidate: clean up
        except OSError:
            pass
    return False, (f"JPEG reconstruction rejected by the decoding oracle "
                   f"({len(starts)} chain start(s) tried, image "
                   f"{width}x{height} announced): {last_msg}")


# Window read to recognise the container REALLY present in the
# content (see detect_headerless_encrypted_container), when we want to
# check that the footer extension is not lying. 8 MB are more than enough:
# on the files where the extension was wrong, the real header fell within
# the first 100 KB.
ALT_CONTAINER_SEARCH_CAP = 8 * 1024 * 1024


def _probe_decodable(path, seconds=30, timeout=180):
    """Verify that a rebuilt file REALLY READS: ffmpeg must find
    at least one track in it and decode its first `seconds` seconds
    without error. Returns (True|False|None, message) -- None = not verified
    (ffmpeg absent)."""
    if shutil.which('ffmpeg') is None:
        return None, "ffmpeg absent: decoding not verified"
    try:
        p = subprocess.run(['ffprobe', '-v', 'error', '-show_entries',
                            'stream=codec_type', '-of', 'csv=p=0', path],
                           capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"ffprobe failed ({e})"
    if not [l for l in (p.stdout or '').splitlines() if l.strip()]:
        return False, "no readable track in the rebuilt file"
    try:
        r = subprocess.run(['ffmpeg', '-v', 'error', '-i', path,
                            '-t', str(seconds), '-f', 'null', '-'],
                           capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"decoding failed ({e})"
    err = (r.stderr or b'').decode('latin1', 'replace').strip()
    if r.returncode != 0 or err:
        return False, ("the decoder rejects the file: " +
                       (err.splitlines()[0][:150] if err else f"code {r.returncode}"))
    return True, f"clean decoding of the first {seconds} seconds"


def _try_alternative_container(real_ext, path, out_dir, base_name, video_len,
                               enc_header_len, mkv_opts=None):
    """Rebuild the file following the container REALLY detected in
    its content, when the footer extension was lying (observed: an `.mp4` that
    was FLV, a `.wmv` that was not ASF).

    Each attempt is a real rebuild, and the result is only
    accepted if it really DECODES (_probe_decodable): a
    rebuilt but unreadable file is deleted and the failure is returned, rather
    than announced as recovered. Returns (True, details) or (False, message)."""
    alt_out = os.path.join(out_dir, base_name + real_ext)
    note = ''
    try:
        if real_ext == '.flv':
            ok, extra = repair_flv_case_b(path, alt_out, video_len, enc_header_len)
            if ok:
                note = f"{extra['tag_count']} FLV tags kept as is"
                if not extra['codec_config_seen']:
                    note += ("; the sequence header tag (codec config) is "
                             "inside the encrypted zone")
                else:
                    note += "; codec config present"
        elif real_ext == '.avi':
            movi = find_riff_movi(path, video_len)
            if not movi:
                return False, "LIST 'movi' not found in the intact zone"
            ok, extra = repair_avi_case_b(path, alt_out, video_len, movi)
            if ok:
                note = f"{extra['width']}x{extra['height']}, {extra['sample_count']} frames"
        elif real_ext in ('.mpg', '.mpeg'):
            ok, extra = repair_mpeg_ps_case_b(path, alt_out, video_len, enc_header_len)
            if ok:
                note = f"resynchronised at offset {extra['start_off']}"
        elif real_ext in ('.ts', '.m2ts', '.mts'):
            ts_tmp = os.path.join(out_dir, base_name + '.ts')
            ok, extra = repair_ts_case_b(path, ts_tmp, video_len, enc_header_len)
            if ok:
                final, remux_note = remux_ts_reconstructed(ts_tmp)
                alt_out = final
                note = ("remuxed to .mp4 (the raw .ts does not demultiplex with "
                        "ffmpeg)" if remux_note is None
                        else f"left as .ts ({remux_note})")
        elif real_ext in ('.wmv', '.wma', '.asf'):
            ok, extra = repair_asf_case_b(path, alt_out, video_len, enc_header_len)
            if ok:
                note = "ASF header recomputed (" + ", ".join(extra['rebuilt']) + ")"
        elif real_ext in ('.jpg', '.jpeg'):
            ok, extra = repair_jpeg_image(path, alt_out, video_len, enc_header_len)
            if ok:
                note = f"image {extra['width']}x{extra['height']}"
        elif real_ext in ('.mkv', '.webm'):
            ok, extra = process_mkv_file(path, out_dir, video_len, **(mkv_opts or {}))
            if ok:
                repair_mkv(path, alt_out, video_len, extra['splice_off'], extra['tracks'])
                note = ("tracks: " + ", ".join(
                    f"{t['track_number']} ({t['kind']})" for t in extra['tracks']))
            else:
                note = str(extra)
        else:
            return False, f"container {real_ext} not handled by the fallback"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    if not ok:
        return False, {'rebuilt': False,
                       'message': note or f"rebuilding {real_ext} impossible"}
    dec_ok, dec_msg = _probe_decodable(alt_out)
    if dec_ok is False:
        try:
            os.remove(alt_out)
        except OSError:
            pass
        return False, {'rebuilt': True,
                       'message': (f"container rebuilt as {real_ext} "
                                   f"({note}) but the result does not read -- "
                                   f"{dec_msg}: file not kept")}
    return True, {'rebuilt': True, 'out_path': alt_out, 'note': note,
                  'decodage': dec_msg}


def process_file(path, out_dir, fps_fallback, keep_nsm=False,

                  width_override=None, height_override=None,
                  auto_resolution=True, auto_resolution_timeout=90,
                  brute_force_resolution=False, resolution_lock=False,
                  sps_pps_donor_files=None, profile_dir=None,
                  use_profiles=True, learn_profiles=True):
    """Process one .nsm file. Returns (ok, mode):
      - (True,  'restored') : reconstruction done (output written), the
        original .nsm is kept (to be moved to _to_delete by the caller,
        unless --keep-nsm).
      - (True,  'renamed')  : the file was only renamed (not encrypted);
        it was renamed/copied to its real extension (the original .nsm is
        consumed, except with keep_nsm).
      - (False, 'failed')   : failure, the original .nsm is kept (to be moved
        to _error by the caller, unless --keep-nsm)."""
    name = os.path.basename(path)
    log(f"\n=== {os.path.abspath(path)} ===")
    try:
        extension, footer_len, payload, video_len = parse_footer(path)
        log(f"  original extension recovered  : {extension}")
        log(f"  useful size (footer excluded) : {video_len} bytes")
    except Exception as e:
        log(f"  HARR footer not found ({e}): the file does not seem "
            f"encrypted by the ransomware a priori...")
        guess = detect_headerless_encrypted_container(path)
        if guess is None:
            return handle_simple_rename(path, out_dir, keep_nsm)
        extension, kind_desc = guess
        footer_len = 0
        payload = None
        video_len = os.path.getsize(path)
        log(f"  [SPECIAL] but header at very high entropy (>= 7.5 "
            f"bits/byte, typical of an encrypted area -- unlike a "
            f"merely renamed file, which would be plaintext from byte 0) "
            f"AND {kind_desc} structure detected further in the file: "
            f"treated as a file encrypted by the ransomware whose "
            f"FOOTER was lost or truncated (no footer metadata "
            f"available: extension deduced from the internal structure "
            f"found, useful size = total file size since there is "
            f"no footer to subtract here). Deduced extension: "
            f"{extension}")

    footer_fields = parse_footer_fields(payload)

    enc_header_len = ENC_HEADER_LEN
    if extension.lower() not in ('.avi',):
        # The EXACT size of the encrypted area at the head is written by the
        # ransomware itself in the footer (zone_size field): when it is
        # available and plausible, it is used directly --
        # more reliable than detection by entropy (see
        # detect_true_enc_header_len), kept only as a fallback for
        # files whose footer is missing/unreadable (headerless
        # case above) or whose value looks aberrant.
        # Not applicable to the AVI format (already handled through its own
        # 'movi' signature search, independent of this mechanism).
        if footer_fields and 0 < footer_fields['zone_size'] <= video_len:
            enc_header_len = footer_fields['zone_size']
            if enc_header_len != ENC_HEADER_LEN:
                log(f"  [SPECIAL] encrypted area at the head of "
                    f"{enc_header_len} bytes (instead of the usual {ENC_HEADER_LEN}) "
                    f"-- value read directly from the footer "
                    f"(mode {footer_fields['mode_label']}), reliable to 100%.")
        else:
            detected = detect_true_enc_header_len(path, video_len)
            if detected != ENC_HEADER_LEN:
                enc_header_len = detected
                log(f"  [SPECIAL] encrypted area at the head larger than "
                    f"usual, detected by entropy analysis (footer "
                    f"missing or zone_size field unreadable): "
                    f"{enc_header_len} bytes (instead of the usual {ENC_HEADER_LEN}) "
                    f"-- used for this reconstruction.")

        if footer_fields and footer_fields['mode'] == FOOTER_MODE_SPOTS and \
           footer_fields['spot_count'] > 0:
            log(f"  [WARNING] SPOTS mode detected in the footer: besides "
                f"the head area, {footer_fields['spot_count']} ADDITIONAL "
                f"area(s) of {footer_fields['zone_size']} bytes "
                f"each are encrypted further in the file (observed "
                f"on files above ~1 GB). Their exact position "
                f"is NOT determinable without the key (an already "
                f"compressed video stream has an entropy too close to that of "
                f"encrypted noise to locate them by statistical analysis): the "
                f"reconstruction below fixes the header but will leave "
                f"these {footer_fields['spot_count']} area(s) as they are -- "
                f"expect short visual/audio corruptions "
                f"(a few tenths of a second to a few seconds, at "
                f"unpredictable positions) elsewhere in the file, on "
                f"top of a reliable start of file.")

    base_name = os.path.splitext(name)[0]
    out_path = os.path.join(out_dir, base_name + extension)

    # --- The footer extension may LIE: the ransomware kept the
    # original name, but a file misnamed from the start stays so (.mp4 that
    # was FLV, .wmv that was not ASF -- observed on 2 of the 3
    # files of a random sample). When the content says otherwise, the
    # container REALLY present is followed, validated by reconstruction +
    # decoding (see _try_alternative_container), before falling back on
    # the path declared by the extension.
    try:
        _real = detect_headerless_encrypted_container(
            path, search_cap=ALT_CONTAINER_SEARCH_CAP)
    except Exception:
        _real = None
    if _real is not None and _real[0].lower() != extension.lower():
        if _real[0] == '.mp4':
            # The content is an MP4 but the extension announced something
            # else: the generic MP4 path is left in charge (end of the
            # cascade), which handles CASE A and CASE B.
            log(f"  [SPECIAL] the content is an MP4 ({_real[1]}) while "
                f"the footer extension announces {extension}: the real "
                f"container is followed.")
            extension = '.mp4'
            out_path = os.path.join(out_dir, base_name + extension)
        else:
            log(f"  [SPECIAL] the footer extension ({extension}) does "
                f"not match the content: {_real[1]} -> trying that "
                f"container first.")
            _ok_alt, _alt = _try_alternative_container(
                _real[0], path, out_dir, base_name, video_len, enc_header_len,
                mkv_opts=dict(width_override=width_override,
                              height_override=height_override,
                              auto_resolution=auto_resolution,
                              auto_resolution_timeout=auto_resolution_timeout,
                              brute_force_resolution=brute_force_resolution,
                              resolution_lock=resolution_lock,
                              sps_pps_donor_files=sps_pps_donor_files,
                              profile_dir=profile_dir,
                              use_profiles=use_profiles))
            if _ok_alt:
                log(f"  -> file rebuilt: {_alt['out_path']}")
                log(f"     real container: {_real[1]}")
                log(f"     {_alt['note']}")
                log(f"     verification: {_alt['decodage']}")
                return True, 'restored'
            log(f"  -> real container not kept: {_alt['message']}")
            if _alt.get('rebuilt'):
                log(f"     the real container was rebuilt but remains "
                    f"unreadable: the path declared by the extension "
                    f"({extension}) cannot do better, the file not being "
                    f"of that type -- failure.")
                return False, 'failed'
            log(f"     back to the path declared by the footer "
                f"extension ({extension})")

    if extension.lower() == '.avi':
        log("  container detected: RIFF/AVI (.avi)")
        try:
            movi_info = find_riff_movi(path, video_len)
            if not movi_info:
                log("  [FAILED] LIST 'movi' not found in an intact area: "
                    "AVI structure not recognised for this file.")
                return False, 'failed'
            log(f"  LIST 'movi' located at position {movi_info['movi_list_off']} "
                f"(declared size {movi_info['movi_list_size']})")
            ok, extra = repair_avi_case_b(path, out_path, video_len, movi_info)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                if extra.get('audio_dropped'):
                    log("     (see warning above: audio track dropped)")
                log(f"     resolution: {extra['width']}x{extra['height']} "
                    f"(read directly from the video stream)")
                log(f"     video frames: {extra['sample_count']}, "
                    f"rate: {extra['fps_fallback']} fps")
                log(f"        ({extra['fps_source']})")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] AVI reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() == '.flv':
        log("  container detected: Adobe FLV (.flv)")
        try:
            ok, extra = repair_flv_case_b(path, out_path, video_len,
                                          enc_header_len)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                tracks = []
                if extra['has_video']:
                    tracks.append('video')
                if extra['has_audio']:
                    tracks.append('audio')
                log(f"     FLV header rewritten (flags: "
                    f"{'+'.join(tracks) or 'no track detected'}); "
                    f"{extra['tag_count']} tags kept AS IS (not a single "
                    f"audio/video data byte modified). Self-describing "
                    f"codecs (Sorenson H.263, VP6, MP3/AAC audio) "
                    f"require no reconstruction and the audio track "
                    f"is preserved.")
                if extra['has_video'] and extra['video_codec_id'] in (7, 12) \
                        and not extra['codec_config_seen']:
                    codec_name = 'H.264/AVC' if extra['video_codec_id'] == 7 \
                        else 'H.265/HEVC'
                    log(f"     [WARNING] {codec_name} video: the sequence "
                        f"header tag (which carries SPS/PPS, written ONCE "
                        f"ONLY in FLV) fell in the encrypted area and was not "
                        f"found again. The video tags are copied, but "
                        f"the decoder no longer has the codec config: playback may "
                        f"fail (unlike the self-describing Sorenson H.263/MP3 "
                        f"of the common case). Check playback "
                        f"before deleting the .nsm.")
                if extra['skipped_bytes']:
                    log(f"     [WARNING] {extra['skipped_bytes']} unrecognised "
                        f"byte(s) skipped (additional encrypted "
                        f"area(s), SPOTS mode): short cuts "
                        f"are to be expected at those places. Check playback "
                        f"before deleting the .nsm.")
                else:
                    log(f"     continuous tag stream (onMetaData kept if "
                        f"it was intact): check playback in a video "
                        f"player anyway before deleting the .nsm.")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] FLV reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() in ('.jpg', '.jpeg'):
        log("  container detected: JPEG image (.jpg)")
        try:
            ok, extra = repair_jpeg_image(path, out_path, video_len, enc_header_len)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                log(f"     main image: {extra['width']}x{extra['height']} "
                    f"({extra['precision']} bits, SOF at offset "
                    f"{extra['sof_off']})")
                log(f"     header chain taken from offset "
                    f"{extra['chain_from']} (quantisation + SOF + Huffman + "
                    f"SOS, preceded by a re-spliced SOI); the metadata "
                    f"(EXIF/IPTC/ICC) and the thumbnail whose header fell in "
                    f"the encrypted area are lost, but the pixels of the main "
                    f"image are the original ones.")
                log(f"     verification: {extra['verified']} "
                    f"({extra['size']} bytes)")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] JPEG reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() in ('.mpg', '.mpeg'):
        log("  container detected: MPEG-1/2 Program Stream (.mpg)")
        try:
            ok, extra = repair_mpeg_ps_case_b(path, out_path, video_len,
                                               enc_header_len)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                if extra.get('width'):
                    log(f"     resolution: {extra['width']}x{extra['height']} "
                        f"(read directly from the video stream)")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] MPEG-PS reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() in ('.ts', '.m2ts', '.mts'):
        log("  container detected: MPEG Transport Stream (.ts)")
        try:
            ok, extra = repair_ts_case_b(path, out_path, video_len, enc_header_len)
            if ok:
                final_path, remux_note = remux_ts_reconstructed(out_path)
                if remux_note is None:
                    log(f"  -> file rebuilt, then REMUXED to .mp4 (the raw "
                        f".ts does not decode correctly with the ffmpeg "
                        f"MPEG-TS demuxer despite an intact "
                        f"H.264 stream -- see remux_ts_reconstructed): "
                        f"{final_path}")
                else:
                    log(f"  -> file rebuilt: {final_path}")
                    log(f"     [WARNING] {remux_note}")
                if extra.get('width'):
                    log(f"     resolution: {extra['width']}x{extra['height']}")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] MPEG-TS reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() in ('.wmv', '.wma', '.asf'):
        log("  container detected: ASF (.wmv/.wma)")
        try:
            ok, extra = repair_asf_case_b(path, out_path, video_len, enc_header_len)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                log(f"     original ASF header: {extra['header_len_orig']} bytes, "
                    f"of which {extra['kept_objects']} object(s) kept intact "
                    f"from byte {extra['kept_from']}; recomputed: "
                    f"{', '.join(extra['rebuilt']) or 'none'}")
                for s in extra['streams']:
                    if s and s['kind'] == 'video':
                        log(f"     video track: {s['codec']} {s['width']}x{s['height']} "
                            f"(original codec config, intact)")
                    elif s and s['kind'] == 'audio':
                        log(f"     audio track: format {s['codec']}, {s['channels']} channel(s), "
                            f"{s['sample_rate']} Hz (original codec config, intact)")
                log(f"     {extra['packets']} packets of {extra['packet_size']} bytes, "
                    f"duration {extra['duration_s']:.1f}s ({extra['duration_source']}), "
                    f"preroll {extra['preroll_ms']} ms")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] ASF reconstruction impossible: {e}")
            return False, 'failed'

    if extension.lower() in ('.mkv', '.webm'):
        log("  container detected: Matroska/EBML (.mkv), checking...")
        try:
            ok, extra = process_mkv_file(path, out_dir, video_len,
                                          width_override=width_override,
                                          height_override=height_override,
                                          auto_resolution=auto_resolution,
                                          auto_resolution_timeout=auto_resolution_timeout,
                                          brute_force_resolution=brute_force_resolution,
                                          resolution_lock=resolution_lock,
                                          sps_pps_donor_files=sps_pps_donor_files,
                                          profile_dir=profile_dir,
                                          use_profiles=use_profiles)
            if ok:
                repair_mkv(path, out_path, video_len, extra['splice_off'], extra['tracks'])
                log(f"  -> file rebuilt: {out_path}")
                kinds = ', '.join(f"track {t['track_number']} ({t['kind']})" for t in extra['tracks'])
                log(f"     tracks included: {kinds}")
                for t in extra['tracks']:
                    if t['kind'] == 'video' and t.get('width'):
                        log(f"     video resolution: {t['width']}x{t['height']}")
                return True, 'restored'
            log(f"  [Matroska] {extra}")
        except Exception as e:
            log(f"  [Matroska] reconstruction impossible: {e}")

        # Fallback: on some sources, files
        # are named .mkv/.webm while their REAL content is a raw
        # MPEG Transport Stream (188-byte packets, standard
        # PAT/PMT) -- found by comparing with files already
        # decoded from the same source. This hypothesis is tried before giving up.
        log("  no usable Matroska Cluster -- checking the "
            "MPEG-TS hypothesis (.mkv/.webm extension potentially "
            "misleading, already observed on this kind of capture)...")
        try:
            ts_out_path = os.path.join(out_dir, base_name + '.ts')
            ok, extra = repair_ts_case_b(path, ts_out_path, video_len, enc_header_len)
            if ok:
                final_path, remux_note = remux_ts_reconstructed(ts_out_path)
                if remux_note is None:
                    log(f"  -> file rebuilt AS .mp4 (remuxed from an "
                        f"intermediate .ts -- the real content was not "
                        f"Matroska despite the original {extension} extension): "
                        f"{final_path}")
                else:
                    log(f"  -> file rebuilt AS .ts (the real content was not "
                        f"Matroska despite the original {extension} extension): "
                        f"{final_path}")
                    log(f"     [WARNING] {remux_note}")
                if extra.get('width'):
                    log(f"     resolution: {extra['width']}x{extra['height']}")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] neither Matroska nor MPEG-TS could be rebuilt: {e}")
            return False, 'failed'

    info = find_moov_and_mdat(path, video_len, enc_header_len=enc_header_len)
    moov = info['moov']
    mdat = info['mdat']

    if moov and (mdat is None or moov[0] > mdat[0]) and moov[0] > enc_header_len and \
       (mdat is None or moov[0] > 2 * 1024 * 1024):
        # CASE A: moov found far from the start (usually at the very end
        # of the file) -> it is entirely intact. The box has already been
        # validated structurally by find_moov_and_mdat (see
        # validate_moov_box): a signature-scan false positive
        # inside mdat can no longer occur here.
        log(f"  layout detected: CASE A (moov intact, position {moov[0]})")
        try:
            repair_case_a(path, out_path, video_len, moov[0], moov[1], DEFAULT_FTYPE,
                           head_len=enc_header_len)
            log(f"  -> file rebuilt: {out_path}")
            return True, 'restored'
        except Exception as e:
            log(f"  [FAILED] CASE A reconstruction impossible: {e}")
            return False, 'failed'

    if mdat:
        log(f"  layout detected: CASE B (moov overlaps the encrypted area, "
            f"mdat at position {mdat[0]}, declared size {mdat[1]})")
        try:
            ok, extra = repair_case_b(path, out_path, video_len, mdat[0], mdat[1],
                                       fps_fallback,
                                       width_override=width_override,
                                       height_override=height_override,
                                       auto_resolution=auto_resolution,
                                       auto_resolution_timeout=auto_resolution_timeout,
                                       brute_force_resolution=brute_force_resolution,
                                       resolution_lock=resolution_lock,
                                       sps_pps_donor_files=sps_pps_donor_files,
                                       profile_dir=profile_dir,
                                       use_profiles=use_profiles,
                                       learn_profiles=learn_profiles,
                                       enc_header_len=enc_header_len)
            if ok:
                log(f"  -> file rebuilt: {out_path}")
                if extra.get('tables_derived_by_audio_avcc'):
                    log(f"     [SPECIAL] NO intact 'trak' track and, for "
                        f"the only surviving audio track, even its 'stsc' was "
                        f"lost (only audio stsz+stco remained): the audio "
                        f"stsc was REBUILT using the video "
                        f"AVCC framing (each length falls exactly on the "
                        f"boundary of the next audio chunk), then the THREE "
                        f"video tables (stco/stsc/stsz) were deduced from "
                        f"the 'holes' left by the audio in mdat. File "
                        f"rebuilt VIDEO ONLY (the audio config, esds/mp4a, "
                        f"was in the encrypted area). Check playback before "
                        f"deleting the .nsm.")
                elif extra.get('tables_derived_from_gaps'):
                    log(f"     [SPECIAL] the THREE video sample tables "
                        f"(stco/stsc/stsz) were lost -- REBUILT with "
                        f"no arbitrary assumption from the \"holes\" left "
                        f"in mdat by the REAL bytes of the audio track (intact): "
                        f"each hole = one video chunk, walked as a sequence "
                        f"of AVCC samples (4-byte length + data) until "
                        f"falling exactly on its end. Check playback "
                        f"anyway before deleting the .nsm.")
                elif extra.get('tables_derived'):
                    log(f"     [SPECIAL] video sample tables (stsc/stsz) "
                        f"also lost (on top of the codec config) -- "
                        f"REBUILT from the real chunk offsets of the "
                        f"video track (stco, intact) and from those of the other "
                        f"intact track, assuming 1 sample per chunk (very "
                        f"frequent for this kind of interlaced capture): reliable if "
                        f"that assumption holds (checked consistent here), but "
                        f"check playback anyway before deleting the .nsm.")
                if extra['codec'] in ('avc-donor', 'hevc-donor'):
                    log(f"     real SPS/PPS not found in the stream (never "
                        f"repeated), but TAKEN AS IS from the donor "
                        f"file {os.path.basename(extra['donor_used'])} "
                        f"(--sps-pps-from): these are REAL parameters of a "
                        f"similar encoding (not a guess), and the test "
                        f"image sequence of THIS file decodes cleanly with "
                        f"them -- far more reliable than a search-based detection. "
                        f"Check playback anyway in a video player "
                        f"before deleting the .nsm.")
                elif extra['codec'] == 'avc-video-track-intact':
                    log(f"     [SPECIAL] unusual track order in this "
                        f"file: it is the AUDIO track that lost its header "
                        f"(never repeated), NOT the video track -- the VIDEO "
                        f"track, for its part, is fully INTACT with its REAL "
                        f"config (real avcC/hvcC, not a reconstruction): "
                        f"reliable to 100% on the image side. However the audio config "
                        f"is not found (it is never repeated in the stream): "
                        f"the audio track was DROPPED, the rebuilt file "
                        f"is VIDEO ONLY (without sound).")
                elif extra['codec'] in ('avc-profile', 'hevc-profile'):
                    pe = extra['profile_used']
                    src_txt = (pe.get('sources') or ['?'])[-1]
                    log(f"     real SPS/PPS not found in the stream (never "
                        f"repeated), but found in the profile database "
                        f"learned automatically (seen {pe.get('count', '?')} times, "
                        f"last example: {src_txt}): these are REAL "
                        f"parameters of an encoding already encountered (probably "
                        f"the same source/encoder), and the test image sequence "
                        f"of THIS file decodes cleanly with them -- far more "
                        f"reliable than a search-based detection. Check "
                        f"playback anyway in a video player before "
                        f"deleting the .nsm.")
                elif extra['codec'] == 'avc-generic-auto':
                    di = extra['detect_info']
                    log(f"     [EXPERIMENTAL] real SPS/PPS not found in the stream "
                        f"(never repeated): resolution and SPS/PPS parameters DETECTED "
                        f"AUTOMATICALLY ({di['width']}x{di['height']}, "
                        f"log2_max_frame_num={di['log2_max_frame_num']}, "
                        f"log2_max_poc_lsb={di['log2_max_poc_lsb']}, "
                        f"pic_order_cnt_type={di.get('poc_type', 0)}, "
                        f"max_num_ref_frames={di['max_num_ref_frames']}, "
                        f"pic_init_qp_minus26={di['pic_init_qp_minus26']}, "
                        f"{di['tested']} combinations tested in {di['elapsed']:.1f}s)"
                        + (f", refined with the SEI x264 settings ({len(extra['x264_opts'])} "
                           f"options detected)" if extra.get('x264_opts') else "")
                        + " -- the key frame decodes without error with these "
                          "parameters (good hint, NOT GUARANTEED pixel-perfect): "
                          "check playback in a video player before deleting the .nsm.")
                elif extra['codec'] == 'mpeg4-generic-auto':
                    di = extra['detect_info']
                    log(f"     [EXPERIMENTAL] MPEG-4 Part 2 (mp4v) video stream whose "
                        f"config (VOL, in the original esds) is lost: "
                        f"RESYNTHESISED ({di['width']}x{di['height']}, "
                        f"vop_time_increment_bits={di['time_bits']}, VOL variant "
                        f"#{di['variant']}, {di['tested']} combinations tested in "
                        f"{di['elapsed']:.1f}s) -- the first frames decode "
                        f"without error with these parameters (good hint, NOT GUARANTEED "
                        f"pixel-perfect). Check playback before deleting "
                        f"the .nsm.")
                elif extra['codec'] == 'avc-generic':
                    log(f"     [EXPERIMENTAL] real SPS/PPS not found in the stream "
                        f"(never repeated), automatic detection with no conclusive result "
                        f"(or ffmpeg unavailable): generic H.264 SPS/PPS synthesised for "
                        f"{extra['width']}x{extra['height']} (--width/--height)"
                        + (f", refined with the SEI x264 settings ({len(extra['x264_opts'])} "
                           f"options detected)" if extra.get('x264_opts') else "")
                        + " -- NOT GUARANTEED to decode correctly, check "
                          "playback in a video player before deleting the .nsm.")
                else:
                    log(f"     video codec detected: {extra['codec']}")
                if extra['codec'] in ('avc-donor', 'hevc-donor'):
                    res_note = f" (from the donor file {os.path.basename(extra['donor_used'])})"
                elif extra['codec'] == 'avc-video-track-intact':
                    res_note = " (video track intact, REAL resolution -- audio dropped)"
                elif extra['codec'] in ('avc-profile', 'hevc-profile'):
                    res_note = " (from the learned SPS/PPS profile database)"
                elif extra['codec'] in ('avc-generic-auto', 'mpeg4-generic-auto'):
                    res_note = " (detected automatically)"
                elif extra['codec'] == 'avc-generic':
                    res_note = " (provided via --width/--height)"
                else:
                    res_note = " (taken from the SPS)"
                log(f"     resolution: {extra['width']}x{extra['height']}{res_note}")
                log(f"     video frames: {extra['sample_count']}, rate: {extra['fps_fallback']} fps")
                log(f"        ({extra['fps_source']})")
                return True, 'restored'
            log(f"  [FAILED] {extra}")
            return False, 'failed'
        except Exception as e:
            log(f"  [FAILED] CASE B reconstruction impossible: {e}")
            return False, 'failed'

    # Fallback: as for .mkv/.webm (see above), some files
    # carry a misleading .mp4/.mov extension (recovered from the footer,
    # hence reliable on the ORIGINAL NAME, but not necessarily on the
    # REAL container) while their real content is a raw MPEG
    # Transport Stream (188-byte packets, 0x47 sync confirmed on
    # dozens of consecutive packets) -- observed on captures from
    # mobile-camera sources, with the same DVR capture
    # tools as for the already encountered .mkv case. This hypothesis is
    # tried before giving up: searching the TS sync over the whole
    # file (not only the first MB), since no ISO-BMFF structure
    # was found anywhere.
    log("  neither moov nor mdat located in an intact area -- checking the "
        "MPEG-TS hypothesis (.mp4/.mov extension potentially "
        "misleading, already observed on this kind of capture)...")
    try:
        ts_out_path = os.path.join(out_dir, base_name + '.ts')
        ok, extra = repair_ts_case_b(path, ts_out_path, video_len, enc_header_len)
        if ok:
            final_path, remux_note = remux_ts_reconstructed(ts_out_path)
            if remux_note is None:
                log(f"  -> file rebuilt AS .mp4 (remuxed from an intermediate "
                    f".ts -- the real content was not "
                    f"ISO-BMFF despite the original {extension} extension): "
                    f"{final_path}")
            else:
                log(f"  -> file rebuilt AS .ts (the real content was not "
                    f"ISO-BMFF despite the original {extension} "
                    f"extension): {final_path}")
                log(f"     [WARNING] {remux_note}")
            if extra.get('width'):
                log(f"     resolution: {extra['width']}x{extra['height']}")
            return True, 'restored'
        log(f"  [FAILED] {extra}")
    except Exception as e:
        log(f"  [FAILED] neither ISO-BMFF nor MPEG-TS could be rebuilt: {e}")

    log("  [FAILED] neither moov nor mdat could be located in an intact area, "
        "and the MPEG-TS hypothesis also failed: structure not "
        "recognised for this file.")
    return False, 'failed'


SUCCESS_DIR = '_to_delete'
ERROR_DIR = '_error'


def move_nsm_to(t, folder_root, subfolder_name):
    """Move the .nsm file t to a subfolder subfolder_name located
    at the folder_root root, reproducing the relative tree of t with
    respect to folder_root (or, if t is not under folder_root -- case
    of --files --, by creating subfolder_name next to the file). Returns the
    final destination path."""
    if folder_root and t.startswith(folder_root + os.sep):
        dest_root = os.path.join(folder_root, subfolder_name)
        rel = os.path.relpath(t, folder_root)
        dest_dir = os.path.join(dest_root, os.path.dirname(rel))
    else:
        dest_dir = os.path.join(os.path.dirname(t), subfolder_name)
    os.makedirs(dest_dir, exist_ok=True)
    base = os.path.basename(t)
    stem, ext = os.path.splitext(base)
    dest = os.path.join(dest_dir, base)
    i = 1
    while os.path.exists(dest):
        dest = os.path.join(dest_dir, f"{stem}_{i}{ext}")
        i += 1
    shutil.move(t, dest)
    return dest


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--folder',
                     help="folder to walk RECURSIVELY in search of .nsm "
                          f"(the '{SUCCESS_DIR}' and '{ERROR_DIR}' folders are created at "
                          "its root and reproduce the tree of the processed files, "
                          "respectively on success and on failure)")
    ap.add_argument('--files', nargs='*', help="explicit list of .nsm files")
    ap.add_argument('--out-dir', default=None,
                     help="output folder (default: same folder as the .nsm)")
    ap.add_argument('--fps', type=float, default=24.0,
                     help="fallback rate (fps) for CASE B files, used "
                          "ONLY if the rate could not be computed automatically "
                          "from the duration of the intact audio track (default 24)")
    ap.add_argument('--width', type=int, default=None,
                     help="EXPERIMENTAL (MP4 CASE B and MKV): video width to use for "
                          "synthesising a fallback SPS/PPS when the original codec config "
                          "is definitively lost (never repeated in the stream -- frequent "
                          "for H.264 muxed directly into MP4 without --repeat-headers). "
                          "Not guaranteed to decode correctly -- to be used as a last "
                          "resort, together with --height")
    ap.add_argument('--height', type=int, default=None,
                     help="EXPERIMENTAL (MP4 CASE B and MKV): video height, see --width")
    ap.add_argument('--no-auto-resolution', action='store_true',
                     help="disables the FAST automatic resolution detection (MP4 "
                          "CASE B, when SPS/PPS are never repeated in the stream): by "
                          "default, the script tries the common resolutions and those "
                          "already encountered in the profile database (default "
                          "settings only -- relatively fast) before falling back on "
                          "--width/--height; --width/--height, if provided, are used "
                          "as the FIRST candidate tested (priority), not as an "
                          "imposed value. See also --brute-force-resolution to go "
                          "further if this fast search fails")
    ap.add_argument('--brute-force-resolution', action='store_true',
                     help="if the fast detection (see above) finds nothing: also "
                          "tries a far wider combinatorial sweep (other values "
                          "of log2_max_frame_num/log2_max_poc_lsb/max_num_ref_frames/QP, "
                          "on the most probable resolutions) -- DISABLED BY DEFAULT "
                          "(experimental, potentially tens of thousands of "
                          "ffmpeg decoding attempts, and NOT guaranteed to find the "
                          "right combination even after several minutes; enable "
                          "it explicitly on a case-by-case basis, ideally with a "
                          "high --auto-resolution-timeout)")
    ap.add_argument('--resolution-lock', action='store_true',
                     help="to be used with --width/--height AND "
                          "--brute-force-resolution: instead of testing that "
                          "resolution in priority AMONG all the others "
                          "(normal behaviour of --width/--height), the wide "
                          "pass (combinatorial sweep) is restricted to EXACTLY "
                          "that resolution -- tens of thousands of "
                          "attempts then drop to a few hundred, hence "
                          "fast (fits comfortably in the default "
                          "--auto-resolution-timeout). Makes sense ONLY if the real "
                          "resolution is known with certainty from a source external to "
                          "the file (thumbnail kept elsewhere, page of the original "
                          "source, another rendition of the same source): if it is "
                          "wrong, this option wrongly discards the right resolution "
                          "instead of finding it more slowly. No effect if "
                          "--width/--height are not provided.")
    ap.add_argument('--auto-resolution-timeout', type=float, default=90.0,
                     help="time budget (seconds) granted to the automatic resolution "
                          "detection per relevant file (default 90s); requires ffmpeg "
                          "in the PATH, otherwise detection is simply disabled")
    ap.add_argument('--sps-pps-from', nargs='+', default=None, metavar='FILE.mp4',
                     help="MP4 CASE B: one or more 'donor' files -- "
                          "already complete/intact MP4s (e.g. other videos from the same "
                          "source/encoder already rebuilt successfully) -- whose "
                          "REAL SPS/PPS (avcC box) will be tried first, before "
                          "the automatic detection: ffmpeg checks that the "
                          "image sequence of the current file decodes "
                          "cleanly with these real parameters -- far more reliable "
                          "than a brute-force search when the SPS/PPS is "
                          "never repeated in the stream; requires ffmpeg in the PATH")
    ap.add_argument('--profile-dir', default=None, metavar='FOLDER',
                     help="MP4 CASE B: folder where the SPS/PPS profiles "
                          "'learned' automatically across runs are stored (see "
                          "--seed-profiles and the dedicated section of the README); by "
                          "default a 'sps_pps_profiles' folder created NEXT TO THE "
                          "SCRIPT (shared between all working folders)")
    ap.add_argument('--no-profile-matching', action='store_true',
                     help="MP4 CASE B: disables the automatic trial of the "
                          "already known SPS/PPS profiles (from most to least frequent) "
                          "before the automatic detection by search")
    ap.add_argument('--no-profile-learning', action='store_true',
                     help="MP4 CASE B: does NOT automatically record in the profile "
                          "database the REAL SPS/PPS recovered (via --sps-pps-from "
                          "or via an already known profile); no effect on the "
                          "automatic detection/--width/--height, never recorded (not "
                          "guaranteed reliable)")
    ap.add_argument('--seed-profiles', nargs='+', default=None, metavar='FILE_OR_FOLDER',
                     help="maintenance mode: seeds (or completes) the SPS/PPS "
                          "profile database from .mp4/.m4v/.mov files ALREADY "
                          "valid (e.g. a folder of videos already rebuilt "
                          "successfully) -- extracts their REAL SPS/PPS (avcC box), "
                          "without touching the .nsm; combinable with --files/--folder "
                          "in the same call (seeding happens before any processing)")
    ap.add_argument('--keep-nsm', action='store_true',
                     help="keep the original .nsm files in place, whether processing "
                          f"succeeds or fails (nothing moved to '{SUCCESS_DIR}'/'{ERROR_DIR}'); "
                          "for merely renamed files (not encrypted), make a COPY "
                          "at the right extension instead of renaming the .nsm in place")
    ap.add_argument('--manifest', default=None, metavar='FILE.csv',
                     help="appends to FILE.csv one CSV row per processed file "
                          f"({', '.join(MANIFEST_HEADER)}), the header being written "
                          "once when the file is created; status is 'restored', "
                          "'renamed' or 'failed'. Without this option the tool keeps "
                          "no record of what it processed.")
    args = ap.parse_args()
    profile_dir = args.profile_dir or DEFAULT_PROFILE_DIR

    if args.seed_profiles:
        seed_profiles_from_paths(args.seed_profiles, profile_dir)

    targets = []
    seen = set()

    def add_target(t):
        t = os.path.abspath(t)
        if t not in seen:
            seen.add(t)
            targets.append(t)

    folder_root = None
    if args.folder:
        # RECURSIVE walk of the whole tree.
        folder_root = os.path.abspath(args.folder)
        # Folders never to be visited, at ANY level of the
        # tree (not only at the root): _to_delete/_error
        # (already processed files, do not touch them again) and #recycle (name
        # of the trash folder on Synology/QNAP NAS -- its content
        # must never be processed nor moved again). Case-
        # insensitive comparison for safety.
        EXCLUDED_DIRNAMES = {SUCCESS_DIR.lower(), ERROR_DIR.lower(), '#recycle'}
        for dirpath, dirnames, filenames in os.walk(folder_root):
            dirnames[:] = [d for d in dirnames
                            if d.lower() not in EXCLUDED_DIRNAMES]
            for fn in filenames:
                if fn.lower().endswith('.nsm'):
                    add_target(os.path.join(dirpath, fn))
        targets.sort()
    if args.files:
        for t in args.files:
            add_target(t)
    if not targets:
        if args.seed_profiles:
            log("No .nsm file to process (profile database seeding done).")
            return 0
        log("No .nsm file to process (check --folder / --files).")
        return 1

    if folder_root:
        log(f"Folder root        : {folder_root} (whole tree walked)")
        log(f"Success folder     : {os.path.join(folder_root, SUCCESS_DIR)}")
        log(f"Failure folder     : {os.path.join(folder_root, ERROR_DIR)}")
    log(f"Output folder      : {args.out_dir or '(same folder as each .nsm)'}")
    n_known_profiles = len(load_profile_store(profile_dir))
    log(f"SPS/PPS profile database: {profile_dir} ({n_known_profiles} known profile(s))")

    failures = []
    for t in targets:
        out_dir = args.out_dir or os.path.dirname(t)
        os.makedirs(out_dir, exist_ok=True)
        ok, mode = process_file(t, out_dir, args.fps,
                                 keep_nsm=args.keep_nsm,
                                 width_override=args.width, height_override=args.height,
                                 auto_resolution=not args.no_auto_resolution,
                                 auto_resolution_timeout=args.auto_resolution_timeout,
                                 brute_force_resolution=args.brute_force_resolution,
                                 resolution_lock=args.resolution_lock,
                                 sps_pps_donor_files=args.sps_pps_from,
                                 profile_dir=profile_dir,
                                 use_profiles=not args.no_profile_matching,
                                 learn_profiles=not args.no_profile_learning)
        if mode == 'renamed':
            # The file was renamed (or copied, with --keep-nsm) to its
            # real extension: the original .nsm is either consumed or
            # kept in place. In both cases there is nothing to move
            # to _to_delete / _error.
            if args.manifest:
                append_manifest(args.manifest, t, 'renamed')
            continue
        final_path = t
        if not args.keep_nsm:
            # Moves the original .nsm to _to_delete (success) or
            # _error (failure), REPRODUCING the tree relative to the
            # --folder root (or simply next to the file if only
            # --files is passed).
            subfolder = SUCCESS_DIR if ok else ERROR_DIR
            final_path = move_nsm_to(t, folder_root, subfolder)
            status = "success" if ok else "failure"
            log(f"  -> {os.path.basename(t)} ({status}) moved to {final_path}")
        if args.manifest:
            # The .nsm location is only meaningful when it was moved:
            # with --keep-nsm it stayed where it was.
            append_manifest(args.manifest, t, 'restored' if ok else 'failed',
                            '' if args.keep_nsm else final_path)
        if not ok:
            failures.append(final_path)

    log("\nDone.")
    if failures:
        loc = f"moved to '{ERROR_DIR}'" if not args.keep_nsm else "kept in place"
        log(f"{len(failures)} file(s) not rebuilt (original .nsm {loc}) :")
        for f in failures:
            log(f"  - {f}")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
