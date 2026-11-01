#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
restore_and_reencode.py
========================

Combine in a single pass, file by file:
  1. the decryption/reconstruction of a .nsm (restore_videos.py);
  2. if the reconstruction succeeded (mode 'restored' -- a video stream was
     actually reconstructed, hence potentially carrying the small
     NAL anomalies that make the upload fail), the clean
     re-encoding to H.265/HEVC of the resulting video
     (reencode_fix.py), BEFORE moving on to the next .nsm.

The final video file, already cleaned, carries the ORIGINAL NAME recovered
from the .nsm footer (e.g. video.nsm -> video.mp4), at the same place
as the .nsm (or in --out-dir if given) -- like restore_videos.py
alone. There is no intermediate "decoded but not yet re-encoded" video
lying around: the decoded file is produced under that final name by
restore_videos.py, then replaced IN PLACE by its re-encoded version as
soon as the latter is ready (temporary file removed/renamed, never
both versions visible at the same time).

Special case -- .nsm file merely RENAMED (not encrypted, mode
'renamed' of restore_videos.py): it is already intact from the
start (never touched by the ransomware), hence handled EXACTLY like
restore_videos.py alone -- simple rename/copy to the
right extension, WITHOUT re-encoding (nothing to clean).

The original .nsm is then moved (same convention as the two
original scripts):
  - on COMPLETE success (decoding AND, if applicable, re-encoding)
    -> '_to_delete';
  - on failure, at ANY stage (decoding OR re-encoding)
    -> '_error'.
(unless --keep-nsm, which disables any move.)

If decoding succeeds but RE-ENCODING fails, the intermediate
decoded file is deleted (no half-cleaned result left
behind) and only the original .nsm goes to '_error' -- putting it
back in place is enough to retry (decoding will be redone, that is
the price of simplicity).

All decoding options of restore_videos.py are reused
unchanged (see its own docstring for the detail of each one).
The re-encoding options reuse those of reencode_fix.py (see
its docstring for the history of the bugs fixed: truncated audio
edit-list, tracks without sound, corrupted AAC stream...).

Usage:
    python restore_and_reencode.py --folder "path/to/folder"
    python restore_and_reencode.py --files "video1.nsm" "video2.nsm"
        [decoding options -- see restore_videos.py]
        [--cpu] [--cq 18] [--copy-audio] [--ffmpeg-path ffmpeg]
        [--timeout 7200] [--scan] [--log] [--keep-nsm]

Dependencies: restore_videos.py and reencode_fix.py must be located
in the same folder as this script (modules imported directly, no
duplication of their logic).
"""

import argparse
import glob
import os
import subprocess
import sys
import time
from pathlib import Path

import restore_videos as rv
import reencode_fix as rf


def locate_decoded_output(out_dir: str, base_name: str, nsm_path: str) -> Path:
    """Find the file produced by restore_videos.process_file() in
    'restored' mode: it ALWAYS writes exactly one file
    `out_dir/base_name.<ext>` (including after a possible remux .ts ->
    .mp4, which deletes the intermediate .ts -- see
    remux_ts_reconstructed in restore_videos.py). We locate it by a name
    pattern rather than guessing the extension ourselves (it can
    change along the way depending on the detected container),
    excluding the .nsm itself and taking, for safety, the most
    recently modified one if several matches already exist."""
    pattern = os.path.join(glob.escape(out_dir), glob.escape(base_name) + '.*')
    candidates = [c for c in glob.glob(pattern)
                  if os.path.abspath(c) != os.path.abspath(nsm_path)]
    if not candidates:
        raise FileNotFoundError(
            f"decoded file not found in {out_dir} (pattern {base_name}.*)")
    return Path(max(candidates, key=os.path.getmtime))


# Containers in which the final remux of reencode_fix (HEVC tagged
# 'hvc1') stays readable -- checked with ffmpeg. The others (ASF .wmv/.wma,
# MPEG-PS .mpg...) either fail or do WORSE: return code 0 but an 'unknown'
# video track (the ASF case), hence a file without video counted as
# successful. The re-encoded result is written as .mp4 there instead.
HEVC_SAFE_SUFFIXES = {'.mp4', '.m4v', '.mov', '.mkv', '.avi'}


def reencoded_target(decoded_path: Path) -> Path:
    """Final path of the re-encoded file: same name as the decoded file,
    unless its container cannot carry HEVC (see
    HEVC_SAFE_SUFFIXES) -- .mp4 extension in that case."""
    if decoded_path.suffix.lower() in HEVC_SAFE_SUFFIXES:
        return decoded_path
    return decoded_path.with_suffix('.mp4')


def reencode_in_place(decoded_path: Path, ffmpeg_path: str, use_nvenc: bool,
                       cq: int, copy_audio: bool, timeout: int,
                       save_log: bool, scan: bool):
    """Re-encode `decoded_path` to H.265 and replace its content IN
    PLACE (same final name, unless the container is not HEVC-compatible -- see
    reencoded_target), via a temporary file next to it. Returns the
    path of the re-encoded file on success (the decoded file is
    then deleted if it had another extension), None otherwise
    (decoded_path is deleted by the caller)."""
    final_path = reencoded_target(decoded_path)
    tmp_output = decoded_path.with_name(
        decoded_path.stem + ".h265reencode.tmp" + final_path.suffix)

    errors_before = None
    if scan:
        print("  [->] Counting errors BEFORE re-encoding...")
        errors_before = rf.count_decode_errors(decoded_path, ffmpeg_path, timeout)
        print(f"  [->] Errors before: {errors_before if errors_before >= 0 else 'timeout'}")

    try:
        rf.reencode_video(decoded_path, tmp_output, ffmpeg_path, use_nvenc,
                           cq, copy_audio, timeout, save_log=save_log)
    except Exception as e:
        print(f"  [X] Re-encoding failed: {e}")
        tmp_output.unlink(missing_ok=True)
        return None

    if not (tmp_output.exists() and tmp_output.stat().st_size > 0):
        print("  [!] Re-encoded file missing/empty after re-encoding.")
        tmp_output.unlink(missing_ok=True)
        return None

    # Safety net: ffmpeg may return 0 after writing an unreadable
    # video track ('unknown' codec) -- we require that at least one frame
    # decodes before replacing the decoded file.
    probe = subprocess.run(
        [ffmpeg_path, "-v", "error", "-i", str(tmp_output), "-map", "0:v:0",
         "-frames:v", "1", "-f", "null", "-"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120)
    if probe.returncode != 0:
        print(f"  [!] Re-encoded file without decodable video track "
              f"({(probe.stderr or '').strip().splitlines()[-1:] or 'no detail'}) "
              f"- rejected.")
        tmp_output.unlink(missing_ok=True)
        return None

    if scan:
        print("  [->] Counting errors AFTER re-encoding...")
        errors_after = rf.count_decode_errors(tmp_output, ffmpeg_path, timeout)
        print(f"  [->] Errors after: {errors_after if errors_after >= 0 else 'timeout'}")
        if errors_before is not None and errors_before >= 0 and errors_after >= 0:
            marker = 'OK' if errors_after < errors_before else '!'
            print(f"  [{marker}] {errors_before} -> {errors_after} errors")

    decoded_path.unlink()
    tmp_output.replace(final_path)
    return final_path


def main():
    ap = argparse.ArgumentParser(
        description="Decrypts a .nsm (restore_videos.py) then re-encodes "
                     "the result to H.265 (reencode_fix.py) immediately, "
                     "file by file, before moving on to the next one.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    # --- decoding options (identical to restore_videos.py) ---
    dec = ap.add_argument_group("decoding (restore_videos.py)")
    dec.add_argument('--folder',
                      help="folder to walk RECURSIVELY looking for .nsm files "
                           f"(the '{rv.SUCCESS_DIR}' and '{rv.ERROR_DIR}' folders are created "
                           "at its root and mirror the tree of the processed files)")
    dec.add_argument('--files', nargs='*', help="explicit list of .nsm files")
    dec.add_argument('--out-dir', default=None,
                      help="output folder for the final file (default: same folder as the .nsm)")
    dec.add_argument('--fps', type=float, default=24.0,
                      help="fallback frame rate (fps) for CASE B files, used "
                           "only if it could not be computed automatically "
                           "(default 24)")
    dec.add_argument('--width', type=int, default=None,
                      help="EXPERIMENTAL (MP4 CASE B and MKV): fallback video width -- "
                           "see restore_videos.py")
    dec.add_argument('--height', type=int, default=None,
                      help="EXPERIMENTAL: fallback video height -- see restore_videos.py")
    dec.add_argument('--no-auto-resolution', action='store_true',
                      help="disables the fast automatic resolution detection")
    dec.add_argument('--brute-force-resolution', action='store_true',
                      help="also tries a combinatorial sweep if the fast detection fails")
    dec.add_argument('--resolution-lock', action='store_true',
                      help="with --width/--height AND --brute-force-resolution: limits the "
                           "sweep to that single resolution")
    dec.add_argument('--auto-resolution-timeout', type=float, default=90.0,
                      help="time budget (s) for the automatic resolution detection "
                           "per affected file (default 90)")
    dec.add_argument('--sps-pps-from', nargs='+', default=None, metavar='FILE.mp4',
                      help="MP4 file(s) providing the REAL SPS/PPS -- see restore_videos.py")
    dec.add_argument('--profile-dir', default=None, metavar='DIR',
                      help="folder of the learned SPS/PPS profile base (default: next to the scripts)")
    dec.add_argument('--no-profile-matching', action='store_true',
                      help="disables the automatic trial of already known SPS/PPS profiles")
    dec.add_argument('--no-profile-learning', action='store_true',
                      help="does not record the newly recovered SPS/PPS profiles")
    dec.add_argument('--seed-profiles', nargs='+', default=None, metavar='FILE_OR_DIR',
                      help="maintenance mode: seeds the SPS/PPS profile base, without processing any .nsm")
    dec.add_argument('--keep-nsm', action='store_true',
                      help="keep the original .nsm files in place, on success or failure "
                           f"(move nothing to '{rv.SUCCESS_DIR}'/'{rv.ERROR_DIR}')")

    # --- re-encoding options (identical to reencode_fix.py) ---
    enc = ap.add_argument_group("re-encoding (reencode_fix.py)")
    enc.add_argument('--cpu', action='store_true', help="forces libx265 (CPU), does not try NVENC")
    enc.add_argument('--cq', type=int, default=18,
                      help="NVENC quality (cq) or libx265 CRF (default: 18; lower = "
                           "better quality/heavier file)")
    enc.add_argument('--copy-audio', action='store_true',
                      help=f"copies the audio as is instead of re-encoding it to AAC "
                           f"{rf.AUDIO_BITRATE} (default: re-encoded)")
    enc.add_argument('--ffmpeg-path', default=rf.DEFAULT_FFMPEG_PATH,
                      help=f"path to ffmpeg (default: {rf.DEFAULT_FFMPEG_PATH!r})")
    enc.add_argument('--timeout', type=int, default=7200,
                      help="timeout per ffmpeg pass in seconds (default 7200)")
    enc.add_argument('--scan', action='store_true',
                      help="indicative count of decode errors before/after re-encoding")
    enc.add_argument('--log', action='store_true',
                      help="writes a <output>.reencode.log file with the full ffmpeg detail")

    args = ap.parse_args()
    profile_dir = args.profile_dir or rv.DEFAULT_PROFILE_DIR

    if args.seed_profiles:
        rv.seed_profiles_from_paths(args.seed_profiles, profile_dir)

    targets = []
    seen = set()

    def add_target(t):
        t = os.path.abspath(t)
        if t not in seen:
            seen.add(t)
            targets.append(t)

    folder_root = None
    if args.folder:
        folder_root = os.path.abspath(args.folder)
        excluded_dirnames = {rv.SUCCESS_DIR.lower(), rv.ERROR_DIR.lower(), '#recycle'}
        for dirpath, dirnames, filenames in os.walk(folder_root):
            dirnames[:] = [d for d in dirnames if d.lower() not in excluded_dirnames]
            for fn in filenames:
                if fn.lower().endswith('.nsm'):
                    add_target(os.path.join(dirpath, fn))
        targets.sort()
    if args.files:
        for t in args.files:
            add_target(t)
    if not targets:
        if args.seed_profiles:
            rv.log("No .nsm file to process (profile base seeding done).")
            return 0
        rv.log("No .nsm file to process (check --folder / --files).")
        return 1

    use_nvenc = not args.cpu
    if use_nvenc and not rf.nvenc_available(args.ffmpeg_path):
        print("[!] hevc_nvenc not detected on this machine - falling back to libx265 (CPU).")
        use_nvenc = False

    if folder_root:
        rv.log(f"Folder root             : {folder_root} (whole tree walked)")
        rv.log(f"Success folder          : {os.path.join(folder_root, rv.SUCCESS_DIR)}")
        rv.log(f"Failure folder          : {os.path.join(folder_root, rv.ERROR_DIR)}")
    rv.log(f"Files to process        : {len(targets)}")
    rv.log(f"Output folder           : {args.out_dir or '(same folder as each .nsm)'}")
    rv.log(f"Encoder (re-encoding)   : {'hevc_nvenc (GPU)' if use_nvenc else 'libx265 (CPU)'}")
    rv.log(f"Quality (cq/crf)        : {args.cq}")
    rv.log(f"Audio (re-encoding)     : {'copied as is' if args.copy_audio else f're-encoded (AAC {rf.AUDIO_BITRATE})'}")
    n_known_profiles = len(rv.load_profile_store(profile_dir))
    rv.log(f"SPS/PPS profile base    : {profile_dir} ({n_known_profiles} known profile(s))")

    failures = []
    for i, t in enumerate(targets, start=1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(targets)}] {os.path.basename(t)}")
        print(f"{'='*60}")

        out_dir = args.out_dir or os.path.dirname(t)
        os.makedirs(out_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(t))[0]

        start = time.monotonic()
        ok, mode = rv.process_file(
            t, out_dir, args.fps,
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
            # Unencrypted file, merely renamed to the right extension by
            # restore_videos.py: already intact from the start (never
            # touched by the ransomware), nothing to clean -- the .nsm has
            # already been handled (moved/consumed or copied) by
            # process_file itself, see its docstring.
            rv.log("  (file merely renamed: no re-encoding needed)")
            continue

        if not ok:
            # Decoding failure (mode == 'failed'): nothing was produced.
            if not args.keep_nsm:
                dest = rv.move_nsm_to(t, folder_root, rv.ERROR_DIR)
                rv.log(f"  -> {os.path.basename(t)} (decoding FAILED) moved to {dest}")
                failures.append(dest)
            else:
                failures.append(t)
            continue

        # mode == 'restored' and decoding succeeded: we immediately chain
        # into the H.265 re-encoding, BEFORE moving on to the next file.
        try:
            decoded_path = locate_decoded_output(out_dir, base_name, t)
        except FileNotFoundError as e:
            rv.log(f"  [ERROR] {e}")
            if not args.keep_nsm:
                dest = rv.move_nsm_to(t, folder_root, rv.ERROR_DIR)
                rv.log(f"  -> {os.path.basename(t)} (FAILED) moved to {dest}")
                failures.append(dest)
            else:
                failures.append(t)
            continue

        decode_elapsed = time.monotonic() - start
        rv.log(f"  [OK] Decoding done in {decode_elapsed:.1f}s -> {decoded_path}")

        print(f"  [->] H.265 re-encoding of {decoded_path.name}...")
        reencode_start = time.monotonic()
        final_path = reencode_in_place(
            decoded_path, args.ffmpeg_path, use_nvenc, args.cq, args.copy_audio,
            args.timeout, args.log, args.scan)
        reencode_elapsed = time.monotonic() - reencode_start

        if final_path is None:
            decoded_path.unlink(missing_ok=True)
            print(f"  [X] Re-encoding failed in {reencode_elapsed/60:.1f} min "
                  f"- intermediate decoded file deleted.")
            if not args.keep_nsm:
                dest = rv.move_nsm_to(t, folder_root, rv.ERROR_DIR)
                rv.log(f"  -> {os.path.basename(t)} (re-encoding FAILED) moved to {dest}")
                failures.append(dest)
            else:
                failures.append(t)
            continue

        print(f"  [OK] Re-encoding done in {reencode_elapsed/60:.1f} min -> {final_path}")
        if final_path != decoded_path:
            print(f"      (container {decoded_path.suffix} not HEVC-compatible: "
                  f"result written as {final_path.suffix})")
        if not args.keep_nsm:
            dest = rv.move_nsm_to(t, folder_root, rv.SUCCESS_DIR)
            rv.log(f"  -> {os.path.basename(t)} (complete success) moved to {dest}")

    rv.log(f"\n{'='*60}")
    rv.log("Done.")
    if failures:
        loc = f"moved to '{rv.ERROR_DIR}'" if not args.keep_nsm else "kept in place"
        rv.log(f"{len(failures)} failed file(s) (original .nsm {loc}):")
        for f in failures:
            rv.log(f"  - {f}")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
