#!/usr/bin/env python3
"""
reencode_fix.py
----------------
Re-encodes a "problem" video (rejected by a video host, decode errors
detected by ffmpeg) to produce a clean version, without (or with far
fewer) stream errors, relying on the fact that most players (VLC,
mpv, MX Player...) already play these videos without any visible
issue: the ffmpeg decoder performs exactly the same silent "repair"
(concealment of corrupted packets) as these players, but instead of
just displaying the result, the stream is fully RE-ENCODED into a
brand new H.265/HEVC stream, which therefore no longer contains the
original corrupted NAL markers.

This is NOT a simple remux (-c copy): that would change nothing, the
corruption is in the video stream itself. The pictures must be decoded
one by one (which ffmpeg already does, with its possible small visual
glitches at the corrupted places) and then re-encoded from scratch.

Trade-offs to be aware of:
  - It takes time (full transcode, not just a copy), even when
    accelerated by the GPU (NVENC).
  - The result is a new GOP/bitstream: minimal quality loss due to
    re-encoding (normal for any transcode), and the few pictures that
    were corrupted in the source may remain visibly damaged or frozen
    on screen (re-encoding does not invent the missing picture, it
    just "cleans" the stream around it).
  - It does not guarantee zero errors if the source file is very
    heavily corrupted, but in most cases it removes almost all the
    "Invalid NAL unit size" / "missing picture in access unit" errors
    that make the upload fail.

Bug fixed (observed 2026-09): on the first versions of the script,
the sound almost completely disappeared (only a few seconds) in the
re-encoded file, while it remained intact in the original - without
any warning in the ffmpeg logs, exit code 0 anyway. Two hypotheses
tested did NOT suffice to fix it:
1) -max_muxing_queue_size (interleaving queue overflow when the GPU
   encoding falls behind the audio);
2) splitting video and audio into two FULLY independent passes
   (see reencode_video()) to remove any GPU/audio interaction.
Even the audio pass alone (-vn, raw copy, no interaction with the
video) truncated the result at the exact same point - the cause was
therefore unrelated to interleaving/the GPU.

REAL cause identified (ffprobe on the original file): the audio track
declares a "duration" of ~5.5s for ~18900 AAC frames (which actually
represent ~8 minutes) - typical signature of a corrupted edit-list
box (`elst`) on that track, probably inherited from the
ransomware/reconstruction by restore_videos.py (which copies the audio
track "as is", edit-list included, without validating it).
ffmpeg strictly honours this edit-list and truncates any stream it
reads on that track (copy or re-encode, no difference); players such
as VLC ignore it and read the samples beyond, hence the illusion that
only re-encoding "broke" the sound. The fix is
`-ignore_editlist 1` on the input: confirmed in a real test (audio
extraction of 5.5s -> 8m18s, same duration as the video).

Encoder: hevc_nvenc (H.265, Nvidia GPU) by default, with automatic
fallback to libx265 (software H.265, CPU) if NVENC fails or is not
available on the machine. The stream is tagged "hvc1" in the MP4
container for better playback compatibility (Apple/QuickTime in
particular, which sometimes reject the default HEVC tag).

The audio is re-encoded by default to AAC-LC 192 kbps / 48 kHz /
stereo: quality far more than enough for voice/ambience at that
bitrate, and above all compatible without exception with
typical video hosts and forum players - unlike "better"
alternatives on paper (Opus, FLAC...) that are poorly supported in an
MP4 container by this kind of platform. Use --copy-audio to keep the
original audio as is from the start (faster, but it does not "repair"
anything on the audio side).

Bug observed (2026-09): an AAC stream corrupted in the middle
can make the audio pass fail fatally (the decoder eventually
misreads a corrupted "program config element" as a switch to
47 channels, which breaks the auto-inserted resampling filter -
exit code -22). Unlike H.264 corruption (see ERROR_MARKERS), this
type of corruption is internal to the codec bitstream and invisible
to the demuxer: -fflags discardcorrupt (tested) has no effect on it.
The script then automatically falls back, for that file only, to a
raw audio copy (-c:a copy, which never decodes the stream and thus
lets the corruption pass through without ever crashing) - see reencode_video().

Case also observed (2026-09): some sources have simply NO
audio track at all (silent captures). An -vn pass on them fails
systematically ("Output file does not contain any stream"),
whether re-encoding or raw-copy fallback - nothing to do with
a corruption. The script detects this case via the ffmpeg probing of
the video pass (has_audio_stream()) and skips the audio pass directly,
to produce a video-only output file (remux with no audio track).

Bug also observed (2026-09): on an .mkv file (Matroska, not
MP4), both passes failed systematically as soon as the file was
opened ("Option ignore_editlist not found" / "Error opening input
file"), identically with NVENC and CPU. Cause: -ignore_editlist is a
PRIVATE option of the MOV/MP4 demuxer, which simply does not exist
for the other demuxers (Matroska, AVI, WebM...) - passing it makes
ffmpeg fail before even opening the file, whatever its
content. The script now only adds this option for
containers of the MOV/MP4 family (see MOV_FAMILY_EXTENSIONS /
_ignore_editlist_args); the other containers have no such
edit-list notion inherited from QuickTime anyway.

The quality scale (--cq, see below) works in the same way
in H.265 as in H.264: lower = better quality/bigger file
(default: 18). At equal visual quality, H.265 nevertheless produces a
lighter file than H.264 (better compression efficiency) - at
identical quality setting, the result is therefore generally a bit
lighter than an H.264 re-encode would have given at the same --cq value.

Usage:
    # A single file, output in ./_reencoded/ next to the original
    python reencode_fix.py "video.mp4"

    # Several files at once
    python reencode_fix.py "video1.mp4" "video2.mp4"

    # A whole folder (all video files directly inside it)
    python reencode_fix.py "/path/to/recovered" --recursive

    # A folder, but only the files created before 2020-01-01
    # (date only, the time is not taken into account)
    python reencode_fix.py "/path/to/recovered" --created-before 2020-01-01

    # Force the CPU (no Nvidia GPU available / NVENC failing)
    python reencode_fix.py "video.mp4" --cpu

    # Different quality (lower cq = better quality, bigger file; default: 18)
    python reencode_fix.py "video.mp4" --cq 15

    # With the indicative count of decode errors before/after (disabled by default)
    python reencode_fix.py "video.mp4" --scan

By default, the script simply re-encodes (no error counting
before/after) - the definitive check remains to upload the
file produced in _reencoded/, which is then ready to be
uploaded to a typical video host. Use --scan to re-enable
the indicative counting of the ffmpeg decode errors before
and after re-encoding.

By default, once the re-encoding succeeds (output file present
and non-empty), the original file is moved to a
_to_delete/ folder created next to it (same convention as
restore_videos.py) rather than being deleted directly: to be checked
and then deleted by yourself once the result is confirmed good (the
file remains recoverable as is in the meantime). Use --keep-original
to keep the original in place instead of moving it.

On re-encoding FAILURE, the original file is on the contrary
moved to an _error/ folder created next to it, and the script moves
on to the next file without stopping - just put the file back in its
original place to try again (another --cq, --cpu, etc.).
"""

import argparse
import re
import shutil
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path
from typing import Optional

DEFAULT_FFMPEG_PATH = "ffmpeg"
VIDEO_EXTENSIONS = {".mp4", ".ts", ".mkv", ".mov", ".avi", ".m4v", ".webm"}

# -ignore_editlist is a PRIVATE option of the MOV/MP4 demuxer (the one
# that handles mp4/mov/m4v/m4a/3gp/3g2/mj2): passing it on a file read by
# another demuxer (.mkv, .avi, .webm, .ts...) makes ffmpeg fail
# immediately with "Option ignore_editlist not found" / "Error opening
# input file", BEFORE even opening the file - observed (2026-09) on
# an .mkv, identical with NVENC and CPU since it is the same input
# command that fails in both cases, nothing to do with an encoding
# issue. Matroska has no such edit-list notion inherited from
# QuickTime/MP4 anyway (cause of the bug documented above): the option
# only makes sense for this container family.
MOV_FAMILY_EXTENSIONS = {".mp4", ".mov", ".m4v", ".m4a", ".3gp", ".3g2", ".mj2"}


def _ignore_editlist_args(input_path: Path) -> list:
    """
    Returns ["-ignore_editlist", "1"] only if the input container
    belongs to the MOV/MP4 family (the only one where the option
    exists), otherwise an empty list - see MOV_FAMILY_EXTENSIONS.
    """
    return ["-ignore_editlist", "1"] if input_path.suffix.lower() in MOV_FAMILY_EXTENSIONS else []

# Decode error messages counted for the before/after (see the history
# in a standalone pre-check / error-scan script - this counting is purely
# indicative here, not a decision criterion).
ERROR_MARKERS = ("Invalid NAL unit size", "missing picture in access unit", "Error submitting packet to decoder")


def count_decode_errors(video: Path, ffmpeg_path: str, timeout: int = 3600) -> int:
    """
    Full decode in -v error mode, simple count of the number of lines
    containing one of the known error markers (without expanding the
    "Last message repeated N times" - indicative only, cf. above).
    """
    cmd = [ffmpeg_path, "-v", "error"] + _ignore_editlist_args(video) + ["-i", str(video), "-f", "null", "-"]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return -1
    lines = proc.stderr.splitlines()
    return sum(1 for l in lines if any(marker in l for marker in ERROR_MARKERS))


def nvenc_available(ffmpeg_path: str) -> bool:
    """Checks that hevc_nvenc is listed among the available encoders."""
    try:
        proc = subprocess.run(
            [ffmpeg_path, "-hide_banner", "-encoders"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=15,
        )
        return "hevc_nvenc" in proc.stdout
    except Exception:
        return False


AUDIO_CODEC = "aac"
AUDIO_BITRATE = "192k"   # AAC-LC stereo 192 kbps: good quality, almost transparent on voice/ambience, compatible with typical video hosts and forum players
AUDIO_SAMPLE_RATE = "48000"

# Known markers, in the ffmpeg output, of a silent packet loss
# (the process still ends with code 0).
WARNING_MARKERS = ("Too many packets buffered", "Non-monotonous DTS", "circular buffer", "st:1 error")


def build_video_cmd(input_path: Path, output_path: Path, ffmpeg_path: str, use_nvenc: bool, cq: int) -> list:
    """
    Encodes ONLY the video (-an), into an intermediate Matroska
    container - see reencode_video() for the reason of this
    video/audio split into independent passes.

    -ignore_editlist 1: ignores a possibly corrupted edit-list on the
    input (real cause of the audio truncation bug, see module
    docstring); no effect here for the video track itself, kept to stay
    consistent with build_audio_cmd on the same file.
    Only added for MOV/MP4 containers (see _ignore_editlist_args): it is
    a private option of that demuxer, absent elsewhere (.mkv, .avi,
    .webm...).
    """
    cmd = [
        ffmpeg_path, "-y",
        "-fflags", "+genpts+discardcorrupt",
        *_ignore_editlist_args(input_path),
        "-i", str(input_path),
        "-an",
    ]
    if use_nvenc:
        cmd += [
            "-c:v", "hevc_nvenc",
            "-preset", "p5",
            "-tune", "hq",
            "-rc", "vbr",
            "-cq", str(cq),
            "-b:v", "0",
        ]
    else:
        cmd += [
            "-c:v", "libx265",
            "-preset", "medium",
            "-crf", str(cq),
        ]
    cmd += ["-avoid_negative_ts", "make_zero", str(output_path)]
    return cmd


def build_audio_cmd(input_path: Path, output_path: Path, ffmpeg_path: str, copy_audio: bool) -> list:
    """
    Handles ONLY the audio (-vn), into an intermediate Matroska
    container (accepts any audio codec, including as a raw copy - no
    container compatibility constraint as a .m4a/.mp4 could
    impose).

    -ignore_editlist 1: ignores a possibly corrupted edit-list (`elst`)
    on the audio track, which otherwise truncates playback well before
    the real end of the stream (cause of the "the sound disappears after
    a few seconds" bug - see module docstring). Without this option,
    even a raw copy (-c:a copy) is truncated at the same point.
    Only added for MOV/MP4 containers (see _ignore_editlist_args):
    private option of that demuxer, absent elsewhere - passing it on an
    .mkv for instance makes ffmpeg fail before even opening the file
    ("Option not found").

    -fflags +genpts+discardcorrupt: same tolerance flags as on the
    video pass (build_video_cmd). Without them, a corrupted AAC source
    stream can crash the decoder (e.g. a "program config element"
    misread as a switch to 47 channels, causing the fatal failure of
    the auto-inserted resampling filter - exit code -22).
    discardcorrupt makes the demuxer drop corrupted packets before
    they reach the decoder, which avoids that crash (at the cost of a
    possible micro gap in the audio at that point, as is already
    tolerated on the video side).
    """
    cmd = [
        ffmpeg_path, "-y",
        "-fflags", "+genpts+discardcorrupt",
        *_ignore_editlist_args(input_path),
        "-i", str(input_path), "-vn",
    ]
    if copy_audio:
        cmd += ["-c:a", "copy"]
    else:
        # AAC-LC: the format best suited here - quality far more than
        # enough for voice/ambience at this bitrate, and above all
        # compatible without exception with typical video hosts and
        # forum players, unlike "better" alternatives on paper
        # (Opus, FLAC...) that are poorly supported in an MP4 container
        # by this kind of platform.
        cmd += ["-c:a", AUDIO_CODEC, "-b:a", AUDIO_BITRATE, "-ar", AUDIO_SAMPLE_RATE, "-ac", "2"]
    cmd += ["-avoid_negative_ts", "make_zero", str(output_path)]
    return cmd


def build_mux_cmd(video_path: Path, audio_path: Optional[Path], output_path: Path, ffmpeg_path: str) -> list:
    """
    Reassembles the intermediate files into a final MP4, as a pure
    stream copy (almost instantaneous, no additional re-encoding).
    The "hvc1" tag (HEVC/MP4 compatibility, notably Apple/QuickTime)
    is applied here, at the moment the video stream enters the final
    MP4 container (it makes no sense in the intermediate Matroska
    of the video pass).

    audio_path=None: source with no audio track at all (see
    has_audio_stream()) - video-only remux, without a 2nd input or audio
    -map.
    """
    cmd = [ffmpeg_path, "-y", "-i", str(video_path)]
    if audio_path is not None:
        cmd += ["-i", str(audio_path), "-map", "0:v:0", "-map", "1:a:0"]
    else:
        cmd += ["-map", "0:v:0"]
    cmd += ["-c", "copy", "-tag:v", "hvc1", "-movflags", "+faststart", str(output_path)]
    return cmd


def has_audio_stream(ffmpeg_probe_output: str) -> bool:
    """
    Detects whether the source has an audio track, from the ffmpeg
    probing output (the "Input #0, ..." section printed at the start of
    any ffmpeg call on that file, before "Stream mapping:").

    Some videos from the pipeline (silent captures) simply have NO
    audio track at all in the source file: asking for an "audio-only"
    -vn pass on them then fails with "Output file does
    not contain any stream" (nothing to do with a corruption) - see
    reencode_video(), which skips the audio pass in that case instead
    of trying, in a loop, a re-encode then a copy fallback on a
    stream that does not exist.
    """
    return bool(re.search(r"Stream #\d+:\d+.*:\s*Audio:", ffmpeg_probe_output))


def reencode_video(input_path: Path, output_path: Path, ffmpeg_path: str, use_nvenc: bool, cq: int, copy_audio: bool, timeout: int, save_log: bool = False) -> None:
    """
    Re-encodes in 3 independent passes (video only, audio only, remux)
    rather than in a single combined run.

    History: the single-pass version (video+audio encoded together, one
    single ffmpeg call) caused the near-total loss of the audio (sound
    cut after a few seconds, while the original remains intact) on large
    files with many video decode errors to conceal - without any warning
    showing up in the ffmpeg logs (exit code 0 anyway). Most likely
    cause: hevc_nvenc (asynchronous GPU encoding, with output latency
    due to its internal buffer) and the audio encoding (almost
    instantaneous) run at very different speeds in a single pass;
    -max_muxing_queue_size (tried first) did not suffice to fix the
    problem. Fully separating the two encodings removes this risk of
    interaction by construction, whatever the exact cause: each pass
    handles a single stream, with no other stream to interact/interleave
    with during encoding. The final remux (pass 3) is a pure stream
    copy, hence almost instantaneous.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Full log (command + complete ffmpeg output of each pass) next to
    # the output file - useful to diagnose an issue with the result,
    # but disabled by default (--log to enable it) so as not to leave
    # a .reencode.log next to every video once the script is
    # stabilised. Warning detection (WARNING_MARKERS) always happens in
    # memory, whether the log is written or not.
    log_path = output_path.parent / (output_path.name + ".reencode.log") if save_log else None
    log_chunks = []

    tmp_dir = output_path.parent / f".tmp_{output_path.stem}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_video = tmp_dir / "video.mkv"
    tmp_audio = tmp_dir / "audio.mka"

    def run_once(cmd):
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        log_chunks.append(f"$ {' '.join(str(c) for c in cmd)}\n{proc.stdout}")
        return proc

    try:
        # -- Pass 1/3: video only --
        tried_nvenc = use_nvenc
        cmd = build_video_cmd(input_path, tmp_video, ffmpeg_path, use_nvenc, cq)
        print(f"  [1/3] Video  : {' '.join(str(c) for c in cmd)}")
        proc = run_once(cmd)
        if proc.returncode != 0 and tried_nvenc:
            print(f"  [!] NVENC failed (code {proc.returncode}) - falling back to libx265 (CPU)...")
            cmd = build_video_cmd(input_path, tmp_video, ffmpeg_path, False, cq)
            print(f"  [1/3] Video (CPU) : {' '.join(str(c) for c in cmd)}")
            proc = run_once(cmd)
        if proc.returncode != 0:
            raise RuntimeError(f"Video encoding failed (code {proc.returncode})" + (f" - full log: {log_path}" if save_log else " - rerun with --log for the full detail"))

        # -- Pass 2/3: audio only, fully independent from the video --
        # Some sources have NO audio track at all (silent captures):
        # a -vn pass on them always fails ("Output file does not
        # contain any stream"), whether a re-encode or a raw copy is
        # attempted - this has nothing to do with a corruption, so no
        # point in trying: it is detected via the probing output of
        # pass 1 (already at hand) and the script jumps straight to the
        # video-only remux if that is the case.
        source_has_audio = has_audio_stream(log_chunks[-1])
        audio_fallback_copy = False
        tmp_audio_final = None

        if not source_has_audio:
            print(f"  [2/3] Audio  : skipped (no audio track in the source)")
        else:
            cmd = build_audio_cmd(input_path, tmp_audio, ffmpeg_path, copy_audio)
            print(f"  [2/3] Audio  : {' '.join(str(c) for c in cmd)}")
            proc = run_once(cmd)

            # Automatic fallback to the raw copy (-c:a copy) if the AAC
            # re-encode fails: observed (2026-09) on an AAC source
            # stream corrupted in the middle - the decoder eventually
            # misreads a corrupted "program config element" as a
            # switch to 47 channels, which makes the auto-inserted
            # resampling filter fail fatally (code -22). -fflags
            # discardcorrupt cannot do anything about it: the corruption
            # is internal to the codec bitstream, invisible to the
            # demuxer (valid container packets). The raw copy never
            # decodes the stream (byte-for-byte copy): the
            # corruption passes through without ever reaching the
            # decoder that crashes - same result as reading the original
            # file as is today, without "repairing" the corruption but
            # without a total failure either.
            if proc.returncode != 0 and not copy_audio:
                print(f"  [!] Audio re-encoding failed (code {proc.returncode}) - falling back to a raw copy (-c:a copy)...")
                cmd = build_audio_cmd(input_path, tmp_audio, ffmpeg_path, True)
                print(f"  [2/3] Audio (raw copy fallback) : {' '.join(str(c) for c in cmd)}")
                proc = run_once(cmd)
                audio_fallback_copy = proc.returncode == 0

            if proc.returncode != 0:
                raise RuntimeError(f"Audio processing failed (code {proc.returncode})" + (f" - full log: {log_path}" if save_log else " - rerun with --log for the full detail"))

            if audio_fallback_copy:
                print(f"  [i] Audio kept as is (not re-encoded, probable corruption of the AAC source stream)")

            tmp_audio_final = tmp_audio

        # -- Pass 3/3: final remux (pure copy) --
        cmd = build_mux_cmd(tmp_video, tmp_audio_final, output_path, ffmpeg_path)
        print(f"  [3/3] Remux  : {' '.join(str(c) for c in cmd)}")
        proc = run_once(cmd)
        if proc.returncode != 0:
            raise RuntimeError(f"Final remux failed (code {proc.returncode})" + (f" - full log: {log_path}" if save_log else " - rerun with --log for the full detail"))

    finally:
        combined_log = "\n\n".join(log_chunks)
        if save_log:
            log_path.write_text(combined_log, encoding="utf-8")

        hits = [m for m in WARNING_MARKERS if m.lower() in combined_log.lower()]
        if hits:
            suffix = f" - see {log_path}" if save_log else " - rerun with --log for the full detail"
            print(f"  [!] Warning(s) detected in the ffmpeg output: {', '.join(hits)}{suffix}")

        for f in (tmp_video, tmp_audio):
            try:
                f.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            tmp_dir.rmdir()
        except OSError:
            pass


def _move_aside(original: Path, subdir_name: str) -> Path:
    """
    Moves `original` into a `subdir_name` subfolder created next to
    it, with name collision handling (suffix _1, _2, ... if the
    name already exists at the destination) - same convention as
    restore_videos.py (_to_delete/, _error/).
    """
    target_dir = original.parent / subdir_name
    target_dir.mkdir(parents=True, exist_ok=True)

    dest = target_dir / original.name
    if dest.exists():
        stem, suffix = original.stem, original.suffix
        i = 1
        while dest.exists():
            dest = target_dir / f"{stem}_{i}{suffix}"
            i += 1

    shutil.move(str(original), str(dest))
    return dest


def move_to_to_delete(original: Path) -> Path:
    """
    Moves the original file into a _to_delete/ folder created next to
    it instead of deleting it directly: the file remains intact
    and recoverable as long as that folder has not been emptied
    manually, once the re-encoding result has been checked as good.
    """
    return _move_aside(original, "_to_delete")


def move_to_error(original: Path) -> Path:
    """
    Moves the original file into an _error/ folder created next to
    it when its re-encoding failed, so as not to leave it mixed
    with the files still to be processed - just put it back in its
    original place to try again (new version of the script, --cpu,
    etc.), as in restore_videos.py.
    """
    return _move_aside(original, "_error")


# Folders ignored during a directory scan: _reencoded/ (outputs already
# produced), _to_delete/ (processed originals moved by move_to_to_delete)
# and _error/ (failed originals moved by move_to_error) - same logic
# as restore_videos.py: files that land there must never be reprocessed
# during a new --recursive run.
IGNORED_DIR_NAMES = {"_reencoded", "_to_delete", "_error"}


def get_creation_date(path: Path) -> date:
    """
    File creation date (without the time) - st_ctime is the creation
    date on Windows (target platform of this script), unlike
    Linux where it is the last metadata modification date.
    """
    return datetime.fromtimestamp(path.stat().st_ctime).date()


def collect_video_files(paths: list, recursive: bool, created_before: Optional[date] = None) -> list:
    videos = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            pattern = "**/*" if recursive else "*"
            videos += [
                f for f in path.glob(pattern)
                if f.is_file()
                and f.suffix.lower() in VIDEO_EXTENSIONS
                and IGNORED_DIR_NAMES.isdisjoint(f.relative_to(path).parts[:-1])
            ]
        elif path.is_file():
            videos.append(path)
        else:
            print(f"[!] Not found, ignored: {path}")

    if created_before is not None:
        before = videos
        videos = [f for f in before if get_creation_date(f) < created_before]
        skipped = len(before) - len(videos)
        if skipped:
            print(f"[i] --created-before {created_before.isoformat()}: {skipped} file(s) ignored (creation date >= {created_before.isoformat()})")

    return videos


def main():
    parser = argparse.ArgumentParser(
        description="Re-encodes one or more videos to H.265/HEVC to remove the stream errors that make the upload fail.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("paths", nargs="+", help="Video file(s) and/or folder(s) to process")
    parser.add_argument("--recursive", action="store_true", help="Also walks the subdirectories of the given folders")
    parser.add_argument("--created-before", metavar="YYYY-MM-DD", help="Only processes the files whose creation date is strictly earlier than this date (date only, the time is not taken into account) - useful to process a folder in batches")
    parser.add_argument("--out-dir", help="Output directory (default: <source_folder>/_reencoded)")
    parser.add_argument("--cpu", action="store_true", help="Forces libx265 (CPU), does not try NVENC")
    parser.add_argument("--cq", type=int, default=18, help="NVENC quality (cq) or libx265 CRF (default: 18; lower = better quality/bigger file)")
    parser.add_argument("--copy-audio", action="store_true", help=f"Copies the audio as is instead of re-encoding it to AAC {AUDIO_BITRATE} (default: re-encoded)")
    parser.add_argument("--ffmpeg-path", default=DEFAULT_FFMPEG_PATH, help=f"Path to ffmpeg (default: {DEFAULT_FFMPEG_PATH!r})")
    parser.add_argument("--timeout", type=int, default=7200, help="Timeout per file in seconds (default: 7200)")
    parser.add_argument("--scan", action="store_true", help="Also counts the errors before/after re-encoding, as an indication (default: disabled, re-encode only)")
    parser.add_argument("--log", action="store_true", help="Writes an <output>.reencode.log file with the full detail of the ffmpeg commands (disabled by default)")
    parser.add_argument("--keep-original", action="store_true", help="Keeps the original file in place instead of moving it to _to_delete/ once the re-encoding succeeded (default: moved)")
    args = parser.parse_args()

    created_before = None
    if args.created_before:
        try:
            created_before = datetime.strptime(args.created_before, "%Y-%m-%d").date()
        except ValueError:
            print(f"[!] Invalid --created-before ({args.created_before!r}) - expected format: YYYY-MM-DD")
            sys.exit(1)

    videos = collect_video_files(args.paths, args.recursive, created_before)
    if not videos:
        print("[!] No video file found.")
        sys.exit(1)

    use_nvenc = not args.cpu
    if use_nvenc and not nvenc_available(args.ffmpeg_path):
        print("[!] hevc_nvenc not detected on this machine - switching to libx265 (CPU).")
        use_nvenc = False

    print(f"{'='*60}")
    print(f"  reencode_fix.py")
    print(f"{'='*60}")
    print(f"  Files to process   : {len(videos)}")
    if created_before:
        print(f"  Date filter        : creation < {created_before.isoformat()}")
    print(f"  Encoder            : {'hevc_nvenc (GPU)' if use_nvenc else 'libx265 (CPU)'}")
    print(f"  Quality (cq/crf)   : {args.cq}")
    print(f"  Audio              : {'copied as is' if args.copy_audio else f're-encoded (AAC {AUDIO_BITRATE})'}")
    print(f"  Original file      : {'kept in place (--keep-original)' if args.keep_original else 'moved to _to_delete/ once successful'}")
    print(f"  Error counting     : {'before/after (--scan)' if args.scan else 'disabled (re-encode only)'}")
    print()

    for i, video in enumerate(videos, start=1):
        out_dir = Path(args.out_dir).resolve() if args.out_dir else video.parent / "_reencoded"
        output_path = out_dir / video.name

        print(f"\n[{i}/{len(videos)}] {video.name}")
        print(f"{'-'*60}")

        errors_before = None
        if args.scan:
            print("  [>] Counting the errors BEFORE re-encoding...")
            errors_before = count_decode_errors(video, args.ffmpeg_path, args.timeout)
            print(f"  [>] Errors before: {errors_before if errors_before >= 0 else 'timeout'}")

        start = time.monotonic()
        try:
            reencode_video(video, output_path, args.ffmpeg_path, use_nvenc, args.cq, args.copy_audio, args.timeout, save_log=args.log)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            print(f"  [!] Failure: {e}")
            try:
                dest = move_to_error(video)
                print(f"  [>] Original file moved to _error/: {dest}")
            except OSError as move_err:
                print(f"  [!] Cannot move the failed file to _error/ ({video}): {move_err}")
            continue
        elapsed = time.monotonic() - start
        print(f"  [OK] Re-encoding finished in {elapsed/60:.1f} min -> {output_path}")

        if args.scan:
            print("  [>] Counting the errors AFTER re-encoding...")
            errors_after = count_decode_errors(output_path, args.ffmpeg_path, args.timeout)
            print(f"  [>] Errors after: {errors_after if errors_after >= 0 else 'timeout'}")
            if errors_before is not None and errors_before >= 0 and errors_after >= 0:
                print(f"  [{'OK' if errors_after < errors_before else '!'}] {errors_before} -> {errors_after} errors")

        if args.keep_original:
            continue

        # The output file was written without error (otherwise we would
        # have already `continue`d above): the original is moved into
        # _to_delete/ rather than deleted directly (see
        # move_to_to_delete). Minimal safety net: check that
        # the output file really exists and is not empty before touching
        # it.
        if output_path.exists() and output_path.stat().st_size > 0:
            try:
                dest = move_to_to_delete(video)
                print(f"  [>] Original file moved to _to_delete/: {dest}")
            except OSError as e:
                print(f"  [!] Cannot move the original file ({video}): {e}")
        else:
            print(f"  [!] Output file missing/empty, original file kept for safety: {video}")

    print(f"\n{'='*60}")
    print("  Done.")
    print("  Re-upload the files from the _reencoded/ folder to retry the upload.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
