# restore_videos.py - structural recovery of `.nsm` / `HARR` files

`restore_videos.py` rebuilds the headers of video files (MP4, MKV/WebM,
AVI, FLV, ASF, MPEG-PS/TS) and JPEG images damaged by a ransomware that:

1. **encrypts a zone at the start of each file** - 4096 bytes on the
   reference samples, sometimes more on other files (up to ~266 KB
   observed);
2. renames the file with a **`.nsm`** extension;
3. **appends a footer** (~54 bytes) at the very end, carrying among other
   things the original extension (double `HARR` marker).

Some `.nsm` files **are not encrypted at all**: the ransomware merely
renamed them (no encrypted zone, no HARR footer). They are ordinary
video, image or audio files. For those, the script detects the real
format from the leading bytes and **simply renames the file** to the
right extension (video -> `.mp4` by default, images -> `.jpg`/`.png`/...
according to the format) - see below.

## What this is, and what this is not

- **Not a decryption tool.** The key is derived and kept on the
  attacker's C2 server, behind a payment. Neither the footer nor any
  recovered artefact contains it: decryption is impossible without that
  server.
- **A structural recovery tool.** Only the head of the file is lost.
  Past the encrypted zone, every byte is strictly identical to the
  original: nothing was moved, inserted or deleted. The script rebuilds
  a valid container header (or a JPEG header) around the intact payload,
  reading **from the file itself** everything that is missing (codec,
  resolution, frame rate, tracks). **No reference file is required.**
- **An honest tool.** When a reconstruction cannot be validated
  (structural tiling check, real decoding with `ffmpeg`), the file is
  reported as failed instead of being produced broken in silence.

> Consequence: the first seconds of video/sound (the samples that fell
> in the encrypted zone) are lost, but the rest of the file becomes
> readable again.

## Disclaimer

Work on **copies** of your files. Keep the `.nsm` originals: the tool
moves them into `_to_delete/` (success) or `_error/` (failure) but never
deletes them, and any run can be repeated with different options.

Always **open a recovered file in a real player** (and skip through it)
before deleting anything. A `0` exit code means the tool produced a file
it could validate, not that the file is a perfect copy of the original
(see the Limitations section below).

Do not pay the ransom: the key is held by the attacker's server, locked
behind a payment, and structural recovery already brings back everything
except the encrypted zone itself.

The software is provided as is, without warranty of any kind. You are
responsible for what you run it on.

## Requirements

- **Python 3.8+**, standard library only. No external dependency is
  required to run `restore_videos.py`.
- **`ffmpeg` and `ffprobe` on `PATH` - optional, strongly recommended.**
  They are used as a *decoding oracle*: a reconstructed codec
  configuration is only accepted once real frames decode cleanly with
  it. Without `ffmpeg`, several recovery paths degrade (no automatic
  codec detection, no candidate validation, no remux of recovered
  transport streams), but the script still runs.
- **Pillow - optional.** Only used to verify a reconstructed JPEG when
  `ffmpeg` is not available.
- The companion scripts (`restore_and_reencode.py`, `reencode_fix.py`)
  call `ffmpeg` to re-encode recovered files; see their `--help`.

## Quick start

Process every `.nsm` under a folder (the whole tree is walked
recursively):

```bash
python restore_videos.py --folder "/path/to/encrypted"
```

Process an explicit list of files, writing results elsewhere and
keeping the originals:

```bash
python restore_videos.py --files "a.nsm" "b.nsm" \
    --out-dir "/path/to/recovered" --keep-nsm
```

Use donor files when the codec configuration was lost, and keep an
append-only log of what was done:

```bash
python restore_videos.py --folder "/path/to/encrypted" \
    --sps-pps-from "/path/to/known_good.mp4" \
    --manifest processed.manifest.csv
```

Seed the learned SPS/PPS database from files already recovered, then
process a new batch:

```bash
python restore_videos.py --seed-profiles "/path/to/recovered" \
    --folder "/path/to/encrypted"
```

Recovered files are written next to each `.nsm` by default, under the
original name (`video.nsm` -> `video.mp4`).

### Where the original `.nsm` files go

After each **encrypted** file is processed, its `.nsm` is moved (unless
`--keep-nsm`) into a folder at the **root** of the `--folder` argument,
**reproducing the directory tree**:

- success -> `_to_delete/`:

  ```text
  root/sub/videos/video.nsm  ->  root/_to_delete/sub/videos/video.nsm
  ```

  delete it, with its contents, once the recovered file has been
  verified;
- failure -> `_error/`:

  ```text
  root/sub/videos/video.nsm  ->  root/_error/sub/videos/video.nsm
  ```

  put the file back where it was to try again (new version of the
  script, `--width`/`--height`, donors, ...).

With `--files` only, `_to_delete/` and `_error/` are created next to each
file. Both folders are skipped on a later walk, so already-moved files
are never touched again. When the destination name already exists, a
`_1`, `_2`, ... suffix is added.

**Files that were only renamed** (no encryption, no footer) are not
"recovered": they are renamed in place to their real extension (or moved
to `--out-dir`), so the `.nsm` is already consumed and does not go to
`_to_delete/`. Only failures (unrecognised format) land in `_error/`.

## How it works

`restore_videos.py` is **self-contained** (standard library only,
Python >= 3.8). For each `.nsm`:

1. **Read the `HARR` footer** (end of file) -> original extension and
   useful size (`file size - footer`). *If the footer is absent, the
   file was probably only renamed: see the dedicated section below.*
2. **Pick the container** from the footer extension:
   - `.mkv` / `.webm` -> **Matroska** mode (MPEG-TS fallback when no
     usable `Cluster` is found, see below);
   - `.avi` -> **RIFF/AVI** mode;
   - `.flv` -> **Adobe FLV** mode;
   - `.mpg` / `.mpeg` -> **MPEG-1/2 Program Stream** mode;
   - `.jpg` / `.jpeg` -> **JPEG image** mode (dedicated section below);
   - `.ts` / `.m2ts` / `.mts` -> **MPEG Transport Stream** mode;
   - `.wmv` / `.wma` / `.asf` -> **ASF** mode;
   - anything else -> **MP4** (ISO-BMFF) mode, with an MPEG-TS fallback
     when no ISO-BMFF structure is found.
3. **Reconstruct** according to the case (sections below).

### The encrypted zone(s): read directly from the footer

The footer carries, in clear, the fields needed to locate EXACTLY the
encrypted zone(s) of a given file - no need to guess. Layout confirmed
by reverse-engineering the locker binary (the resulting recovery notes
are not part of this project): 41 bytes of payload, between the
extension and the last `HARR` marker:

| Field | Size | Content |
|---|---|---|
| mode | 1 byte | `0x15` = **HEAD** (a single zone, at the start); `0x17` = **SPOTS** (head zone plus extra zones) |
| nonce | 24 bytes | XChaCha20, unique per file - unusable without the attacker's key |
| original size | 8 bytes (BE) | size of the file before encryption |
| zone size | 4 bytes (BE) | EXACT size of each encrypted zone, in bytes (4096 most of the time, up to 262144 observed on large files) |
| extra zones | 4 bytes (BE) | 0 in HEAD mode; usually 4 in SPOTS mode |

The script reads those fields and uses the zone size directly as the
length of the head zone - **100% reliable**, since it is the value
written by the ransomware itself. The nonce is unique per file and is
never reused (checked across the files examined).

The former **entropy-based detection** is kept **as a fallback only**,
for files whose footer is absent or unreadable (see the section on files
that were merely renamed): encrypted bytes are nearly indistinguishable
from random noise (Shannon entropy ~7.8-7.95 out of 8), while the real
MP4 metadata that follows (`stsz`/`stco`/`stsc` tables, repetitive
structures) has a clearly lower entropy. The fallback looks, starting
from 4096, for the first point where entropy drops sharply, then refines
the boundary by binary search.

#### SPOTS mode: extra zones cannot be located without the key

On files larger than about 1 GB, the ransomware encrypts, in addition to
the head zone, **several extra zones** (usually 4 observed) of the same
size, spread further into the file. The script detects this from the
footer and says so explicitly (`[WARNING] SPOTS mode detected...`), but
**does not try to locate those zones from the content**: an
already-compressed video stream has a Shannon entropy almost identical
to encrypted noise (~7.9-7.95 bits/byte in both cases), which makes
entropy detection useless here (checked empirically: no measurable
transition on a real 1.3 GB SPOTS sample, entropy high from beginning to
end). Consequence: a file in SPOTS mode, once rebuilt, remains
**globally readable** (header fixed, frame rate/audio track intact) but
shows short visual/sound corruptions at unpredictable positions (a few
tenths of a second to a few seconds, usually 4 occurrences) - the
explicit warning lists the size and number of zones involved for each
file.

**Corner case observed**: on a large SPOTS file, one of the extra zones
can fall exactly on the `moov` box when the latter sits at the end of
the file - case A (see below) then becomes impossible: the `moov` box
still exists by its tag, but its content is no longer a valid structure.
The file is then reported as failed rather than rebuilt with an
unreadable stream (see the structural validation of `moov` below).

### MP4 - case A: `moov` intact

The `moov` index sits **after** `mdat` (at the end of the file), hence
outside the encrypted zone: it is intact. The script only rewrites the
first `N` bytes (`N` = zone size determined above; standard `ftyp` +
recomputed `mdat` header) and copies the rest as is.

**Structural validation of the `moov` candidate.** Before accepting it,
the script checks that the box found tiles EXACTLY with valid sub-boxes
(recursively into `trak`/`mdia`/`minf`/`stbl`..., down to `mvhd` and
`trak`), with no hole and no overlap. This check was added after
observing, on two real files, that a 4-byte `moov` sequence could appear
**by coincidence** inside already compressed video data (H.264/HEVC
entropy is close to noise, so an accidental tag plus a plausible size is
not that rare on a large file) - the earlier version of the script then
announced a "success" for a file whose output actually contained **no
readable stream** (checked with `ffprobe`). If no `moov` candidate
validates, the script tries case B; if that fails too, the file is
honestly reported as failed instead of being produced broken in silence.

### MP4 - case B: `moov` destroyed ("faststart" layout)

The first boxes (`ftyp`, `mvhd`, start of the tracks...) are lost, but
the sample tables (`stss`/`stsc`/`stsz`/`stco`) survive. The script then
rebuilds the video track **from the data in the file**:

- **codec**: SPS/PPS (H.264) or VPS/SPS/PPS (H.265/HEVC) are read in
  clear at the start of the first video sample (encoders repeat them
  before every keyframe) -> `avcC`/`hvcC` boxes are rebuilt;
- **resolution**: recomputed from the parsed SPS;
- **audio track**: copied as is (intact, located beyond the encrypted
  zone). Its `edts`/`elst` edit list and `tkhd` duration, still expressed
  in the ORIGINAL (lost) movie timescale, are dropped/recomputed: the
  original movie timescale went with the deleted `mvhd`, so the encoder's
  priming delay of a few milliseconds is no longer trimmed from playback;
- **video frame rate**: **computed automatically** = number of intact
  video frames / exact duration of the audio track (`mdhd`), rounded to
  the nearest standard rate (23.976 / 24 / 25 / 29.97 / 30...); `--fps`
  is only a fallback when that computation fails;
- **sample offsets**: every `stco`/`co64` table is shifted to stay
  consistent with the new header.

#### Automatic resolution detection: formats already seen first

When neither a donor file, nor a known SPS/PPS profile, nor the stream
itself provides a usable SPS/PPS, the script attempts a brute-force
detection: it tries a list of common resolutions, each time generating a
generic SPS/PPS, and checks through `ffmpeg` (decoding oracle over
several real frames) whether that decodes cleanly.

Before the generic list, the script first tries resolutions **already
seen in the profile database** (`--seed-profiles` / automatic learning),
sorted by actual frequency - many libraries concentrate most of their
videos on a few recurring formats (portrait 720x1280 / 960x1280 for
mobile-camera capture, for instance, which are absent from the generic
list): testing them first speeds up detection considerably on files
coming from a source already encountered, even when no SPS/PPS profile
itself matches.

The **fast pass** (common + already-seen resolutions, default settings
only) is active by default: each resolution is checked by a real
`ffmpeg` decode, but with a single settings set per candidate, so it
stays reasonably fast in most cases. If it fails, the **broad pass**
(`--brute-force-resolution`, see the options table) also sweeps other
parameter combinations on the most likely resolutions: a far more
exhaustive and expensive test, with no guarantee of success even given
time - it therefore stays optional. The time budget
(`--auto-resolution-timeout`, 90 s by default) is enforced strictly in
both passes (checked before every attempt, not only before every
resolution); to let the broad pass run to completion without an external
execution limit, launch the script locally with `--brute-force-resolution`
and a high value (e.g. `--auto-resolution-timeout 1800`).

**Extra diagnostic, if even an exhaustive search fails:** the first
bytes of SEI NAL units (often present before the keyframe) sometimes
identify the encoding engine in clear (e.g. a `x264 - core ... -
options: ...` string for x264 - used automatically when present, see
below - or the name of a professional broadcast/cloud transcoding
engine). A stream produced by that kind of engine is generally not
x264: the default settings of automatic detection (modelled on usual
x264 behaviour) may then fit less well, and the real resolution is not
necessarily among the formats already seen in the corpus nor in the
generic list. In that case, evidence external to the file itself (a
thumbnail or preview kept elsewhere on disk, the original download page,
another rendition of the same title) is often more reliable than a wider
brute-force search.

#### Corner case: SPS/PPS never repeated in the stream

Some files (typically when x264/x265 encodes straight to MP4, without
`--repeat-headers`) **never** repeat the SPS/PPS before keyframes: the
first sample holds only a SEI (often the `x264 - core ... - options: ...`
string with the encoder settings, in clear) directly followed by the IDR
frame, with no SPS NAL (type 7) and no PPS NAL (type 8). In that case
the codec config lived **only** in the original `avcC` box, itself
within the first 4096 encrypted bytes: it is therefore irrecoverably
lost.

The script detects this case and offers two strategies, tried in this
order:

**1. Donor file(s) (`--sps-pps-from`, highest priority, recommended when
available)**: if other files already rebuilt successfully are available,
coming from the **same source / same encoder** (hence very probably the
same encoder with the same settings), one or more donor `.mp4` files can
be passed with `--sps-pps-from FILE.mp4 [FILE.mp4 ...]`. The script
extracts the **real** `avcC` box (hence the **real** SPS/PPS, not a
guessed reconstruction) from each donor, and checks - with `ffmpeg` as a
decoding oracle over a real sequence of several consecutive frames of
the file being repaired (IDR **and** P/B frames, not the IDR alone) -
whether that SPS/PPS decodes the target stream cleanly. The first donor
that works is used as is (resolution included, read directly from its
SPS). This is the most reliable method: unlike automatic detection or
manual mode, the parameters are not guessed or swept but **actually
identical to those of the original encoder**, which in practice also
recovers the P/B frames (not only keyframes). Real case: on a file where
the exhaustive automatic search (below) had only achieved a partial
recovery (keyframes only), supplying 3 already-rebuilt files from the
same encoder through `--sps-pps-from` gave a **complete and clean**
recovery (keyframe and P/B frames), the first donor tested being enough.

**1b. SPS/PPS profiles "learned" automatically (active by default,
between the two)**: the script maintains, in a `profiles.json` file
created **next to the script** (`sps_pps_profiles/`, shared between all
working folders), a database of the REAL SPS/PPS already encountered,
with an occurrence counter. For each case B file, if no explicit donor
worked, those profiles are tried automatically - **from the most to the
least frequently encountered** - with the same multi-frame `ffmpeg`
oracle as donor files. Since many videos come from the same source
(hence the same encoder), the right profile is usually found very
quickly without supplying anything by hand. Two ways to feed this
database:

- **automatically**: every success through `--sps-pps-from`, through an
  already-known profile, **or through SPS/PPS/VPS read directly in clear
  in the stream** (the most frequent case - no search needed) records
  (or increments the counter of) a profile. That last case (added after
  a gap seen in practice: several HEVC files already recovered
  successfully through their clear VPS/SPS/PPS, but **no** HEVC profile
  in the whole database) matters precisely because
  `restore_and_reencode.py` deletes the decoded file right after
  re-encoding it to HEVC: without that immediate recording, the REAL
  parameters of the file that succeeded disappear forever, and the next
  file from the same source - which has no clear SPS/PPS/VPS - ends up
  with no donor and no profile (automatic detection covers H.264 only);
- **manually, in one go** with `--seed-profiles FILE_OR_DIR [...]`:
  seeds (or completes) the database from **already valid** videos (e.g. a
  folder of successfully rebuilt files), without touching any `.nsm` -
  combinable with `--files`/`--folder` in the same call.

Deliberately, only REAL SPS/PPS (donor, already-validated profile, or an
already valid `.mp4` through `--seed-profiles`) feed this database -
never the parameters guessed by automatic detection or by
`--width`/`--height`, which are not guaranteed to be reliable. See
`--profile-dir`, `--no-profile-matching` and `--no-profile-learning` in
the options table to move the database or disable that step.

**Reinforced candidate validation (multi-GOP window).** A candidate
(donor or learned profile) is accepted only after decoding cleanly not
only a short head sequence (12 frames, unchanged fast filter) but **also
a window covering several GOPs**: `keyint x 4` read from the x264 SEI,
floor 150 frames, ceiling 300 - and 150 when the SEI is absent. Rationale:
12 frames are shorter than one GOP in most streams (`keyint` 50 to 250),
so an SPS/PPS from **another** encoder may decode them by coincidence and
then break the file from a few keyframes on. Real case: a learned profile
from a different encoder accepted a 1280x720 x264 stream for 12 then 120
frames, but produced 7244 `ffmpeg` errors and lost 527 of 34,671 frames
on the full file (corrupt blocks at every keyframe, roughly every 1.7 s);
the config deduced from the SEI, in contrast, decoded everything without
error. The long window is only tested on candidates that already passed
the fast filter, so sweeping hundreds of profiles stays fast; automatic
detection, for its part, only emits a warning when its config does not
confirm beyond one GOP.

**2. AUTOMATIC detection (no donor or known profile worked)**: by
default, if `ffmpeg` is installed and on `PATH`, the script generates
SPS/PPS candidates - refined with the real x264 settings read in clear
from the SEI when it is present (CABAC, P/B weights, 8x8 transform,
constrained intra, `keyint`...) - and checks, using `ffmpeg` as a decoding
oracle, whether a **small real sequence of frames** (the IDR keyframe
followed by several P/B frames, not the IDR alone: a wrong setting can
by coincidence let the IDR decode cleanly while being wrong and then
break every following frame) decodes without error. The search sweeps a
list of common resolutions (1920x1080 first, the most widespread for this
kind of content, then the other usual mobile-camera/streaming sizes),
plus the bit width of `frame_num`/`poc`, the number of reference frames
and the initial QP - a starting point is first computed from the x264
options in the SEI (see below), then refined by sweeping.

SPS/PPS parameters taken from the x264 options (SEI):

- `pic_order_cnt_type`: **2** when `bframes=0` (x264 then writes no POC
  field in slice headers), 0 otherwise;
- `log2_max_frame_num` / `log2_max_pic_order_cnt_lsb`: formula of recent
  x264 versions, based on the number of reference frames (`ref`,
  B-frames, pyramid) - often only 4 bits - then, as a fallback, the older
  formula based on `keyint`;
- PPS: `num_ref_idx_l0_default_active` = `ref`, `chroma_qp_index_offset`
  = `chroma_qp_offset`, plus CABAC, `weightp`/`weightb`, 8x8 transform,
  constrained intra;
- initial QP (`pic_init_qp`): x264 writes the integer part of `crf` in
  CRF mode (and `qp` in CQP); in ABR/CBR/2-pass the value cannot be
  deduced from the SEI (real case: `rc=2pass`, only 20 = 26 - 6 works),
  so the script tries 26 then sweeps down to 14. With **CABAC**, a wrong
  initial QP corrupts context initialisation and the whole frame decodes
  wrong from the first macroblock (real case: `crf=22`, only the value 22
  works); with CAVLC it has no effect on decoding;
- `max_num_ref_frames`: the value written by x264 (at least `ref`, plus
  B-frame reordering and the pyramid).

**Geometric pass (resolution outside any list)**: if the fast pass
fails, the script looks for the resolution without a predefined list.
With the right settings, only the **real width** (in macroblocks) decodes
cleanly, even in a grid higher than the picture, because intra prediction
and entropy contexts depend on the left/top neighbours. The height is
then read on the IDR frame alone: `ffmpeg` conceals the macroblocks of
the grid that the slice does not cover (`concealing N DC...`), and that
number directly gives the number of real rows. Real case: a vertical
416x720 video (404x720 displayed) whose filename announced 720p, found
in 266 attempts (~16 s) without a profile database. Only the fine crop (a
few pixels on the right/bottom) cannot be read from the stream: the
geometric pass returns the coded size, to a multiple of 16 (except
1088 -> 1080). `--width`/`--height`, when provided, serve as the **first,
priority candidate** for the resolution (not as an imposed value).

**EXPERIMENTAL**: a clean decode over the few frames tested is a good
indication, not absolute proof beyond them - the reconstructed codec
config is never the original one. If automatic detection finds no
conclusive combination (or if `ffmpeg` is not installed) and
`--width`/`--height` are provided, the script falls back to the older
behaviour (generic SPS/PPS for that resolution, no guarantee). **Check
playback in a video player before deleting the `.nsm`.**

**Fast search enabled by default**, **broad pass disabled by default**.
The search happens in two stages: first a cheap **fast pass** over common
and already-seen resolutions with the default settings - that one is
active by default (`--no-auto-resolution` disables it). If it finds
nothing, an optional **broad pass** can additionally sweep other
parameter combinations (`log2_max_frame_num`, `log2_max_poc_lsb`,
`max_num_ref_frames`, QP) on the most likely resolutions: far more
expensive, and **not guaranteed to succeed even given time** - on a real
case (file encoded by a professional non-x264 engine, no SPS/PPS repeated
anywhere in the stream, checked sample by sample over the whole
duration), a full local run (57 resolutions, 20,277 `ffmpeg` decode
attempts, ~22 minutes) found **no** conclusive combination. That broad
pass therefore stays disabled by default, to be enabled explicitly with
`--brute-force-resolution` (see the options table below;
`--auto-resolution-timeout` adjusts the overall time budget).

Those methods can be combined and are tried in this order:
`--sps-pps-from` (explicit donors) -> learned profiles
(`sps_pps_profiles/` database) -> fast automatic detection (unless
disabled through `--no-auto-resolution`) -> broad pass **if enabled**
(`--brute-force-resolution`) -> `--width`/`--height` as a last resort.

On a real case encountered (stream whose original SEI said `ref=1`,
`bframes=3`), automatic detection found the **right resolution** and a
combination that decodes the **keyframe** correctly, but **not** the P/B
frames that follow it (the file therefore stays readable/previewable
keyframe by keyframe, about every `keyint` frames, with corrupted frames
in between) despite an exhaustive search including the number of
reference frames. That case is precisely what motivated the addition of
`--sps-pps-from`: on the same file, supplying donors from the same
encoder gave a complete recovery this time (see point 1 above). Without
any usable donor, a partial recovery (keyframes only) remains the
expected outcome for that kind of stream.

**Fix (synthesised SPS/PPS)**: until then the generated SPS always used
`pic_order_cnt_type=0` and a `log2_max_frame_num` deduced from `keyint`,
and the PPS set `num_ref_idx_l0_default_active` to 1. On an x264 stream
with `bframes=0` (real case: x264 core 144, CAVLC, `ref=3`, `keyint=250`),
the real slice header holds only 4 bits of `frame_num` and no POC field:
every attempt therefore read the header wrong
(`deblocking_filter_idc 14 out of range`), whatever the resolution, and
the file failed systematically. With the parameters taken from the SEI
(list above), the fast pass finds 1280x720 in 11 attempts, and the two
files involved decode **entirely** without `ffmpeg` errors (P frames
included). The `ref=1`/`bframes=3` case described just above has not been
re-tested since that fix.

#### Corner case: HEVC/H.265 stream without VPS/SPS/PPS in the stream

Same situation as above, but in HEVC: the codec config lived only in the
original `hvcC` box, lost in the encrypted zone (real case: 3200x1600
HEVC files). The script recognises an HEVC stream from the NAL
headers of the first sample and then applies a dedicated HEVC cascade:

1. **donor files** (`--sps-pps-from`): the real `hvcC` box of an HEVC
   `.mp4` is extracted, then validated by `ffmpeg` over the first 12 real
   samples of the file (raw HEVC decoding without error, and at least one
   decoded frame per stream frame);
2. **learned HEVC profiles**: same `sps_pps_profiles/` database as H.264
   (entries marked `"codec": "hevc"`, with the VPS), fed by successes
   through donors and by `--seed-profiles`.

Automatic detection, the broad pass and `--width`/`--height` only concern
H.264: they are skipped on an HEVC stream.

**Beware of re-encoded files.** Outputs of `reencode_fix.py` /
`restore_and_reencode.py` are HEVC, but with the re-encoder's parameters
(`hevc_nvenc`/`libx265`), not those of the source's original encoder:
they work neither as donors nor as profiles (real case: the keyframe
decodes, the following frames do not). They are recognised through the
`compressorname` written by `ffmpeg` (`Lavc<version> hevc_nvenc` or
`libx265`, with the libavcodec version of the `ffmpeg` on `PATH`):
`--seed-profiles` ignores them, and `--sps-pps-from` prints a warning
(the decode test decides anyway). After an `ffmpeg` upgrade, re-encodes
made with the previous version are no longer recognised.

Known limitation, shared with H.264: the `ctts` table (display offsets of
B-frames) is not rebuilt. On a stream with B-frames the decoded frames
are exact, but timestamps ignore reordering (`non monotonically
increasing dts` when read by `ffmpeg`, and the last two frames may be
lost).

#### Corner case: MPEG-4 Part 2 stream (Xvid/DivX/`mp4v`) - experimental

Same situation: the VOL (width, height, `vop_time_increment_resolution`,
flags) lived only in the lost `esds`. The script recognises the stream by
the MPEG-4 start codes of the first sample (`00 00 01 B3` GOP / `B6`
VOP), before trying AVC/HEVC. It deduces from the first VOP the bit width
of `vop_time_increment`, synthesises a VOL + `esds` for each candidate
resolution (`--width`/`--height` first, known profiles, common
resolutions) and keeps only the candidate that `ffmpeg` decodes without
any error over the first real samples. The file is written with an
`mp4v` entry. Real case: a 1280x720 file, found in 5 attempts, 0.3 s.

Limitations: no `stss` table (seeking lands on P-frames, with `ffmpeg`
warnings until the decoder resynchronises); the resolution must be in the
list or given through `--width`/`--height`; a single real proof to date.
If nothing decodes, the failure message says so explicitly.

#### Corner case: inverted track order (audio before video)

The case B algorithm above assumes the **video** track is listed first in
`moov` (the most common convention): its own `trak` box then falls in the
encrypted zone (lost), while the **audio** track, listed second, is fully
visible/intact and copied as is. Some recording software inverts that
order (audio first): in that case it is the **video** track that ends up
visible/intact, with its **REAL** config (real `avcC`/`hvcC`, not a
reconstruction), and it is the **audio** track whose header is lost.

The script detects that case automatically (presence of a video sample
entry `avc1`/`avc3`/`hev1`/`hvc1` inside the first visible `trak`) and
produces a **video-only** file (no sound): unlike the normal case, the
video config here is 100% real and reliable - it is the **audio** config
that is unrecoverable, audio never repeating its own config (`esds`/
`mp4a`) in the stream (unlike video SPS/PPS, which is sometimes
repeated). No option is needed; this detection is automatic.

#### Corner case: video sample tables (`stsc`/`stsz`) also lost

Normally, when only the video codec config (`stsd`/`avcC`) is lost, its
`stsc`/`stsz`/`stco` tables (which follow just after in `stbl`) still
survive: they are bulky (proportional to the number of samples) and thus
extend far beyond the encrypted zone. But when `stsc` is itself very
bulky (frequent for a real-time capture chunked irregularly), its OWN tag
can still fall in the encrypted zone, also causing the loss of `stsz`
(which immediately follows it). In that case only `stco` (the last of the
three) remains visible.

The script then attempts a reconstruction: assuming the capture
interleaves video and audio by writing **each sample as a separate
chunk** (1 sample = 1 chunk, very common for that kind of recording),
merging the chunk offsets of the video track (`stco`, recovered) with
those of the OTHER intact track gives the split position of every sample
in `mdat`, video and audio combined - the size of a video sample is then
simply the distance to the next split. The result is checked (plausible
sizes) before being used; if the assumption fails, the script reverts to
the usual error rather than producing a wrong file.

#### Corner case: very large files (`mdat` > 4 GB, `co64`)

On a very long recording (several hours), two limits of the classic
ISO-BMFF format come into play once the file exceeds ~4 GB:

- **64-bit `mdat` size**: beyond ~4 GB, a box can no longer declare its
  size on the usual 4 bytes; the size field then holds `1` (marker),
  followed by the real size on 8 bytes. Without recognising that format,
  a multi-GB `mdat` goes completely unnoticed (neither `moov` nor `mdat`
  seems findable) although it is perfectly intact - the script now
  detects it correctly.
- **`co64` instead of `stco`**: chunk offsets must also switch to 64 bits
  as soon as a sample lies beyond 4 GB in `mdat` - almost systematic on
  a very long interleaved recording. The script recognises `co64`
  wherever `stco` is looked for (rebuilt video track as well as copied
  audio track).

Both cases combine with everything above (learned SPS/PPS, donor,
auto-detection, derived tables) - no option is needed, detection is
automatic.

#### Corner case: only the `stsc` table is lost

A finer variant of the previous case: `stco` (chunk offsets) and `stsz`
(size of each sample) both survive intact, but the `stsc` tag itself
(chunk -> number of samples mapping) falls in the encrypted zone - for
instance because it sits just before `stsz`/`stco` in `stbl` and a bulky
`udta`/`meta` at the start of the track pushed that boundary exactly into
the lost zone.

Unlike the case above, here there is **no need** to assume "1 sample = 1
chunk": `stco` gives the exact byte boundaries of each chunk, and `stsz`
gives the exact size of each sample, in order. The script therefore
rebuilds `stsc` rigorously by accumulating the real sizes until they land
exactly on each chunk boundary (merged with those of the other track,
since `mdat` interleaves both) - if the accumulation never lands exactly,
the assumption is rejected and the script reverts to the usual error
rather than producing a wrong file.

#### Corner case: ALL THREE tables (`stco`/`stsc`/`stsz`) are lost

Extreme case, rarer than the previous ones: even `stco` (chunk offsets),
the bulkiest of the three and therefore the most resilient, falls entirely
in the encrypted zone - none of the three video tables is visible, so
there is no starting point for the methods above (all of which need at
least `stco`). Only the **audio** track is intact (with its own real
`stco`/`stsc`/`stsz`).

The script then attempts a different reconstruction, without assuming
that video and audio share the same chunking (unlike the "1 sample = 1
chunk" case above):

1. from the REAL audio `stco`/`stsc`/`stsz`, compute the byte ranges
   **actually** occupied by audio in `mdat`, chunk by chunk (no
   assumption: these are the real sample sizes assigned to the real audio
   chunking);
2. whatever remains in `mdat` and is covered by none of those audio
   ranges can only belong to video (`mdat` holds only those two tracks):
   those are the "holes" left by audio, and each corresponds to one
   complete video chunk;
3. each hole is parsed as a sequence of AVCC samples (4-byte length
   prefix + data): if that parse lands **exactly** on the end of the
   hole, it also yields the number of samples in the chunk and the exact
   size of each. On very rare chunks (observed frequency: ~1 in 900, a
   periodic pattern consistent with SPS/PPS reinserted before a
   keyframe), one video sample can actually group several distinct NAL
   units; in that precise case (and only that one), the script falls back
   to a single large sample covering the whole hole (exact size, no
   assumption about internal splitting) - at worst a micro anomaly of
   local frame rate over that handful of frames, far preferable to
   abandoning the whole file.

This method thus yields the video `stco`, `stsc` **and** `stsz` at once,
without any arbitrary assumption about chunking (unlike the "1 sample = 1
chunk" case) - only about the AVCC sampling format (length prefix),
verified end to end by construction (`stco`/`stsc`/`stsz`, no option
needed, detection is automatic). If a single hole never lands exactly
(even with the fallback above), or if the audio ranges overlap each other
(a sign that the assumption "`mdat` holds only audio + video" is false
for that file), the script abandons that method rather than producing a
wrong file.

#### Corner case: `avcC` intact + video `stsz`/`stts` lost (multi-slice muxing)

A variant seen on one series in the corpus: the head encrypted zone covers
**only the very start of `moov`** (4096 bytes, HEAD mode), so the first
boxes (`ftyp`, `mvhd`, video `trak` header) are lost **but the `avcC` box
survives, entirely intact, in the clear zone** - so the TRUE SPS/PPS of
the encoder is available. On the video sample tables side, `stco`/
`ctts`/`stss` survive, but **`stsz` (and most often `stts`) fall within
the 4096 encrypted bytes**. The script then failed on "video sample
tables not found before the next track" (no branch handled "`stco`
present but `stsz` lost").

Two additions fix that case:

1. **Intact `avcC` used directly.** If the `avcC` box is found in the
   clear zone (`scan_boxes`), its real SPS/PPS is read and used as is -
   no detour through the stream (which, with that kind of muxing, does
   not repeat the parameters before keyframes), no donors, no profiles,
   no automatic detection. Those real SPS/PPS also feed the profile
   database (learning), which helps the next files from the same source.
2. **Deriving the video tables from the audio track "holes"** when at
   least one of the three video tables is missing (and no longer only
   when all three are). The audio track is intact; the remaining video
   bytes are grouped into **access units** (`au_grouping=True`),
   indispensable here because a frame is encoded in **several slices**
   (~12 per frame on that series): without grouping, each slice was
   counted as a frame and the computed frame rate became absurd
   (observed: 323 fps instead of 25). The grouping into access units uses
   the codec index deduced from `avcC`/`hvcC`, because `_detect_avcc_codec`
   used to get these streams wrong: a non-IDR H.264 slice NAL (`0x41`)
   evaluates to `(0x41>>1)&0x3F == 32`, confused with an HEVC VPS ->
   wrong `hevc` detection (fixed: `b0` must now be exactly `0x40`/`0x42`/
   `0x44`, with `temporal_id_plus1 != 0`).

Measured on a real 850 MB, 25 fps, 14,641-frame file: `ffmpeg` playback
**clean to within 14,628/14,641 frames** (the ~13 lost frames concentrate
on 2 of the 203 chunks, where a NAL could not be split individually and
the whole chunk is kept as a single sample).

**SPOTS mode of the same series (256 KB head zone).** The `avcC` falls
entirely in the encrypted zone -> config genuinely lost. Three additions
unblock those files:

1. **AVC detection without clear SPS** (`_detect_avcc_codec`): an H.264
   slice NAL **always has an odd first byte** (the type is 1-5 and
   `nal_ref_idc` does not touch bit 0), whereas in single-layer HEVC it is
   **always even** (`b0 = type<<1`). That criterion decides even without
   parameters in clear; detection also tries several head offsets (the
   holes computed from audio can be off by a few bytes).
2. **Rebuilding the video tables from the CONTENT of `mdat`**
   (`_recover_video_tables_from_content`): in SPOTS mode the container
   tables are misleading (a visible "first trak" that is not audio, `stsz`
   with 0 entries surviving...). As soon as no intact config
   (`avcC`/`hvcC`) is available, the script finds the real start of the
   AVCC stream, walks it with **resynchronisation** after every break
   (the 256 KB encrypted zone, an audio chunk) and a **NAL size guard**,
   and groups it into access units. A fake `avcC` tag (noise) is discarded
   by validation (`_has_valid_intact_avcc`). The config then comes from
   the learned profile of the same encoder.
3. **Frame rate read from the VUI of the real SPS** (`_fps_from_sps`): in
   SPOTS mode the audio track is unusable (`mdhd` at 0); the frame rate is
   taken from the `timing_info` in the SPS (reliable config). Result:
   5 SPOTS files rebuilt at 25 fps, near-clean decoding (a few localised
   warnings on the 4 unlocatable SPOTS zones).

**MPEG-4 Part 2 (`mp4v`)**: a 720x400 file had its **real config
(`esds`, with the VOL) intact** in the moov - used directly
(`_intact_mpeg4_config`, exact resolution) instead of being resynthesised
- and its video tables rebuilt by **splitting at the VOPs INSIDE the
holes of the audio track** (so as not to include interleaved audio
bytes). 32,017 frames at 29.97 fps.

#### Corner case: video tables lost AND audio `stsc` lost

An even more degraded case, met in SPOTS mode when `moov` is at the start
and the encrypted zone (sometimes 256 KB) swallows **the whole video
`trak`** as well as the header of the audio `trak` - including its `stsc`.
What remains of the audio track is then only the two bulky tables `stsz`
(sample sizes) and `stco` (chunk offsets); no intact `trak` is left. With
no `stsc` available, one knows neither how many samples each audio chunk
holds, nor therefore which ranges of `mdat` audio occupies - and without
that, video cannot be isolated.

The script **first rebuilds the audio `stsc`** using the chunking of the
**video itself**: `mdat` alternates video chunks (samples prefixed by
their 4-byte length, AVC/HEVC) and audio chunks. For each audio chunk
(offset known from `stco`), it takes the **smallest** number of samples
(real sizes read from `stsz`) such that the remainder up to the next audio
chunk parses **exactly** as a sequence of AVCC samples, or is empty; AVCC
parsing being very constraining (every length must land exactly on the
boundary), that resumption point is in practice unique. The sum of
consumed samples must equal the `stsz` total exactly, otherwise the
method is abandoned. Verified in practice on a synthetic MP4: the rebuilt
audio `stsc` is **identical, entry for entry**, to the real audio `stsc`.

Once the audio ranges are known, video occupies the remaining **holes** of
`mdat`; the script **groups the NAL units there into access units
(frames)**: an H.264/HEVC sample is an access unit - optional parameter/SEI
NALs followed by the slice NALs of the same frame - and a chunk may hold
several. A new unit starts at the first slice NAL whose header says
"first slice of the picture" (`first_mb_in_slice == 0` in H.264,
`first_slice_segment_in_pic_flag == 1` in H.265), the non-VCL NALs before
it being attached to it. The codec is deduced from the parameter NALs
present in clear (H.264 SPS; HEVC VPS/SPS); failing that, each hole is
kept as a single sample. The file is rebuilt **video-only** (the audio
config `esds`/`mp4a`, inside the zone, is unrecoverable), through the same
SPS/PPS cascade as usual case B (donor `--sps-pps-from` -> learned
profiles -> automatic detection -> `--width`/`--height`). Verified on two
synthetic MP4s (H.264+AAC and HEVC+AAC): exact video tables (3600 and 500
frames, resolutions 640x360 and 320x240 read from the SPS), full `ffmpeg`
decoding without error, extracted frames **pixel-identical** to the
original.

### Audio track unusable in case B: video-only reconstruction

The chunk offsets (`stco`) of a track can fall **inside the encrypted
zone**: their values are then noise. Since the rebuilt `moov` is shifted,
the script corrects those offsets; if the correction becomes negative (an
absurd value), it no longer abandons the whole file - a real case where
the codec config had been validated by decoding and the file was lost
over a mere audio track:

1. the audio track is **dropped** (explicit warning), the file is rebuilt
   **video-only**;
2. if the video tables had additionally been **derived** (`stsc`/`stsz`
   lost), they were derived from the offsets of that very audio track -
   exactly the ones just declared unusable. The result is then
   **verified by decoding**: if it does not play, it is **deleted** and
   the failure is explicit. Never a file handed back unreadable.

### MKV / WebM (Matroska / EBML)

- **locating the first intact `Cluster`** (signature scan beyond the
  encrypted zone);
- **track identification** by direct sniffing of the frames:
  - audio **AC3 / DTS / MP3**: self-describing, recovered without
    `CodecPrivate` (sample rate and channel count read from the frame
    header);
  - video **H.264 / H.265**: SPS/PPS(/VPS) re-read in clear in the frames
    (same method as MP4 case B). A **single** prefix-length hypothesis is
    used - the one validated by the frame structure (>= 90% of frames
    split exactly) - and the retained pair goes through a plausibility
    guard (size, dimensions) before being accepted;
- **never a false success**: a configuration "found in clear" is only used
  if the first frames *actually* decode with it (`ffmpeg` oracle, when
  present). Without that check, a phantom SPS/PPS - produced by a wrong
  read of the stream, the earlier version trying 4 **then** 2-byte
  prefixes - gave a `.mkv` announced as rebuilt... and entirely unreadable
  (real case, 2026-10: a 41,667-byte "SPS", decoded as 2x96);
- **cut aligned on a real keyframe (IDR)**: the rebuilt stream starts on a
  decodable cluster, not in the middle of a GOP;
- **automatic detection of the video config** when it is definitively
  lost (it was in `CodecPrivate`, hence in the encrypted zone, and the
  encoder does not repeat it in the stream):
  - **H.264**: reuses as is the decode-verified machinery of MP4 case B
    (`auto_detect_avc_generic_params` - common resolutions + learned
    profiles, then geometric sweep), with its options
    (`--auto-resolution-timeout`, `--brute-force-resolution`,
    `--resolution-lock`, `--no-auto-resolution`, `--profile-dir`). Those
    tracks having **no x264 SEI** in clear (unknown encoder), a small grid
    of usual `(log2_max_frame_num, log2_max_pic_order_cnt_lsb)` pairs is
    tried in addition to the two values deduced from the x264 formulas -
    real case: only `(8, 8)` decoded a 1080p stream, absent from the
    formulas, which made reconstruction fail;
  - **H.265**: reuse of the VPS/SPS/PPS of a donor file
    (`--sps-pps-from`) or of a learned HEVC profile, as in MP4 case B
    (`hevc_config_from_donors_or_profiles`, shared). With no synthetic
    HEVC SPS/PPS generator, there is no geometric sweep: without a donor
    or a matching profile, the failure is explicit;
  - in both cases the **codec is determined before the keyframe search**
    (the rule differs: NAL 5 in H.264, NAL 19/20/21 in H.265) - otherwise
    an H.265 stream without parameters in clear never had a recognised
    keyframe and was rejected outright. For the HEVC oracle, **RASL** NALs
    (types 8/9) are discarded when the sequence starts on a **CRA** frame
    (21): in an open GOP their references precede the cut, so no decoder
    can render them - counting them would fail the oracle wrongly;
- **"best effort" codec config synthesis** (generic x264 SPS/PPS, High
  profile / CABAC / 4:2:0) as a last resort, **only if** automatic
  detection fails **and** `--width`/`--height` is provided -
  **experimental, not guaranteed**;
- a new `EBML + Segment + Info + Tracks` header is synthesised in front of
  the intact clusters. The **frame rate does not have to be guessed**
  here: in Matroska it comes from the block timestamps, copied as is,
  unlike MP4 containers.

### AVI (RIFF)

Same ransomware (first 4096 bytes encrypted + footer), but a completely
different container (RIFF, not ISO-BMFF): the RIFF header (`hdrl`, with
`avih` + one `strl` per track - the AVI equivalent of `moov`, codec,
resolution and audio format included) is lost, but the `LIST 'movi'`
(raw audio/video data, interleaved chunk by chunk) that follows it is
located directly by its signature.

- **MPEG-4 Part 2 video codec** (Xvid / DivX / FMP4...): unlike H.264
  SPS/PPS (never guaranteed to be repeated), that format writes its
  `video_object_layer()` - which holds width/height **and the exact frame
  rate** - in clear at the start of every video sequence, with
  `marker_bit`s (value always `1`) checked one by one during bit-by-bit
  parsing: **reliable** reconstruction, values actually read from the
  stream (not guessed);
- **sample tables rebuilt by walking the whole `movi`** (chunk headers
  only, never the data - fast even on a `movi` of several hundred MB),
  without depending on an original `idx1` (absent in some files);
- **audio track dropped**: its exact format (`strf`/`WAVEFORMATEX`) never
  repeats in clear in the stream (unlike video SPS/PPS) - if an audio
  track is detected in `movi`, it is reported then dropped rather than
  guessing an audio format at random (same choice as the MP4 case "video
  track intact / audio config not found"). File rebuilt **video-only**,
  verified in practice (`ffprobe` + `ffmpeg` decoding + extracted frame)
  on a real file;
- video codecs other than MPEG-4 Part 2 (H.264-in-AVI, MJPEG...): **not
  handled yet**, explicit error rather than a hazardous reconstruction.

### ASF (`.wmv` / `.wma` / `.asf`)

An ASF file starts with the **Header** object, a series of objects (File
Properties, one **Stream Properties** per track, Header Extension, Codec
List, metadata...), followed by the **Data** object (fixed-size packets)
and optionally a **Simple Index** at the end of the file. No absolute
offset is stored: indexes reference packet numbers, so the header can be
replaced by a header of a different size without touching the rest.

With a Windows Media encoder, the header often exceeds the 4096 encrypted
bytes (real case: 5265 bytes). The objects placed **after** the encrypted
zone are then intact, and among them the Stream Properties, which carry
the **complete, original codec config** (BITMAPINFOHEADER + WMV3/VC-1
private data, WAVEFORMATEX + WMA private data). Nothing is guessed on the
codec side. The script:

- finds the Data object, then the first intact header object: the one from
  which the object chain (GUID + size) lands **exactly** on the Data
  object;
- recomputes what was lost at the head: **File Properties** (File ID
  copied from the Data object, packet count/size, duration read from the
  Simple Index or, failing that, from the last packet, preroll read from
  the first packet, bitrate from Stream Bitrate Properties) and an empty
  **Header Extension** (its content is not needed for playback);
- writes the new header, then copies the Data object and the index as is.

Explicit failure if the Data object or the Stream Properties are
themselves inside the encrypted zone (ASF header shorter than ~4 KB): the
codec config is then lost and is not rebuilt.

Verified on a real file (WMV3 1024x576 + WMA 9.2, 26 min): full decoding
without any `ffmpeg` error.

**Re-encoding (`restore_and_reencode.py`)**: ASF cannot carry the HEVC
produced by re-encoding. `ffmpeg` writes the file with return code 0, but
the video track becomes `unknown`, hence unreadable. The re-encoded result
of a `.wmv`/`.wma`/`.asf` (and of any container outside
`.mp4`/`.m4v`/`.mov`/`.mkv`/`.avi`) is therefore written to **`.mp4`**.
The pipeline also now checks that at least one video frame of the
re-encoded file decodes before replacing the decoded file.

### MPEG-1/2 Program Stream (`.mpg` / `.mpeg`)

Same ransomware (encrypted head + footer), but a stream entirely different
from the previous containers: an MPEG-1/2 Program Stream has **no external
index table** comparable to `moov` (MP4) or `hdrl` (AVI). It is a
self-synchronising stream where every unit (pack, system header, audio/
video PES packet) starts with a 4-byte *start code* `00 00 01 XX` in
clear, unique by construction of the stream (unlike H.264, MPEG-1/2
syntax guarantees such a pattern can only appear as a real start code - no
emulation-prevention bytes needed). Any MPEG-PS player therefore
resynchronises automatically on the first valid start code encountered.

- the script locates, after the encrypted zone, the first usable
  resynchronisation point - preferably a **pack header** (`00 00 01 BA`),
  otherwise a **video sequence header** (`00 00 01 B3`) or a **video PES
  packet** (`00 00 01 E0`-`EF`) - then copies the whole stream from that
  point to the end of the useful data as is;
- **resolution and frame rate recovered with certainty**: unlike the H.264
  SPS (entropy-coded, never guaranteed to be repeated in clear), the
  MPEG-1/2 sequence header writes width/height/frame rate **in clear**,
  directly readable bit by bit just after its start code - as soon as it
  is found, no automatic detection and no profile database are needed;
- the few dozen/hundred bytes *before* the resynchronisation point
  (unrecognised remnant of the encrypted zone) are lost, strictly
  analogous to the loss of the `ftyp`/`moov` header in MP4 case B: no
  consequence for the readability of the stream that follows. Verified in
  practice (`ffprobe` + full `ffmpeg` decoding + extracted frame) on a
  real file (173 bytes lost on that file, resynchronisation almost
  immediate).

### Adobe FLV (`.flv`)

Same ransomware (encrypted head zone + footer), but an Adobe FLV
container. An FLV file is a **linear sequence of tags**: a fixed 9-byte
header (`FLV` + version + audio/video flags + `DataOffset`), a 4-byte
`PreviousTagSize0`, then consecutive tags of the form
`[type (1) | DataSize (3) | timestamp (3+1) | StreamID (3) | data |
PreviousTagSize (4)]`, where `PreviousTagSize` equals **exactly**
`11 + DataSize`.

That last constraint (32 bits) is what serves as verification: a fake tag
has very little chance of satisfying it by accident, whereas a lone type
byte `8`/`9`/`18` (audio/video/`onMetaData` script) is frequent. The
script thus finds the **first fully intact tag** just after the encrypted
zone, with no reference file, then:

- rewrites in front of it a **valid FLV header** (9 bytes +
  `PreviousTagSize0`), with the audio/video flags **deduced from the tag
  types actually encountered**;
- copies the tags **as is** - no audio/video data byte is modified.
  **Self-describing** codecs (Sorenson H.263, VP6, MP3/AAC audio - the
  case of the real file targeted, MP3 + H.263) need no reconstruction,
  and the **audio track is kept** (unlike the AVI header/`esds`, its
  config repeats in every tag);
- **known limitation**: in H.264/HEVC (`CodecID` 7/12), the SPS/PPS live
  in a **single sequence header tag**, written once and therefore lost if
  it fell in the encrypted zone (unlike MP4 case B, where SPS/PPS is often
  repeated in clear before every IDR). The script detects that case and
  **warns explicitly** that playback may fail; it still copies all the
  tags (a player able to pick up in-band SPS/PPS may cope). See the Roadmap
  section for a possible injection of a header tag from SPS/PPS repeated
  in keyframes;
- the first tag (`onMetaData`, duration/bitrate, not required for
  playback) often falls in the encrypted zone: the script therefore
  starts at the first fully valid tag. Validated on a synthetic FLV
  (MP3 + Sorenson H.263) in HEAD and SPOTS mode: header re-read, both
  tracks recognised by `ffprobe`, clean `ffmpeg` decoding apart from the
  very start of the file (HEAD). The real 2.4 GB SPOTS sample remains to
  be re-tested when available (see the Roadmap section).

**SPOTS mode**: the extra zones break the tag chain when they overlap a
tag header or its `PreviousTagSize`. The script then **resynchronises** on
the following chain and resumes copying from there (the tags whose bytes
fell in the zone are lost), rather than inserting random bytes that the
FLV demuxer would misread. When a zone falls **entirely inside the data**
of a tag (without touching its structure fields), the chain stays valid
and the tag is copied as is: the container then remains fully readable,
only the few frames/instants whose bytes were encrypted are corrupted (a
limitation common to SPOTS mode described above).

### JPEG images (`.jpg` / `.jpeg`)

`.nsm` files whose original extension is an image are **not videos**: the
encrypted head zone only destroys the **beginning** of the JPEG header.
Such photos have a long header (EXIF with preview, IPTC, ICC profile -
often more than 4 KB): the encrypted zone then only swallows the `SOI`,
the start of the EXIF and the preview it contains. The **quantisation
tables** (`DQT`), the **dimensions** (`SOF`), the **Huffman tables**
(`DHT`) and the `SOS` of the **main image** are in clear, like its whole
entropy stream up to the final `EOI`. The script:

1. requires a final **`EOI`** (a truncated stream cannot be rebuilt);
2. locates the **`SOF` of the main image** among those present in clear,
   keeping the one covering the **most pixels** - the others are the
   previews/thumbnails nested in EXIF/IPTC, and two `SOF`s in clear are
   frequent;
3. checks that the `DQT` (the nearest one upstream), the `DHT`s and the
   `SOS` are also in clear;
4. writes `SOI + [DQT ... end of the useful part]`, then **verifies by
   decoding** (`ffmpeg`, otherwise Pillow) that the image reads *and* has
   the size announced by its `SOF`. A rejected candidate is deleted and
   another chain start is tried - never a file handed back unreadable.

Lost: the metadata (EXIF/IPTC/ICC) and the preview whose header fell in
the encrypted zone. The **pixels of the main image are the original ones**
(tables and entropy stream intact) - verified by comparing the rebuilt
image with the intact preview of the same file (correlation 0.99+).

If the image header is **entirely** inside the encrypted zone (dimensions
*and* tables lost), the failure is explicit: no heuristic is attempted,
nothing would decode the stream. In our test batch, the large majority
of failed images (~84%) fell in the first case.

*Other image formats (`.webp`, `.png`...) are not handled: their header is
much shorter, hence almost always inside the encrypted zone, and the
stream that follows (RIFF/WebP, zlib/PNG) does not resynchronise the same
way.*

### Misleading extension: real content differs from the footer extension

The name kept by the ransomware - from which the extension comes - can be
**wrong from the start**: in a small batch of large files (> 50 MB), two
were (a `.mp4` actually holding **FLV**, and a `.wmv` that was not ASF).
The script therefore **recognises the container from the CONTENT** (beyond
the encrypted zone) **before** following the extension:

- if the content contradicts the extension, the real container is tried
  **first**: its reconstruction must succeed **and** the result must
  **decode** (`ffmpeg`, first 30 seconds) to be kept. Otherwise the
  rebuilt file is deleted and the failure is explicit - and if that
  reconstruction succeeded without the result playing, the declared path
  is not even attempted (the file is plainly not of that type), which
  saves minutes of doomed attempts;
- if the content says **MP4** while the extension announced something
  else, the usual MP4 cascade (case A / case B) simply takes over;
- detection is **deliberately strict** for MPEG-PS: it requires **valid
  marker bits** and at least **two** pack headers
  (`_mpeg_pack_header_ok` / `find_mpeg_ps_start_strict`). The mere
  `00 00 01 BA` pattern is not enough: it appeared in islands of six,
  spaced 3,200 bytes apart, in the packets of a `.wmv` that was not
  MPEG-PS at all - a **false positive** that triggered a useless
  reconstruction.

*Corner case already covered elsewhere: a `.mkv`/`.webm` whose real
content is an MPEG Transport Stream (see below).*

### Misleading extension: real content is an MPEG Transport Stream (`.ts`)

On some captures made by DVR-style capture tools, the file is named
`.mp4`, `.mkv` or `.webm` by the HARR footer (hence reliable as to the
original NAME) while its real content is a raw **MPEG Transport Stream**
(188-byte packets, sync `0x47`) - not ISO-BMFF nor Matroska at all. When
neither `moov`/`mdat` (MP4) nor a usable Matroska `Cluster` is found, the
script tests that hypothesis before giving up: search for a valid TS
packet alignment (sync `0x47` confirmed over at least 64 consecutive
packets - eliminates false positives) over the whole file, PAT/PMT
re-read in clear (repeated periodically, as the TS standard expects) to
identify the tracks, then a straight copy of the whole stream from the
resynchronisation point.

**Refined start point: first clean keyframe.** The first `0x47` alignment
found may land in the *middle* of a truncated PES packet (the encrypted
zone boundary cuts the PES in half). A stream starting with those orphan
fragments references SPS/PPS never declared: the `ffmpeg` demuxer then
fails (`non-existing PPS referenced` / `no frame!`), the MP4 remux does
not pass its check and the file stayed in error - a real case observed on
a file (declared `.mp4`, TS content, ~2 h 09, corrupted head over ~258 KB
plus 3 corrupted blocks at ~25%/50%/75%). The script therefore looks, just
after the alignment, for the first *clean* keyframe: a video PES starting
with **SPS + PPS + IDR** in that order (the signature produced by any
standard encoder that repeats SPS/PPS before every IDR), and starts the
copy **there**. The codec config is then present from the first byte of
the rebuilt stream: the MP4 remux extracts it cleanly and the first frames
decode without error. Only the orphan fragments preceding the keyframe (a
few dozen to a few thousand bytes, undecodable anyway) are skipped. If no
clean keyframe is found in the analysed window, the script falls back to
the raw alignment (original behaviour). As a bonus, when the PAT/PMT
tables are absent or malformed (already observed on a real file), the
video PID is deduced from the located keyframe packet and the resolution
is read directly from its SPS.

**Automatic remux to `.mp4`.** The H.264/AAC stream recovered that way is
intact (identical SPS/PPS, correctly repeated before every IDR, checked
NAL by NAL on a real file) and decodes without any error once extracted
as a raw elementary stream - but `ffmpeg`'s MPEG-TS demuxer fails to
decode the rebuilt `.ts` **in place** (`ffmpeg -i file.ts`), with
`non-existing PPS referenced` errors over the whole file: the TS packet
structure around the resynchronisation point seems to derail its internal
demuxing state, even though the video bytes are intact. Reliable
workaround, applied automatically as soon as `ffmpeg` is available: the
`.ts` is **remuxed** (stream copy, `-c copy`, no re-encoding hence no
loss) into a fresh MP4 container, then playback is **verified** (real
decoding of the first seconds, no error) before trusting the result -
verified in practice on a real ~21-minute file (clean decoding confirmed
from start to end after remux). If the remux or the verification fails
(or if `ffmpeg` is absent), the raw `.ts` is kept as is instead, with an
explicit warning.

### Files that were merely renamed (not encrypted, no footer)

If a `.nsm` **has no HARR footer**, it is probably a file the ransomware
only renamed. The script then:

1. **detects the real format** from the first bytes (magic bytes);
2. **renames the file** (no reconstruction needed) to the right
   extension, **at its current location** (or into `--out-dir` if that
   option is passed).

Recognised formats:

| Category | Extensions produced |
|---|---|
| **video** | `.mp4` (default: MP4/MOV/ISO-BMFF), `.mkv`, `.webm`, `.avi`, `.flv`, `.wmv` (ASF, recognised by its fixed header GUID), `.ts` (MPEG Transport Stream, recognised by the sync byte `0x47` confirmed over several consecutive 188-byte packets) |
| **image** | `.jpg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.heic`, `.avif` |
| **audio** | `.mp3`, `.ogg`, `.flac` |

- if the target name already exists, a `_1`, `_2`, ... suffix is added;
- with `--keep-nsm`: the file is **copied** to the right extension and the
  original `.nsm` is **kept**;
- if the format is not recognised: the file is treated as a failure
  (moved to `_error/`, unless `--keep-nsm`).

## Command-line options

| Option | Description |
|---|---|
| `--folder` | folder to process: **the whole tree is walked recursively**; `_to_delete/` and `_error/` are created at its root, **reproducing the tree** of the `.nsm` files moved there |
| `--files` | explicit list of `.nsm` files |
| `--out-dir` | output folder (default: **the same folder as each `.nsm`**, with the **same name as the original** - e.g. `video.nsm` -> `video.mp4`); also applies to merely renamed files (moved into that folder) |
| `--fps` | fallback frame rate (fps) for MP4 case B (default 24), used **only** if the computation from the audio duration fails |
| `--width` | **MP4 case B and MKV**: video width used as the **priority candidate** by automatic detection (or as a last resort if it fails) when the codec config is definitively lost (never repeated in the stream) - **experimental, not guaranteed**, see the dedicated section above. Use with `--height` |
| `--height` | **MP4 case B and MKV**: video height, see `--width` |
| `--no-auto-resolution` | **MP4 case B only**: disables the **fast** automatic detection of resolution/SPS-PPS parameters (common + already-seen resolutions, default settings - **enabled by default**); useful if `ffmpeg` is not installed, or to force `--width`/`--height` directly without a search |
| `--brute-force-resolution` | **MP4 case B only**, **disabled by default**: if the fast detection fails, additionally attempts a far broader and more expensive combinatorial sweep (experimental, not guaranteed to find the right combination - see the dedicated section above); requires `ffmpeg` on `PATH` |
| `--resolution-lock` | **MP4 case B only**, to be used with `--width`/`--height` **and** `--brute-force-resolution`: instead of trying that resolution first **among** all others (the normal behaviour of `--width`/`--height`), restricts the broad pass to **exactly** that resolution - tens of thousands of attempts then drop to a few hundred, hence fast (well within the default `--auto-resolution-timeout`, instead of the ~20+ minutes of a full sweep). Only makes sense **if** the real resolution is known for certain from a source external to the file (a thumbnail kept elsewhere, the original download page, another rendition of the same title): if it is wrong, the option wrongly discards the right resolution instead of finding it more slowly. No effect when `--width`/`--height` are not provided |
| `--auto-resolution-timeout` | time budget (seconds, default 90) granted to automatic detection **per file concerned** (fast pass, then broad pass if `--brute-force-resolution` is enabled). If exhausted during the fast pass, the script **automatically extends it once** (x4, floor 480 s, ceiling 900 s) before giving up - real case: a 656x480 file found at ~285 s while the default budget is 90 s. Requires `ffmpeg` on `PATH` |
| `--sps-pps-from FILE.mp4 [...]` | **MP4 case B (H.264 and HEVC) only**, higher priority than everything else: one or more already rebuilt `.mp4` files (ideally from the same source/encoder) from which the **real** SPS/PPS is extracted (`avcC`, or VPS/SPS/PPS `hvcC` if the stream is HEVC); checked against the target file through the multi-frame `ffmpeg` oracle before being used - see the dedicated sections above. For HEVC, use original files, not re-encoded outputs |
| `--profile-dir DIR` | folder of the learned SPS/PPS profile database (default: `sps_pps_profiles/` next to the script) |
| `--no-profile-matching` | **MP4 case B only**: disables the automatic trial of already-known SPS/PPS profiles before automatic detection |
| `--no-profile-learning` | **MP4 case B only**: does not record newly found REAL SPS/PPS into the profile database |
| `--seed-profiles FILE_OR_DIR [...]` | maintenance mode: seeds (or completes) the learned SPS/PPS profile database from already valid videos (files or folders, `.mp4`/`.m4v`/`.mov`), without processing any `.nsm`; combinable with `--files`/`--folder` in the same call |
| `--keep-nsm` | move nothing, on success or failure: the `.nsm` files stay where they are; for merely renamed files (not encrypted), make a **copy** with the right extension instead of renaming the `.nsm` in place |
| `--manifest PATH` | append-only CSV log of every processed file: four columns, `timestamp_utc,source,status,nsm_location` (default: none), see the next section |

The exit code is `0` when everything succeeded, `1` otherwise (failed
files are listed at the end of the run).

## Processing log (`--manifest`)

An optional, append-only CSV log, one row per processed file:

```bash
python restore_videos.py --folder "/path/to/encrypted" \
    --manifest processed.manifest.csv
```

The header is written once, when the file is created:

```text
timestamp_utc,source,status,nsm_location
```

| Column | Meaning |
|---|---|
| `timestamp_utc` | UTC timestamp of the processing of that file |
| `source` | path of the `.nsm` that was processed |
| `status` | one of `restored` (rebuilt from the encrypted content), `renamed` (no footer, only renamed), `failed` |
| `nsm_location` | where the `.nsm` was moved: `_to_delete/` or `_error/`; empty when `--keep-nsm` left the `.nsm` in place, and for `renamed`, where nothing is moved |

Rows are appended as processing goes, one line per file, and are never
rewritten. A write error on the manifest only produces a warning: it
never stops the run. This matters because the tool otherwise keeps **no
record** of what it did: it physically moves the `.nsm` files into
`_to_delete/` or `_error/` and writes the recovered file next to them.
After an interrupted run, or when resuming a large batch weeks later, the
manifest is the only way to know which sources were already handled, and
with which outcome. It is optional, contains nothing beyond the paths you
gave the tool, and should not be committed.

## Tests

A pytest suite lives in `tests/`. It runs without any media file,
without `ffmpeg` and without network access:

```bash
python -m pytest -q
```

`pytest` is the only dev dependency; install it first if needed:

```bash
pip install pytest
```

The tests cover footer parsing, entropy-based zone detection, ISO-BMFF
box scanning and `moov` validation, JPEG marker walking, sample-table
derivation, the SPS/PPS profile store and manifest writing.

## Privacy

Everything runs locally. The script makes **no network access at all**:
no HTTP client, no telemetry, no update check, no crash report. The only
files it writes are the recovered media, the `_to_delete/` and `_error/`
folders, the optional manifest, and the learned profile database.

That database (`sps_pps_profiles/profiles.json`, next to the script)
holds real SPS/PPS byte strings, the resolution deduced from them, an
occurrence counter and up to 8 source labels (file names of the donors or
seeds that produced the profile). It holds no media content. The manifest,
for its part, records the source path of every file processed, with a
UTC timestamp and a status. Both stay on your machine and **should not be
committed**: the shipped `.gitignore` already excludes
`sps_pps_profiles/`, `profiles.json` and `*.manifest.csv`, as well as any
media file.

## Limitations

- The first seconds of every encrypted file are gone: the encrypted zone
  is not recoverable.
- **SPOTS mode** (files > ~1 GB): short visual/sound corruptions at
  unpredictable positions (a few tenths of a second to a few seconds,
  usually 4 occurrences), in addition to the head. This is a limitation
  of what was destroyed, not a script failure.
- **The codec configuration is reconstructed, never original** (MP4 case
  B, MKV): a clean decode over the tested frames is a good sign, not a
  proof. With no donor and no matching profile, a partial recovery
  (keyframes only, with corrupted frames in between, roughly every
  `keyint` frames) is the expected outcome for streams that never repeat
  their SPS/PPS.
- The `ctts` table (B-frame display offsets) is not rebuilt: with B-frames
  the decoded frames are exact but timestamps ignore reordering
  (`non monotonically increasing dts` from `ffmpeg`, and the last two
  frames may be lost).
- **MPEG-4 Part 2** (`mp4v`): no `stss` table (seeking lands on P-frames
  until the decoder resynchronises), the resolution must be in the
  candidate list or given with `--width`/`--height`, and there is a single
  real proof to date.
- **AVI**: only MPEG-4 Part 2 video is handled (H.264-in-AVI, MJPEG...
  fail explicitly). The audio track is dropped, since its format never
  repeats in the stream.
- **FLV**: with H.264/HEVC the sequence header tag (SPS/PPS), written
  once, is lost if it fell in the encrypted zone; the file is still
  written, with an explicit warning, and playback may fail.
- **ASF**: explicit failure when the header is shorter than the encrypted
  zone (Data object or Stream Properties inside it).
- **JPEG**: metadata (EXIF/IPTC/ICC) and the embedded preview are lost
  when their header fell in the zone; images whose whole header is
  encrypted fail, since nothing would decode the stream. Other image
  formats (`.webp`, `.png`...) are not handled.
- A misleading extension is detected from the content, but the declared
  path is only skipped when a successful reconstruction of the real
  container proved the file is not of that type.
- Files produced by `restore_and_reencode.py` / `reencode_fix.py` are
  **not** usable as donors or profiles for HEVC: they carry the
  re-encoder's parameters, not the original encoder's.
- An MP4 case B whose first frames do not play is expected: the file is
  readable from the first keyframe onwards, the preceding frames having
  been destroyed.

## Roadmap

Open tracks, in rough gain/effort order:

- MPEG-4 Part 2: geometric resolution scan, `stss` built by scanning VOP
  types, `vop_time_increment_resolution` derived from the real frame
  rate, more real samples.
- FLV: validate the large SPOTS sample; measure the recovery level in
  SPOTS mode on it; inject a sequence-header tag rebuilt from SPS/PPS
  repeated in keyframes (H.264/HEVC in FLV).
- MP4 case B: `ctts` reconstruction for streams with B-frames.
- MKV: HEVC automatic detection without donors (no synthetic HEVC
  SPS/PPS generator today).
- Image formats other than JPEG (`.webp`, `.png`...).
- More samples for every container: most paths rest on one or two real
  proofs.

## Contributing

Issues and pull requests are welcome. Keep the constraints the tool lives
by: standard library only at runtime, `ffmpeg` optional and used as an
oracle, and no silent success - a reconstruction that cannot be validated
must be reported as a failure. Add a pytest test with any behaviour
change, and keep media samples out of the repository.

## License

MIT.
