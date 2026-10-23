#!/usr/bin/env bash
# Renders demo/zecathon.mp4 from the five tapes in demo/tapes/ and the five
# narration WAVs in demo/audio/ (demo/voice.sh writes them).
#
# For each segment:
#   1. Its length is fixed first: the narration plus two seconds, or the
#      tape's `# min-seconds:` if that is longer.
#   2. `@@HOLD@@` in the tape becomes that length less the tape's
#      `# command-seconds:`, the time its commands are expected to take, and
#      vhs records it to demo/video/<segment>.mp4.
#   3. The recording is padded with its last frame, or cut after its output
#      is complete, to exactly that length, and the narration is laid over
#      it, padded with silence. A segment whose output is not complete by
#      then fails the render rather than being cut short.
# Two renders of the same narration therefore have the same length, even
# though the Tests and Verify commands run live.
#
# Usage: demo/render.sh   (or `just demo-video`), from anywhere in the repo.
set -euo pipefail

cd "$(dirname "$0")/.."

SEGMENTS=(pitch tests verify fill refund)
AUDIO=demo/audio
VIDEO=demo/video
OUT=demo/zecathon.mp4

die() {
    echo "render.sh: $*" >&2
    exit 1
}

duration() {
    ffprobe -v error -show_entries format=duration -of csv=p=0 "$1"
}

tape_value() {
    sed -n "s/^# $2: *//p" "$1"
}

# Nothing that could identify a key, a transaction, or the workspace this
# was built in goes on screen or into the narration.
guards() {
    local hex
    hex=$(grep -lE "[0-9a-f]{64}" demo/narration.md demo/pitch.txt || true)
    [ -z "$hex" ] || die "a 64-hex string is in $hex"
    local paths
    paths=$(grep -rlE "Obey-Agent-Econom[y]|festival[s]/" demo \
        --exclude-dir=audio --exclude-dir=video || true)
    [ -z "$paths" ] || die "a workspace path is in $paths"
}

audio_for() {
    local wav
    wav="$AUDIO/$(printf '%03d' "$1")-$2.wav"
    [ -f "$wav" ] || die "missing $wav; run demo/voice.sh first"
    echo "$wav"
}

segment() {
    local name=$1 wav=$2 tape="demo/tapes/$1.tape"
    local speech command_s min_s length hold recorded
    speech=$(duration "$wav")
    command_s=$(tape_value "$tape" command-seconds)
    min_s=$(tape_value "$tape" min-seconds)
    length=$(awk -v s="$speech" -v m="${min_s:-0}" 'BEGIN { t = s + 2; if (m > t) t = m; printf "%.3f", t }')
    hold=$(awk -v t="$length" -v c="$command_s" 'BEGIN { h = t - c; if (h < 0.5) h = 0.5; printf "%.1f", h }')

    sed "s/@@HOLD@@/${hold}s/" "$tape" >"$VIDEO/$name.tape"
    vhs -q "$VIDEO/$name.tape"
    recorded=$(duration "$VIDEO/$name.mp4")
    awk -v r="$recorded" -v h="$hold" -v t="$length" 'BEGIN { exit !(r - h <= t - 0.25) }' ||
        die "$name: the output took $(awk -v r="$recorded" -v h="$hold" 'BEGIN { print r - h }') s, past the ${length} s segment"

    ffmpeg -v error -y -i "$VIDEO/$name.mp4" -i "$wav" \
        -filter_complex "[0:v]tpad=stop_mode=clone:stop_duration=${length}[v];[1:a]apad[a]" \
        -map "[v]" -map "[a]" -t "$length" \
        -c:v libx264 -pix_fmt yuv420p -r 30 -c:a aac -ar 48000 -ac 2 \
        "$VIDEO/$name.av.mp4"
    mv "$VIDEO/$name.av.mp4" "$VIDEO/$name.mp4"
    echo "$name: narration ${speech} s, recorded ${recorded} s, segment ${length} s"
}

main() {
    guards
    local wavs=() i=1
    for name in "${SEGMENTS[@]}"; do
        wavs+=("$(audio_for "$i" "$name")")
        i=$((i + 1))
    done

    # Build first, so no segment records a compile.
    cargo build -q --release --bins
    cargo test -q --no-run 2>/dev/null

    mkdir -p "$VIDEO"
    : >"$VIDEO/list.txt"
    for i in "${!SEGMENTS[@]}"; do
        segment "${SEGMENTS[$i]}" "${wavs[$i]}"
        echo "file '${SEGMENTS[$i]}.mp4'" >>"$VIDEO/list.txt"
    done
    ffmpeg -v error -y -f concat -safe 0 -i "$VIDEO/list.txt" -c copy -movflags +faststart "$OUT"
    echo "$OUT: $(duration "$OUT") s"
}

main "$@"
