#!/bin/sh
# Renders demo/narration.md to demo/audio/, one WAV per `##` section plus a
# manifest, with obey-voice's local Kokoro engine.
#
# obey-voice reads its settings from $HOME. A personal setting there, such
# as another engine's voice name, changes or breaks the render, so this runs
# it under a throwaway HOME whose only settings are the engine and the voice.
# The narration then renders the same way on any machine with obey-voice
# and its Kokoro model installed. The model cache is linked in from the real
# HOME; nothing in the real HOME is written.
#
# Usage: demo/voice.sh            (from the repository root)
#        VOICE=af_sky demo/voice.sh
set -eu

VOICE="${VOICE:-am_onyx}"
models="$HOME/.cache/festival-voice"
if [ ! -d "$models" ]; then
    echo "voice.sh: no obey-voice model cache at $models; run obey-voice models ensure" >&2
    exit 1
fi

voice_home=$(mktemp -d)
trap 'rm -rf "$voice_home"' EXIT INT TERM
mkdir -p "$voice_home/.obey/agents/voice/festival-voice" "$voice_home/.cache"
printf 'tts_provider: kokoro\ntts_voice: %s\n' "$VOICE" \
    > "$voice_home/.obey/agents/voice/festival-voice/config.yaml"
ln -s "$models" "$voice_home/.cache/festival-voice"

HOME="$voice_home" obey-voice render demo/narration.md --out-dir demo/audio \
    --voice "$VOICE" --pause-heading 300ms --pause-paragraph 400ms --overwrite
