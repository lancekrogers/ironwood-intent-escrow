#!/bin/sh
# Renders demo/narration.md to demo/audio/, one WAV per `##` section plus a
# manifest, with obey-voice's local TTS. The default is the Qwen3-TTS preset
# voice Ryan on the 1.7B model; Kokoro is the fallback.
#
# obey-voice reads its settings from $HOME. A personal setting there, such
# as another engine's voice name, changes or breaks the render, so this runs
# it under a throwaway HOME whose only settings are the engine and the voice.
# The narration then renders the same way on any machine with obey-voice
# and the chosen model installed. The model caches are linked in from the
# real HOME; nothing in the real HOME is written.
#
# The paths below are obey-voice's own layout, where it reads its config
# and keeps its models, plus the Hugging Face cache that holds the Qwen3-TTS
# weights. If obey-voice moves them, update them here.
#
# Usage: demo/voice.sh                               (from the repository root)
#        VOICE=Aiden demo/voice.sh                    (the other Qwen3-TTS English preset)
#        PROVIDER=kokoro VOICE=am_onyx demo/voice.sh  (the Kokoro render)
set -eu

PROVIDER="${PROVIDER:-qwen3-tts}"
case "$PROVIDER" in
    qwen3-tts) VOICE="${VOICE:-Ryan}" ;;
    kokoro) VOICE="${VOICE:-am_onyx}" ;;
    *) echo "voice.sh: PROVIDER must be qwen3-tts or kokoro, not $PROVIDER" >&2; exit 1 ;;
esac
models="$HOME/.cache/festival-voice"
if [ ! -d "$models" ]; then
    echo "voice.sh: no obey-voice model cache at $models; run obey-voice models ensure" >&2
    exit 1
fi
hf="$HOME/.cache/huggingface"
if [ "$PROVIDER" = qwen3-tts ] && [ ! -d "$hf" ]; then
    echo "voice.sh: no Hugging Face cache at $hf; the Qwen3-TTS weights are not installed" >&2
    exit 1
fi

voice_home=$(mktemp -d)
trap 'rm -rf "$voice_home"' EXIT INT TERM
mkdir -p "$voice_home/.obey/agents/voice/festival-voice" "$voice_home/.cache"
{
    printf 'tts_provider: %s\ntts_voice: %s\n' "$PROVIDER" "$VOICE"
    if [ "$PROVIDER" = qwen3-tts ]; then
        printf 'qwen_tts_voice: %s\nqwen_tts_consent: true\nqwen_tts_mode: customvoice\n' "$VOICE"
        printf 'qwen_tts_model_tier: 1.7b\nqwen_tts_language: English\nqwen_tts_timeout: 600\n'
    fi
} > "$voice_home/.obey/agents/voice/festival-voice/config.yaml"
ln -s "$models" "$voice_home/.cache/festival-voice"
[ -d "$hf" ] && ln -s "$hf" "$voice_home/.cache/huggingface"

HOME="$voice_home" obey-voice render demo/narration.md --out-dir demo/audio \
    --voice "$VOICE" --pause-heading 300ms --pause-paragraph 400ms --overwrite
