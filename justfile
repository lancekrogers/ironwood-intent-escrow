# The demo video renders from files: demo/narration.md, demo/tapes/, and the
# recorded runs. It needs obey-voice with the Qwen3-TTS model, vhs, and ffmpeg.

# List the recipes
default:
    @just --list

# Render the narration to demo/audio/ with obey-voice (Qwen3-TTS Ryan; PROVIDER=kokoro for the old voice)
demo-audio:
    demo/voice.sh

# Record the five tapes with vhs, lay the narration over them, write demo/zecathon.mp4
demo-video:
    demo/render.sh

# Render the narration, then the video
demo: demo-audio demo-video

# Check the web report adapter and browser report validation.
web-check:
    python3 -m unittest discover -s scripts -p 'test_*.py'
    node --test web/report.test.mjs

# Package the static page; verifier hosting is configured in web/config.json.
web-build:
    cargo build --release --locked --bin verify
    python3 scripts/build_web.py
    python3 scripts/verification_report.py --output target/web/verification.json

# Serve the packaged page locally.
web-preview:
    python3 -m http.server 8765 --bind 127.0.0.1 --directory target/web
