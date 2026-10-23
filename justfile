# The demo video renders from files: demo/narration.md, demo/tapes/, and the
# recorded runs. It needs obey-voice (Kokoro), vhs, and ffmpeg.

# List the recipes
default:
    @just --list

# Render the narration to demo/audio/ with obey-voice's Kokoro voice
demo-audio:
    demo/voice.sh

# Record the five tapes with vhs, lay the narration over them, write demo/zecathon.mp4
demo-video:
    demo/render.sh

# Render the narration, then the video
demo: demo-audio demo-video
