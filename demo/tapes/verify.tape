# Verify: the judge's check, live against the light server and the archival
# NEAR RPC. The fetch is live, so the segment is bounded by its budget: the
# tape waits for the prompt, at most 60 s, and the render fails if the
# output is not complete within the segment.
# command-seconds: 7
Output demo/video/verify.mp4
Set Shell "bash"
Set Width 1280
Set Height 720
Set FontSize 18
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Hide
Type "clear"
Enter
Sleep 300ms
Show
Type "cargo run -q --release --bin verify"
Enter
Wait@60s
Sleep @@HOLD@@
