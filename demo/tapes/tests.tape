# Tests: the whole suite, offline, run live. The sed drops the build
# directory cargo prints after each test binary. command-seconds covers the
# typing and a warm `cargo test` (about 30 s measured); min-seconds keeps the
# segment as long as the slowest run measured, so every render of the same
# narration has the same length.
# command-seconds: 33
# min-seconds: 40
Output demo/video/tests.mp4
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
Type "cargo test 2>&1 | grep --line-buffered -E 'Running|test result' | sed 's/ (.*)$//'"
Enter
Wait@90s
Sleep @@HOLD@@
