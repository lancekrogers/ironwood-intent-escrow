# Pitch: the plain-text summary, held for the narration.
# command-seconds: 1
Output demo/video/pitch.mp4
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
Type "cat demo/pitch.txt"
Enter
Wait@10s
Sleep @@HOLD@@
