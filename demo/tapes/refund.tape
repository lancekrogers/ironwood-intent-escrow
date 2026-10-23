# Refund: the real refund run's output, replayed from its captured log.
# command-seconds: 4
Output demo/video/refund.mp4
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
Type "demo/replay.sh demo/logs/refund.log"
Enter
Wait@30s
Sleep @@HOLD@@
