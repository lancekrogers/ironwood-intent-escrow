# Fill: the recorded fill run's record, then the NEAR payment's call
# arguments decoded from the fetched payload: amount, memo, receiver.
# command-seconds: 6
Output demo/video/fill.mp4
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
Type "cat runs/fill.json; echo"
Enter
Wait@10s
Sleep 1500ms
Type `grep -o '"args":"[^"]*"' runs/fill.near.json | cut -d'"' -f4 | base64 -d | python3 -m json.tool`
Enter
Wait@10s
Sleep @@HOLD@@
