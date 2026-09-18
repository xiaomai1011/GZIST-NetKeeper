' CampusNet keepalive silent launcher (no window at all)
' Derives its own folder, so no hardcoded path inside.
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
Set sh = CreateObject("WScript.Shell")
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dir & "\campus_net.ps1"" -Watch"
sh.Run cmd, 0, False
