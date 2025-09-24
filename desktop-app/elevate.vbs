
Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "C:\Program Files\nodejs\node.exe", "C:\SECURE_THREAT_INTEL\Fortress\APOLLO\desktop-app\src\test-osint-integration.js", "", "runas", 1
            