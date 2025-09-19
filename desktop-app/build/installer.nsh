; Apollo NSIS Installer Script Extensions

!macro preInit
    SetRegView 64
    WriteRegStr HKLM "Software\Apollo" "InstallPath" "$INSTDIR"
!macroend

!macro customInstall
    ; Install Apollo Service
    DetailPrint "Installing Apollo Protection Service..."
    ExecWait '"$INSTDIR\Apollo.exe" --install-service'

    ; Create firewall rules
    DetailPrint "Configuring Windows Firewall..."
    ExecWait 'netsh advfirewall firewall add rule name="Apollo Protection" dir=in action=allow program="$INSTDIR\Apollo.exe" enable=yes'

    ; Add to Windows Defender exclusions
    DetailPrint "Configuring Windows Defender..."
    ExecWait 'powershell -Command "Add-MpPreference -ExclusionPath \"$INSTDIR\""'

    ; Set service to auto-start
    DetailPrint "Configuring auto-start..."
    ExecWait 'sc config ApolloProtection start=auto'

    ; Start the service
    DetailPrint "Starting Apollo Protection..."
    ExecWait 'sc start ApolloProtection'
!macroend

!macro customUnInstall
    ; Stop and remove service
    DetailPrint "Stopping Apollo Service..."
    ExecWait 'sc stop ApolloProtection'
    ExecWait 'sc delete ApolloProtection'

    ; Remove firewall rules
    DetailPrint "Removing firewall rules..."
    ExecWait 'netsh advfirewall firewall delete rule name="Apollo Protection"'

    ; Clean up registry
    DeleteRegKey HKLM "Software\Apollo"
!macroend