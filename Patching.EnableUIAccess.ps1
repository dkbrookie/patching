$hideUpdateKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
If((Get-ItemProperty $hideUpdateKey -Name SettingsPageVisibility | Select -ExpandProperty SettingsPageVisibility) -ne 'hide:') {
    Set-ItemProperty -Path $hideUpdateKey -Name SettingsPageVisibility -Value 'hide:'
    Write-Host "Unhid the Windows Update UI"
    $reboot = $True
}

If($reboot) {
    Write-Warning "Please restart your machine for the changes to apply!"
}
