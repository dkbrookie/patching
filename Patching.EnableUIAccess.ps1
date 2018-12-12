$hideUpdateKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$disableUpdateKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
If((Get-ItemProperty $hideUpdateKey -Name NoWindowsUpdate | Select -ExpandProperty NoWindowsUpdate) -ne 0) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoWindowsUpdate -Value 0
    Write-Host "Unhid the Windows Update UI"
    $reboot = $True
}

If((Test-Path $disableUpdateKey)) {
    If((Get-ItemProperty $disableUpdateKey -Name DisableWindowsUpdateAccess | Select -ExpandProperty DisableWindowsUpdateAccess) -ne 0) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name DisableWindowsUpdateAccess -Value 0
        Write-Output "Re-enabled Windows Updates"
        $reboot = $True
    }
}

If($reboot) {
    Write-Warning "Please restart your machine for the changes to apply!"
}
