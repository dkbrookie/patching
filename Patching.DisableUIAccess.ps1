$hideUpdateKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$disableUpdateKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
If((Get-ItemProperty $hideUpdateKey -Name NoWindowsUpdate | Select -ExpandProperty NoWindowsUpdate) -ne 1) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoWindowsUpdate -Value 1
    Write-Host "Hid the Windows Update UI"
    $reboot = $True
}

If((Test-Path $disableUpdateKey)) {
    If((Get-ItemProperty $disableUpdateKey -Name DisableWindowsUpdateAccess | Select -ExpandProperty DisableWindowsUpdateAccess) -ne 1) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name DisableWindowsUpdateAccess -Value 1
        Write-Output "Disabled Windows Updates"
        $reboot = $True
    }
} Else {
  New-Item $disableUpdateKey | Out-Null
  New-ItemProperty $disableUpdateKey -PropertyType DWORD -Name DisableWindowsUpdateAccess -Value 1 | Out-Null
  Write-Output "Windows Update disable keys didn't exist, successfully created keys"
}

If($reboot) {
    Write-Warning "Please restart your machine for the changes to apply!"
}
