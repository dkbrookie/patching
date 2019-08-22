<#

To run this from CMD:
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -command "& {Set-ExecutionPolicy Bypass -Force -Confirm:$False ; (new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-checkModule}"

powershell.exe -command "& {(new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-patchProcess}"

powershell.exe -command "& {(new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-checkModule ; PSU-unhideAll ; PSU-installPatches}"

powershell.exe -command "& {(new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-getInstalled | Select-Object ComputerName, Status, KB, Title | Export-Csv -Path c:\RECORDER-installedPatches.csv -Encoding ascii -NoTypeInformation}"

#>asd

$ErrorActionPreference = "SilentlyContinue"
$patchComponentDir = "$env:windir\LTSVc\Patching"

##Checks important services needed to patch Windows, starts them if not running
Function PSU-serviceCheck{
    Write-Output "===Windows Update Service Check==="
    ##Verify the wuauserv service is running and the startup type is set to automatic
    $service = 'wuauserv'
    $wuau = Get-Service -Name $service
    $servStartus1 = $wuau.Status
    $servStart1 = $wuau.StartType
    IF ($wuau.Status -ne 'Running' -or $wuau.StartType -ne 'Automatic') {
        Set-Service -Name $service -StartupType Automatic -Status Running
        Start-Sleep -Seconds 30
        $wuau = Get-Service -Name $service
        IF ($wuau.Status -ne 'Running') {
            Write-Output "!ERRWU01: Failed to start the wuauserv service, unable to patch this machine"
            Exit
        } ELSE {
            $servStatus2 = $wuau.Status
            $servStart2 = $wuau.StartType
            Write-Output "The $service service was in the $servStartus1 state, and the startup type was set to $servStart1. Automation has set the status to $servStatus2, and the startup type to $servStart2."
        }#End Else
    } ELSE {
        Write-Output "Verified the $service service is running"
    }#End Else
}#End Function PSU-serviceCheck

##Checks the version of Powershell, need powershell 3+ for this script to work
Function PSU-versCheck{
    Write-Output "===Powershell Check==="
    $vers = $PSVersionTable.PSVersion | Select-Object -ExpandProperty Major
    IF($vers -ge 3){
        Write-Output "Verified powershell version is sufficient"
    }
    ELSE{
        Write-Output "!ERRPS01: Powershell version is insufficient, must be 3 or higher. Current version is $vers"
        Exit
    }#End Else
}#End Function versCheck

##Checks for all needed Powershell modules for patching to function
Function PSU-checkModule{
    Write-Output "===Module Check==="
    ##Available module dir check
    IF ($env:PSModulePath -notlike "*c:\Program Files\WindowsPowerShell\Modules*") {
        $env:PSModulePath = $env:PSModulePath + ";c:\Program Files\WindowsPowerShell\Modules"
        Write-Output "Added 'c:\Program Files\WindowsPowerShell\Modules' to available module dirs"
    } ELSE {
        Write-Output "Verified 'c:\Program Files\WindowsPowerShell\Modules' is added to available module dirs"
    }#End Else

    ##PackeManagement check
    IF (!(Get-Module -ListAvailable -Name PackageManagement)) {
        PSU-installPackage
    } ELSE {
        Write-Output "Verified the PackageManagement module is installed"
    }#End Else

    ##PowerShellGet check
    IF (!(Get-Module -ListAvailable -Name PowerShellGet)) {
        PSU-installGet
    } ELSE {
        Write-Output "Verified the PowerShellGet module is installed"
    }#End Else

    ##Nuget check
    IF (!(Get-Package -Name Nuget )) {
        PSU-installNuget
    } ELSE {
        Write-Output "Verified the Nuget module is installed"
    }#End Else

    ##PSWindowsUpdate check
    $moduleCheck = Get-Module -ListAvailable -Name PSWindowsUpdate
    IF (($moduleCheck).Count -gt 1 -or $moduleCheck -eq $Null -or $moduleCheck.Version -ne '1.5.2.6') {
        PSU-installModule
    } ELSE {
        Write-Output "Verified PSWindowsUpdate is installed"
    }#End Else
}#End Function PSU-checkModule

##Installs the PackageManagement Powershell module
Function PSU-installPackage{
    IF (!(Test-Path $patchComponentDir)) {
        New-Item $patchComponentDir -Type Directory | Out-Null
    }

    $packageDir = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PackageManagement"
    Try{
        IF (!($packageDir)) {
            Invoke-WebRequest -Uri "https://$dkbURL/labtech/transfer/patching/PackageManagement/1.1.7.2.zip" -Outfile "$patchComponentDir\1.1.7.2.zip"
            Add-Type -Assembly "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory("$patchComponentDir\1.1.7.2.zip", "C:\Windows\System32\WindowsPowerShell\v1.0\Modules")
            Write-Output "Successfully installed the PackageManagement module"
        }
    }#End Try

    Catch{
        Write-Warning "There was a problem installing the PackageManagement module"
    }#End Catch
}#End Function PSU-installPackage

##Installs the PowerhShellGet Powershell module
Function PSU-installGet{
    IF(!$patchComponentDir){
        New-Item $patchComponentDir -Type Directory | Out-Null
    }
    $powerShelGetDir = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellGet"
    IF (!($powerShelGetDir)) {
        Try{
            Invoke-WebRequest -Uri "https://$dkbURL/labtech/transfer/patching/PowerShellGet/1.6.6.zip" -Outfile "$patchComponentDir\1.6.6.zip"
            Add-Type -Assembly "system.io.compression.filesystem"
            [io.compression.zipfile]::ExtractToDirectory("$patchComponentDir\1.6.6.zip", "C:\Windows\System32\WindowsPowerShell\v1.0\Modules")
            Write-Output "Successfully installed the PowerShellGet module"
        }#End Try

        Catch{
            Write-Warning "There was an issue trying to install the PowershellGet module"
        }#End Catch
    }#End If
}#End Function PSU-installGet

##Install the Nuget Powershell module
Function PSU-installNuget{
    Try{
        Install-Package -Name NuGet -Force -EA 0 -Confirm:$False | Out-Null
        Write-Output "Nuget module successfully installed"
    }#End Try

    Catch{
        Write-Warning "There was a problem installing the Nuget module"
    }#End Catch
}#End Function PSU-installNuget

##Installs the PSWindowsUpdate Powershell module
Function PSU-installModule{
    $modVers = '1.5.2.6'

    ##Check for existing install of PSWindowsUpdate
    $moduleTest = Get-Module -ListAvailable -Name PSWindowsUpdate
    IF($moduleTest -ne $Null){
        Remove-Module PSWindowsUpdate -Force -EA 0 | Out-Null
        Uninstall-Module PSWindowsUpdate -AllVersions -Force -EA 0 | Out-Null
        $moduleTest = Get-Module -ListAvailable -Name PSWindowsUpdate
        IF($moduleTest -ne $Null){
            Write-Output "!ERRMOD04: Failed to remove the PSWindowsUpdate module"
        }
        ##Verify the PSWindowsUpdate dir removed during uninstall
        $psDirTest = Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate"
        IF($psDirTest -ne $Null){
            Remove-Item -Recurse -Force "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate" -EA 0 | Out-Null
        }
        ELSE{
            Write-Output "Verified there is no C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate folder to delete"
        }

    }

    Install-Module -Name PSWindowsUpdate -RequiredVersion $modVers -EA 0 -Confirm:$False -Force | Out-Null
    $verifyInstall = Get-Module -ListAvailable -Name PSWindowsUpdate
    IF($verifyInstall -eq $Null){
        Write-Output "!ERRMOD05: PSWindowsUpdate install failed."
    }
    ELSE{
        Write-Output "PSWindowsUpdate module successfully installed."
    }
}

##Outputs the the latest patching attempt date
Function PSU-lastSuccess{
    Write-Output "===Update History==="
    $days = 30
    $currentDate = Get-Date
    $dayCount = (Get-Date).adddays($days)
    $history = Get-WUHistory | Select-Object Result,Date,Title
    $lastSuccess = $history.Date | Sort-Object Descending | Select-Object -First 1

    IF($lastSuccess -gt $dayCount){
        "No patches have been installed or attempted for $days+ days. This usually implies paching issues. Please verify this machine is scheduled for regular patching."
    }
}

##Pulls list of denied patches from the Automate server
Function PSU-denyPatchesLEGACY{
    Write-Output "===Denied Patches==="
    $clientID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ClientID | Select-Object -ExpandProperty ClientID
    $computerID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ID | Select-Object -ExpandProperty ID
    $denyList = (new-object Net.WebClient).DownloadString("https://$dkbURL/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt") | Invoke-Expression
    #$urlTest = iwr https://$dkbURL/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt | % {$_.StatusCode}
    IF($denyList -ne $Null){
        Hide-WUUpdate -MicrosoftUpdate -HideStatus:$false -Verbose -Confirm:$false | Out-Null
        Hide-WUUpdate -Category Driver -Confirm:$false
        Hide-WUUpdate -KBArticleID $denyList -Verbose -Confirm:$False
        Write-Output "Patches Denied: $denyList"
    }
    ELSE{
        Write-Output "!ERRDE01: There is no deny file located at https://$dkbURL/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt. Please generate the deny file before patching."
        Exit
    }
}

##Pulls list of denied patches from the Automate server
Function PSU-denyPatches{
    Write-Output "===Denied Patches==="
    $clientID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ClientID | Select-Object -ExpandProperty ClientID
    $computerID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ID | Select-Object -ExpandProperty ID
    $approveList = IWR -Uri "https://$dkbURL/labtech/transfer/patching/$clientID/$computerID/patchApprove.txt" -EA 0
    $approveList = $approveList.Content
    IF(!$approveList){
        Write-Output "!ERRDE01: There is no deny file located at https://$dkbURL/labtech/transfer/patching/$clientID/$computerID/patchApprove.txt. Please generate the deny file before patching."
        Break
    }
    ELSE{
        $pending = Get-WUList -MicrosoftUpdate | Select-Object -ExpandProperty KB
        Hide-WUUpdate -MicrosoftUpdate -HideStatus:$false -Verbose -Confirm:$false | Out-Null
        Hide-WUUpdate -Category Driver -Confirm:$false
        ForEach($kb in $pending){
            IF($approveList.Contains($kb) -eq $False){
                Hide-WUUpdate -KBArticleID $kb -Verbose -Confirm:$False
            }
        }
    }
}

##Patches the machine
Function PSU-installPatches{
    $dateTime = Get-Date
    Write-Output "===Patching Started==="
    Write-Output "Patch Start Time: $dateTime"
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false | Out-Null
    Get-WUInstall -Verbose -AcceptAll -IgnoreReboot -IgnoreUserInput -Confirm:$false
}

##Repair windows updates
Function PSU-repairUpdates{
    Write-Output "===Windows Update Repair==="
    ##Stop update services
    $bits = Get-Service bits
    IF ($bits.Status -eq 'Running'){
        Stop-Service bits -Force
    }
    $cryptSvc = Get-Service cryptsvc
    IF ($cryptSvc.Status -eq 'Running'){
        Stop-Service cryptsvc -Force
    }
    $wuauServ = Get-Service wuauserv
    IF ($wuauServ.Status -eq 'Running'){
        Stop-Service wuauserv -Force
    }

    ##Delete Windows Updates downloads & cache
    Get-ChildItem "C:\Windows\system32\catroot2\*" -Recurse | Remove-Item -Force -EA 0 -Confirm:$False -Recurse
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse | Remove-Item -Force -EA 0 -Confirm:$False -Recurse

    ##Reset proxy
    netsh winhttp reset proxy

    ##Reset BITS
    sc.exe sdset bits "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    sc.exe sdset wuauserv "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"

    ##Re-register DLLs
    regsvr32.exe atl.dll /s
    regsvr32.exe urlmon.dll /s
    regsvr32.exe mshtml.dll /s
    regsvr32.exe shdocvw.dll /s
    regsvr32.exe browseui.dll /s
    regsvr32.exe jscript.dll /s
    regsvr32.exe vbscript.dll /s
    regsvr32.exe scrrun.dll /s
    regsvr32.exe msxml.dll /s
    regsvr32.exe msxml3.dll /s
    regsvr32.exe msxml6.dll /s
    regsvr32.exe actxprxy.dll /s
    regsvr32.exe softpub.dll /s
    regsvr32.exe wintrust.dll /s
    regsvr32.exe dssenh.dll /s
    regsvr32.exe rsaenh.dll /s
    regsvr32.exe gpkcsp.dll /s
    regsvr32.exe sccbase.dll /s
    regsvr32.exe slbcsp.dll /s
    regsvr32.exe cryptdlg.dll /s
    regsvr32.exe oleaut32.dll /s
    regsvr32.exe ole32.dll /s
    regsvr32.exe shell32.dll /s
    regsvr32.exe initpki.dll /s
    regsvr32.exe wuapi.dll /s
    regsvr32.exe wuaueng.dll /s
    regsvr32.exe wuaueng1.dll /s
    regsvr32.exe wucltui.dll /s
    regsvr32.exe wups.dll /s
    regsvr32.exe wups2.dll /s
    regsvr32.exe wuweb.dll /s
    regsvr32.exe qmgr.dll /s
    regsvr32.exe qmgrprxy.dll /s
    regsvr32.exe wucltux.dll /s
    regsvr32.exe muweb.dll /s
    regsvr32.exe wuwebv.dll /s

    ##Reset winsock
    netsh winsock reset

    ##Start update services
    Start-Service bits
    Start-Service cryptsvc
    Start-Service wuauserv

    ##Reset Windows update certifcate
    #$cert = (gci -Path Cert:\LocalMachine\AuthRoot\97817950D81C9670CC34D809CF794431367EF474);
    #$filepath = "c:\bin\GTE.cer";
    #Export-Certificate -Cert $cert -FilePath $filepath;
    #$cert | Remove-Item;
    #Import-Certificate -CertStoreLocation Cert:\LocalMachine\AuthRoot -FilePath $filepath;
}

##Get total patching %
Function PSU-getScore{
    IF (!$mute){
        Write-Output "===Patching Percentage==="
    }
    $ErrorActionPreference = 'SilentlyContinue'

    ##Start WUAUSERV if it's not started
    $wuStatus = Get-Service wuauserv | Select-Object -Expand Status | Out-Null
    IF ($wuStatus -eq 'Stopped'){
        Start-Service wuauserv
    }

    ##Ensures Powershell is looking in the modules dir in Program Files for available modules
    IF($env:PSModulePath -notlike "*c:\Program Files\WindowsPowerShell\Modules*"){
        $env:PSModulePath = $env:PSModulePath + ";c:\Program Files\WindowsPowerShell\Modules"
    }

    ##Import PSWU module
    Import-Module PSWindowsUpdate | Out-Null
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$False | Out-Null
    ##Set vars for how many updates are installed and how many are missing
    $installedPS = @(Get-WUList -IsInstalled -MicrosoftUpdate | Where {$_.kb -ne ""}).count
    $missing = @(Get-WUList -MicrosoftUpdate | Where-Object {$_.Status -notlike "*H*"}).count

    IF ($installedPS -eq 0 -and $missing -eq 0 -or $installedPS -eq $Null -and $missing -eq $Null){
        Write-Output 'No Data Available'
    }
    ELSE{
        ##Calculate how many are missing by dividing the total installed by the total not installed
        $percent = ($InstalledPS / ($InstalledPS + $missing) * 100)
        ##Output the percentage
        "{0:N2}" -f $percent
    }
}

##Get a list of pending patches
Function PSU-getPending{
    Write-Output "===Pending Updates==="
    Get-WUList -MicrosoftUpdate | Where-Object {$_.Status -notlike "*H*"}
}

##Get a list of installed patches
Function PSU-getInstalled{
    Write-Output "===Installed Updates==="
    Get-WUList -IsInstalled -MicrosoftUpdate
}

##Unhide all patches
Function PSU-unhideAll{
    Write-Output "===Unhide Updates==="
    Hide-WUUpdate -MicrosoftUpdate -HideStatus:$false -Verbose -Confirm:$false
}

Function PSU-rebootStatus{
    $status = Get-WURebootStatus
    IF($status -eq "localhost: Reboot is not Required."){
        Write-Output "No reboot pending"
    }
    ELSE{
        Write-Output "Reboot pending"
    }
}

##Output list of installed updates into a CSV at $patchComponentDir\[companyid]-[computerid]-[computername]-installedUpdates.csv
Function PSU-installedToCSV{
    Write-Output "===Exporting Installed Patches==="
    $computerName = $env:computername
    $clientID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ClientID | Select-Object -ExpandProperty ClientID
    $computerID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ID | Select-Object -ExpandProperty ID
    $dirTest = Test-Path "$patchComponentDir"
    IF(!$dirTest){
        New-Item "$patchComponentDir" -Type Directory | Out-Null
    }
    $csvTest = Test-Path "$patchComponentDir\$computerName-$clientID-$computerID-installedPatches.csv" -PathType Leaf
    IF($csvTest){
      Remove-Item -Path "$patchComponentDir\$computerName-$clientID-$computerID-installedPatches.csv" -Force -EA 0
    }
    PSU-getInstalled | Select-Object ComputerName, Status, KB, Title | Export-Csv -Path "$patchComponentDir\$computerName-$clientID-$computerID-installedPatches.csv" -Encoding ascii -NoTypeInformation
}

##Run all tasks to complete a successful patching session
Function PSU-patchProcess{
    PSU-versCheck
    PSU-serviceCheck
    PSU-checkModule
    PSU-denyPatches
    PSU-installPatches
}
