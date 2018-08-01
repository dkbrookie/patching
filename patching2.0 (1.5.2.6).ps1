<#

To run this from CMD:
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -command "& {Set-ExecutionPolicy Bypass -Force -Confirm:$False ; (new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-checkModule}"

powershell.exe -command "& {(new-object Net.WebClient).DownloadString('https://goo.gl/hVciTi') | iex ; PSU-checkModule}"

#>

##Checks important services needed to patch Windows, starts them if not running
Function PSU-serviceCheck{
    Write-Output "===Windows Update Service Check==="
    ##Verify the wuauserv service is running and the startup type is set to automatic
    $service = 'wuauserv'
    $wuau = Get-Service -Name $service
    $servStartus1 = $wuau.Status
    $servStart1 = $wuau.StartType
    IF($wuau.Status -ne 'Running' -or $wuau.StartType -ne 'Automatic'){
        Set-Service -Name $service -StartupType Automatic -Status Running
        Start-Sleep -Seconds 30
        $wuau = Get-Service -Name $service
        IF($wuau.Status -ne 'Running'){
            Write-Output "Failed to start the wuauserv service, unable to patch this machine"
            Exit
        }
        ELSE{
            $servStatus2 = $wuau.Status
            $servStart2 = $wuau.StartType
            Write-Output "The $service service was in the $servStartus1 state, and the startup type was set to $servStart1. Automation has set the status to $servStatus2, and the startup type to $servStart2."
        }
    }
    ELSE{
        Write-Output "Verified the $service service is running"
    }
}

##Checks the version of Powershell, need powershell 3+ for this script to work
Function PSU-versCheck{
    Write-Output "===Powershell Check==="
    $vers = $PSVersionTable.PSVersion | Select -ExpandProperty Major
    IF($vers -ge 3){
        Write-Output "Verified powershell version is sufficient"
    }
    ELSE{
        Write-Output "Powershell version is insufficient, must be 3 or higher. Current version is $vers"
        Exit
    }
}

##Checks for all needed Powershell modules for patching to function
Function PSU-checkModule{
    Write-Output "===Module Check==="
    ##Available module dir check
    IF($env:PSModulePath -notlike "*c:\Program Files\WindowsPowerShell\Modules*"){
        $env:PSModulePath = $env:PSModulePath + ";c:\Program Files\WindowsPowerShell\Modules"
        Write-Output "Added 'c:\Program Files\WindowsPowerShell\Modules' to available module dirs"
    }
    ELSE{
        Write-Output "Verified 'c:\Program Files\WindowsPowerShell\Modules' is added to available module dirs"
    }

    ##PackeManagement check
    $packageTest = Get-Module -ListAvailable -Name PackageManagement
    IF($packageTest -eq $Null){
        PSU-installPackage
    }
    ELSE{
        Write-Output "Verified the PackageManagement module is installed"
    }

    ##PowerShellGet check
    $getTest = Get-Module -ListAvailable -Name PowerShellGet
    IF($getTest -eq $Null){
        PSU-installGet
    }
    ELSE{
        Write-Output "Verified the PowerShellGet module is installed"
    }

    ##Nuget check
    $nugetTest = Get-Package -Name Nuget -EA 0
    IF($nugetTest -eq $Null){
        PSU-installNuget
    }
    ELSE{
        Write-Output "Verified the Nuget module is installed"
    }

    ##PSWindowsUpdate check
    $moduleTest = Get-Module -ListAvailable -Name PSWindowsUpdate
    IF(($moduleTest).Count -gt 1 -or $moduleTest -eq $Null -or $moduleTest.Version -ne '1.5.2.6'){
        PSU-installModule
    }
    ELSE{
        Write-Output "Verified PSWindowsUpdate is installed"
    }
}

##Installs the PackageManagement Powershell module
Function PSU-installPackage{
    $dirTest = Test-Path "$env:windir\LTSvc\Patching"
    IF(!$dirTest){
        New-Item "$env:windir\LTSvc\Patching" -Type Directory | Out-Null
    }
    $dirTest = Test-Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PackageManagement"
    IF(!$dirTest){
        Invoke-WebRequest -Uri "https://support.dkbinnovative.com/labtech/transfer/patching/PackageManagement/1.1.7.2.zip" -Outfile "$env:windir\LTSVc\Patching\1.1.7.2.zip"
        Add-Type -Assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::ExtractToDirectory("$env:windir\LTSVc\Patching\1.1.7.2.zip", "$env:windir\System32\WindowsPowerShell\v1.0\Modules")
        $dirTest = Test-Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PackageManagement"
        IF(!$dirTest){
            Write-Output "Failed to installed the PackageManagement module"
        }
        ELSE{
            Write-Output "Successfully installed the PackageManagement module"
        }
    }
}

##Installs the PowerhShellGet Powershell module
Function PSU-installGet{
    $dirTest = Test-Path "$env:windir\LTSvc\Patching"
    IF(!$dirTest){
        New-Item "$env:windir\LTSvc\Patching" -Type Directory | Out-Null
    }
    $dirTest = Test-Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerShellGet"
    IF(!$dirTest){
        Invoke-WebRequest -Uri "https://support.dkbinnovative.com/labtech/transfer/patching/PowerShellGet/1.6.6.zip" -Outfile "$env:windir\LTSVc\Patching\1.6.6.zip"
        Add-Type -Assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::ExtractToDirectory("$env:windir\LTSVc\Patching\1.6.6.zip", "$env:windir\System32\WindowsPowerShell\v1.0\Modules")
        $dirTest = Test-Path "$env:windir\System32\WindowsPowerShell\v1.0\Modules\PowerShellGet"
        IF(!$dirTest){
            Write-Output "Failed to installed the PowerShellGet module"
        }
        ELSE{
            Write-Output "Successfully installed the PowerShellGet module"
        }
    }
}

##Install the Nuget Powershell module
Function PSU-installNuget{
    Install-Package -Name NuGet -Force -EA 0 -Confirm:$False | Out-Null
    $nugetTest = Get-Package -Name Nuget -EA 0
    IF($nugetTest -eq $Null){
        Write-Output "Failed to install the Nuget module"
    }
    ELSE{
        Write-Output "Nuget module successfully installed"
    }
}

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
            Write-Output "Failed to remove the PSWindowsUpdate module"
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
        Write-Output "PSWindowsUpdate install failed."
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
    $history = Get-WUHistory | Select Result,Date,Title
    $lastSuccess = $history.Date | Sort-Object Descending | Select-Object -First 1

    IF($lastSuccess -gt $dayCount){
        "No patches have been installed or even attempted for $days+ days. This usually implies paching issues. Please verify this machine is scheduled for regular patching."
    }
}

##Pulls list of denied patches from the Automate server
Function PSU-denyPatchesLEGACY{
    Write-Output "===Denied Patches==="
    $clientID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ClientID | Select -ExpandProperty ClientID
    $computerID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ID | Select -ExpandProperty ID
    $denyList = (new-object Net.WebClient).DownloadString("https://support.dkbinnovative.com/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt") | iex
    #$urlTest = iwr https://support.dkbinnovative.com/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt | % {$_.StatusCode}
    IF($denyList -ne $Null){
        Hide-WUUpdate -MicrosoftUpdate -HideStatus:$false -Verbose -Confirm:$false | Out-Null
        Hide-WUUpdate -Category Driver -Confirm:$false
        Hide-WUUpdate -KBArticleID $denyList -Verbose -Confirm:$False
        Write-Output "Patches Denied: $denyList"
    }
    ELSE{
        Write-Output "There is no deny file located at https://support.dkbinnovative.com/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt. Please generate the deny file before patching."
        Exit
    }
}

##Pulls list of denied patches from the Automate server
Function PSU-denyPatches{
    Write-Output "===Denied Patches==="
    $clientID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ClientID | Select -ExpandProperty ClientID
    $computerID = Get-ItemProperty -Path "HKLM:\SOFTWARE\LabTech\Service" -Name ID | Select -ExpandProperty ID
    $approveList = IWR -Uri "https://support.dkbinnovative.com/labtech/transfer/patching/$clientID/$computerID/patchApprove.txt"
    $approveList = $approveList.Content
    $pending = Get-WUList -MicrosoftUpdate | Select -ExpandProperty KB
    Hide-WUUpdate -MicrosoftUpdate -HideStatus:$false -Verbose -Confirm:$false | Out-Null
    Hide-WUUpdate -Category Driver -Confirm:$false
    ForEach($kb in $pending){
        IF($approveList.Contains($kb) -eq $False){
            Hide-WUUpdate -KBArticleID $kb -Verbose -Confirm:$False
        }
    }
    ELSE{
        Write-Output "There is no deny file located at https://support.dkbinnovative.com/labtech/transfer/patching/$clientID/$computerID/patchDeny.txt. Please generate the deny file before patching."
        Exit
    }
}

##Displays a list of pending patches
Function PSU-pendingPatches{
    Write-Host "===Pending Patches==="
    Get-WindowsUpdate -MicrosoftUpdate
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
    netsh winsock reset

    ##Start update services
    Start-Service bits
    Start-Service cryptsvc
    Start-Service wuauserv
}

##Get total patching %
Function PSU-getScore{
    IF ($mute -eq $Null){
        Write-Output "===Patching Percentage==="
    }
    $ErrorActionPreference = 'SilentlyContinue'

    ##Start WUAUSERV if it's not started
    $wuStatus = Get-Service wuauserv | Select -Expand Status | Out-Null
    IF ($wuStatus -eq 'Stopped'){
        Start-Service wuauserv
    }

    IF($env:PSModulePath -notlike "*c:\Program Files\WindowsPowerShell\Modules*"){
        $env:PSModulePath = $env:PSModulePath + ";c:\Program Files\WindowsPowerShell\Modules"
    }

    ##Search for the PSWU module
    $modInstalled = Get-Module -ListAvailable -Name PSWindowsUpdate
    IF ($modInstalled -eq $Null){
        Write-Host "PSWU Missing"
    }
    ELSE{
        ##Import PSWU module
        Import-Module PSWindowsUpdate | Out-Null
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false | Out-Null

        ##Set vars for how many updates are installed and how many are missing
        $installedPS = @(Get-WUList -IsInstalled -MicrosoftUpdate | Where {$_.kb -ne ""}).count
        $missing = @(Get-WUList -MicrosoftUpdate | Where-Object {$_.Status -notlike "*H*"}).count

        IF ($installedPS -eq 0 -and $missing -eq 0 -or $installedPS -eq $Null -and $missing -eq $Null){
            Write-Host '0'
        }
        ELSE{
            ##Calculate how many are missing by dividing the total installed by the total not installed
            $percent = ($InstalledPS / ($InstalledPS + $missing) * 100)
            ##Output the percentage
            "{0:N2}" -f $percent
        }
    }
}

##Get a list of pending patches
Function PSU-getPending{
    Write-Output "===Pending Updates==="
    PSU-denyPatches
    Get-WUList -MicrosoftUpdate | Where-Object {$_.Status -notlike "*H*"}
}

##Get a list of installed patches
Function PSU-getInstalled{
    Write-Output "===Installed Updates==="
    Get-WUList -IsInstalled -MicrosoftUpdate
}

##Run all tasks to complete a successful patching session
Function PSU-patchProcess{
    PSU-versCheck
    PSU-serviceCheck
    PSU-checkModule
    PSU-denyPatches
    PSU-installPatches
    PSU-getScore
}
