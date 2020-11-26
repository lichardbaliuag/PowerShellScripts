<##########################################################

Script Name: WinUp_Reporter.ps1
Date: 2020.10.16
Release: Version 1.0
Writen by: Lichard Baliuag | lichard.baliuag@datacom.co.nz

Parent script: None
Dependencies: Get-PendingReboot.ps1
Description: 
 - Collect the following system information on a remote computer;
   - Server name
   - OS
   - Number of installed update in the current month (can manually override)
   - Last bootup time, 
   - Check pending reboot

Note: 
- Script is day sensitive, $server variable refer from day to get reference server list.
- $currenMonth variable can be override with interger month value, e.g 10 for October

Update History:
2020.11.19: Update reference on server list. For week days, used Patching_INT_Preprod_MasterList.txt and for weekend used Patching_INT_Production_MasterList.txt
2020.11.16: Bug Fixes - ($numberOfUpdatesThisMonth).Count | The $hotfixCount variable only returns  value from Windows Server 2008, 2012 & 2019 and while on Windows Server 2016 returns zero (0).
            Replace with ($numberOfUpdatesThisMonth | Measure-Object).Count

##########################################################>

Import-Module 'C:\Scripts\Admin_SXDatacom\Get-PendingReboot.ps1'

$servers = ""
[int]$currentMonth = (Get-Date).month  # this can use number month.

$today = (Get-Date).DayOfWeek
if ($today -eq 'Saturday' -or $today -eq 'Sunday') {
    
    # On weekend - Get Production server list
    $servers = Get-Content 'C:\Scripts\Admin_SXDatacom\ServerList\Patching_INT_Production_MasterList.txt'

} else {
    
    # On weekday - Get Pre-prod server list
    $servers = Get-Content 'C:\Scripts\Admin_SXDatacom\ServerList\Patching_INT_Preprod_MasterList.txt'
}


Foreach ($svr in $servers) {

    try {

        $testConnection = Test-Connection -Count 1 -Quiet -ComputerName $svr
        $getComputerInfo = try {Invoke-Command -ComputerName $svr -ScriptBlock {  Get-ComputerInfo }  -ErrorAction SilentlyContinue } catch { Write-Host "$($svr) unreachable" -ForegroundColor Yellow}
        $getOtherInfo = Get-PendingReboot -ComputerName $svr

        #[array]$numberOfUpdatesThisMonth =  Get-HotFix -ComputerName $svr | Where-Object {($_.InstalledOn).Month -eq ((Get-Date).Month) -and ($_.InstalledOn).year -eq ((Get-Date).Year) } | select HotFixID,Description
        #$hotfixCount = ($numberOfUpdatesThisMonth).Count

        $numberOfUpdatesThisMonth = Get-HotFix -ComputerName $svr | Where-Object {($_.InstalledOn).month -eq $currentMonth -and ($_.InstalledOn).year -eq ((Get-Date).Year) }
        $hotfixCount = ($numberOfUpdatesThisMonth | Measure-Object).Count
        $lastBoot = $getComputerInfo.OsLastBootUpTime
        $os = (Get-WmiObject -ComputerName $svr -class Win32_OperatingSystem ).Caption    
        $pr = $getOtherInfo.RebootPending

        if ($testConnection -eq $true) {
            if ($lastBoot) {
                if ($pr -eq $true) { 
                    Write-Host "$($svr) | OS: $($os) | Updates: $($hotfixCount) | Last Reboot: $($lastBoot) | Pending Reboot: $($pr) | Comment: Reboot required." -ForegroundColor Yellow   # Pending reboot = True
                } else {
                    if ($hotfixCount -ne 0) {
                        Write-Host "$($svr) | OS: $($os) | Updates: $($hotfixCount) | Last Reboot: $($lastBoot) | Pending Reboot: $($pr) | Comment: OK" -ForegroundColor Green # Pending reboot = False, hotfix not 0
                    } else {
                        Write-Host "$($svr) | OS: $($os) | Updates: $($hotfixCount) | Last Reboot: $($lastBoot) | Pending Reboot: $($pr) | Comment: OK - Stale" -ForegroundColor Green
                    }
                }      
            } else { 
                Write-Host "$($svr) | OS: $($os) | Updates: $($hotfixCount) | Last Reboot: $($lastBoot) | Pending Reboot: $($pr) | Comment: Unknown last boot" -ForegroundColor Magenta # lastboot = null

            }
        } else {
            Write-Host "$($svr) - Unreachable | OS: Unknown | Updates: Unknown | Last Reboot: Unknown | Pending Reboot: Unknown" -ForegroundColor DarkRed
        }

    } catch {Write-Verbose "Exception: $($Error[0])"}

} 






        
        