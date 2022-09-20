<#

.Description
    Script to remove SCCM agent from PCs

    Completly based on James Chambers and Chad Simmons powershell scripts to remove the SCCM agent.
    Updated with other scripts and testing. 

    $ccmpath is path to SCCM Agent's own uninstall routine.

.Notes

    Script created or based on the following:

    Source: https://github.com/robertomoir/remove-sccm/blob/master/remove-sccmagent.ps1
    Source: https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/
    Source: https://jamesachambers.com/remove-microsoft-sccm-by-force/
    Source: https://github.com/ChadSimmons/Scripts/blob/default/ConfigMgr/Troubleshooting/Remove-ConfigMgrClient.ps1

#>

#region Settings

$Error.Clear()
$t = Get-Date
$CCMpath = "$Env:WinDir\ccmsetup\ccmsetup.exe"

#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"
#Log start time.
Write-Output "SCCM Agent cleanup start time: $t"

#endregion

#region Functions
Function Test-IsAdmin {

    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

        # Does not have Admin privileges
        Write-Host "Script need to run with Administrative privileges"
        Exit 9

    }
    else {

        #Has Admin rights
        Write-Host "Adminitrator rights have been confirmed"
    
    }
    
}
    
Function Stop-WinService {
    Param
    (
        [string]$ServiceName
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceprocess = Get-Process -Name $ServiceName -ErrorAction SilentlyContinue
        $service
        if ($null -ne $service) {
            Write-Host "Service $ServiceName found, stopping... `r`n"
            
            #Stop the service
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            
            #Wait for services to exit.
            if ($null -ne $serviceprocess) {
                $serviceprocess.WaitForExit()
            }

        }
        else {
            Write-Host "Service $ServiceName not found"
        }
    }
    catch {
        throw $_
        Exit 1
    }
}

Function Remove-RegKey {
    Param
    (
        [string]$RegKeyPath
    )

    try {
        $RegKey = Get-Item -Path $RegKeyPath -ErrorAction SilentlyContinue
        if ($null -ne $RegKey) {
            Write-Host "Found Registry Path $RegKeyPath, deleting..."
            #Delete Registry Path
            Remove-Item -Path $RegKeyPath -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "Registry Path $RegKeyPath not found"
        }
    }
    catch {
        throw $_
        Exit 1
    }
}

Function Clear-Files {
    Param
    (
        [string]$FilePath
    )

    try {
        $Files = Get-Item -Path $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $Files) {
            Write-Host "Found File or Folder $FilePath, deleting..."
            #Delete File or Folder
            $null = takeown.exe /F "$FilePath" /R /A /D Y 2>&1
            Remove-Item -Path $FilePath -Force -Recurse -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "File or Folder $FilePath not found"
        }
    }
    catch {
        throw $_
        Exit 1
    }
}

Function Remove-WmiNamespace {
    Param
    (
        [string]$WmiName,
        [string]$WmiNameSpace
    )

    try {
        $WmiRepository = Get-CimInstance -query "SELECT * FROM __Namespace WHERE Name='$WmiName'" -Namespace "$WmiNameSpace" -ErrorAction SilentlyContinue
        if ($null -ne $WmiRepository) {
            Write-Host "Found WMI Repository $WmiName, removing..."
            #Remove WMI Repository
            Get-CimInstance -query "SELECT * FROM __Namespace WHERE Name='$WmiName'" -Namespace "$WmiNameSpace" | Remove-CimInstance -Confirm:$false
        }
        else {
            Write-Host "WMI Repository $WmiName not found"
        }
    }
    catch {
        throw $_
        Exit 1
    }
}

Function Verify-SccmClientDelete {
    
    $SccmService = "CcmExec"
    $SccmFilePath = "$Env:WinDir\ccmsetup\ccmsetup.exe"
    $ExitCode = 0

    try {
        $CCMexecService = Get-Service -Name $SccmService -ErrorAction SilentlyContinue
        $CCMexecSetupFile = Get-Item -Path $SccmFilePath -ErrorAction SilentlyContinue

        if (($null -eq $CCMexecService) -and ($null -eq $CCMexecSetupFile)) {
            
            #SCCM Client deletion confirmed.
            Write-Host "Confirmation. SCCM client service does not exist!"
            #Sync to Intune.
            Sync-Intune

        }
        Else {

            if ($null -ne $CCMexecService) {

                $ExitCode = 90 #0x431 ERROR_SERVICE_EXISTS / The specified service already exists.
                Write-Warning "Service $CCMexecService still exists, completing with failure $ExitCode"
    
            }    

            if ($null -ne $CCMexecSetupFile) {

                $ExitCode = 91 # The specified file still exists.
                Write-Warning "File $CCMexecSetupFile, completing with failure $ExitCode"
    
            } 

        }
    }
    catch {
        throw $_
        Exit 1
    }
}

Function Sync-Intune {

    try {
          
        #Look for Intune Sync ScheduledTask
        $MEMSyncTask = Get-ScheduledTask | where-object TaskName -like '*OMADMClient by client*' -ErrorAction SilentlyContinue

        if ($null -ne $MEMSyncTask) {

            #Found Intune Sync ScheduledTask
            Write-Host "`nFound ScheduledTask for IntuneSync: $($MEMSyncTask.TaskName)"

            #Get info from last run
            $ScheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $MEMSyncTask.TaskName -TaskPath $MEMSyncTask.TaskPath -ErrorAction SilentlyContinue
            #Get current time
            Write-Host "Previous run time: $($ScheduledTaskInfo.LastRunTime)"
            Write-Host "Result from previous run: $($ScheduledTaskInfo.LastTaskResult)"

            #Execute ScheduledTask
            Write-Host "Starting Scheduled Task for Intune Sync: $($MEMSyncTask.TaskName)"
            Start-ScheduledTask -TaskName $MEMSyncTask.TaskName -TaskPath $MEMSyncTask.TaskPath -ErrorAction SilentlyContinue

            #Wait 1 sec, get run result
            Start-Sleep -Seconds 3
            $ScheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $MEMSyncTask.TaskName -TaskPath $MEMSyncTask.TaskPath -ErrorAction SilentlyContinue
            Write-Host "Task execution time: $($ScheduledTaskInfo.LastRunTime)"
            Write-Host "Task execution result: $($ScheduledTaskInfo.LastTaskResult)"

        }

        else {
            Write-Host "`nDidn't find Scheduled Task to execute Intune Sync."
        }
        
    }
    catch {
        throw $_
        Exit 1
    }
}

#endregion

#region Main

#Test Admin rights
Test-IsAdmin

#Stop SCCM services.
Stop-WinService CcmExec
Stop-WinService ccmsetup
Stop-WinService smstsmgr
Stop-WinService CmRcService

# Remove SCCM client.
if (Test-Path $CCMpath) {

    Write-Host "Found $CCMpath, Uninstalling SCCM agent. `n"
    Start-Process -FilePath $CCMpath -ArgumentList "/uninstall" -Wait -NoNewWindow
    
    # wait for exit
    $CCMProcess = Get-Process ccmsetup -ErrorAction SilentlyContinue
    try{
        $CCMProcess.WaitForExit()
    }
    catch{
    }
}
 
# Remove Services from Registry.
# Set $CurrentPath to services registry keys
$CurrentPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
Remove-RegKey "$CurrentPath\CcmExec"
Remove-RegKey "$CurrentPath\CCMSetup"
Remove-RegKey "$CurrentPath\smstsmgr"
Remove-RegKey "$CurrentPath\CmRcService"

# Remove SCCM Client from Registry
# Update $CurrentPath to HKLM/Software/Microsoft
$CurrentPath = "HKLM:\SOFTWARE\Microsoft"
Remove-RegKey "$CurrentPath\CCM"
Remove-RegKey "$CurrentPath\CCMSetup"
Remove-RegKey "$CurrentPath\SMS"
$CurrentPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft"
Remove-RegKey "$CurrentPath\CCM"
Remove-RegKey "$CurrentPath\CCMSetup"
Remove-RegKey "$CurrentPath\SMS"

# Remove WMI Namespaces
Remove-WmiNamespace "ccm" "root"
Remove-WmiNamespace "sms" "root\cimv2"

# Reset MDM Authority
# Removing HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DeviceManageabilityCSP
Write-Host "MDM Authority, reviewing and deleting registry key if necessary"
$CurrentPath = "HKLM:\SOFTWARE\Microsoft"
Remove-RegKey "$CurrentPath\DeviceManageabilityCSP"


# Remove Folders and Files
# Tidy up garbage in Windows folder
$CurrentPath = "$Env:WinDir"
Clear-Files "$CurrentPath\CCM"
Clear-Files "$CurrentPath\ccmsetup"
Clear-Files "$CurrentPath\ccmcache"
Clear-Files "$CurrentPath\SMSCFG.ini"
Clear-Files "$CurrentPath\SMS*.mif"

#Remove SCCM certificates
$CurrentPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates"
Remove-RegKey "$CurrentPath\*"

#Check to confirm if SCCM client was removed.
Verify-SccmClientDelete

#Log SCCM client cleanup end time.
$t = Get-Date
Write-Output "SCCM Agent cleanup finish time: $t"

#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"

#Finished!
Exit 0

#endregion
