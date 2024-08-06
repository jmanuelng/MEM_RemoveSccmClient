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

#region Functions

function Test-IsAdmin {
    <#
    .SYNOPSIS
        Checks if the current user has administrative privileges.

    .DESCRIPTION
        Function determines whether the current user has administrative privileges by attempting to create a new WindowsPrincipal object and checking the IsInRole method for the "Administrator" role. 
        If the check fails, it throws an exception indicating the lack of administrative privileges.

    .EXAMPLE
        Test-IsAdmin
        If the current user has administrative privileges, the function completes without any output. If not, it throws an exception.

    .NOTES
        This function should be called at the beginning of scripts that require administrative privileges to ensure proper execution.

    #>

    try {
        # Create a new WindowsPrincipal object for the current user
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

        # Check if the current user is in the "Administrators" role
        if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "Script needs to run with Administrative privileges."
        }
    } catch {
        throw "Must be run with Administrative priviliges."
    }
}
    
function Stop-WinService {
    <#
    .SYNOPSIS
        Stops a specified Windows service if it exists and is running.

    .DESCRIPTION
        Function checks if a specified Windows service exists and retrieves its status. If the service is running,
        it attempts to stop it. Includes error handling to catch and throw any issues encountered, with specific messages
        for services that do not exist.

    .PARAMETER ServiceName
        The name of the Windows service to stop.

    .EXAMPLE
        Stop-WinService -ServiceName "wuauserv"
        Attempts to stop the Windows Update service if it exists and is running.

    .NOTES
        This function requires administrative privileges to stop Windows services.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    try {
        # Check if the service exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if ($null -eq $service) {
            throw "Service '$ServiceName' does not exist."
        }

        # Check if the service is running
        if ($service.Status -eq 'Running') {
            # Attempt to stop the service
            Write-Host "Stopping service '$ServiceName'..."
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Write-Host "Service '$ServiceName' stopped successfully."
        } else {
            Write-Host "Service '$ServiceName' is not running."
        }
    } catch {
        throw "$_"
    }
}

function Remove-RegKey {
    <#
    .SYNOPSIS
        Deletes a specified registry key and its subkeys.

    .DESCRIPTION
        This function removes a specified registry key from the Windows Registry, including all its subkeys and values.
        It includes error handling to catch and throw any issues encountered during the operation.

    .PARAMETER RegKeyPath
        The path of the registry key to delete.

    .EXAMPLE
        Remove-RegKey -RegKeyPath "HKLM:\SOFTWARE\MyApp"
        Deletes the "MyApp" key and all its subkeys and values from the HKEY_LOCAL_MACHINE\SOFTWARE path.

    .NOTES
        This function requires administrative privileges to modify the Windows Registry.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$RegKeyPath
    )

    try {
        # Check if the registry key exists
        if (Test-Path -Path $RegKeyPath) {
            # Attempt to remove the registry key
            Write-Host "Removing registry key '$RegKeyPath'..."
            Remove-Item -Path $RegKeyPath -Recurse -Force -Confirm:$false -ErrorAction Stop
            Write-Host "Registry key '$RegKeyPath' removed successfully."
        } else {
            Write-Host "Registry key '$RegKeyPath' does not exist."
        }
    } catch {
        throw "Error removing registry key '$RegKeyPath'"
    }
}

function Clear-Files {
    <#
    .SYNOPSIS
        Deletes specified files or folders, including subdirectories, and takes ownership if necessary.

    .DESCRIPTION
        This function iterates through an array of file paths, taking ownership of each file or directory and then deleting it.
        It ensures both files and subdirectories are removed, handling any errors encountered during the process.

    .PARAMETER FilePaths
        An array of file paths to delete. These can be files or directories.

    .EXAMPLE
        $filesToDelete = @("C:\Temp\File1.txt", "C:\Temp\Folder1")
        Clear-Files -FilePaths $filesToDelete

    .NOTES
        This function requires administrative privileges to take ownership and delete files or directories.
    #>
    param (
        [string[]]$FilePaths
    )
    
    foreach ($FilePath in $FilePaths) {
        try {
            # Take ownership of the file or folder
            $null = takeown.exe /F "$FilePath" /R /A /D Y 2>&1
            
            # Delete the file or folder, including subdirectories
            Remove-Item -Path $FilePath -Force -Recurse -ErrorAction Stop
            
            Write-Host "Successfully deleted: $FilePath"
        } catch {
            Write-Host "Error deleting $($FilePath)"
        }
    }
}

function Remove-WmiNamespace {
    <#
    .SYNOPSIS
        Removes a specified WMI namespace.

    .DESCRIPTION
        This function checks if a specified WMI namespace exists and removes it if found. It uses CIM (Common Information Model) cmdlets
        to query and delete the WMI namespace. Errors are handled silently to ensure smooth execution.

    .PARAMETER WmiName
        The name of the WMI namespace to be removed.

    .PARAMETER WmiNameSpace
        The parent namespace where the specified WMI namespace resides.

    .EXAMPLE
        Remove-WmiNamespace -WmiName "ccm" -WmiNameSpace "root\ccm"

    .NOTES
        Ensure the script runs with administrative privileges to modify WMI namespaces.

    .SOURCE
        References:
        - https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1
        - https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-powershell-cim-cmdlets?view=powershell-7.1

    #>
    param (
        [string]$WmiName,
        [string]$WmiNameSpace
    )

    try {
        # Query for the specified WMI namespace
        $WmiRepository = Get-CimInstance -query "SELECT * FROM __Namespace WHERE Name='$WmiName'" -Namespace "$WmiNameSpace" -ErrorAction SilentlyContinue
        
        # Check if the namespace exists
        if ($null -ne $WmiRepository) {
            Write-Host "Found WMI Repository $WmiName, removing..."
            
            # Remove the WMI namespace
            Get-CimInstance -query "SELECT * FROM __Namespace WHERE Name='$WmiName'" -Namespace "$WmiNameSpace" | Remove-CimInstance -Confirm:$false -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "WMI Repository $WmiName not found"
        }
    }
    catch {
        throw "Error udpating WMI namespace."
    }
}


function Verify-SccmClientDelete {
    <#
    .SYNOPSIS
        Verifies the deletion of the SCCM client by checking for the absence of specific services and files.

    .DESCRIPTION
        Checks if the SCCM (System Center Configuration Manager) client has been successfully deleted from the system.
        It does this by verifying the absence of the SCCM client service (`CcmExec`) and the SCCM setup file (`ccmsetup.exe`).
        If neither the service nor the setup file is found, the deletion is considered successful.
        If either the service or the setup file still exists, appropriate warnings are issued, and the function sets an exit code indicating failure.

    .PARAMETER None

    .EXAMPLE
        $exitCode = Verify-SccmClientDelete
        Write-Host "Exit Code: $exitCode"

    .NOTES
        This function requires administrative privileges to check the existence of services and files.
        Ensure that the script is run with appropriate permissions to avoid errors.

    #>
    # Variables to store the SCCM service name and file path
    $SccmService = "CcmExec"
    $SccmFilePath = "$Env:WinDir\ccmsetup\ccmsetup.exe"
    $ExitCode = 0

    try {
        # Attempt to retrieve the SCCM service
        $CCMexecService = Get-Service -Name $SccmService -ErrorAction SilentlyContinue
        # Attempt to retrieve the SCCM setup file
        $CCMexecSetupFile = Get-Item -Path $SccmFilePath -ErrorAction SilentlyContinue

        # Check if both the service and the setup file do not exist
        if (($null -eq $CCMexecService) -and ($null -eq $CCMexecSetupFile)) {
            # SCCM Client deletion confirmed.
            Write-Host "Confirmation. SCCM client service does not exist!"
        }
        else {
            # Check if the SCCM service still exists
            if ($null -ne $CCMexecService) {
                # Set exit code for existing service
                $ExitCode = 90 # 0x431 ERROR_SERVICE_EXISTS / The specified service already exists.
                Write-Warning "Service $CCMexecService still exists, completing with failure $ExitCode"
            }    

            # Check if the SCCM setup file still exists
            if ($null -ne $CCMexecSetupFile) {
                # Set exit code for existing file
                $ExitCode = 91 # The specified file still exists.
                Write-Warning "File $CCMexecSetupFile still exists, completing with failure $ExitCode"
            } 
        }
    }
    catch {
        # Handle any errors that occur during the check
        throw "Error verifying SCCM client deletion."
    }

    # Return the exit code
    return $ExitCode
}

function Start-CompleteIntuneSync {
    <#
    .SYNOPSIS
        Initiates an Intune sync session and verifies its completion through Event Viewer logs.

    .DESCRIPTION
        This function performs an Intune sync by creating and starting an MDM session using Windows.Management.MdmSessionManager.
        It waits for 60 seconds to allow the sync process to initiate. It then checks for specific events in the Event Viewer
        to confirm the sync's start and completion: Looks for events 208 and 209 in the "Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin".
        The function returns the time these events were logged, or "Not found" if the events are not present.

        The Journey: 
        Initial approach used `intunemanagementextension://syncapp` protocol as suggested by Jannik Reinhard's blog (https://jannikreinhard.com/2022/07/31/summary-of-the-intune-management-extension/). However, this method did not yield consistent results across different devices
        Focus then shifted to leveraging the `Windows.Management.MdmSessionManager` class, known for managing Mobile Device Management (MDM) sessions. The use of `[Windows.Management.MdmSessionManager,Windows.Management,ContentType=WindowsRuntime]` to create and start an MDM session was adopted based on documentation and community blogs:
        - https://oofhours.com/2024/03/30/when-does-a-windows-client-sync-with-intune/
 
        Note: There was an initial attempt to use `Add-Type -AssemblyName "Windows.Management"` which resulted in an error indicating the assembly could not be found. This led to the realization that direct referencing and instantiation of the Windows Runtime type was necessary.

    .REFERENCES
        - "Intune Management Extension" by Jannik Reinhard: https://jannikreinhard.com/2022/07/31/summary-of-the-intune-management-extension/
        - "When Does a Windows Client Sync with Intune?" by Michael Niehaus: https://oofhours.com/2024/03/30/when-does-a-windows-client-sync-with-intune/

    .PARAMETER None

    .EXAMPLE
        Start-CompleteIntuneSync

    .NOTES
        This function requires administrative privileges to access Event Viewer logs.
        Make sure to run this script with appropriate permissions.
    #>
    
    # Initialize variables for event checking
    $eventLog = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
    $syncStartEventID = 208
    $syncCompleteEventID = 209
    $syncStartTime = Get-Date

    # Log the start of the sync attempt
    Write-Host "Starting Intune sync at $syncStartTime"

    try {
        # Create and start the MDM session using Windows.Management.MdmSessionManager
        [Windows.Management.MdmSessionManager,Windows.Management,ContentType=WindowsRuntime] > $null
        $session = [Windows.Management.MdmSessionManager]::TryCreateSession()
        $session.StartAsync() | Out-Null

        # Wait for 60 seconds to allow the sync to initiate
        Start-Sleep -Seconds 60

        # Check for the sync start event in Event Viewer
        $syncStartEvent = Get-WinEvent -LogName $eventLog | Where-Object { $_.Id -eq $syncStartEventID -and $_.TimeCreated -ge $syncStartTime }
        if ($syncStartEvent) {
            Write-Host "Sync start event (ID $syncStartEventID) found."
            $syncStartEventTime = $syncStartEvent.TimeCreated
        } else {
            Write-Host "Sync start event (ID $syncStartEventID) not found."
            $syncStartEventTime = "Not found"
        }

        # Check for the sync complete event in Event Viewer
        $syncCompleteEvent = Get-WinEvent -LogName $eventLog | Where-Object { $_.Id -eq $syncCompleteEventID -and $_.TimeCreated -ge $syncStartTime }
        if ($syncCompleteEvent) {
            Write-Host "Sync complete event (ID $syncCompleteEventID) found."
            $syncCompleteEventTime = $syncCompleteEvent.TimeCreated
        } else {
            Write-Host "Sync complete event (ID $syncCompleteEventID) not found."
            $syncCompleteEventTime = "Not found"
        }

        # Return details of the sync process
        return @{
            SyncStartEvent = $syncStartEventTime
            SyncCompleteEvent = $syncCompleteEventTime
            SyncStartTime = $syncStartTime
        }
    } catch {
        throw "Error during Intune sync process. "
    }
}

function WriteAndExitWithSummary {
    <#
    .SYNOPSIS
        Writes a summary of the script's execution to the console and then exits the script with a specified status code.

    .DESCRIPTION
        The function takes a status code and a summary string as parameters. It writes the summary along with the current date and time to the console using Write-Host. 
        After writing the summary, it exits the script with the given status code. If the given status code is below 0 (negative) it changes exit status code to 0.

    .PARAMETER StatusCode
        The exit status code to be used when exiting the script. 
        0: OK
        1: FAIL
        Other: WARNING

    .PARAMETER Summary
        The summary string that describes the script's execution status. This will be written to the console.

    .EXAMPLE
        WriteAndExitWithSummary -StatusCode 0 -Summary "All operations completed successfully."

    .EXAMPLE
        WriteAndExitWithSummary -StatusCode 1 -Summary "Error: SCCM client removal failed."

    .NOTES
        Last Modified: August 27, 2023
        Author: Manuel Nieto
    #>

    param (
        [int]$StatusCode,
        [string]$Summary
    )
    
    # Combine the summary with the current date and time.
    $finalSummary = "$([datetime]::Now) = $Summary"
    
    # Determine the prefix based on the status code.
    $prefix = switch ($StatusCode) {
        0 { "OK" }
        1 { "FAIL" }
        default { "WARNING" }
    }
    
    # Easier to read in log file
    Write-Host "`n`n"

    # Write the final summary to the console.
    Write-Host "$prefix $finalSummary"
    
    # Easier to read in log file
    Write-Host "`n`n"

    # Exit the script with the given status code.
    if ($StatusCode -lt 0) {$StatusCode = 0}
    Exit $StatusCode
}

#endregion

#region Main

# Initialize
$Error.Clear()                                  # Clear any previous errors.
$t = Get-Date                                   # Get current date and time.
$CCMpath = "$Env:WinDir\ccmsetup\ccmsetup.exe"  # Path to SCCM setup executable.
$verifyBeginResult                              # Variable to store beginning SCCM verification result.
$verifyEndResult                                # Variable to store ending SCCM verification result.
$summary = ""                                   # Initialize summary string.
$StatusCode = 0                                 # Initialize status code to zero.

# New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"
#Log start time.
Write-Host "SCCM Agent cleanup start time: $t"

try {
    #Test Admin rights
    Test-IsAdmin

    # Confirm if SCCM client is present.
    $verifyBeginResult = Verify-SccmClientDelete

    # Only execute if we have confirmation that SCCM client exists.
    if ($verifyBeginResult -gt 0) {

        # Stopping SCCM services.
        try {
            #Stop SCCM services.
            Stop-WinService CcmExec
            Stop-WinService ccmsetup
            Stop-WinService smstsmgr
            Stop-WinService CmRcService
            $summary += "SCCM services stopped. "
        } catch {
            $summary += "Error stopping SCCM services: $_ "
            $StatusCode = -2
        }

        # Remove SCCM client.
        try {
            # Remove SCCM client.
            if (Test-Path $CCMpath) {
                Write-Host "Found $CCMpath, Uninstalling SCCM agent. `n"
                #Start Uninstall, Included -WorkingDirectory to Start-Process cmdlet as Workaround to error when working directory has characters "[" "]"
                Start-Process -WorkingDirectory $Env:WinDir -FilePath $CCMpath -ArgumentList "/uninstall" -Wait -NoNewWindow
                # wait for exit
                $CCMProcess = Get-Process ccmsetup -ErrorAction SilentlyContinue
                try {
                    $CCMProcess.WaitForExit()
                } catch {}
                $summary += "SCCM client removed. "
            }
            else {
                $summary += "SCCM client not found. "
            }
        } catch {
            $summary += "Error removing SCCM client. "
            $StatusCode = -2
        }
        
        # Removing services from registry
        try {
            # Remove Services from Registry.
            $CurrentPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
            Remove-RegKey "$CurrentPath\CcmExec"
            Remove-RegKey "$CurrentPath\CCMSetup"
            Remove-RegKey "$CurrentPath\smstsmgr"
            Remove-RegKey "$CurrentPath\CmRcService"
            $summary += "SCCM services removed from registry. "
        } catch {
            $summary += "Error removing SCCM services from registry: $_. "
            $StatusCode = -2
        }

        try {
            # Remove SCCM Client from Registry
            $CurrentPath = "HKLM:\SOFTWARE\Microsoft"
            Remove-RegKey "$CurrentPath\CCM"
            Remove-RegKey "$CurrentPath\CCMSetup"
            Remove-RegKey "$CurrentPath\SMS"
            $CurrentPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft"
            Remove-RegKey "$CurrentPath\CCM"
            Remove-RegKey "$CurrentPath\CCMSetup"
            Remove-RegKey "$CurrentPath\SMS"
            $summary += "SCCM client registry keys removed. "
        } catch {
            $summary += "Error removing SCCM client registry keys: $_. "
            $StatusCode = -2
        }

        try {
            # Remove WMI Namespaces
            Remove-WmiNamespace "ccm" "root"
            Remove-WmiNamespace "sms" "root\cimv2"
            $summary += "SCCM WMI namespaces removed. "
        } catch {
            $summary += "Error removing SCCM WMI namespaces: $_. "
            $StatusCode = -2
        }

        try {
            # Reset MDM Authority
            Write-Host "MDM Authority, reviewing and deleting registry key if necessary"
            $CurrentPath = "HKLM:\SOFTWARE\Microsoft"
            Remove-RegKey "$CurrentPath\DeviceManageabilityCSP"
            $summary += "MDM authority reset. "
        } catch {
            $summary += "Error resetting MDM authority. "
            $StatusCode = -2
        }

        try {
            # Remove Folders and Files
            $CurrentPath = "$Env:WinDir"
            Clear-Files "$CurrentPath\CCM"
            Clear-Files "$CurrentPath\ccmsetup"
            Clear-Files "$CurrentPath\ccmcache"
            Clear-Files "$CurrentPath\SMSCFG.ini"
            Clear-Files "$CurrentPath\SMS*.mif"
            $summary += "SCCM related files and folders removed. "
        } catch {
            $summary += "Error removing SCCM files and folders: $_. "
            $StatusCode = -2
        }

        try {
            # Remove SCCM certificates
            $CurrentPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates"
            Remove-RegKey "$CurrentPath\*"
            $summary += "SCCM certificates removed. "
        } catch {
            $summary += "Error removing SCCM certificates: $_. "
            $StatusCode = -2
        }

        try {
            # Confirm if SCCM client was removed.
            $verifyEndResult = Verify-SccmClientDelete
            if ($verifyEndResult -eq 0) {
                $summary += "SCCM client removal verified. "
            } else {
                $StatusCode = $verifyEndResult
                $summary += "SCCM client removal failed with code $verifyEndResult. "
            }
        } catch {
            $summary += "Error verifying SCCM client removal: $_. "
            $StatusCode = -2
        }

    }

}
catch {
    # Log error and set status code to failure
    $summary += "Execution Error: $_ "
    $StatusCode = 1
}

# Perform Intune sync and log the result. Only if no errors.
if ($StatusCode -le 0) {
    try {
        $syncDetails = Start-CompleteIntuneSync
        $summary += "Intune sync request: $($syncDetails.SyncStartTime), Start: $($syncDetails.SyncStartEvent), Completed: $($syncDetails.SyncCompleteEvent). "
    } catch {
        $summary += "Error during Intune sync. "
    }
}

# Write the summary and exit with the appropriate status code
WriteAndExitWithSummary -StatusCode $StatusCode -Summary $summary

#Finished!

#endregion
