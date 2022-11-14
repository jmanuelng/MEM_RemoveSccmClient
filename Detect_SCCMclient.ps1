<#

.Description
    Script to detect if there is any trace of SCCM agent.
    Will check for CcmExec service and registry keys for services, SMS Certs and MDM Authority

.Notes
    Source: https://github.com/robertomoir/remove-sccm/blob/master/remove-sccmagent.ps1
    Source: https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/
    Source: https://jamesachambers.com/remove-microsoft-sccm-by-force/
    Source: https://github.com/ChadSimmons/Scripts/blob/default/ConfigMgr/Troubleshooting/Remove-ConfigMgrClient.ps1

#>

#region Settings

$Error.Clear()
$Result = 0
$DetectSummary = ""

#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"

#endregion Settings

#region Functions
Function Test-IfServiceExistExit1 {

    Param
    (
        [string]$ServiceName
    )

    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    If ($null -eq $Service) {
        Write-Host "Service $ServiceName was not found."
    }
    else {

        $Result = 1
        Write-Warning "Service $ServiceName exists."
        if ( -not ($DetectSummary -eq "")) { $DetectSummary += ", "}
        $DetectSummary += "$ServiceName exists"
        
    }
}

Function Test-IfRegKeyExistExit1 {

    Param
    (
        [string]$RegKeyPath
    )

    $RegKey = Get-Item -Path $RegKeyPath -ErrorAction SilentlyContinue
    
    if ($null -eq $RegKey) {

        Write-Host "Registry Key $RegKeyPath was not found."

    }
    else {

        $Result = 1
        Write-Warning "$RegKeyPath exists."
        if ( -not ($DetectSummary -eq "")) { $DetectSummary += ", "}
        $DetectSummary += "$RegKeyPath exists"

    }
}

#endregion Functions


#region Main

#Look for the services related to SCCM client.
$Services = ("CcmExec", "CCMSetup", "smstsmgr", "CmRcService")

foreach ($Serv in $Services) {

    #Verify that services do no exist
    Test-IfServiceExistExit1 $Serv

}

#Verify that all registry keys from SCCM agent do not exist.
$RegServicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$RegSoftwarePath = "HKLM:\SOFTWARE\Microsoft"
$RegSoftwareWowPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft"
$RegSmsCertsPath = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates"
 
$RegServices = (
    "$RegServicesPath\CcmExec",
    "$RegServicesPath\CCMSetup", 
    "$RegServicesPath\smstsmgr", 
    "$RegServicesPath\CmRcService",
    "$RegSoftwarePath\CCM",
    "$RegSoftwarePath\CCMSetup",
    "$RegSoftwarePath\SMS",
    "$RegSoftwarePath\DeviceManageabilityCSP",
    "$RegSoftwareWowPath\CCM",
    "$RegSoftwareWowPath\CCMSetup",
    "$RegSoftwareWowPath\SMS",
    "$RegSmsCertsPath\*"
    )

foreach ($RegService in $RegServices) {

    #Verify that Registry Keys do no exist
    Test-IfRegKeyExistExit1 $RegService

}

#New lines, easier to read Agentexecutor Log file.
Write-Host "`n`n"

#Return result
if ($Result -eq 0) {

    Write-Host "OK $([datetime]::Now) : SCCM not found."
    Exit 0
}
else {
    Write-Host "WARNING $([datetime]::Now) : $DetectSummary"
    Exit 1
}

#endregion Main