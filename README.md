<H1> SCCM Agent remove via Proactive Remediations v1.0 </H1> 

Removes SCCM Client via MEM Intune Proactive Remediation.
I used it to move co-managed devices to Intune managed devices in an environment where SCCM was no longer present.

This script is based on the original work from the following sources:

    remove-sccmagent.ps1
    Author: Robert M.
    source: https://github.com/robertomoir/remove-sccm/blob/master/remove-sccmagent.ps1
    
    Remove-ConfigMgrClient.ps1
    Author: Chad Simmons
    Source: https://github.com/ChadSimmons/Scripts/blob/default/ConfigMgr/Troubleshooting/Remove-ConfigMgrClient.ps1
    
    Remove All Traces of Microsoft SCCM w/ PowerShell (By Force)
    Author: James A. chambers
    Source: https://jamesachambers.com/remove-microsoft-sccm-by-force/
    
    SCCM Client Complete Uninstall / Remove + Powershell Script
    Source: https://www.optimizationcore.com/deployment/sccm-client-complete-remove-uninstall-powershell-script/
    
