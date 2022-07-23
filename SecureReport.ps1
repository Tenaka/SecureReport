<#
.Synopsis
Check for common and known security vulnerabilities and create an html report based on the findings

.DESCRIPTION

The report is saved to C:\Securereport\FinishedReport.htm

Before everyone gets critical regarding the script formatting, some are due to how ConvertTo-HTML expects the data, most are to help those that aren’t familiar with scripting. There is a conscious decision not to use aliases or abbreviations and where possible to create variables. 

#List of checks and balances:
Host Details, CPU, Bios, Windows Version
Accounts, Groups and Password Policy
Install Applications and installed Windows Updates
Virtualization, UEFI, Secure Boot, DMA, TPM and Bitlocker Settings
LSA, DLL Safe Search Order, Hypervisor Code Integrity
Autologon Credentials in the Registry
Unquoted paths
Processes that contain passwords in the command line
Enabled legacy Network protocols
Registry Keys with weak Permissions
System Folders with weak Permissions
Firewall settings and rules
Schedules Tasks
Files with hash mismatch
Driver Query for unsigned drivers
Shares and permissions

#TPM and Bitlocker
"TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM.
Further information can be found @
https://www.tenaka.net/bitlocker

#Secure Boot
Secure Boot is a security standard to ensure only trusted OEM software is allowed at boot. At startup, the UEFi and boot software's digital signatures are validated preventing rootkits
More on Secure Boot can be found @
https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF

#VBS
Virtualization-based security (VBS), isolates core system resources to create secure regions of memory. Enabling VBS allows for Hypervisor-Enforced Code Integrity (HVCI), Device Guard and Credential Guard.
Further information can be found @
https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs
https://www.tenaka.net/deviceguard-vs-rce
https://www.tenaka.net/pass-the-hash 
​
#Hypervisor Enforced Code Integrity
Hypervisor Enforced Code Integrity prevents the loading of unsigned kernel-mode drivers and system binaries from being loaded into system memory.
Further information can be found @  
https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity

#Security Options
Prevent credential relay with Impacket and Man in the Middle by Digitally Signing for SMB and LDAP connections enforcement.
Further information can be found @
https://www.tenaka.net/smb-relay-attack

#LSA
Enabling RunAsPPL for LSA Protection allows only digitally signed binaries to load as a protected process preventing credential theft and access by code injection and memory access by processes that aren’t signed.
Further information can be found @ https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

#DLL Safe Search
When applications do not fully qualify the DLL path and instead allow searching the default behaviour is for the ‘Current Working Directory’ to be called, then system paths. This allows an easy route to call malicious DLL’s. Setting ‘DLL Safe Search’ mitigates the risk by moving CWD to later in the search order.
Further information can be found @
https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

#DLL Hijacking (Permissions)
DLL Hijacking is when a malicious dll replaces a legitimate dll due to a path vulnerability. A program or service makes a call on that dll gaining the privileges of that program or service. Additionally missing dll’s presents a risk where a malicious dll is dropped into a path where no current dll exists but the program or service is making a call to that non-existent dll.
This audit is reliant on programs being launched so that DLL’s are loaded. Each process’s loaded dll’s are checked for permissions issues and whether they are signed.  
The DLL hijacking audit does not currently check for missing dll’s being called. Process Monitor filtered for ‘NAME NOT FOUND’ and path ends with ‘DLL’ will.


#Automatically Elevate User
Auto Elevate User is a setting that elevates users allowing them to install software without being an administrator. 

#Password in Files
Searches the following locations:
C:\Users\
C:\ProgramData\
C:\Windows\System32\Tasks\
C:\Windows\Panther\
C:\Windows\system32\
C:\Windows\system32\sysprep

Searches the following file extensions:
txt, ini, .xml

For the following words:
password, credential

Ignore these files as they contain the word 'Password' by default:
C:\Windows\system32\NarratorControlTemplates.xml
C:\Windows\system32\DDFs\NGCProDDF_v1.2_final.xml
C:\Windows\system32\icsxml\ipcfg.xml
C:\Windows\system32\icsxml\pppcfg.xml
C:\Windows\system32\slmgr\0409\slmgr.ini
C:\Windows\system32\winrm\0409\winrm.ini

#Passwords in the Registry
Searches HKLM and HKCU for the words 'password' and 'passwd', then displays the password value in the report. 
The search will work with VNC encrypted passwords stored in the registry, from Kali run the following command to decrypt

echo -n PasswordHere | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

​
#Password embedded in Processes
Processes that contain credentials to authenticate and access applications. Launching Task Manager, Details and add ‘Command line’ to the view.
​
#AutoLogon
Checks "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" for any clear text credentials remaining from a MECM\SCCM\MDT deployment.

#Unquoted
The Unquoted Path vulnerability is when a Windows Service's 'Path to Executable' contains spaces and is not wrapped in double-quotes providing a route to System.
Further information can be found @
https://www.tenaka.net/unquotedpaths

#Legacy Network Protocols
LLMNR and other legacy network protocols can be used to steal password hashes.
Further information can be found @
https://www.tenaka.net/responder

#Permissions Weakness in Default System Directories - Write
System default Folders that allow a User the Write permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.

Searches:
C:\PerfLogs
C:\Program Files
C:\Program Files (x86)
C:\Windows

Expected folders that a user can Write to:
C:\Windows\System32\LogFiles\WMI
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\Tasks
C:\Windows\System32\Tasks\Microsoft\Windows\RemoteApp and Desktop Connections Update
C:\Windows\SysWOW64\Tasks
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\RemoteApp and Desktop Connections Update
C:\Windows\tracing

Further information can be found @
https://www.tenaka.net/unquotedpaths
https://www.tenaka.net/applockergpo

#Permissions Weakness in Default System Directories - Create Files
System default Folders that allow a User the CreateFile permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.

Expected folders that a user can CreateFiles to:
C:\Windows\PLA\Reports
C:\Windows\PLA\Reports\en-GB
C:\Windows\PLA\Reports\en-US
C:\Windows\PLA\RulesC:\Windows\PLA\Rules\en-GB
C:\Windows\PLA\Rules\en-US
C:\Windows\PLA\Templates
C:\Windows\Registration\CRMLog
C:\Windows\System32\Com\dmp
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\SysWOW64\Com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
C:\Windows\TasksC:\Windows\Temp
C:\Windows\Temp\MsEdgeCrashpad
C:\Windows\Temp\MsEdgeCrashpad\reports

Further information can be found @
https://www.tenaka.net/unquotedpaths
https://www.tenaka.net/applockergpo

#Permissions weaknesses in Non-Default Directories
A vulnerability exists when enterprise software has been installed on the root of C:\. The default permissions allow a user to replace approved software binaries with malicious binaries.
Further information can be found @
https://www.tenaka.net/unquotedpaths

#Files that are Writeable
System files that allow users to write can be swapped out for malicious software binaries.

Further information can be found @
https://www.tenaka.net/unquotedpaths

#Firewalls
Firewalls should always block inbound and exceptions should be to a named IP and Port.

Further information can be found @
https://www.tenaka.net/whyhbfirewallsneeded

#Scheduled Tasks
Checks for Scheduled Tasks excluding any that reference System32 as a directory. 
These potential user-created tasks are checked for scripts and their directory permissions are validated. 
No user should be allowed to access the script and make amendments, this is a privilege escalation route.

Checks for encoded scripts, PowerShell or exe's that make calls off box or run within Task Scheduler.

#Shares
Finds all shares and reports on share permissions
Does not show IPC$ and permissions due to access issues.

#Driver Query Signing
All Drivers should be signed with a digital signature to verify the integrity of the packages. 64bit kernel Mode drivers must be signed without exception

#Authenticode Hash Mismatch
Checks that digitally signed files have a valid and trusted hash. If any Hash Mis-Matches then the file could have been altered
  
.VERSION
YYMMDD
211221.1 - Added Security Options
211222.1 - Changed f$.Replace  | Out-File $Report to Foreach {$_ -replace "",""}
211222.2 - Added Warning to be RED with a replace and set-content
211223.1 - Added -postContent with explanations
211223.2 - Bitlocker fixed null response
211229.1 - Added explanations and changed colour
211229.2 - Added .xml in Password in file search added further excluded directories due to the number of false-positive being returned
211230.1 - Restored search for folder weaknesses in C:\Windows
211230.2 - Added CreateFiles Audit - hashed out until testing is complete
220107.1 - Corrected Legacy Network Netbios, incorrectly showing a warning despite being the correct setting.
220107.2 - The report file name is dated
220120.1 - Office 2016 and older plus updates that create keys in Uninstall hive. 
           This is required to correctly report on legacy apps and to cover how MS is making reporting of installed updates really difficult.
220202.1 - Fixed issue with hardcode the name of the script during id of PS or ISE
220203.1 - Added error actions
220203.2 - Warning about errors generated during the report run.
220204.1 - Added Dark and Light colour themes.
220207.1 - Fixed VBS and MSInfo32 formatting issues. 
220208.1 - Added start and finish warning for each section to provide some feedback
220208.2 - Fixed the file\folder parsing loops, including processing that should have been completed after the loops had finished
220211.1 - Added Scheduled task audit looking for embedded code.
220211.2 - Added < hash hash > to comment out the folder audits.
220214.1 - Added Driver Query
220214.1 - Temporary fix to scheduled task where multiple triggers or action breaks the html output
220215.1 - Report on shares and their permissions
220216.1 - Fixed Schedule task reporting to show multiple arguments and actions 
220218.1 - Added Autenticode Signature Hash Mis-Match (Long running process, will be optional, unhash section to enable )
220222.1 - Embedded passwords reworked to be more efficient 
220224.1 - General cleanup of spacing and formatting purely aesthetic
220228.1 - Multi drive support for Folder and File permission and password audits
220411.1 - Added "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" to list x86 install applications
220604.1 - Added Root of drive for permission check Non System Folders
220604.2 - Added | where {$_.displayroot -notlike "*\\*"} to get drive letters and not mounted shares
220605.1 - Added loaded dll hijacking vulnerability scanner
220605.2 - Added READ-HOSTS to prompt to run slow processes.
220606.1 - Added DLL hijacking for dlls not signed and where the user can write.
220606.2 - Tidy up and formatting of script
220607.1 - Password within file search $fragFilePass=@() moved to outside loop as it was dropping previous drives and data
220708.1 - Added depth to Folder and File search to give option to speed up search
220708.2 - Moved DLL not signed and user access, update to Folder search, not an option to run or not
220708.3 - Added filters to Folder and File search to skip winSXS and LCU folders, time consuming and pointless  - Improves preformance 
220708.4 - DLL not signed and user access, wrong setting on filter and excluded the files I'm looking for.
220708.5 - Changed 'where' clause for excluding folder to $_.fullName -match
220708.6 - Added ProgramData to folder checks as performance will allow it
220708.7 - Added Windows directory to check for writeable files. 
220708.8 - Updated Authenticode to exclude winSxS and LCU directories - Improves preformance 
220708.9 - Default System Folder check was returning wrong data, updated the directory listing where statement
220709.1 - Added Credential Guard support
220709.2 - Added LAPS support
220711.1 - Added URA Support - uses SecEdit, extracts Rights Assignments and then maps GUID's to User or Group Name
220711.2 - Updated the description tags and added line separators <br>.
220712.1 - Updated the out-file format for the URA
220712.2 - Created if based on Folder audit, if not then the following vars wont be passed to the report, part of the prettification of the output
           $fragwFile           $frag_wFile           
           $fragReg             $frag_SysRegPerms     
           $fragwFold           $frag_wFolders        
           $fragsysFold         $frag_SysFolders      
           $fragcreateSysFold   $frag_CreateSysFold   
           $fragDllNotSigned    $frag_DllNotSigned    
           $fragAuthCodeSig     $frag_AuthCodeSig  
220712.3 - Added Grey Theme  
220713.1 - Added warning for Powershell verison 4 - Win8\2012\2012 R2 - The Get-childitem -depth is not supported - generates a sea of red. Script generates report minus the file,folder,reg audit data.         
220715.1 - Fixed issue with URA, Debug was missed off the list.  
220716.1 - Updated Reg Search from -notlike to match   
220718.1 - Added Filter to remove null content so its not displayed in the final report
220718.2 - Added Passwords embedded in the Registry  
220719.1 - Added ASR    
220719.2 - Added WDigest   
220720.1 - Added whoami groups 
220720.2 - Added whoami privs
220720.3 - Fixed issue with Host Details
220721.1 - Updated warning message to include URA
220721.2 - Updated local accounts to warn when enabled, Groups will warn on DA, EA and Schema Admin
220721.3 - Adding support for MS Recommended Sec settings
220722.1 - Adding support for MS Recommended Sec settings 
220723.1 - Adding support for MS Recommended Sec settings
220723.2 - Fixed misconfig in Security Options for 4 and 10. added Windows 2000 strong encryption
220723.3 - Added Kerberos encryption types to Security Options

#>

#Remove any DVD from client
$drv = (psdrive | where{$_.Free -eq 0})

if($drv.free -eq "0" -and $_.name -ne "C")
    {
        Write-Host "Eject DVD and try again"
    }
 
#Confirm for elevated admin
    if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        Write-Host "An elevated administrator account is required to run this script." -ForegroundColor Red
    }
else
{
    #Enable detection of PowerShell or ISE, enable to run from both
    #Script name has been defined and must be saved as that name.
    $VulnReport = "C:\SecureReport"
    
    if($psise -ne $null)
    {
        $ISEPath = $psise.CurrentFile.FullPath
        $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
        $ISEWork = $ISEPath.TrimEnd("$ISEDisp")
        New-Item -Path C:\SecureReport -ItemType Directory -Force
    }
    else
    {
        $PSWork = split-path -parent $MyInvocation.MyCommand.Path
        New-Item -Path C:\SecureReport -ItemType Directory -Force
    }

function reports
{
    $psver4 = $psversiontable.PSVersion 
    if ($psver4 -le "4.0")
    {
    write-host " " 
    Write-Host "PowerShell version 4 is installed (Windows8.1\Server 2012 R2), the Get-ChildItem -Depth is not supported, don't waste your time selecting audit Files, Folders and Registry for permissions issues" -ForegroundColor Red
    write-host " "
    }

    #Start Message
    Write-Host " "
    Write-Host "The report requires at least 30 minutes to run, depending on hardware and amount of data on the system, it could take much longer"  -ForegroundColor Yellow
    Write-Host " "
    Write-Host "Ignore any errors or red messages its due to Administrator being denied access to parts of the file system." -ForegroundColor Yellow
    Write-Host " "
    Write-Host "Some audits take a long time to complete and do not output progress as this adds to the time taken." -ForegroundColor Yellow
    Write-Host " "
    Write-Host "READ ME - To audit for Dll Hijacking vulnerabilities applications and services must be active, launch programs before continuing." -ForegroundColor Yellow
    Write-Host " "

    $Scheme = Read-Host "Type either Tenaka, Dark, Grey or Light for choice of colour schemes" 

    $folders = Read-Host "Long running audit - Do you want to audit Files, Folders and Registry for permissions issues....type `"Y`" to audit, any other key for no"

    if ($folders -eq "Y") {$depth = Read-Host "What depth do you wish the folders to be auditied, the higher the number the slower the audit, recommended is 2"}

    $authenticode = Read-Host "Long running audit - Do you want to check that digitally signed files are valid with a trusted hash....type `"Y`" to audit, any other key for no"

################################################
#################  BITLOCKER  ##################
################################################
Write-Host " "
Write-Host "Auditing Bitlocker" -foregroundColor Green
sleep 5

    #Bitlocker Details
    $fragBitLocker=@()
    $getBit = Get-BitLockerVolume -MountPoint C: | Select-Object * -ErrorAction SilentlyContinue
    $GetTPM = Get-Tpm -ErrorAction SilentlyContinue

    $BitMP = $getBit.MountPoint
    $BitEM = $getBit.EncryptionMethod
    $BitKP = $getBit.KeyProtector -Replace("{","") -replace("}","")
    $bitKPJ = $BitKP[0] +","+ $BitKP[1]+","+ $BitKP[2]
    $bitVS = $getBit.VolumeStatus
    $bitPS = $getBit.ProtectionStatus

    #TPM Details
    $TPMPres = $GetTPM.TpmPresent
    $TPMEn = $GetTPM.TpmEnabled
    $TPMVer = $GetTPM.ManufacturerVersion
    $TPMSpec = wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get specversion 
    $TPMSpecVer = $TPMSpec[2]

    if ($bitVS -eq "FullyEncrypted")
    {
        $newObjBit = New-Object psObject
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name MountPoint -Value $BitMP
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name EncryptionMethod -Value $BitEM
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name KeyProtector  -Value $BitKPJ
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name VolumeStatus -Value $bitVS
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name TPMPresent -Value $TPMPres
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name TPMEnabled  -Value $TPMEn
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name TPMManufacVersion -Value $TPMVer
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name TPMSpecVersion -Value $TPMSpecVer
        $fragBitLocker += $newObjBit
    }
    Else
    { 
        $BitDisabled = "Warning - Bitlocker is disabled Warning"
        $newObjBit = New-Object psObject
        Add-Member -InputObject $newObjBit -Type NoteProperty -Name BitLockerDisabled -Value $BitDisabled
        $fragBitLocker += $newObjBit
    }

Write-Host " "
Write-Host "Completed Bitlocker Audit" -foregroundColor Green
################################################
################  OS DETAILS  ##################
################################################
Write-Host " "
Write-Host "Gathering Host and Account Details" -foregroundColor Green
sleep 5

    #OS Details
    $fragHost = Get-CimInstance -ClassName win32_computersystem 
    $OS = Get-CimInstance -ClassName win32_operatingsystem 
    $bios = Get-CimInstance -ClassName win32_bios
    $cpu = Get-CimInstance -ClassName win32_processor

################################################
##############  ACCOUNT DETAILS  ###############
################################################
    #Pasword Policy
    cd C:\
    $getPWPol = & net accounts
    $PassPol=@()
    foreach ($PWPol in $getPWPol)
    {
        $PWName = $PWPol.split(":")[0]
        $PWSet = $PWPol.split(":")[1]

        $newObjPassPol = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjPassPol -Type NoteProperty -Name PasswordPolicy -Value $PWName
        Add-Member -InputObject $newObjPassPol -Type NoteProperty -Name Value -Value $PWSet
        $PassPol += $newObjPassPol
    }
    #Accounts
    $getAcc = Get-LocalUser
    $AccountDetails=@()
    
    foreach ($AccName in $getAcc.name)
    {
        $accounts = Get-LocalUser $AccName
        $accName = $accounts.name
        $accEnabled = $accounts.Enabled
            if ($accEnabled -eq $true)
            {
            $accEnabled = "Warning - Enabled Warning"
            } 
        $accLastLogon = $accounts.LastLogon
        $accLastPass = $accounts.PasswordLastSet
        $accPassExpired = $accounts.PasswordExpires
        $accSource = $accounts.PrincipalSource

        $newObjAccount = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name AccountName -Value $accName
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name IsAccountEnabled -Value $accEnabled
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name AccountLastLogon -Value $accLastLogon
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name AccountLastPassChange -Value $accLastPass
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name AccountExpiresOn -Value $accPassExpired
        Add-Member -InputObject $newObjAccount -Type NoteProperty -Name AccountSource -Value $accSource
        $AccountDetails += $newObjAccount
    }

#Group Members
#Cant remove "," as looping the Split breaks HTML import...back to drawing board - to fix
    $getLGrp = Get-LocalGroup 
    $GroupDetails=@()
    foreach ($LGpItem in $getLGrp)
    {
        $grpName = $LGpItem.Name 
        $grpMember = Get-LocalGroupMember -Group $LGpItem.ToString()
        $grpMemSplit = $grpMember -split(",") -replace("{","") -replace("}","")
        $grpMemAdd = $grpMemSplit[0] +","+ $grpMemSplit[1]  +","+ $grpMemSplit[2]+","+ $grpMemSplit[3]+","+ $grpMemSplit[4]
        if ($grpMember -ne $null)
            {
                $newObjGroup = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjGroup -Type NoteProperty -Name GroupName -Value $grpName
                Add-Member -InputObject $newObjGroup -Type NoteProperty -Name GroupMembers -Value  $grpMemAdd
                $GroupDetails += $newObjGroup
            }
   }
Write-Host " "
Write-Host "Completed Gathering Host and Account Details" -foregroundColor Green

################################################
#########  USER RIGHTS ASSIGNMENTS  ############
################################################
Write-Host " "
Write-Host "Starting User Rights Assignments" -foregroundColor Green
sleep 5

    $VulnReport = "C:\SecureReport"
    $OutFunc = "URA" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $secEditPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.Inf"
    $secEditOutPath = "C:\SecureReport\output\$OutFunc\" + "URAOut.txt"
    $secEditImpPath = "C:\SecureReport\output\$OutFunc\" + "URAImport.txt"
    Set-Content -Path $secEditOutPath -Value " "
    Set-Content -Path $secEditImpPath -Value " "
    
    $hn = hostname

    $URALookup =[ordered]@{
        "Access this computer from the network" = "SeNetworkLogonRight","Access this computer from the network"
        "Add workstations to domain" = "SeMachineAccountPrivilege","Add workstations to domain"
        "Back up files and directories" = "SeBackupPrivilege", "Back up files and directories"
        "Bypass traverse checking" = "SeChangeNotifyPrivilege", "Bypass traverse checking"
        "Change the system time" = "SeSystemtimePrivilege", "Change the system time"
        "Create a pagefile" = "SeCreatePagefilePrivilege", "Create a pagefile"
        "Debug programs" = "SeDebugPrivilege", "Debug programs"
        "Force shutdown from a remote system" = "SeRemoteShutdownPrivilege", "Force shutdown from a remote system"
        "Generate security audits" = "SeAuditPrivilege", "Generate security audits" 
        "Adjust memory quotas for a process" = "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"
        "Increase scheduling priority" = "SeIncreaseBasePriorityPrivilege","Increase scheduling priority"
        "Load and unload device drivers" = "SeLoadDriverPrivilege", "Load and unload device drivers"
        "Log on as a batch job" = "SeBatchLogonRight", "Log on as a batch job"
        "Log on as a service" = "SeServiceLogonRight", "Log on as a service" 
        "Allow log on locally" = "SeInteractiveLogonRight", "Allow log on locally" 
        "Manage auditing and security log" = "SeSecurityPrivilege", "Manage auditing and security log"
        "Modify firmware environment values" = "SeSystemEnvironmentPrivilege","Modify firmware environment values"  
        "Profile single process" = "SeProfileSingleProcessPrivilege", "Profile single process" 
        "Profile system performance" = "SeSystemProfilePrivilege", "Profile system performance"
        "Replace a process level token" = "SeAssignPrimaryTokenPrivilege", "Replace a process level token" 
        "Restore files and directories" = "SeRestorePrivilege","Restore files and directories" 
        "Shut down the system" = "SeShutdownPrivilege", "Shut down the system"
        "Take ownership of files or other objects" = "SeTakeOwnershipPrivilege", "Take ownership of files or other objects"
        "Deny access to this computer from the network"   = "SeDenyNetworkLogonRight", "Deny access to this computer from the network" 
        "Deny log on as a batch job" = "SeDenyBatchLogonRight", "Deny log on as a batch job"
        "Deny log on as a service" = "SeDenyServiceLogonRight", "Deny log on as a service" 
        "Deny log on locally" = "SeDenyInteractiveLogonRight", "Deny log on locally" 
        "Remove computer from docking station" = "SeUndockPrivilege","Remove computer from docking station" 
        "Perform volume maintenance tasks" = "SeManageVolumePrivilege", "Perform volume maintenance tasks"
        "Deny log on through Remote Desktop Services" = "SeRemoteInteractiveLogonRight","Deny log on through Remote Desktop Services" 
        "Impersonate a client after authentication" = "SeImpersonatePrivilege", "Impersonate a client after authentication" 
        "Create global objects" = "SeCreateGlobalPrivilege", "Create global objects"
        "Increase a process working set" = "SeIncreaseWorkingSetPrivilege","Increase a process working set" 
        "Change the time zone" = "SeTimeZonePrivilege", "Change the time zone" 
        "Create symbolic links" = "SeCreateSymbolicLinkPrivilege","Create symbolic links" 
        "Obtain an impersonation token for another user in the same session"  = "SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session" 
        }

    #Export Security Settings inc User Rights Assignments with secedit.exe
    secEdit.exe /export /cfg $secEditPath
   
   $URA = get-content -path  $secEditPath |  Select-String  -Pattern 'S-1'
   $fragURA=@()
   foreach ($uraLine in $URA)
   {
   $uraItem = $uraLine.ToString().split("*").split("=") #.replace(",","")
   #write-host $uraItem -ForegroundColor Yellow
 
        foreach ($uralookupName in $URALookup.Values)
        {
        $uraItemTrim = $uraItem[0].trim()
        $uralookupTrim = $uralookupName.trim()[0]

            if ($uralookuptrim -eq $uraItemTrim)
                {
                   $uraDescripName = $uralookupName.trim()[1]
                   Write-Host $uraDescripName -ForegroundColor Cyan

                   #$uraDescripName | Out-File $secEditOutPath -Append
                   Add-Content $secEditOutPath -Value " "  -encoding UTF8
                   $uraDescripName + " " + "`(" +$uraItem.trim()[0] +"`)" | Out-File $secEditOutPath -Append -encoding UTF8
                }
        }
       
       $uraItemTrimStart = ($uraItem | where {$_ -like "S-1*"}).replace(",","")

       $objSid=@()
     
       set-content -Path $secEditImpPath -Value " "
       $NameURA=@()
       foreach($uraSidItems in $uraItemTrimStart)
       {
       $objSid = New-Object System.Security.Principal.SecurityIdentifier("$uraSidItems")
       $objUserName = $objSID.Translate( [System.Security.Principal.NTAccount])
       Write-Host $objUserName.Value -ForegroundColor Magenta
       
       #$objUserName.Value  | Out-File $secEditOutPath -Append
       "   " + $objUserName.Value  | Out-File $secEditOutPath -Append  -encoding UTF8

       [string]$NameURA += $objUserName.Value + ", "

       }
            
       $newObjURA = New-Object -TypeName PSObject
       Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Name -Value $uraDescripName
       Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Priv -Value $uraItemTrim
       Add-Member -InputObject $newObjURA -Type NoteProperty -Name URA-GroupName -Value $NameURA
       $fragURA += $newObjURA
   }
    
Write-Host " "
Write-Host "Completed User Rights Assignments" -foregroundColor Green    

################################################
##############  WINDOWS UPDATES  ###############
################################################
Write-Host " "
Write-Host "Gathering Windows Update and Installed Application Information" -foregroundColor Green
sleep 5

    $HotFix=@()
    $getHF = Get-HotFix -ErrorAction SilentlyContinue  | Select-Object HotFixID,InstalledOn,Caption 

    foreach ($hfitem in $getHF)
    {
        $hfid = $hfitem.hotfixid
        $hfdate = $hfitem.installedon
        $hfurl = $hfitem.caption

        $newObjHF = New-Object psObject
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name HotFixID -Value $hfid
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name InstalledOn -Value ($hfdate).Date.ToString("dd-MM-yyyy")
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name Caption -Value $hfurl 
        $HotFix += $newObjHF
    }

################################################
##############  INSTALLED APPS  ################
################################################

    $getUninx64 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
    $getUninx86 = Get-ChildItem  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
    $getUnin = $getUninx64 + $getUninx86
    $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
    $InstallApps =@()
    
    foreach ($uninItem in  $UninChild)
    {
        $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue | where {$_.displayname -notlike "*kb*"}
    
        #Write-Host $getUninItem.DisplayName
        $UninDisN = $getUninItem.DisplayName -replace "$null",""
        $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
        $UninPub = $getUninItem.Publisher -replace "$null",""
        $UninDate = $getUninItem.InstallDate -replace "$null",""
    
        $newObjInstApps = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value  $UninDisN
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value   $UninDate
        $InstallApps += $newObjInstApps
    }
  
################################################
###########  INSTALLED UPDATES  ################
################################################
#MS are making a bit of a mess of udpates, get-hotfix only returns the latest 10 installed
#Office 2019 onwards doesnt register installed KB's
#But for Office 2016 and older installed KB's do create keys in the Uninstall 

    $getUnin16 = Get-ChildItem  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
    $UninChild16 = $getUnin16.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
    $InstallApps16 =@()
    
    foreach ($uninItem16 in  $UninChild16)
    {
        $getUninItem16 = Get-ItemProperty $uninItem16 -ErrorAction SilentlyContinue | where {$_.displayname -like "*kb*"}
        $UninDisN16 = $getUninItem16.DisplayName -replace "$null",""
        $UninDisVer16 = $getUninItem16.DisplayVersion -replace "$null",""
        $UninPub16 = $getUninItem16.Publisher -replace "$null",""
        $UninDate16 = $getUninItem16.InstallDate -replace "$null",""
    
        $newObjInstApps16 = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjInstApps16 -Type NoteProperty -Name Publisher -Value  $UninPub16 
        Add-Member -InputObject $newObjInstApps16 -Type NoteProperty -Name DisplayName -Value  $UninDisN16
        Add-Member -InputObject $newObjInstApps16 -Type NoteProperty -Name DisplayVersion -Value  $UninDisVer16
        Add-Member -InputObject $newObjInstApps16 -Type NoteProperty -Name InstallDate -Value   $UninDate16
        $InstallApps16 += $newObjInstApps16
    }  
 
Write-Host " "
Write-Host "Completed Gathering Windows Update and Installed Application Information" -foregroundColor Green
        
################################################
################  MSINFO32  ####################
################################################
Write-Host " "
Write-Host "Starting MSInfo32 and Outputting to File" -foregroundColor Green
sleep 5

    #Virtualization - msinfo32
    $VulnReport = "C:\SecureReport"
    $OutFunc = "MSInfo" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $msinfoPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"
    $msinfoPathcsv = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.csv"
    $msinfoPathXml = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.xml"

    & cmd /c msinfo32 /nfo "C:\SecureReport\output\$OutFunc\" /report $msinfoPath
    $getMsinfo = Get-Content $msinfoPath | select -First 50

    <#
    Device Guard Virtualization based security	Running	
    Device Guard Required Security Properties	Base Virtualization Support, Secure Boot, DMA Protection	
    Device Guard Available Security Properties	Base Virtualization Support, Secure Boot, DMA Protection, UEFI Code Readonly	
    Device Guard Security Services Configured	Credential Guard, Hypervisor enforced Code Integrity	
    Device Guard Security Services Running	Credential Guard, Hypervisor enforced Code Integrity
    A hypervisor has been detected. Features required for Hyper-V will not be displayed.
    #>

    Set-Content -Path $msinfoPathcsv -Value 'Virtualization;On\Off'
    ($getMsinfo | Select-String "Secure Boot State") -replace "off",";off" -replace "on",";on" |Out-File $msinfoPathcsv -Append

    ($getMsinfo | Select-String "Kernel DMA Protection") -replace "off",";off" -replace " on",";on"  |Out-File $msinfoPathcsv -Append

    ($getMsinfo | Select-String "Guard Virtualization based") -replace "security	Run","security;	Run" |Out-File $msinfoPathcsv -Append

    ($getMsinfo | Select-String "Required Security Properties") -replace "Required Security Properties","Required Security Properties;" |Out-File $msinfoPathcsv -Append
   
    ($getMsinfo | Select-String "Available Security Properties") -replace "Available Security Properties","Available Security Properties;" |Out-File $msinfoPathcsv -Append 
   
    ($getMsinfo | Select-String "based security services configured") -replace "based security services configured","based security services configured;"  |Out-File $msinfoPathcsv -Append
   
    ($getMsinfo | Select-String "based security services running") -replace "based security services running","based security services running;" |Out-File $msinfoPathcsv -Append
    
    ($getMsinfo | Select-String "Application Control Policy") -replace "policy	Enforced","policy;	Enforced" -replace "Policy  Audit","Policy;  Audit"|Out-File $msinfoPathcsv -Append 
    
    ($getMsinfo | Select-String "Application Control User") -replace "off",";off" -replace " on",";on" -replace "policy	Enforced","policy;	Enforced"  -replace "Policy  Audit","Policy;  Audit" |Out-File $msinfoPathcsv -Append 
    
    ($getMsinfo | Select-String "Device Encryption Support") -replace "Encryption Support","Encryption Support;" |Out-File $msinfoPathcsv -Append

    Import-Csv $msinfoPathcsv -Delimiter ";" | Export-Clixml $msinfoPathXml
    $MsinfoClixml = Import-Clixml $msinfoPathXml 

    Get-Content $msinfoPathXml 

Write-Host " "
Write-Host "Finished Collectiong MSInfo32 data for VBS" -foregroundColor Green

################################################
################  DRIVERQRY  ###################
################################################
Write-Host " "
Write-Host "Starting DriverQuery and Out putting to File" -foregroundColor Green
sleep 5

    $VulnReport = "C:\SecureReport"
    $OutFunc = "DriverQuery" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $devQryPathtxt = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"
    $devQryPathcsv = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.csv"
    $devQryPathXml = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.xml"

    $drvSign = driverquery.exe /SI >>  $devQryPathtxt
    $getdrvQry = Get-Content  $devQryPathtxt | Select-String "FALSE" 

    $DriverQuery=@()

    foreach($drvQryItem in $getdrvQry)
    {
        if ($drvQryItem -match "FALSE")
        {
            $drvQryItem = "Warning - $drvQryItem warning"
        }
    
        $newObjDriverQuery = New-Object PSObject
        Add-Member -InputObject $newObjDriverQuery -Type NoteProperty -Name DriverName -Value $drvQryItem 
        $DriverQuery += $newObjDriverQuery
    }

Write-Host " "
Write-Host "Finished Collectiong DriverQuery data for VBS" -foregroundColor Green

################################################
#############  MISC REG SETTINGS  ##############
################################################
Write-Host " "
Write-Host "Auditing Various Registry Settings" -foregroundColor Green
sleep 5

    #LSA
    $getLSA = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\lsa\' -ErrorAction SilentlyContinue
    $getLSAPPL =  $getLSA.GetValue("RunAsPPL")
    $fragLSAPPL =@()

    if ($getLSAPPL -eq "1")
    {
        $lsaSet = "LSA is enabled the RunAsPPL is set to $getLSAPPL" 
        $lsaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\lsa\"
        $lsaCom = "Win10 and above Credential Guard should be used for Domain joined clients"
    }
    else
    {
        $lsaSet = "Warning - Secure LSA is disabled set RunAsPPL to 1 Warning" 
        $lsaReg = "HKLM:\SYSTEM\CurrentControlSet\Control\lsa\"
        $lsaCom = "Required for Win8.1 and below"
    }

    $newObjLSA = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSASetting -Value  $lsaSet
    Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSARegValue -Value $lsaReg 
    #Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSAComment -Value $lsaCom
    $fragLSAPPL += $newObjLSA
 
    #WDigest
    $getWDigest = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\' -ErrorAction SilentlyContinue
    $getWDigestULC =  $getWDigest.GetValue("UseLogonCredential")
    $fragWDigestULC =@()

    if ($getWDigestULC -eq "1")
    {
        $WDigestSet = "Warning - WDigest is enabled and plain text passwords are stored in LSASS Warning" 
        $WDigestReg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\"

    }
    else
    {
        $WDigestSet = "Secure WDigest is disabled" 
        $WDigestReg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\"
    }

    $newObjWDigest = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWDigest -Type NoteProperty -Name WDigestSetting -Value  $WDigestSet
    Add-Member -InputObject $newObjWDigest -Type NoteProperty -Name WDigestRegValue -Value $WDigestReg 
    $fragWDigestULC += $newObjWDigest


    #Credential Guard
    $getCredGu = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\' -ErrorAction SilentlyContinue
    $getCredGuCFG =  $getCredGu.GetValue("LsaCfgFlags")
    $fragCredGuCFG =@()

    if ($getCredGuCFG -eq "1")
    {
        $CredGuSet = "Credential Guard is enabled, the LsaCfgFlags value is set to $getCredGuCFG" 
        $CredGuReg = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard is enabled with UEFI persistance."
    }
    if ($getCredGuCFG -eq "2")
    {
        $CredGuSet = "Credential Guard is enabled, the LsaCfgFlags value is set to $getCredGuCFG" 
        $CredGuReg = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard is enable without UEFI persistence."
    }
    else
    {
        $CredGuSet = "Warning - Secure Credential Guard is disabled, LsaCfgFlags is set to 0 Warning" 
        $CredGuReg = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard requires the client to be Domain joined"
    }

    $newObjCredGu = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name CredentialGuardSetting -Value  $CredGuSet
    Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name CredentialGuardRegValue -Value $CredGuReg 
    #Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name CredGuComment -Value $CredGuCom
    $fragCredGuCFG += $newObjCredGu
  

    #LAPS is installed
    $getLapsPw = Get-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -ErrorAction SilentlyContinue
    $getLapsPwEna =  $getLapsPw.GetValue("AdmPwdEnabled")
    $getLapsPwCom =  $getLapsPw.GetValue("PasswordComplexity")
    $getLapsPwLen =  $getLapsPw.GetValue("PasswordLength")
    $getLapsPwDay =  $getLapsPw.GetValue("PasswordAgeDays")
    $fragLapsPwEna =@()

    if ($getLapsPwEna -eq "1")
    {
        $LapsPwSetena = "LAPS is installed and enabled, the AdmPwdEnabled value is set to $getLapsPwEna" 
        $LapsPwSetcom = "LAPS password complexity value is set to $getLapsPwCom" 
        $LapsPwSetlen = "LAPS password length value is set to $getLapsPwLen" 
        $LapsPwSetday = "LAPS password age value is to $getLapsPwDay" 
        $LapsPwReg = "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" 

    }
    else
    {
        $LapsPwSet = "LAPS is not installed or the value is set to 0 Warning" 
        $LapsPwReg = "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" 
        $LapsPwCom = "LAPS is not installed or configured - Ignore if not Domain Joined"
    }
 
    if ($getLapsPwEna -eq "1")
    {
        $newObjLapsPw = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordEnabled -Value $LapsPwSetena
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordComplexity -Value $LapsPwSetcom 
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordLength -Value $LapsPwSetlen
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordDay -Value $LapsPwSetday 
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordReg -Value $LapsPwReg
        $fragLapsPwEna += $newObjLapsPw
    }
    else 
    {
        $newObjLapsPw = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordEnabled -Value  $LapsPwSet
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordReg -Value $LapsPwReg 
        #Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LapsPwComment -Value $LapsPwCom
        $fragLapsPwEna += $newObjLapsPw
    }

        
    #DLL Safe Search
    $getDLL = Get-Item 'HKLM:\System\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    $getDLLSafe =  $getDLL.GetValue("SafeDLLSearchMode")

    $fragDLLSafe =@()
    if ($getDLLSafe -eq "1")
    {
        $dllSet = " DLLSafeSearch is enabled the SafeDLLSearchMode is set to $getDLLSafe" 
        $dllReg = "HKLM:\System\CurrentControlSet\Control\Session Manager"
        $dllCom = "Protects against DLL search order hijacking"
    }
    else
    {
        $dllSet = "Warning - DLLSafeSearch is disabled set SafeDLLSearchMode to 1 Warning" 
        $dllReg = "HKLM:\System\CurrentControlSet\Control\Session Manager"
        $dllCom = "Protects against DLL search order hijacking"
    }

    $newObjDLLSafe = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeSetting -Value  $dllSet
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeValue -Value $dllReg 
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeComment -Value $dllCom
    $fragDLLSafe += $newObjDLLSafe

    #Code Integrity
    $getCode = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
    $getCode =  $getCode.GetValue("Enabled")

    $fragCode =@()
    if ($getCode -eq "1")
    {
        $CodeSet = "Hypervisor Enforced Code Integrity is enabled" 
        $CodeReg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $CodeCom = "Protects against credential theft"
    }
    else
    {
        $CodeSet = "Warning - Hypervisor Enforced Code Integrity is disabled set Enabled to 1 Warning" 
        $CodeReg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        #$CodeCom = "Protects against credential theft"
    }

    $newObjCode = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeSetting -Value  $CodeSet
    Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeValue -Value $CodeReg 
    #Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeComment -Value $CodeCom
    $fragCode += $newObjCode

    #InstallElevated
    $getPCInstaller = Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    $getUserInstaller = Get-Item HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    $PCElevate =  $getUserInstaller.GetValue("AlwaysInstallElevated")
    $UserElevate = $getPCInstaller.GetValue("AlwaysInstallElevated")

    $fragPCElevate =@()
    if ($PCElevate -eq "1")
    {
        $ElevateSet = "Warning - Client setting Always Install Elevate is enabled Warning" 
        $ElevateReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    }
    else
    {
        $ElevateSet = "Client setting  Always Install Elevate is disabled" 
        $ElevateReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    }

    $newObjElevate = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateSetting -Value  $ElevateSet
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateRegistry -Value $ElevateReg
    $fragPCElevate += $newObjElevate 

    if ($UserElevate -eq "1")
    {
        $ElevateSet = "Warning - User setting Always Install Elevate is enabled Warning" 
        $ElevateReg = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    }
    else
    {
        $ElevateSet = "User setting Always Install Elevate is disabled" 
        $ElevateReg = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    }
       
    $newObjElevate = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateSetting -Value  $ElevateSet
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateRegistry -Value $ElevateReg
    $fragPCElevate += $newObjElevate 

    #AutoLogon Details in REG inc password   
    $getAutoLogon = Get-Item  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    $AutoLogonDefUser =  $getAutoLogon.GetValue("DefaultUserName")
    $AutoLogonDefPass =  $getAutoLogon.GetValue("DefaultPassword ") 

    $fragAutoLogon =@()

    if ($AutoLogonDefPass  -ne "$null")
    {
        $AutoLPass = "There is no Default Password set for AutoLogon" 
        $AutoLUser = "There is no Default User set for AutoLogon" 
        $AutoLReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    }
    else
    {
        $AutoLPass = "Warning - AutoLogon default password is set with a vaule of $AutoLogonDefPass Warning" 
        $AutoLUser = "Warning - AutoLogon Default User is set with a vaule of $AutoLogonDefUser Warning" 
        $AutoLReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    }

    $newObjAutoLogon = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonUsername -Value $AutoLUser
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonPassword -Value  $AutoLPass
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonRegistry -Value $AutoLReg
    $fragAutoLogon += $newObjAutoLogon
        
################################################
#########  LEGACY NETWORK PROTOCOLS  ##########
################################################
#Legacy Network
    $VulnReport = "C:\SecureReport"
    $OutFunc = "llmnr" 
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }
    $llnmrpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"
   
    $fragLegNIC=@()
    #llmnr = 0 is disabled
    cd HKLM:
    $getllmnrGPO = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $enllmnrGpo = $getllmnrgpo.EnableMulticast

    if ($enllmnrGpo -eq "0" -or $enllmnrReg -eq "0")
    {
        $legProt = "LLMNR (Responder) is disabled GPO = $enllmnrGpo" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.EnableMulticast"
    }
    else
    {
        $legProt = "Warning - LLMNR (Responder) is Enabled Warning" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.EnableMulticast"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #NetBIOS over TCP/IP (NetBT) queries = 0 is disabled
    cd HKLM:
    $getNetBTGPO = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $enNetBTGPO = $getNetBTGPO.QueryNetBTFQDN

    if ($enNetBTGPO -eq "0")
    {
        $legProt = "NetBios is disabled the Registry = $enNetBTGPO" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.QueryNetBTFQDN"
    }
    else
    {
        $legProt = "Warning - NetBios is enabled Warning" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.QueryNetBTFQDN"
        $legValue = $enNetBTGPO
        $legWarn = "Incorrect"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
  
    #ipv6 0xff (255)
    cd HKLM:
    $getIpv6 = get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ErrorAction SilentlyContinue
    $getIpv6Int = $getIpv6.DisabledComponents
    
    if ($getIpv6Int -eq "255")
    {
        $legProt = "IPv6 is disabled the Registry = $getIpv6Int" 
        $legReg = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters.DisabledComponents"
    }
    else
    {
        $legProt = "Warning - IPv6 is enabled Warning" 
        $legReg = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters.DisabledComponents"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #Report on LMHosts file = 1
    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.EnableLMHosts
    
    if ($enLMHostsReg -eq "1")
    {
        $legProt = "LMHosts is disabled the Registry = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.EnableLMHosts"
    }
    else
    {
        $legProt = "Warning - Disable LMHosts Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.EnableLMHosts"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #NetBios Node Type set to 2 - Only Reg Setting
    cd HKLM:
    $getNetBtNodeReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
    $enNetBTReg = $getNetBtNodeReg.NodeType
    
    if ($enNetBTReg -eq "2")
    {
        $legProt = "NetBios Node Type is set to 2 in the Registry" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.NodeType"
    }
    else
    {
        $legProt = "Warning - NetBios Node Type is set to $enNetBTReg, its incorrect and should be set to 2 Warning"
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.NodeType"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #disable netbios
    cd HKLM:
    $getNetBiosInt = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    
    foreach ($inter in $getNetBiosInt)
    {
        $getNetBiosReg = Get-ItemProperty $inter.Name
        $NetBiosValue = $getNetBiosReg.NetbiosOptions
        $NetBiosPath = $getNetBiosReg.PSChildName
        $NEtBiosPara = $NetBiosPath,$NetBiosValue
    
        if ($NetBiosValue -eq "0")
        {
            $legProt = "NetBios is set to $NetBiosValue in the Registry" 
            $legReg = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces.$NetBiosPath"
        }
        else
        {
            $legProt = "Warning - NetBios is set to $NetBiosValue, its incorrect and should be set to 0 Warning"
            $legReg = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces.$NetBiosPath"
        }
    
        $newObjLegNIC = New-Object psObject
        Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
        Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
        $fragLegNIC += $newObjLegNIC
    }

    cd HKLM:

    #Peer Net
    $getPeer = Get-ItemProperty  "HKLM:\Software\policies\Microsoft\Peernet" -ErrorAction SilentlyContinue
    $getPeerDis = $getPeer.Disabled
    
    if ($getPeerDis -eq "0")
    {
        $legProt = "Peer to Peer is set to $getPeerDis and disabled" 
        $legReg = "HKLM:\Software\policies\Microsoft\Peernet"
    }
    else
    {
        $legProt = "Warning - Peer to Peer is enabled Warning"
        $legReg = "HKLM:\Software\policies\Microsoft\Peernet"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #Enable Font Providers
    cd HKLM:
    $getFont = Get-ItemProperty  "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
    $getFontPr = $getFont.EnableFontProviders
    
    if ( $getFontPr -eq "0")
    {
        $legProt = "Enable Font Providers is set to $getFontPr and is disabled" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\System"
    }
    else
    {
        $legProt = "Warning - Enable Font Providers is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\System"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #LLTD
    $getNetLLTDInt = Get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" -ErrorAction SilentlyContinue

    $getLTDIO =  $getNetLLTDInt.GetValue("EnableLLTDIO")
    $getRspndr = $getNetLLTDInt.GetValue("EnableRspndr")
    $getOnDomain =  $getNetLLTDInt.GetValue("AllowLLTDIOOnDomain")
    $getPublicNet = $getNetLLTDInt.GetValue("AllowLLTDIOOnPublicNet")
    $getRspOnDomain = $getNetLLTDInt.GetValue("AllowRspndrOnDomain")
    $getRspPublicNet = $getNetLLTDInt.GetValue("AllowRspndrOnPublicNet")
    $getLLnPrivateNet = $getNetLLTDInt.GetValue("ProhibitLLTDIOOnPrivateNet") 
    $getRspPrivateNet = $getNetLLTDInt.GetValue("ProhibitRspndrOnPrivateNet")

    #EnableLLTDIO
    if ($getLTDIO -eq "0")
    {
        $legProt = "EnableLLTDIO is set to $getLTDIO in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - EnableLLTDIO is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #EnableRspndr
    if ($getRspndr -eq "0")
    {
        $legProt = "EnableRspndr is set to $getRspndr in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - EnableRspndr is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #AllowLLTDIOOnDomain
    if ($getOnDomain -eq "0")
    {
        $legProt = "AllowLLTDIOOnDomain is set to $getOnDomain in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - AllowLLTDIOOnDomain is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
   
    #AllowLLTDIOOnPublicNet
    if ($getPublicNet -eq "0")
    {
        $legProt = "AllowLLTDIOOnPublicNet is set to $getPublicNet in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - AllowLLTDIOOnPublicNet is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
   
    #AllowRspndrOnDomain  
    if ($getRspOnDomain -eq "0")
    {
        $legProt = "AllowRspndrOnDomain is set to $getRspOnDomain in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - AllowRspndrOnDomain is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC

    #AllowRspndrOnPublicNet    
    if ($getRspPublicNet -eq "0")
    {
        $legProt = "AllowRspndrOnPublicNet is set to $getRspPublicNet in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - AllowRspndrOnPublicNet is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
   
    #ProhibitLLTDIOOnPrivateNe
    if ($getLLnPrivateNet -eq "1")
    {
        $legProt = "ProhibitLLTDIOOnPrivateNet is set to $getLLnPrivateNet in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - ProhibitLLTDIOOnPrivateNet is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
   
    #ProhibitRspndrOnPrivateNet      $getRspPrivateNet = $getNetLLTDInt.GetValue("ProhibitRspndrOnPrivateNet")
    if ($getRspPrivateNet -eq "1")
    {
        $legProt = "ProhibitLLTDIOOnPrivateNet is set to $getRspPrivateNet in the Registry" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    else
    {
        $legProt = "Warning - ProhibitLLTDIOOnPrivateNet is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    $fragLegNIC += $newObjLegNIC
  
################################################
############  SECURITY OPTIONS  ################
################################################ 
    $fragSecOptions=@()
    $secOpTitle1 = "Domain member: Digitally encrypt or sign secure channel data (always)" # = 1
    $getSecOp1 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue
    $getSecOp1res = $getSecOp1.getvalue("RequireSignOrSeal")

    if ($getSecOp1res -eq "1")
    {
        $SecOptName = "$secOpTitle1 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle1 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions 
    
    $secOpTitle2 = "Microsoft network client: Digitally sign communications (always)" # = 1
    $getSecOp2 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
    $getSecOp2res = $getSecOp2.getvalue("RequireSecuritySignature")

    if ($getSecOp2res -eq "1")
    {
        $SecOptName = "$secOpTitle2 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle2 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle3 = "Microsoft network server: Digitally sign communications (always)" # = 1
    $getSecOp3 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
    $getSecOp3res = $getSecOp3.getvalue("RequireSecuritySignature")

    if ($getSecOp3res -eq "1")
    {
        $SecOptName = "$secOpTitle3 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle3 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle4 = "Microsoft network client: Send unencrypted password to connect to third-party SMB servers" #  = 0
    $getSecOp4 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
    $getSecOp4res = $getSecOp4.getvalue("EnablePlainTextPassword")

    if ($getSecOp4res -eq "0")
    {
        $SecOptName = "$secOpTitle4 - Disabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle4 - Enabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle5 = "Network security: Do not store LAN Manager hash value on next password change" #  = 1
    $getSecOp5 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp5res = $getSecOp5.getvalue("NoLmHash")

    if ($getSecOp5res -eq "1")
    {
        $SecOptName = "$secOpTitle5 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle5 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle6 = "Network security: LAN Manager authentication level (Send NTLMv2 response only\refuse LM & NTLM)" #  = 5
    $getSecOp6 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp6res = $getSecOp6.getvalue("lmcompatibilitylevel")

    if ($getSecOp6res -eq "5")
    {
        $SecOptName = "$secOpTitle6 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle6 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle7 = "Network access: Do not allow anonymous enumeration of SAM accounts" #  = 1
    $getSecOp7 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp7res = $getSecOp7.getvalue("restrictanonymoussam")

    if ($getSecOp7res -eq "1")
    {
        $SecOptName = "$secOpTitle7 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle7 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle8 = "Network access: Do not allow anonymous enumeration of SAM accounts and shares" #  = 1
    $getSecOp8 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp8res = $getSecOp8.getvalue("restrictanonymous")

    if ($getSecOp8res -eq "1")
    {
        $SecOptName = "$secOpTitle8 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle8 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle9 = "Network access: Let Everyone permissions apply to anonymous users" # = 0
    $getSecOp9 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp9res = $getSecOp9.getvalue("everyoneincludesanonymous")

    if ($getSecOp9res -eq "0")
    {
        $SecOptName = "$secOpTitle9 - Disabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle9 - Enabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle10 = "Network security: LDAP client signing requirements" # = 2 Required
    $getSecOp10 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\parameters' -ErrorAction SilentlyContinue
    $getSecOp10res = $getSecOp10.getvalue("ldapserverintegrity")

    if ($getSecOp10res -eq "2")
    {
        $SecOptName = "$secOpTitle10 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle10 - Disabled Warning"
    }
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    <#
    All allows the AES encryption types aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96, as well as the RC4 encryption type rc4-hmac. AES takes precedence if the server supports AES and RC4 encryption types.

    * Strong or leaving it unset allows only the AES types.
    * Legacy allows only the RC4 type. RC4 is insecure. It should only be needed in very specific circumstances. 

    If possible, reconfigure the server to support AES encryption.
    
    Caution - removing RC4 can break trusts between parent\child where rc4 is configured
    
    Also see https://wiki.samba.org/index.php/Samba_4.6_Features_added/changed#Kerberos_client_encryption_types.
    #>
    
    $secOpTitle12 = "Domain member: Require strong (Windows 2000 or later) session key" 
    $getSecOp12 = get-item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' -ErrorAction SilentlyContinue
    $getSecOp12res = $getSecOp12.getvalue("supportedencryptiontypes")

    if ($getSecOp12res -eq "2147483640")
    {
        $SecOptName = "$secOpTitle12 - Enabled, (AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types)"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle12 - Disabled Warning"
    }
    

    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle11 = "Domain member: Require strong (Windows 2000 or later) session key" 
    $getSecOp11 = get-item 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' -ErrorAction SilentlyContinue
    $getSecOp11res = $getSecOp11.getvalue("RequireStrongKey")

    if ($getSecOp11res -eq "1")
    {
        $SecOptName = "$secOpTitle11 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle11 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

#Network access: Restrict anonymous access to Named Pipes and Shares
#Network security: Do not store LAN Manager hash value on next password change
Write-Host " "
Write-Host "Finished Auditing Various Registry Settings" -foregroundColor Green

################################################
############  FIREWALL DETAILS  ################
################################################                
#Firewall Enabled \ Disabled
Write-Host " "
Write-Host "Auditing Firewall Rules" -foregroundColor Green
sleep 5

    $getFWProf = Get-NetFirewallProfile -PolicyStore activestore -ErrorAction SilentlyContinue
    $fragFWProfile=@()
    
    Foreach ($fwRule in $getFWProf)
    {
        $fwProfileNa = $fwRule.Name
        $fwProfileEn = $fwRule.Enabled
        $fwProfileIn = $fwRule.DefaultInboundAction 
        $fwProfileOut = $fwRule.DefaultOutboundAction 
     
        $newObjFWProf = New-Object psObject
        Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Name -Value $fwProfileNa
        Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Enabled -Value $fwProfileEn
        Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Inbound -Value $fwProfileIn
        Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Outbound -Value $fwProfileOut
        $fragFWProfile += $newObjFWProf 
    }

    #Firewall Rules
    $VulnReport = "C:\SecureReport"
    $OutFunc = "firewall" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $fwpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"
    $fwpathcsv = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.csv"
    $fwpathxml = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.xml"

    [System.Text.StringBuilder]$fwtxt = New-Object System.Text.StringBuilder

    $getFw = Get-NetFirewallRule | 
    Select-Object Displayname,ID,Enabled,Direction,Action,Status  | 
    where {$_.enabled -eq "true"} | 
    Sort-Object direction -Descending
    
    foreach($fw in $getFw)
    {
        $fwID = $fw.ID
        $fwAddFilter = Get-NetFirewallAddressFilter | where {$_.InstanceID -eq $fwID}
        $fwPrtFilter = Get-NetFirewallPortFilter | where {$_.InstanceID -eq $fwID}
        $fwAppFilter = Get-NetFirewallApplicationFilter | where {$_.InstanceID -eq $fwID}
        $fwtxt.Append($fw.DisplayName)
        $fwtxt.Append(", ")
        $fwtxt.Append($fw.Direction)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwPrtFilter.Protocol)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwAddFilter.LocalIP)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwID.RemoteIP)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwPrtFilter.LocalPort)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwPrtFilter.RemotePort)
        $fwtxt.Append(", ")
        $fwtxt.Append($fwAppFilter.Program)
        $fwtxt.AppendLine()

        Set-Content -Path $fwpath -Value 'DisplayName,Direction,Protocol,LocalIP,LocalPort,RemoteIP,RemotePort,Program'
    }

    Add-Content -Path $fwpath -Value $fwtxt -ErrorAction SilentlyContinue
    Get-Content $fwpath | Out-File $fwpathcsv -ErrorAction SilentlyContinue
    $fwCSV = Import-Csv $fwpathcsv -Delimiter "," | Export-Clixml $fwpathxml
    $fragFW = Import-Clixml $fwpathxml

Write-Host " "
Write-Host "Finished Auditing Firewall Rules" -foregroundColor Green

################################################
##############  SCHEDULED TAsKS  ###############
################################################ 
Write-Host " "
Write-Host "Auditing Scheduled Tasks" -foregroundColor Green
sleep 5

    $getScTask = Get-ScheduledTask 
    $TaskHash=@()
    $SchedTaskPerms=@()

    foreach ($shTask in $getScTask | where {$_.Actions.execute -notlike "*system32*"})
    {
        $taskName = $shTask.TaskName
        $taskPath = $shTask.TaskPath
        $taskArgs = $shTask.Actions.Arguments | Select-Object -First 1
        $taskExe =  $shTask.Actions.execute | Select-Object -First 1
        $taskSet =  $shTask.Settings
        $taskSour = $shTask.Source
        $taskTrig = $shTask.Triggers
        $taskURI =  $shTask.URI
 
        #find file paths to check for permissions restricted to Admins Only
        if ($taskExe -ne $null)
        {
        #find file paths to check for permissions restricted to Admins Only
            if ($taskArgs -match "^[a-zA-Z]:")
            {
                $getAclArgs = Get-Acl $taskArgs 
                $getAclArgs.Path.Replace("Microsoft.PowerShell.Core\FileSystem::","")
                $taskUser = $getAclArgs.Access.IdentityReference
                $taskPerms = $getAclArgs.Access.FileSystemRights
        
                $getTaskCon = Get-Content $taskArgs 
                $syfoldAcl = Get-Acl $taskArgs -ErrorAction SilentlyContinue
            
            if ($syfoldAcl | where {$_.accesstostring -like "*Users Allow  Write*" `
                -or $_.accesstostring -like "*Users Allow  Modify*" `
                -or $_.accesstostring -like "*Users Allow  FullControl*"})
            {
                $taskUSerPers = "Warning - User are allowed to WRITE or MODIFY $taskArgs Warning"
            }

            if ($syfoldAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" `
                -or $_.accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $taskUSerPers = "Warning - Everyone are allowed to WRITE or MODIFY $taskArgs Warning"
            }

            if ($syfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $taskUSerPers = "Warning - Authenticated User are allowed to WRITE or MODIFY $taskArgs Warning"
            }
                $newObjSchedTaskPerms = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSchedTaskPerms -Type NoteProperty -Name TaskName -Value $taskName
                Add-Member -InputObject $newObjSchedTaskPerms -Type NoteProperty -Name TaskPath -Value $taskArgs
                Add-Member -InputObject $newObjSchedTaskPerms -Type NoteProperty -Name TaskContent -Value $getTaskCon 
                Add-Member -InputObject $newObjSchedTaskPerms -Type NoteProperty -Name TaskPermissions -Value $taskUSerPers
                $SchedTaskPerms += $newObjSchedTaskPerms
            }
        }  
    }

 $getScTask = Get-ScheduledTask 
 $SchedTaskListings=@()

foreach ($shTask in $getScTask | where {$_.Actions.execute -notlike "*system32*" -and $_.Actions.execute -notlike "*MpCmdRun.exe*"})
    {
        $arrayTaskArgs=@()
        $arrayTaskExe=@()
        $TaskHash=@()
        $getTaskCon=@()

        $taskName = $shTask.TaskName
        $taskPath = $shTask.TaskPath
        $taskArgs = $shTask.Actions.Arguments 
        $taskExe =  $shTask.Actions.execute 
        $taskSet =  $shTask.Settings
        $taskSour = $shTask.Source
        $taskTrig = $shTask.Triggers
        $taskURI =  $shTask.URI

        if ($taskExe -ne $null)
        {
            if ($taskArgs -notmatch "^[a-zA-Z]:" -or $taskArgs -match "^[a-zA-Z]:")
            {
                foreach($Args in $taskArgs)
                {
                    $arrayTaskArgs += $Args
                }
                    $arrayjoinArgs = $arrayTaskArgs -join ", "
    
                foreach($Exes in $taskExe)
                {
                    $arrayTaskExe += $Exes
                }
        
                $arrayjoinExe = $arrayTaskExe -join ", "
                $newObjSchedTaskListings = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSchedTaskListings -Type NoteProperty -Name TaskName -Value $taskName
                Add-Member -InputObject $newObjSchedTaskListings -Type NoteProperty -Name TaskExe -Value $arrayjoinExe
                Add-Member -InputObject $newObjSchedTaskListings -Type NoteProperty -Name TaskArguments -Value $arrayjoinArgs
                #Add-Member -InputObject $newObjSchedTaskListings -Type NoteProperty -Name TaskContent -Value $getTaskCon 
                #Add-Member -InputObject $newObjSchedTaskListings -Type NoteProperty -Name TaskPermissions -Value $taskUserPers
                $SchedTaskListings += $newObjSchedTaskListings
            }
        }
    }

Write-Host " "
Write-Host "Completed Scheduled Tasks" -foregroundColor Green

################################################
############  UNQUOTED PATHS  ##################
################################################
Write-Host " "
Write-Host "From this point onwards things will slow down, in some cases it may appear nothing is happening, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for UnQuoted Path Vulnerabilities" -foregroundColor Green
sleep 7

    #Unquoted paths   
    $VulnReport = "C:\SecureReport"
    $OutFunc = "UnQuoted" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $qpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"
 
    #Unquoted paths
    $vulnSvc = gwmi win32_service | foreach{$_} | 
    where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
    where {-not $_.pathname.startswith("`"")} | 
    where {($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 )) -match ".* .*" }
    $fragUnQuoted=@()
    
    foreach ($unQSvc in $vulnSvc)
    {
    $svc = $unQSvc.name
    $SvcReg = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\$svc -ErrorAction SilentlyContinue
    
        if ($SvcReg.imagePath -like "*.exe*")
        {
            $SvcRegSp =  $SvcReg.imagePath -split ".exe"
            $SvcRegSp0 = $SvcRegSp[0]
            $SvcRegSp1 = $SvcRegSp[1]
            $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
                
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value $SvcReg.PSChildName
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value $SvcReg.ImagePath 
            $fragUnQuoted += $newObjSvc
        }
    
        if ($SvcReg.imagePath -like "*.sys*")
        {
            $SvcRegSp =  $SvcReg.imagePath -split ".sys"
            $SvcRegSp0 = $SvcRegSp[0]
            $SvcRegSp1 = $SvcRegSp[1]
            $image = "`"$SvcRegSp0" + ".sys`""+   " $SvcRegSp1"
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
                       
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value $SvcReg.PSChildName
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value $SvcReg.ImagePath 
            $fragUnQuoted += $newObjSvc
        }
    
        if ($SvcReg.imagePath -like "*.exe") 
        {
            $image = $SvcReg.ImagePath
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value $SvcReg.PSChildName
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value $SvcReg.ImagePath 
            $fragUnQuoted += $newObjSvc
        }
    }

Write-Host " "
Write-Host "Finished Searching for UnQuoted Path Vulnerabilities" -foregroundColor Green

################################################
##########  FILES, FOLDERS, REG AUDITS  ########
################################################


#START OF IF
if ($folders -eq "y")
{

################################################
############  WRITEABLE FILES  #################
################################################
Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all folders and their permissions, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Writeable Files Vulnerabilities" -foregroundColor Green
sleep 7

    $VulnReport = "C:\SecureReport"
    $OutFunc = "WriteableFiles"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $hpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"})
    $drvRoot = $drv.root

    foreach ($rt in $drvRoot)
    {
        $hfiles =  Get-ChildItem $rt -ErrorAction SilentlyContinue |
        where {$_.Name -eq "PerfLogs" -or ` 
        $_.Name -eq "ProgramData" -or `
        $_.Name -eq "Program Files" -or `
        $_.Name -eq "Program Files (x86)" -or `
        $_.Name -eq "Windows"}

        $filehash = @()
        foreach ($hfile in $hfiles.fullname)
        {
            $subfl = Get-ChildItem -Path $hfile -force -Recurse -Include *.exe, *.dll -ErrorAction SilentlyContinue | 
            Where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"} 
            $filehash+=$subfl
            $filehash 
        }
    
        foreach ($cfile in $filehash.fullname)
        {
            $cfileAcl = Get-Acl $cfile -ErrorAction SilentlyContinue

            if ($cfileAcl | 
            where {$_.accesstostring -like "*Users Allow  Write*" `
                -or $_.accesstostring -like "*Users Allow  Modify*" `
                -or $_.accesstostring -like "*Users Allow  FullControl*"})
            
            {
                $cfile | Out-File $hpath -Append
                #Write-Host $cfile -ForegroundColor Yellow
            }

            if ($cfileAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" `
                -or $_.accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfile | Out-File $hpath -Append
                #Write-Host $cfile -ForegroundColor Yellow
            }
    
            if ($cfileAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $cfile | Out-File $hpath -Append
                #Write-Host $cfile -ForegroundColor Yellow
            }
        }
    
        $wFileDetails = Get-Content  $hpath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
        $fragwFile =@()
    
        foreach ($wFileItems in $wFileDetails)
        {
            $newObjwFile = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjwFile -Type NoteProperty -Name WriteableFiles -Value $wFileItems
            $fragwFile += $newObjwFile
            #Write-Host $wFileItems -ForegroundColor Yellow
        }
       
    }
Write-Host " "
Write-Host "Finished Searching for Writeable Files Vulnerabilities" -foregroundColor Green

################################################
#########  WRITEABLE REGISTRY HIVES  ###########
################################################
Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all Registry Hives and permissions, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Writeable Registry Hive Vulnerabilities" -foregroundColor Green
sleep 7

    $VulnReport = "C:\SecureReport"
    $OutFunc = "WriteableReg"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $rpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"

    #Registry Permissions
    $HKLMSvc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $HKLMSoft = 'HKLM:\Software'
    $HKLMCheck = $HKLMSoft,$HKLMSvc

    Foreach ($key in $HKLMCheck) 
    {
        #Get a list of key names and make a variable
        cd hklm:
        $SvcPath = Get-childItem $key -Recurse -Depth 1 -ErrorAction SilentlyContinue | where {$_.Name -notmatch "Classes"}
        #Update HKEY_Local.... to HKLM:
        $RegList = $SvcPath.name.replace("HKEY_LOCAL_MACHINE","HKLM:")
    
        Foreach ($regPath in $RegList)
        {
            $acl = Get-Acl $regPath -ErrorAction SilentlyContinue
            $acc = $acl.AccessToString
            #Write-Output $regPath 
            #Write-Host $regPath  -ForegroundColor DarkCyan

            foreach ($ac in $acc)
                {
                    if ($ac | Select-String -SimpleMatch "BUILTIN\Users Allow  FullControl")
                    {
                        $regPath | Out-File $rpath -Append
                        #Write-Host $ac -ForegroundColor DarkCyan
                    } 

                    if ($ac | Select-String -SimpleMatch "NT AUTHORITY\Authenticated Users Allow  FullControl")
                    {
                        $regPath | Out-File $rpath -Append
                        #Write-Host $ac -ForegroundColor DarkCyan
                    }

                    if ($ac | Select-String -SimpleMatch "Everyone Allow  FullControl")
                    {
                        $regPath | Out-File $rpath -Append
                        #Write-Host $ac -ForegroundColor DarkCyan
                    }
                }
        }
        
        $regDetails = Get-Content $rpath -ErrorAction SilentlyContinue    #|  where {$_ -ne ""} |select -skip 3
        $fragReg =@()
    
        foreach ($regItems in $regDetails)
        {
            #Write-Host $regItems -ForegroundColor DarkCyan
            $newObjReg = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjReg -Type NoteProperty -Name RegWeakness -Value $regItems
            $fragReg += $newObjReg    
        }
   }

Write-Host " "
Write-Host "Finished Searching for Writeable Registry Hive Vulnerabilities" -foregroundColor Green

################################################
#############  WRITEABLE FOLDERS  ##############
############  NON SYSTEM FOLDERS  ##############
################################################
Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all folders and their permissions, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Writeable Folder Vulnerabilities" -foregroundColor Green
sleep 7

    $VulnReport = "C:\SecureReport"
    $OutFunc = "WriteableFolders"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }
    
    $fpath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"
    #Additional Folders off the root of C: that are not system
    
    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root 
    $getRoot = Get-Item $drvRoot

    foreach ($rt in $drvRoot)
    {
        $hfolders =  Get-ChildItem $rt -ErrorAction SilentlyContinue  | 
        where {$_.Name -ne "PerfLogs" -and ` 
        $_.Name -ne "Program Files" -and `
        $_.Name -ne "Program Files (x86)" -and `
        $_.Name -ne "Users" -and `
        $_.Name -ne "Windows"}
    
        $foldhash = @()
        foreach ($hfold in $hfolders.fullname)
        {
            $subfl = Get-ChildItem -Path $hfold -Depth $depth -Directory -Recurse -Force -ErrorAction SilentlyContinue
            $foldhash+=$hfolders
            $foldhash+=$subfl
            $foldhash+=$getRoot
            #Write-Host $hfold -ForegroundColor Gray   
        }
    
        foreach ($cfold in $foldhash.fullname)
        {
        #Write-Host $cfold -ForegroundColor green
        $cfoldAcl = Get-Acl $cfold -ErrorAction SilentlyContinue

            if ($cfoldAcl | where {$_.accesstostring -like "*Users Allow  Write*" `
                -or $_.accesstostring -like "*Users Allow  Modify*" `
                -or $_.accesstostring -like "*Users Allow  FullControl*"})
            {
                $cfold | Out-File $fpath -Append
                #Write-Host $cfold -ForegroundColor red
            }

            if ($cfoldAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" `
                -or $_.accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfold | Out-File $fpath -Append
                #Write-Host $cfold -ForegroundColor red
            }

            if ($cfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $cfold | Out-File $fpath -Append
                #Write-Host $cfold -ForegroundColor red
            } 
        }
        
        get-content $fpath | Sort-Object -Unique | set-Content $fpath -ErrorAction SilentlyContinue

        #Get content and remove the first 3 lines
        $wFolderDetails = Get-Content  $fpath  -ErrorAction SilentlyContinue   #|  where {$_ -ne ""} |select -skip 3
        $fragwFold =@()
    
        foreach ($wFoldItems in $wFolderDetails)
        {
            $newObjwFold = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjwFold -Type NoteProperty -Name FolderWeakness -Value $wFoldItems
            $fragwFold += $newObjwFold
            #Write-Host $wFoldItems -ForegroundColor Gray
        }
        
    }
     
Write-Host " "
Write-Host "Finisehd Searching for Writeable Folder Vulnerabilities" -foregroundColor Green
 
################################################
#############  WRITEABLE FOLDERS  ##############
###############  SYSTEM FOLDERS  ###############
################################################
Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all folders and their permissions, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Writeable System Folder Vulnerabilities" -foregroundColor Green
sleep 7
    
    $VulnReport = "C:\SecureReport"
    $OutFunc = "SystemFolders"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $sysPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root
    $getRoot = Get-Item $drvRoot

    foreach ($rt in $drvRoot)
    {
        $sysfolders =  Get-ChildItem $rt -ErrorAction SilentlyContinue | 
        where {$_.Name -eq "PerfLogs" -or ` 
        $_.Name -eq "ProgramData" -or `
        $_.Name -eq "Program Files" -or `
        $_.Name -eq "Program Files (x86)" -or `
        $_.Name -eq "Windows"}
        $sysfoldhash = @()
        $sysfolders  #+=$getRoot
    
        foreach ($sysfold in $sysfolders.fullname)
        {
            #Write-Host $sysfold
            $subsysfl = Get-ChildItem -Path $sysfold -Depth $depth -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
            Where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"}

            $sysfoldhash+=$subsysfl
            #Write-Host $subsysfl -ForegroundColor White
        }
    
        foreach ($syfold in $sysfoldhash.fullname)
        {
            $syfoldAcl = Get-Acl $syfold -ErrorAction SilentlyContinue
            #Write-Host $sysfoldhash -ForegroundColor green
            if ($syfoldAcl | where {$_.accesstostring -like "*Users Allow  Write*" `
                -or $_.accesstostring -like "*Users Allow  Modify*" `
                -or $_.accesstostring -like "*Users Allow  FullControl*"})
            {
                $syfold | Out-File $sysPath -Append
                #Write-Host $syfold -ForegroundColor red
            }

            if ($syfoldAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" `
                -or $_.accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $syfold | Out-File $sysPath -Append
                #Write-Host $syfold -ForegroundColor red
            }

            if ($syfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})

            {
                $syfold | Out-File $sysPath -Append
                #Write-Host $syfold -ForegroundColor red
            }
        }
    
        get-content $sysPath | Sort-Object -Unique | set-Content $sysPath 

        #Get content and remove the first 3 lines
        $sysFolderDetails = Get-Content $sysPath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
        $fragsysFold =@()
    
        foreach ($sysFoldItems in $sysFolderDetails)
        {
            $newObjsysFold = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjsysFold -Type NoteProperty -Name FolderWeakness -Value $sysFoldItems
            $fragsysFold += $newObjsysFold
            #Write-Host $sysFoldItems -ForegroundColor White
        }
    }
  
Write-Host " "
Write-Host "Finished Searching for Writeable System Folder Vulnerabilities" -foregroundColor Green

################################################
#################  CREATEFILES  ################
###############  SYSTEM FOLDERS  ###############
################################################
Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all folders and their permissions, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for CreateFile Permissions Vulnerabilities" -foregroundColor Green
sleep 7
  
    $VulnReport = "C:\SecureReport"
    $OutFunc = "CreateSystemFolders"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }
    
    $createSysPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root
    $getRoot = Get-Item $drvRoot

    foreach ($rt in $drvRoot)
    {   
        $createSysfolders =  Get-ChildItem $rt  -ErrorAction SilentlyContinue | 
        where {$_.Name -eq "PerfLogs" -or ` 
        $_.Name -eq "ProgramData" -or `
        $_.Name -eq "Program Files" -or `
        $_.Name -eq "Program Files (x86)" -or `
        $_.Name -eq "Windows"}
        $createSysfoldhash=@()
  
        foreach ($createSysfold in $createSysfolders.fullname)
        {
            $createSubsysfl = Get-ChildItem -Path $createSysfold -Depth $depth -Directory -Recurse -Force  -ErrorAction SilentlyContinue | 
            Where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"}
            
            $createSysfoldhash+=$createSubsysfl
            #Write-Host $createSubsysfl -ForegroundColor Green
        }

        foreach ($createSyfold in $createSysfoldhash.fullname)
        {
            $createSyfoldAcl = Get-Acl $createSyfold -ErrorAction SilentlyContinue
            #Write-Host $createSyfold -ForegroundColor green

            if ($createSyfoldAcl | where {$_.accesstostring -like "*Users Allow  CreateFiles*"})
            {
                $createSyfold | Out-File $createSysPath -Append
                #Write-Host $createSyfold -ForegroundColor red
            }

            if ($createSyfoldAcl | where {$_.accesstostring -like "*Everyone Allow  CreateFiles*"})
            {
                $createSyfold | Out-File $createSysPath -Append
                #Write-Host $createSyfold -ForegroundColor red
            }

            if ($createSyfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  CreateFiles*"})
            {
                $createSyfold | Out-File $createSysPath -Append
                #Write-Host $createSyfold -ForegroundColor red
            }
         }

            get-content $createSysPath | Sort-Object -Unique | set-Content $createSysPath 

            #Get content and remove the first 3 lines
            $createSysFolderDetails = Get-Content $createSysPath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
            $fragcreateSysFold=@()
        
            foreach ($createSysFoldItems in $createSysFolderDetails)
            {
                $newObjcreateSysFold = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjcreateSysFold -Type NoteProperty -Name CreateFiles -Value $createSysFoldItems
                $fragcreateSysFold += $newObjcreateSysFold
                #Write-Host $createSysFoldItems -ForegroundColor green
            }
        }
        
Write-Host " "
Write-Host "Finised Searching for CreateFile Permissions Vulnerabilities" -foregroundColor Green

################################################
###############  DLL HIJACKING  ################
################################################
#All dlls' that are NOT signed and user permissions allow write  
    $VulnReport = "C:\SecureReport"
    $OutFunc = "DLLNotSigned"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }
    
    $dllLogPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.log"
    $dllLogPathtxt = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root 
    $getRoot = Get-Item $drvRoot

    foreach ($rt in $drvRoot)
    {
        $dllFolders =  Get-ChildItem $rt -ErrorAction SilentlyContinue  |
        where {$_.fullName -match "Program Files" -or `
        $_.fullName -match "(x86)" -or `
        $_.fullName -match "Windows"}
      
        foreach ($dllFold in $dllFolders.fullname)
        {$dllSigned =  Get-ChildItem -Path $dllFold -Recurse -depth $depth -force | 
              where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"} |
              where {$_.Extension -eq ".dll"} | get-authenticodesignature | 
              where {$_.status -ne "valid"} | get-acl | 
              where {$_.accesstostring -like "*Users Allow  Write*" `
              -or $_.accesstostring -like "*Users Allow  Modify*" `
              -or $_.accesstostring -like "*Users Allow  FullControl*" `
              -or $_.accesstostring -like "*Everyone Allow  Write*" `
              -or $_.accesstostring -like "*Everyone Allow  Modify*" `
              -or $_.accesstostring -like "*Everyone Allow  FullControl*" `
              -or $_.accesstostring -like "*Authenticated Users Allow  Write*" `
              -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" `
              -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"} 
             #write-host $dllSigned
             $dllSigned.path | out-file $dllLogPath -Append
         }
    }

    Get-Content $dllLogPath  | 
    foreach {$_ -replace "Microsoft.PowerShell.Core",""} |
    foreach {$_ -replace 'FileSystem::',""} |
    foreach {$_.substring(1)} |
    Set-Content $dllLogPathtxt -Force

    $fragDllNotSigned=@()
    $getDllPath = get-content $dllLogPathtxt

    foreach ($dllNotSigned in $getDllPath)
    {
        $newObjDllNotSigned = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjDllNotSigned -Type NoteProperty -Name CreateFiles -Value $dllNotSigned
        $fragDllNotSigned += $newObjDllNotSigned
    }  




###########################################################################################################################
###########################################################################################################################
###########################################################################################################################

#END OF IF
}


################################################
########  AUTHENTICODE SIGNATURE  ##############
################################################
#WARNING - Very long running process - enable only when required
#START OF IF
if ($authenticode -eq "y")
{

Write-Host " "
Write-Host "Searching for authenticode signature hashmismatch" -foregroundColor Green

    $fragAuthCodeSig=@()
    $newObjAuthSig=@()

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root
 
    foreach ($rt in $drvRoot)
        {
            $getAuthfiles = Get-ChildItem -Path $rt -Recurse -depth $depth -force | 
            where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"} |
            where { ! $_.PSIsContainer `
            -and $_.extension -ne ".log" `
            -and $_.extension -ne ".hve" `
            -and $_.extension -ne ".txt" `
            -and $_.extension -ne ".evtx" `
            -and $_.extension -ne ".elt"}

            foreach($file in $getAuthfiles)
            {
                $getAuthCodeSig = get-authenticodesignature -FilePath $file.FullName | where {$_.Status -eq "hashmismatch"
            }

        if ($getAuthCodeSig.path -eq $null){}
        else 
            {
                $authPath = $getAuthCodeSig.path
                $authStatus = $getAuthCodeSig.status

                $newObjAuthSig = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjAuthSig -Type NoteProperty -Name PathAuthCodeSig -Value $authPath
                Add-Member -InputObject $newObjAuthSig -Type NoteProperty -Name StatusAuthCodeSig -Value $authStatus
                $fragAuthCodeSig += $newObjAuthSig
            }
        }
    }

Write-Host " "
Write-Host "Completed searching for authenticode signature hashmismatch" -foregroundColor Green
#END OF IF
}

################################################
##############  SHARES AND PERMS  ##############
################################################ 

Write-Host " "
Write-Host "Auditing Shares and permissions" -foregroundColor Green
sleep 3

    $getShr = Get-SmbShare | where {$_.name -ne "IPC$"}
    $Permarray=@()
    $fragShare=@()

    foreach($shr in $getShr)
    {
        $Permarray=@()
        $shrName = $Shr.name
        $shrPath = $Shr.path
        $shrDes = $Shr.description

        $getShrPerms = Get-FileShareAccessControlEntry -Name $shr.Name
    
        foreach($perms in $getShrPerms)
        {
            $Permarray += $perms.AccountName
        }
    
            $arrayjoin = $Permarray -join ",  "
    
            $newObjShare = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjShare -Type NoteProperty -Name Name -Value $shrName
            Add-Member -InputObject $newObjShare -Type NoteProperty -Name Path -Value $shrPath
            Add-Member -InputObject $newObjShare -Type NoteProperty -Name Perms -Value $arrayjoin
            $fragShare += $newObjShare
        }

Write-Host " "
Write-Host "Finised Auditing Shares and permissions" -foregroundColor Green

################################################
############  EMBEDDED PASSWORDS  ##############
################################################  

Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all files for passwords, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Embedded Password in Files" -foregroundColor Green
sleep 7
  
#Passwords in Processes
    $getPSPass = gwmi win32_process -ErrorAction SilentlyContinue | 
    Select-Object Caption, Description,CommandLine | 
    where {$_.commandline -like "*pass*" -or $_.commandline -like "*credential*" -or $_.commandline -like "*username*"  }

    $fragPSPass=@()
    foreach ($PStems in $getPSPass)
    {
        $PSCap = $PStems.Caption
        $PSDes = $PStems.Description
        $PSCom = $PStems.CommandLine

        $newObjPSPass = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessCaption -Value  $PSCap
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessDescription -Value  $PSDes
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessCommandLine -Value  $PSCom
        $fragPSPass += $newObjPSPass
    }

#passwords embedded in files
#findstr /si password *.txt - alt

    $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
    $drvRoot = $drv.root
    $fragFilePass=@()
    $depthExtra = [int]$depth + 2
    foreach ($rt in $drvRoot)
        {
            $getUserFolder = Get-ChildItem -Path $rt -Recurse -Depth $depthExtra -Force -ErrorAction SilentlyContinue |
            where {$_.FullName -notmatch "WinSXS" `
            -and $_.FullName -notmatch "Packages" `
            -and $_.FullName -notmatch "Containers\BaseImages" `
            -and $_.FullName -notmatch  "MicrosoftOffice" `
            -and $_.FullName -notmatch "AppRepository" `
            -and $_.FullName -notmatch "IdentityCRL" `
            -and $_.FullName -notmatch "UEV" `
            -and $_.FullName -notlike "MicrosoftOffice201" `
            -and $_.FullName -notmatch "DriverStore" `
            -and $_.FullName -notmatch "spool" `
            -and $_.FullName -notmatch "icsxm"  } |
            where {$_.Extension -eq ".txt"`
            -or $_.Extension -eq ".ini" `
            -or $_.Extension -eq ".xml"}  #xml increase output, breaks report

            foreach ($PassFile in $getUserFolder)
            {
                #Write-Host $PassFile.fullname -ForegroundColor Yellow
                $SelectPassword  = Get-Content $PassFile.FullName |  Select-String -Pattern password, credential
 
            if ($SelectPassword -like "*password*")
            {
                $newObjFilePass = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjFilePass -Type NoteProperty -Name FilesContainingPassword -Value  $PassFile.FullName 
                $fragFilePass += $newObjFilePass
            }
        }
    }

Write-Host " "
Write-Host "Finished Searching for Embedded Password in Files" -foregroundColor Green


################################################
#####  SEARCHING FOR REGISTRY PASSWORDS   ######
################################################
Write-Host " "
Write-Host "Auditing Registry Passwords" -foregroundColor Green
sleep 5

    $VulnReport = "C:\SecureReport"
    $OutFunc = "RegPasswords" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $secEditPath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"

    #Enter list of words to search
    $regSearchWords = "password", "passwd"

    foreach ($regSearchItems in $regSearchWords){
        #swapped to native tool, Powershell is too slow
        reg query HKLM\SOFTWARE /f $regSearchItems /t REG_SZ /s >> $secEditPath
        reg query HKCU\SOFTWARE /f $regSearchItems /t REG_SZ /s >> $secEditPath
}

$getRegPassCon = (get-content $secEditPath | where {$_ -notmatch "classes" -and $_ -notmatch "ClickToRun" -and $_ -notmatch "microsoft" -and $_ -notmatch "default"} | Select-String -Pattern "hkey_")
$fragRegPasswords=@()
foreach ($getRegPassItem in $getRegPassCon)
{
    foreach ($regSearchItems in $regSearchWords)
    {
        $regPassValue = get-itemproperty $getRegPassItem | where {$_ -like "*$regSearchItems*"}
        
        if ($regPassValue -ne $null){
            #$regPassValue | write-host -ForegroundColor yellow
            $regPassPath = $regPassValue.PSPath.Replace("Microsoft.PowerShell.Core\Registry::","") 
        
            $regPassword = $regPassValue.$regSearchItems
         
            $newObjRegPasswords = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPath -Value $regPassPath
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryValue -Value $regSearchItems
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPassword -Value $regPassword 
            $fragRegPasswords += $newObjRegPasswords
        }
    }
}


Write-Host " "
Write-Host "Finished Searching for Embedded Password in the Registry" -foregroundColor Green

################################################
###############  DLL HIJACKING  ################
################################################
#Loaded  dll's that are vulnerable to dll hijacking - users permissions allow write

Write-Host " "
Write-Host "Searching for active processes that are vulnerable to dll hijacking" -foregroundColor Green
sleep 2

$getDll = Get-Process
$fragDLLHijack=@()
foreach ($dll in $getDll)
{
    $procName = $dll.Name
    $dllMods = $dll | Select-Object -ExpandProperty modules 
    $dllFilename = $dllMods.filename

    foreach ($dllPath in $dllFilename)
    {
        $dllFileAcl = Get-Acl $dllPath -ErrorAction SilentlyContinue

        if ($dllFileAcl | where {$_.accesstostring -like "*Users Allow  Write*" -or `
        $_.accesstostring -like "*Users Allow  Modify*" -or `
        $_.accesstostring -like "*Users Allow  FullControl*" -or `
        $_.accesstostring -like "*Everyone Allow  Write*" -or `
        $_.accesstostring -like "*Everyone Allow  Modify*" -or `
        $_.accesstostring -like "*Everyone Allow  FullControl*" -or `
        $_.accesstostring -like "*Authenticated Users Allow  Write*" -or `
        $_.accesstostring -like "*Authenticated Users Allow  Modify*" -or `
        $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $getAuthCodeSig = get-authenticodesignature -FilePath $dllPath 
                $dllStatus = $getAuthCodeSig.Status

                $newObjDLLHijack = New-Object psObject
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLProcess -Value $procName
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLPath -Value $dllPath
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLSigStatus -Value $dllStatus
                $fragDLLHijack += $newObjDLLHijack
            }              
     }
}

################################################
####################  ASR  #####################
################################################

Write-Host " "
Write-Host "Starting ASR Audit" -foregroundColor Green
sleep 5

$VulnReport = "C:\SecureReport"
$OutFunc = "ASR" 
                
$tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
if ($tpSec10 -eq $false)
{
   New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
}

$ASRPathtxt = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"
$getASRGuids = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ErrorAction SilentlyContinue

if ($getASRGuids -eq $null)
    {
    Set-Content -Path $ASRPathtxt -Value "ASP Policy is not set: 0"
    $getASRCont = Get-Content $ASRPathtxt | Select-String -Pattern ": 1", ": 0"
    }
else
    {
    $getASRGuids | Out-File $ASRPathtxt
    $getASRCont = Get-Content $ASRPathtxt | Select-String -Pattern ": 1", ": 0"
    }


#List of known ASR's
$asrDescription = 
"Block abuse of exploited vulnerable signed drivers - 56a863a9-875e-4185-98a7-b882c64b5ce5",
"Block adobe Reader from creating child processes - 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
"Block all Office applications from creating child processes - d4f940ab-401b-4efc-aadc-ad5f3c50688a",
"Block credential stealing from the Windows local security authority subsystem (lsass.exe) - 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
"Block executable content from email client and webmail - be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
"Block executable files from running unless they meet a prevalence, age, or trusted list criterion - 01443614-cd74-433a-b99e-2ecdc07bfc25",
"Block execution of potentially obfuscated scripts - 5beb7efe-fd9a-4556-801d-275e5ffc04cc",
"Block JavaScript or VBScript from launching downloaded executable content - d3e037e1-3eb8-44c8-a917-57927947596d",
"Block Office applications from creating executable content - 3b576869-a4ec-4529-8536-b80a7769e899",
"Block Office applications from injecting code into other processes - 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
"Block Office communication application from creating child processes - 26190899-1602-49e8-8b27-eb1d0a1ce869",
"Block persistence through WMI event subscription * File and folder exclusions not supported. - e6db77e5-3df2-4cf1-b95a-636979351e5b",
"Block process creations originating from PSExec and WMI commands - d1e49aac-8f56-4280-b9ba-993a6d77406c",
"Block untrusted and unsigned processes that run from USB - b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
"Block Win32 API calls from Office macros - 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
"Block Use advanced protection against ransomware - c1db55ab-c21a-4637-bb3f-a12568109d35"


$ASRList = 
"9BE9BA2D9-53EA-4CDC-84E5-9B1EEEE4655",
"D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
"3B576869-A4EC-4529-8536-B80A7769E899",
"75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
"D3E037E1-3EB8-44C8-A917-57927947596D",
"5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
"92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
"01443614-CD74-433A-B99E-2ECDC07BFC25",
"C1DB55AB-C21A-4637-BB3F-A12568109D35",
"9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
"D1E49AAC-8F56-4280-B9BA-993A6D77406C",
"B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
"26190899-1602-49E8-8B27-EB1D0A1CE869",
"7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
"E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
"BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
"56a863a9-875e-4185-98a7-b882c64b5ce5"

$fragASR=@()
$asrGuidSetObj=@()

foreach ($getASRContItems in $getASRCont)
{
$asrGuid = $getASRContItems.ToString().split(":").replace(" ","")[0]
$asrGuidSetting = $getASRContItems.ToString().split(":").replace(" ","")[1]

    foreach ($asrGuiditem in $asrGuid)
        {
        $asrGuidContains = $ASRList.Contains($asrGuiditem) 
        write-host "$asrGuiditem"
        Write-Host $asrGuidContains-ForegroundColor Green
        if ($asrGuidContains -eq "true")
            {
            $ASRGuidObj = "ASR Guid $asrGuiditem is set" 
            }
        else
            {
            $ASRGuidObj = "Warning - ASR Guid $asrGuiditem is not set  Warning" 
            }
        
        if ($asrGuidSetting -eq "1")
            {
            $asrGuidSetObj = "ASR = 1"    
            }
        else
            {
            $asrGuidSetObj = "Warning - ASR is disabled Warning"
            }

           $ASRDescripObj = $asrDescription | Select-String -Pattern $asrGuid

           $newObjASR = New-Object -TypeName PSObject
           Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRGuid -Value $ASRGuidObj
           Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRSetting -Value $asrGuidSetObj
           Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRDescription -Value $ASRDescripObj
           $fragASR += $newObjASR
        }
}

################################################
##########  DOMAIN USER DETAILS  ###############
################################################
#Reports on the credentials of the user running this report 
    $VulnReport = "C:\SecureReport"
    $OutFunc = "DomainUser"  

    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }
    
    $DomainUserPath = "C:\SecureReport\output\$OutFunc\"


    $HostDomain = ((Get-CimInstance -ClassName win32_computersystem).Domain).split(".")[0] + "\" 

    $DomA = $HostDomain + "Domain Admins"
    $DomAWarn = "Warning - " + $HostDomain + "Domain Admins" + "  Warning"

    $EntA = $HostDomain + "Enterprise Admins"
    $EntAWarn = "Warning - " + $HostDomain + "Enterprise Admins" + "  Warning"

    $SchA = $HostDomain + "Schema Admins"
    $SchAWarn = "Warning - " + $HostDomain + "Schema Admins" + "  Warning"

    #WHOAMI /User /FO CSV /NH > C:\SecureReport\output\DomainUser\User.csv
    WHOAMI /Groups /FO CSV /NH > C:\SecureReport\output\DomainUser\Groups.csv
    WHOAMI /Priv /FO CSV /NH > C:\SecureReport\output\DomainUser\Priv.csv

    (Get-Content C:\SecureReport\output\DomainUser\Groups.csv).replace("Mandatory group,","").replace("Enabled by default,","").replace("Enabled group,","").replace("Enabled group","").replace("Group owner","").replace(',"Attributes"',"").replace(',"  "',"").replace(',""',"").replace($EntA,$EntAWarn).replace($DomA,$DomAWarn).replace($SchA,$SchAWarn)  | out-file C:\SecureReport\output\DomainUser\Groups.csv     
    (Get-Content C:\SecureReport\output\DomainUser\Priv.csv).replace("Enabled","Review - Enabled Review") | out-file C:\SecureReport\output\DomainUser\Priv.csv
    
    #import-csv C:\SecureReport\output\DomainUser\User.csv -Delimiter "," | Export-Clixml C:\SecureReport\output\DomainUser\User.xml
    #$whoamiUser = Import-Clixml C:\SecureReport\output\DomainUser\User.xml

    import-csv C:\SecureReport\output\DomainUser\groups.csv -Delimiter "," | Export-Clixml C:\SecureReport\output\DomainUser\groups.xml
    $whoamiGroups = Import-Clixml C:\SecureReport\output\DomainUser\groups.xml

    import-csv C:\SecureReport\output\DomainUser\Priv.csv -Delimiter "," | Export-Clixml C:\SecureReport\output\DomainUser\Priv.xml
    $whoamiPriv = Import-Clixml C:\SecureReport\output\DomainUser\Priv.xml


################################################
#######  RECOMMENDED SECURITY SETTINGS  ########
################################################
    $fragNetCredVal=@()

    <#

    Do not display network selection UI Enabled

    Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI Enabled

    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.
    If you enable this policy setting, the PC's network connectivity state cannot be changed without signing into Windows.
    If you disable or don't configure this policy setting, any user can disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
    #>

    $NetCredDescrip = "Do not display network selection UI Enabled"
    $gpopath = "Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "DontDisplayNetworkSelectionUI"

    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal=@()
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal")

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting  -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    
    <#
    Enumerate local users on domain-joined computers

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows local users to be enumerated on domain-joined computers.
    If you enable this policy setting, Logon UI will enumerate all local users on domain-joined computers.
    If you disable or do not configure this policy setting, the Logon UI will not enumerate local users on domain-joined computers.
    #>
    
    $NetCredDescrip = "Enumerate local users on domain-joined computers"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "EnumerateLocalUsers"

    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal=@()
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal")

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is Disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Do not display the password reveal button

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.
    If you enable this policy setting, the password reveal button will not be displayed after a user types a password in the password entry text box.
    If you disable or do not configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box.
    By default, the password reveal button is displayed after a user types a password in the password entry text box. To display the password, click the password reveal button.
    The policy applies to all Windows components and applications that use the Windows system controls, including Internet Explorer.
    
    #>

    $NetCredDescrip = "Do not display the password reveal button"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\CredUI\'
    $NetCredVal=@()
    $NetCredVal = "DisablePasswordReveal"
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal=@()
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal")

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is Enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


   <#
    Enumerate administrator accounts on elevation

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\

    This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application. By default, administrator accounts are not displayed when the user attempts to elevate a running application.
    If you enable this policy setting, all local administrator accounts on the PC will be displayed so the user can choose one and enter the correct password.
    If you disable this policy setting, users will always be required to type a user name and password to elevate.
    #>

    $NetCredDescrip = "Enumerate administrator accounts on elevation"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\'
    $NetCredVal=@()
    $NetCredVal = "EnumerateAdministrators"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is Disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Require trusted path for credential entry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface

    This policy setting requires the user to enter Microsoft Windows credentials using a trusted path, to prevent a Trojan horse or other types of malicious code from stealing the user's Windows credentials.
    Note: This policy affects nonlogon authentication tasks only. As a security best practice, this policy should be enabled.
    If you enable this policy setting, users will be required to enter Windows credentials on the Secure Desktop by means of the trusted path mechanism.
    If you disable or do not configure this policy setting, users will enter Windows credentials within the user's desktop session, potentially allowing malicious code access to the user's Windows credentials.
    #>

    $NetCredDescrip = "Require trusted path for credential entry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\'
    $NetCredVal=@()
    $NetCredVal = "EnableSecureCredentialPrompting"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is Enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Prevent the use of security questions for local accounts

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface

    If you turn this policy setting on, local users won't be able to set up and use security questions to reset their passwords.    
    #>

    $NetCredDescrip = "Prevent the use of security questions for local accounts"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "NoLocalPasswordResetQuestions"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is Enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Disable or enable software Secure Attention Sequence

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options
    
    This policy setting controls whether or not software can simulate the Secure Attention Sequence (SAS).

    If you enable this policy setting, you have one of four options:

    If you set this policy setting to "None," user mode software cannot simulate the SAS.
    If you set this policy setting to "Services," services can simulate the SAS.
    If you set this policy setting to "Ease of Access applications," Ease of Access applications can simulate the SAS.
    If you set this policy setting to "Services and Ease of Access applications," both services and Ease of Access applications can simulate the SAS.

    If you disable or do not configure this setting, only Ease of Access applications running on the secure desktop can simulate the SAS.   
    #>

    $NetCredDescrip = "Disable or enable software Secure Attention Sequence"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "SoftwareSASGeneration"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq $null)
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Sign-in last interactive user automatically after a system-initiated restart

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options 

    This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system.

    If you enable or do not configure this policy setting, the device securely saves the user's credentials 
    (including the user name, domain and encrypted password) to configure automatic sign-in after a Windows Update restart. 
    After the Windows Update restart, the user is automatically signed-in and the session is automatically locked with all 
    the lock screen apps configured for that user.
    If you disable this policy setting, the device does not store the user's credentials for automatic sign-in after a 
    Windows Update restart. The users' lock screen apps are not restarted after the system restarts.
    #>
    $NetCredDescrip = "Sign-in last interactive user automatically after a system-initiated restart"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "	DisableAutomaticRestartSignOn"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0" -or $getNetCredVal -eq $null)
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled or not Set Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is Enabled " 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Interactive logon: Do not require CTRL+ALT+DEL

    Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options 

    This security setting determines whether pressing CTRL+ALT+DEL is required before a user can log on.

    If this policy setting is enabled on a device, a user is not required to press CTRL+ALT+DEL to log on.
    If this policy is disabled, any user is required to press CTRL+ALT+DEL before logging on to the Windows operating system 
    (unless they are using a smart card for logon).
    Microsoft developed this feature to make it easier for users with certain types of physical impairments to log on to device
    running the Windows operating system; however, not having to press the CTRL+ALT+DELETE key combination leaves users susceptible 
    to attacks that attempt to intercept their passwords. Requiring CTRL+ALT+DELETE before users log on ensures that users are
    communicating by means of a trusted path when entering their passwords.
    A malicious user might install malware that looks like the standard logon dialog box for the Windows operating system, and 
    capture a user's password. The attacker can then log on to the compromised account with whatever level of user rights that user has.
    #>

    $NetCredDescrip = "Interactive logon: Do not require CTRL+ALT+DEL"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$NetCredDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "disablecad"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is Disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is Enabled or not defined Warning " 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Interactive logon: Number of previous logons to cache (in case domain controller is not available)

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    Windows caches previous users' logon information locally so that they can log on if a logon server is unavailable during later logon attempts.
    If a domain controller is unavailable and a user's logon information is cached, the user will be prompted with a dialog that says:
    A domain controller for your domain could not be contacted. You have been logged on using cached account information. Changes to your profile 
    since you last logged on may not be available.
    With caching disabled, the user is prompted with this message:
    The system cannot log you on now because the domain <DOMAIN_NAME> is not available.

    #>

    $NetCredDescrip = "Interactive logon: Number of previous logons to cache"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$NetCredDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'
    $NetCredVal=@()
    $NetCredVal = "CachedLogonsCount"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -lt "2")
    {
        $NetCredSet = "$NetCredDescrip caches $getNetCredVal previous logons, ideally this should be set to 1" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is $getNetCredVal, ideally this should be set to 1 Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Network access: Do not allow storage of passwords and credentials for network authentication

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This security setting determines whether Credential Manager saves passwords and credentials for later use when it gains domain authentication.

    Possible values
    Enabled

    Credential Manager does not store passwords and credentials on the device

    Disabled

    Credential Manager will store passwords and credentials on this computer for later use for domain authentication.

    Not defined

    Best practices
    It is a recommended practice to disable the ability of the Windows operating system to cache credentials on any 
    device where credentials are not needed. Evaluate your servers and workstations to determine the requirements. 
    Cached credentials are designed primarily to be used on laptops that require domain credentials when disconnected from the domain.

    #>
    $NetCredDescrip = "Network access: Do not allow storage of passwords and credentials for network authentication"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$NetCredDescrip"
    $RegKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "disabledomaincreds"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred
 

    <#
    Apply UAC restrictions to local accounts on network logons

    This setting controls whether local accounts can be used for remote administration via network logon 
    (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the 
    same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.

    Enabled (recommended): Applies UAC token-filtering to local accounts on network logons. Membership in 
    powerful group such as Administrators is disabled and powerful privileges are removed from the resulting 
    access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.

    Disabled: Allows local accounts to have full administrative rights when authenticating via network logon, 
    by configuring the LocalAccountTokenFilterPolicy registry value to 1.

    For more information about local accounts and credential theft, see "Mitigating Pass-the-Hash (PtH) 
    Attacks and Other Credential Theft Techniques": http://www.microsoft.com/en-us/download/details.aspx?id=36036.

    For more information about LocalAccountTokenFilterPolicy, see http://support.microsoft.com/kb/951016.

    #>
    $NetCredDescrip = "Apply UAC restrictions to local accounts on network logons"
    $gpopath ="No GPO Setting available"
    $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "LocalAccountTokenFilterPolicy"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled, mitigates Pass-the-Hash" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Network access: Allow anonymous SID/Name translation

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting enables or disables the ability of an anonymous user to request security identifier (SID) attributes for another user.
    If this policy setting is enabled, a user might use the well-known Administrators SID to get the real name of the built-in Administrator account, even if the account has been renamed. That person might then use the account name to initiate a brute-force password-guessing attack.
    Misuse of this policy setting is a common error that can cause data loss or problems with data access or security.

    #>
    $NetCredDescrip = "Network access: Allow anonymous SID/Name translation"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "AnonymousNameLookup"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Network access: Let Everyone permissions apply to anonymous users

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options


    This policy setting determines what additional permissions are granted for anonymous connections to the device. 
    If you enable this policy setting, anonymous users can enumerate the names of domain accounts and shared folders and 
    perform certain other activities. This capability is convenient, for example, when an administrator wants to grant 
    access to users in a trusted domain that does not maintain a reciprocal trust.

    By default, the token that is created for anonymous connections does not include the Everyone SID. Therefore, permissions 
    that are assigned to the Everyone group do not apply to anonymous users.

    #>
    $NetCredDescrip = "Network access: Let Everyone permissions apply to anonymous users"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "everyoneincludesanonymous"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Network access: Do not allow anonymous enumeration of SAM accounts

    RestrictAnonymousSAM (Sam accounts)

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting determines which additional permissions will be assigned for anonymous connections to the 
    device. Windows allows anonymous users to perform certain activities, such as enumerating the names of domain 
    accounts and network shares. This is convenient, for example, when an administrator wants to give access to users 
    in a trusted domain that does not maintain a reciprocal trust. However, even with this policy setting enabled,
     anonymous users will have access to resources with permissions that explicitly include the built-in group, ANONYMOUS LOGON.
    This policy setting has no impact on domain controllers. Misuse of this policy setting is a common error that 
    can cause data loss or problems with data access or security.

    #>
    $NetCredDescrip = "Network access: Do not allow anonymous enumeration of SAM accounts"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "RestrictAnonymousSAM"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Network access: Do not allow anonymous enumeration of SAM accounts and shares

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    RestrictAnonymous (Sam accounts and shares)

    This policy setting determines which additional permissions will be assigned for anonymous connections to the device. 
    Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares. 
    This is convenient, for example, when an administrator wants to give access to users in a trusted domain that does not 
    maintain a reciprocal trust. However, even with this policy setting enabled, anonymous users will have access to resources 
    with permissions that explicitly include the built-in group, ANONYMOUS LOGON.
    This policy setting has no impact on domain controllers. Misuse of this policy setting is a common error that can cause data 
    loss or problems with data access or security.

    #>
    $NetCredDescrip = "Network access: Do not allow anonymous enumeration of SAM accounts and shares"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "RestrictAnonymous"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Network access: Restrict anonymous access to Named Pipes and Shares

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting enables or disables the restriction of anonymous access to only those shared folders and 
    pipes that are named in the Network access: Named pipes that can be accessed anonymously and Network access: 
    Shares that can be accessed anonymously settings. The setting controls null session access to shared folders 
    on your computers by adding RestrictNullSessAccess with the value 1 in the registry key 
    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters. This registry value toggles null session 
    shared folders on or off to control whether the Server service restricts unauthenticated clients' access to named resources.
    Null sessions are a weakness that can be exploited through the various shared folders on the devices in your environment.


    #>
    $NetCredDescrip = "Network access: Restrict anonymous access to Named Pipes and Shares"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\'
    $NetCredVal=@()
    $NetCredVal = "RestrictNullSessAccess"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Network access: Restrict clients allowed to make remote calls to SAM

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
    O:BAG:BAD:(A;;RC;;;BA) = Administrator
    #>
    $NetCredDescrip = "Network access: Restrict clients allowed to make remote calls to SAM"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "RestrictRemoteSam"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "O:BAG:BAD:(A;;RC;;;BA)")
    {
        $NetCredSet = "$NetCredDescrip is enabled to allow Administrator remote access (O:BAG:BAD:(A;;RC;;;BA))" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"

    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled or not set Warning " 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Network security: Allow Local System to use computer identity for NTLM

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    When services connect to devices that are running versions of the Windows operating system earlier than 
    Windows Vista or Windows Server 2008, services that run as Local System and use SPNEGO (Negotiate) that revert 
    to NTLM will authenticate anonymously. In Windows Server 2008 R2 and Windows 7 and later, if a service connects 
    to a computer running Windows Server 2008 or Windows Vista, the system service uses the computer identity.
    When a service connects with the device identity, signing and encryption are supported to provide data protection. 
    (When a service connects anonymously, a system-generated session key is created, which provides no protection, 
    but it allows applications to sign and encrypt data without errors. Anonymous authentication uses a NULL session, 
    which is a session with a server in which no user authentication is performed; and therefore, anonymous access is allowed.)
    
    #>
    $NetCredDescrip = "Network security: Allow Local System to use computer identity for NTLM"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $NetCredVal=@()
    $NetCredVal = "UseMachineId"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Network security: Allow LocalSystem NULL session fallback

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy affects session security during the authentication process between devices running Windows Server 2008 R2 and Windows 7 
    and later and those devices running earlier versions of the Windows operating system. For computers running Windows Server 2008 R2 
    and Windows 7 and later, services running as Local System require a service principal name (SPN) to generate the session key. However, 
    if Network security: Allow Local System to use computer identity for NTLM is set to disabled, services running as Local System will 
    fall back to using NULL session authentication when they transmit data to servers running versions of Windows earlier than Windows 
    Vista or Windows Server 2008. NULL session does not establish a unique session key for each authentication; and thus, it cannot provide 
    integrity or confidentiality protection. The setting Network security: Allow LocalSystem NULL session fallback determines whether services 
    that request the use of session security are allowed to perform signature or encryption functions with a well-known key for application compatibility.
    
    #>
    $NetCredDescrip = "Network security: Allow LocalSystem NULL session fallback"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0\'
    $NetCredVal=@()
    $NetCredVal = "allownullsessionfallback"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "Warning - $NetCredDescrip is enabled Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred   

<#
    Disallow Autoplay for non-volume devices - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Disallow Autoplay for non-volume devices"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoAutoplayfornonVolume"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Disallow Autoplay for non-volume devices - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Disallow Autoplay for non-volume devices"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoAutoplayfornonVolume"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Set the default behavior for AutoRun - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Set the default behavior for AutoRun"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoAutorun"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Set the default behavior for AutoRun - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Set the default behavior for AutoRun"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoAutorun"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Turn off Autoplay - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Turn off Autoplay"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoDriveTypeAutoRun"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "255")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Turn off Autoplay - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $NetCredDescrip = "Turn off Autoplay"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "NoDriveTypeAutoRun"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "255")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

<#
    Prevent access to the command prompt

    User Configuration\Policies\Administrative Templates\System

    This policy setting prevents users from running the interactive command prompt Cmd.exe.

    This policy setting also determines whether batch files (.cmd and .bat) can run on the computer.
    If you enable this policy setting and the user tries to open a command window, the system displays a message explaining that a setting prevents the action. .
    If you disable this policy setting or don't configure it, users can run Cmd.exe and batch files normally.

    #>
    $NetCredDescrip = "Prevent access to the command prompt"
    $gpopath ="User Configuration\Policies\Administrative Templates\System\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "DisableCMD"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Prevent access to registry editing tools

    User Configuration\Policies\Administrative Templates\System

    #>
    $NetCredDescrip = "Prevent access to registry editing tools"
    $gpopath ="User Configuration\Policies\Administrative Templates\System\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "DisableRegistryTools"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "2")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Configure Windows Defender SmartScreen

    Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    This policy allows you to turn Windows Defender SmartScreen on or off. SmartScreen helps protect PCs by warning users before 
    running potentially malicious programs downloaded from the Internet. This warning is presented as an interstitial dialog shown 
    before running an app that has been downloaded from the Internet and is unrecognized or known to be malicious. No dialog is shown 
    for apps that do not appear to be suspicious.

    Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.
    If you enable this policy, SmartScreen will be turned on for all users. Its behavior can be controlled by the following options:
    • Warn and prevent bypass
    • Warn

    #>
    $NetCredDescrip = "Configure Windows Defender SmartScreen (File Explorer)"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "EnableSmartScreen"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled to Warn and prevent bypass" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is set warn and allow bypass" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Configure Windows Defender SmartScreen

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer

    This policy allows you to turn Windows Defender SmartScreen on or off. SmartScreen helps protect PCs by warning users before 
    running potentially malicious programs downloaded from the Internet. This warning is presented as an interstitial dialog shown 
    before running an app that has been downloaded from the Internet and is unrecognized or known to be malicious. No dialog is shown 
    for apps that do not appear to be suspicious.

    Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.
    If you enable this policy, SmartScreen will be turned on for all users. Its behavior can be controlled by the following options:
    • Warn and prevent bypass
    • Warn

    Info: looks like both GPO's set the same registry setting

    #>
    $NetCredDescrip = "Configure Windows Defender SmartScreen (Windows Defender SmartScreen)"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $NetCredVal=@()
    $NetCredVal = "EnableSmartScreen"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled to Warn and prevent bypass" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is set warn and allow bypass" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Allow user control over installs

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, some of the security features of Windows Installer are bypassed. It permits installations to 
    complete that otherwise would be halted due to a security violation.
        If you disable or do not configure this policy setting, the security features of Windows Installer prevent users from changing 
        installation options typically reserved for system administrators, such as specifying the directory to which files are installed.

    #>
    $NetCredDescrip = "Allow user control over installs"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Installer\'
    $NetCredVal=@()
    $NetCredVal = "EnableUserControl"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip enabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Always install with elevated privileges - Computer

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, privileges are extended to all programs. These privileges are usually reserved for programs 
    that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available 
    in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    If you disable or do not configure this policy setting, the system applies the current user's permissions when it installs programs 
    that a system administrator does not distribute or offer.
    Note: This policy setting appears both in the Computer Configuration and User Configuration folders. To make this policy setting 
    effective, you must enable it in both folders.

    #>
    $NetCredDescrip = "Always install with elevated privileges"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Installer\'
    $NetCredVal=@()
    $NetCredVal = "AlwaysInstallElevated"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip enabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Always install with elevated privileges - User

    User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, privileges are extended to all programs. These privileges are usually reserved for programs 
    that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available 
    in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    If you disable or do not configure this policy setting, the system applies the current user's permissions when it installs programs 
    that a system administrator does not distribute or offer.
    Note: This policy setting appears both in the Computer Configuration and User Configuration folders. To make this policy setting 
    effective, you must enable it in both folders.

    #>
    $NetCredDescrip = "Always install with elevated privileges"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$NetCredDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Installer\'
    $NetCredVal=@()
    $NetCredVal = "AlwaysInstallElevated"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip enabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Devices: Prevent users from installing printer drivers

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    #>
    $NetCredDescrip = "Devices: Prevent users from installing printer drivers"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$NetCredDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\'
    $NetCredVal=@()
    $NetCredVal = "AddPrinterDrivers"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled, only Admin can install printer drivers" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Do not process the legacy run list

    Computer Configuration\Policies\Administrative Templates\System\Logon

    Once malicious code has been copied to a workstation, an adversary with registry access can remotely schedule it 
    to execute (i.e. using the run once list) or to automatically execute each time Microsoft Windows starts (i.e. using the legacy run list). 
    To reduce this risk, legacy and run once lists should be disabled. This may interfere with the operation of legitimate applications that 
    need to automatically execute each time Microsoft Windows starts. In such cases, the Run these programs at user logon Group Policy 
    setting can be used to perform the same function in a more secure manner when defined at a domain level; however, if not used this Group Policy 
    setting should be disabled rather than left in its default undefined state.

    #>
    $NetCredDescrip = "Do not process the legacy run list"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "DisableCurrentUserRun"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Do not process the legacy run list

    Computer Configuration\Policies\Administrative Templates\System\Logon

    Once malicious code has been copied to a workstation, an adversary with registry access can remotely schedule it 
    to execute (i.e. using the run once list) or to automatically execute each time Microsoft Windows starts (i.e. using the legacy run list). 
    To reduce this risk, legacy and run once lists should be disabled. This may interfere with the operation of legitimate applications that 
    need to automatically execute each time Microsoft Windows starts. In such cases, the Run these programs at user logon Group Policy 
    setting can be used to perform the same function in a more secure manner when defined at a domain level; however, if not used this Group Policy 
    setting should be disabled rather than left in its default undefined state.

    #>
    $NetCredDescrip = "Do not process the run once list"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $NetCredVal=@()
    $NetCredVal = "DisableLocalMachineRunOnce"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Do not process the legacy run list

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting specifies additional programs or documents that Windows starts automatically when a user logs on to the system.
    If you enable this policy setting, you can specify which programs can run at the time the user logs on to this computer that has this policy applied.
    To specify values for this policy setting, click Show. In the Show Contents dialog box in the Value column, type the name of the executable program (.exe) 
    file or document file. To specify another name, press ENTER, and type the name. Unless the file is located in the %Systemroot% directory, you must specify 
    the fully qualified path to the file.
    If you disable or do not configure this policy setting, the user will have to start the appropriate programs after logon

    #>
    $NetCredDescrip = "Run these programs at user logon"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\'
    $NetCredVal=@()
    $NetCredVal = "1"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq 1)
    {
        $NetCredSet = "Warning - $NetCredDescrip is enabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "$NetCredDescrip disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

<#
    Restrict Unauthenticated RPC clients

    Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call

    Remote Procedure Call (RPC) is a technique used for facilitating client and server application communications using a common interface. 
    RPC is designed to make client and server interaction easier and safer by using a common library to handle tasks such as security, 
    synchronisation and data flows. If unauthenticated communications are allowed between client and server applications, it could result in 
    accidental disclosure of sensitive information or the failure to take advantage of RPC security functionality. To reduce this risk, all 
    RPC clients should authenticate to RPC servers.

    This policy setting impacts all RPC applications.  In a domain environment this policy setting should be used with caution as it can impact a 
    wide range of functionality including group policy processing itself.  Reverting a change to this policy setting can require manual intervention 
    on each affected machine. 
    
    This policy setting should never be applied to a domain controller.

    #>
    $NetCredDescrip = "Restrict Unauthenticated RPC clients"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\'
    $NetCredVal=@()
    $NetCredVal = "RestrictRemoteClients"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled - Not to be applied against DCs Warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Restrict Unauthenticated RPC clients

    Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call

    This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call 
    they are making contains authentication information. The Endpoint Mapper Service on computers running Windows 
    NT4 (all service packs) cannot process authentication information supplied in this manner.
    If you disable this policy setting, RPC clients will not authenticate to the Endpoint Mapper Service, but they 
    will be able to communicate with the Endpoint Mapper Service on Windows NT4 Server.
    If you enable this policy setting, RPC clients will authenticate to the Endpoint Mapper Service for calls that 
    contain authentication information. Clients making such calls will not be able to communicate with the Windows 
    NT4 Server Endpoint Mapper Service.

    #>
    $NetCredDescrip = "Enable RPC Endpoint Mapper Client Authentication"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\'
    $NetCredVal=@()
    $NetCredVal = "EnableAuthEpResolution"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider

    Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool

    #>
    $NetCredDescrip = "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\$NetCredDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\'
    $NetCredVal=@()
    $NetCredVal = "DisableQueryRemoteServer"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is disabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip enabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Turn off Inventory Collector

    Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility

    The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft. 
    This information is used to help diagnose compatibility problems.
    If you enable this policy setting, the Inventory Collector will be turned off and data will not be sent to Microsoft. Collection of
     installation data through the Program Compatibility Assistant is also disabled.
    If you disable or do not configure this policy setting, the Inventory Collector will be turned on.

    #>
    $NetCredDescrip = "Turn off Inventory Collector"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $NetCredVal=@()
    $NetCredVal = "DisableInventory"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Turn off Steps Recorder

    Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility
    Steps Recorder keeps a record of steps taken by the user. The data generated by Steps Recorder can be used in feedback systems 
    such as Windows Error Reporting to help developers understand and fix problems. The data includes user actions such as keyboard 
    input and mouse input, user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.

    #>
    $NetCredDescrip = "Turn off Steps Recorder"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $NetCredVal=@()
    $NetCredVal = "DisableUAR"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Prevent access to 16-bit applications

    Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility

    Specifies whether to prevent the MS-DOS subsystem (ntvdm.exe) from running on this computer. This setting affects the launching of 16-bit
     applications in the operating system.
    You can use this setting to turn off the MS-DOS subsystem, which will reduce resource usage and prevent users from running 16-bit applications. 
    To run any 16-bit application or any application with 16-bit components, ntvdm.exe must be allowed to run. The MS-DOS subsystem starts when the 
    first 16-bit application is launched. While the MS-DOS subsystem is running, any subsequent 16-bit applications launch faster, but overall resource 
    usage on the system is increased.
    If the status is set to Enabled, the MS-DOS subsystem is prevented from running, which then prevents any 16-bit applications from running. 
    In addition, any 32-bit applications with 16-bit installers or other 16-bit components cannot run.

    #>
    $NetCredDescrip = "Prevent access to 16-bit applications"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $NetCredVal=@()
    $NetCredVal = "VDMDisallowed"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Allow Telemetry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds

    Diagnostic data is categorized into four levels, as follows:
    - 0 (Security). Information that's required to help keep Windows, Windows Server, and System Center secure, including data about the Connected User Experiences and Telemetry component settings, the Malicious Software Removal Tool, and Windows Defender.
    - 1 (Required). Basic device info, including: quality-related data, app compatibility, and data from the Security level.
    - 2 (Enhanced). Additional insights, including: how Windows, Windows Server, System Center, and apps are used, how they perform, advanced reliability data, and data from both the Required and the Security levels.
    - 3 (Optional). All data necessary to identify and help to fix problems, plus data from the Security, Required, and Enhanced levels.

    #>
    $NetCredDescrip = "Allow Telemetry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection\'
    $NetCredVal=@()
    $NetCredVal = "AllowTelemetry"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is enabled for Enterprise Only - Computer" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


        <#
    Allow Telemetry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds

    Diagnostic data is categorized into four levels, as follows:
    - 0 (Security). Information that's required to help keep Windows, Windows Server, and System Center secure, including data about the Connected User Experiences and Telemetry component settings, the Malicious Software Removal Tool, and Windows Defender.
    - 1 (Required). Basic device info, including: quality-related data, app compatibility, and data from the Security level.
    - 2 (Enhanced). Additional insights, including: how Windows, Windows Server, System Center, and apps are used, how they perform, advanced reliability data, and data from both the Required and the Security levels.
    - 3 (Optional). All data necessary to identify and help to fix problems, plus data from the Security, Required, and Enhanced levels.

    #>
    $NetCredDescrip = "Allow Telemetry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\$NetCredDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection\'
    $NetCredVal=@()
    $NetCredVal = "AllowTelemetry"
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "0")
    {
        $NetCredSet = "$NetCredDescrip is enabled for Enterprise Only - User" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip disabled warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred

    <#
    Configure Corporate Windows Error Reporting

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings

    This policy setting specifies a corporate server to which Windows Error Reporting sends reports (if you do not want to send error reports to Microsoft).
    If you enable this policy setting, you can specify the name or IP address of an error report destination server on your organization's network. 
    You can also select Connect using SSL to transmit error reports over a Secure Sockets Layer (SSL) connection, and specify a port number on the destination 
    server for transmission.

    #>
    $NetCredDescrip = "Configure Corporate Windows Error Reporting"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings\$NetCredDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\'
    $NetCredVal=@()
    $NetCredVal = "CorporateWerUseSSL"   #query for SSL to be enabled
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is not set warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


    <#
    Safe Mode

    An adversary with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with 
    Command Prompt options may be able to bypass system protections and security functionality. To reduce this risk, users with standard credentials 
    should be prevented from using Safe Mode options to log in.

    The following registry entry can be implemented using Group Policy preferences to prevent non-administrators from using Safe Mode options.

    #>
    $NetCredDescrip = "Prevent SafeMode for Non Admins"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings\$NetCredDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\'
    $NetCredVal=@()
    $NetCredVal = "SafeModeBlockNonAdmins"   
    $getNetCredVal=@()
    $getNetCred = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getNetCredVal = $getNetCred.GetValue("$NetCredVal") 

    if ($getNetCredVal -eq "1")
    {
        $NetCredSet = "$NetCredDescrip is enabled" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }
    else
    {
        $NetCredSet = "Warning - $NetCredDescrip is not set warning" 
        $NetCredReg = "<div title=$gpoPath>$RegKey"
    }

    $newObjNetCred = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialSetting -Value  $NetCredSet
    Add-Member -InputObject $newObjNetCred -Type NoteProperty -Name CredentialRegValue -Value $NetCredReg 
    $fragNetCredVal += $newObjNetCred


################################################
##########  HTML GENERATION  ###################
################################################

#Tenaka and Default Colour scheme of dark brown and copper text
#B87333 = copper
#250F00 = root beer
#181818 = alt background 
#4682B4 = Blue dark pastel
#FF4040 = Red pastel
#DBDBDB = grey
#766A6A = Dark Grey with hint of beige
#A88F7E = mouse
#<font color="red"> <font>

#Blue - dark
#FFF9EC = copper
#28425F = root beer
#06273A = alt background 
#FFEEE0 = Blue dark pastel
#FF4040 = Red pastel
#FFFEF8 = grey
#766A6A = Dark Grey with hint of beige
#A88F7E = mouse
#<font color="red"> <font>

#Light
#79253D = copper
#EBEAE7 = root beer
#F4F2EC = alt background 
#FFEEE0 = Blue dark pastel
#FF4040 = Red pastel
#D0D0D0 = grey
#766A6A = Dark Grey with hint of beige
#A88F7E = mouse
#<font color="red"> <font>

if ($Scheme -eq "Tenaka")
{
$titleCol = "#4682B4"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body|aq
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#B87333;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:150%;
        font-family:helvetica;
        margin:0,0,10px,0;
        word-break:normal; 
        word-wrap:break-word
    }
    h2
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:120%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    h3
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#250F00; 
        color:#766A6A;
        font-size:90%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#B87333;
        background-color:#250F00
    }
    td
    {
        border-width: 1px;
        padding:7px;
        border-style: solid; 
        border-style: #B87333
    }
    tr:nth-child(odd) 
    {
        background-color:#250F00;
    }
    tr:nth-child(even) 
    {
        background-color:#181818;
    }

    </Style>
"@
}

if ($Scheme -eq "Dark")
{
$titleCol = "#4682B4"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#FFF9EC;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:150%;
        font-family:helvetica;
        margin:0,0,10px,0;
        word-break:normal; 
        word-wrap:break-word
    }
    h2
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:120%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    h3
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#06273A; 
        color:#766A6A;
        font-size:90%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#FFF9EC;
        background-color:#06273A
    }
    td
    {
        border-width: 1px;
        padding:7px;
        border-style: solid; 
        border-style: #FFF9EC
    }
    tr:nth-child(odd) 
    {
        background-color:#06273A;
    }
    tr:nth-child(even) 
    {
        background-color:#28425F;
    }

    </Style>
"@
}

if ($Scheme -eq "Light")
{
$titleCol = "#000000"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body
    {
        background-color:#EBEAE7; 
        color:#79253D;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#FFF9EC;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#EBEAE7 
        color:#79253D;
        font-size:150%;
        font-family:helvetica;
        margin:0,0,10px,0;
        word-break:normal; 
        word-wrap:break-word
    }
    h2
    {
        background-color:#EBEAE7; 
        color:#79253D;
        font-size:120%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    h3
    {
        background-color:#EBEAE7; 
        color:#79253D;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#EBEAE7; 
        color:#877F7D;
        font-size:90%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#79253D;
        background-color:#EBEAE7
    }
    td
    {
        border-width: 1px;
        padding:7px;
        border-style: solid; 
        border-style: #79253D
    }
    tr:nth-child(odd) 
    {
        background-color:#EBEAE7;
    }
    tr:nth-child(even) 
    {
        background-color:#F4F2EC;
    }

    </Style>
"@
}

if ($Scheme -eq "Grey")
{
$titleCol = "#D3BAA9"

#HTML GENERATOR CSS
$style = @"
    <Style>
    
    body
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#D3BAA9;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:150%;
        font-family:helvetica;
        margin:0,0,10px,0;
        word-break:normal; 
        word-wrap:break-word
    }
    h2
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:120%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    h3
    {
        background-color:#454545; 
        color:#A88F7E;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal;
        width:auto
    }
        h4
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:90%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#D3BAA9;
        background-color:#454545
    }
    td
    {
        border-width: 1px;
        padding:7px;
        border-style: solid; 
        border-style: #D3BAA9
    }
    tr:nth-child(odd) 
    {
        background-color:#404040;
    }
    tr:nth-child(even) 
    {
        background-color:#4d4d4d;
    }

    

    </Style>
"@
}

else 
{#Dark Theme

$titleCol = "#4682B4"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#FFF9EC;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:150%;
        font-family:helvetica;
        margin:0,0,10px,0;
        word-break:normal; 
        word-wrap:break-word
    }
    h2
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:120%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word
    }
    h3
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:100%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#06273A; 
        color:#9f9696;
        font-size:90%;
        font-family:helvetica;
        margin:0,0,10px,0; 
        word-break:normal; 
        word-wrap:break-word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        border-style: solid;
        border-color:#FFF9EC;
        background-color:#06273A
    }
    td
    {
        border-width: 1px;
        padding:7px;
        border-style: solid; 
        border-style: #FFF9EC
    }
    tr:nth-child(odd) 
    {
        background-color:#06273A;
    }
    tr:nth-child(even) 
    {
        background-color:#28425F;
    }

    </Style>
"@
}

    $VulnReport = "C:\SecureReport"
    $OutFunc = "SystemReport"  
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $working = "C:\SecureReport\output\$OutFunc\"
    $Report = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.html"

################################################
##########  HELPS AND DESCRIPTIONS  ############
################################################

    $Intro = "Thanks for using the vulnerability report written by Tenaka.net, please show your support and visit my site, it's non-profit and Ad-free. <br> <br>Any issues with the report's accuracy please do let me know and I'll get it fixed asap. The results in this report are a guide and not a guarantee that the tested system is not without further defects or vulnerability. <br>
    <br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail. <br> <br>Further support for the output can be found @ https://www.tenaka.net/windowsclient-vulnscanner<br>"

    $Intro2 = "The results in this report are a guide and not a guarantee that the tested system is not without further defect or vulnerability. <br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail.<br>"

    $Finish = "This script has been provided by Tenaka.net, if it's beneficial, please provide feedback and any additional feature requests gratefully received. "

    $descripBitlocker = "TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM. <br> <br>Further information can be found @ https://www.tenaka.net/bitlocker<br>"

    $descripVirt = "Secure Boot is a security standard to ensure only trusted OEM software is allowed at boot. At startup the UEFi and boot software's digital signatures are validated preventing rootkits. <br> <br>More on Secure Boot can be found here @ https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF<br>"

    $descripVirt2 = "Virtualization-based security (VBS), isolates core system resources to create secure regions of memory. Enabling VBS allows for Hypervisor-Enforced Code Integrity (HVCI), Device Guard and Credential Guard. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs<br> <br>https://www.tenaka.net/deviceguard-vs-rce and https://www.tenaka.net/pass-the-hash <br>"

    $descripSecOptions = "<br>GPO settings can be found @ Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options<br><br>Prevent credential relay with Impacket and Man in the Middle by Digitally Signing for SMB and LDAP connections enforcement. <br> <br>Further information can be found @ https://www.tenaka.net/smb-relay-attack<br>"

    $descripLSA = "Enabling RunAsPPL for LSA Protection allows only digitally signed binaries to load as a protected process preventing credential theft and access by code injection and memory access by processes that aren’t signed. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection<br>"

    $descripDLL = "Loading DLL's default behaviour is to call the dll from the current working directory of the application, then the directories listed in the environmental variable. Setting ‘DLL Safe Search’ mitigates the risk by moving CWD to later in the search order. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order<br>"

    $descripHyper = "Hypervisor Enforced Code Integrity prevents the loading of unsigned kernel-mode drivers and system binaries from being loaded into system memory. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity<br>"

    $descripElev = "Auto Elevate User is a setting that elevates users allowing them to install software without being an administrator. "

    $descripFilePw = "Files that contain password or credentials"

    $descripAutoLogon = "MECM\SCCM\MDT could leave Autologon credentials including a clear text password in the Registry."

    $descripUnquoted = "The Unquoted paths vulnerability is when a Windows Service's 'Path to Executable' contains spaces and not wrapped in double-quotes providing a route to System. <br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripProcPw = "Processes that contain credentials to authenticate and access applications. Launching Task Manager, Details and add ‘Command line’ to the view."

    $descripLegacyNet = "LLMNR and other legacy network protocols can be used to steal password hashes. <br> <br>Further information can be found @https://www.tenaka.net/responder<br>"

    $descripRegPer ="Weak Registry permissions allowing users to change the path to launch malicious software.<br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths"

    $descripSysFold = "Default System Folders that allow a User the Write permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br> Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripCreateSysFold = "Default System Folders that allows a User the CreateFile permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripNonFold = "A vulnerability exists when enterprise software has been installed on the root of C:\. The default permissions allow a user to replace approved software binaries with malicious binaries. <br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripFile = "System files that allow users to write can be swapped out for malicious software binaries. <br> <br>Further  information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripFirewalls = "Firewalls should always block inbound and exceptions should be to a named IP and Port.<br> <br>Further  information can be found @ https://www.tenaka.net/whyhbfirewallsneeded<br>" 

    $descripTaskSchPerms = "Checks for Scheduled Tasks excluding any that reference System32 as a directory. These potential user-created tasks are checked for scripts and their directory permissions are validated. No user should be allowed to access the script and make amendments, this is a privilege escalation route." 

    $descripTaskSchEncode = "Checks for encoded scripts, PowerShell or exe's that make calls off box or run within Task Scheduler" 

    $descriptDriverQuery = "All Drivers should be signed with a digital signature to verify the integrity of the packages. 64bit kernel Mode drivers must be signed without exception"

    $descriptAuthCodeSig = "Checks that digitally signed files have a valid and trusted hash. If any Hash Mis-Matches then the file could have been altered"

    $descriptDLLHijack = "DLL Hijacking is when a malicious dll replaces a legitimate dll due to a path vulnerability. A program or service makes a call on that dll gaining the privileges of that program or service. Additionally missing dll’s presents a risk where a malicious dll is dropped into a path where no current dll exists but the program or service is making a call to that non-existent dll. This audit is reliant on programs being launched so that DLL’s are loaded. Each process’s loaded dll’s are checked for permissions issues and whether they are signed. The DLL hijacking audit does not currently check for missing dll’s being called. Process Monitor filtered for ‘NAME NOT FOUND’ and path ends with ‘DLL’ will."

    $descripCredGu = "Credential Guard securely isolating the LSA process preventing the recovery of domain hashes from memory. Credential Guard only works for Domain joined clients and servers.<br> <br>Further information can be found @ https://www.tenaka.net/pass-the-hash<br>"

    $descripLAPS = "Local Administrator Password Solution (LAPS0) is a small program with some GPO settings that randomly sets the local administrator password for clients and servers across the estate. Domain Admins have default permission to view the local administrator password via DSA.MSC. Access to the LAPS passwords may be delegated unintentionally, this could lead to a serious security breach, leaking all local admin accounts passwords for all computer objects to those that shouldn't have access. <br> <br>Installation guide can be found @ https://www.tenaka.net/post/local-admin-passwords. <br> <br>Security related issue details can be found @ https://www.tenaka.net/post/laps-leaks-local-admin-passwords<br>"

    $descripURA = "User Rights Assignments (URA) control what tasks a user can perform on the local client, server or Domain Controller. For example the ‘Log on as a service’ (SeServiceLogonRight) provides the rights for a service account to Logon as a Service, not Interactively. <br> <br> Access to URA can be abused and attack the system. <br> <br>Both SeImpersonatePrivilege (Impersonate a client after authentication) and SeAssignPrimaryTokenPrivilege (Replace a process level token) are commonly used by service accounts and vulnerable to escalation of privilege via Juicy Potato exploits.<br> <br>SeBackupPrivilege (Back up files and directories), read access to all files including SAM Database, Registry and NTDS.dit (AD Database). <br> <br>SeRestorePrivilege (Restore files and directories), Write access to all files. <br> <br>SeDebugPrivilege (Debug programs), allows the ability to dump and inject into process memory inc kernel. Passwords are stored in memory in the clear and can be dumped and easily extracted. <br> <br>SeTakeOwnershipPrivilege (Take ownership of files or other objects), take ownership of file regardless of access.<br> <br>SeNetworkLogonRight (Access this computer from the network) allows pass-the-hash when Local Admins share the same password, remove all the default groups and apply named groups, separating client from servers.<br> <br>Further details can be found @ https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment<br>"

    $descripRegPasswords = "Searches HKLM and HKCU for the words 'password' and 'passwd', then displays the password value in the report.<br><br>The search will work with VNC encrypted passwords stored in the registry, from Kali run the following command<br> <br>echo -n PasswordHere | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv<br>"

    $descripASR = "Attack Surface Reduction (ASR) requires Windows Defender Real-Time Antivirus and works in conjunction with Exploit Guard to prevent malware abusing legitimate MS Office functionality<br> <br>Further information can be found @ https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide<br>"

    $descripWDigest = "WDigest was introduced with Windows XP\2003 and has been enabled by default until and including Windows 8 and Server 2012. Enabling allows clear text passwords to be recoverable from LSASS with Mimikatz"

    $descripDomainGroups = "Group membership of the user executing this script. Local admins are required, the account should not have Domain Admins as this can result in privilege escalation."

    $descripDomainPrivs = "Reference User Rights Assignment (USR) section below for further details"

    $descripLocalAccounts = "Local accounts should be disabled when the client or server is part of a Domain. LAPS should be deployed to ensure all local account passwords are unique"

    $descripCredRecom = "These are recommended GPO settings to secure Windows. Due to the sheer number of settings, the script contains details and the equivalent GPO settings, search for RECOMMENDED SECURITY SETTINGS section<br><br>MS Security Compliance Toolkit can be found @ https://admx.help/?Category=security-compliance-toolkit" 


################################################
################  FRAGMENTS  ###################
################################################
  
    #Top and Tail
    $FragDescrip1 =  $Descrip1 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Intro</span></h3>" | Out-String
    $FragDescrip2 =  $Descrip2 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Intro2</span></h3>" | Out-String
    $FragDescripFin =  $DescripFin | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Finish</span></h3>" | Out-String
    $Frag_descripVirt2 = ConvertTo-Html -as table -Fragment -PostContent "<h4>$descripVirt2</h4>" | Out-String
            
    #Host details    
    $frag_Host = $fragHost | ConvertTo-Html -As List -Property Name,Domain,Model -fragment -PreContent "<h2><span style='color:$titleCol'>Host Details</span></h2>"  | Out-String
    $fragOS = $OS | ConvertTo-Html -As List -property Caption,Version,OSArchitecture,InstallDate -fragment -PreContent "<h2><span style='color:$titleCol'>Windows Details</span></h2>" | Out-String
    $FragAccountDetails = $AccountDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Local Account Details</span></h2>" -PostContent "<h4>$descripLocalAccounts</h4>" | Out-String 
    $FragGroupDetails =  $GroupDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Local Group Members</span></h2>" | Out-String
    $FragPassPol = $PassPol | Select-Object -SkipLast 3 | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Local Password Policy</span></h2>" | Out-String
    $fragInstaApps  =  $InstallApps | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2><span style='color:$titleCol'>Installed Applications</span></h2>" | Out-String
    $fragHotFix = $HotFix | ConvertTo-Html -As Table -property HotFixID,InstalledOn,Caption -fragment -PreContent "<h2><span style='color:$titleCol'>Latest 10 Installed Updates</span></h2>" | Out-String
    $fragInstaApps16  =  $InstallApps16 | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2><span style='color:$titleCol'>Updates to Office 2016 and older or Updates that create KB's in the Registry</span></h2>" | Out-String
    $fragBios = $bios | ConvertTo-Html -As List -property Name,Manufacturer,SerialNumber,SMBIOSBIOSVersion,ReleaseDate -fragment -PreContent "<h2><span style='color:$titleCol'>Bios Details</span></h2>" | Out-String
    $fragCpu = $cpu | ConvertTo-Html -As List -property Name,MaxClockSpeed,NumberOfCores,ThreadCount -fragment -PreContent "<h2><span style='color:$titleCol'>Processor Details</span></h2>" | Out-String
    $frag_whoamiGroups =  $whoamiGroups | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Current Users Group Membership</span></h2>" -PostContent "<h4>$descripDomainGroups</h4>"   | Out-String
    $frag_whoamiPriv =  $whoamiPriv | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Current Users Local Privileges</span></h2>" -PostContent "<h4>$descripDomainPrivs</h4>"  | Out-String
    
    #Security Review
    $frag_BitLocker = $fragBitLocker | ConvertTo-Html -As List -fragment -PreContent "<h2><span style='color:$titleCol'>Bitlocker and TPM Details</span></h2>" -PostContent "<h4>$descripBitlocker</h4>" | Out-String
    $frag_Msinfo = $MsinfoClixml | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Virtualization and Secure Boot Details</span></h2>" -PostContent "<h4>$descripVirt</h4>"  | Out-String
    $frag_LSAPPL = $fragLSAPPL | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>LSA Protection for Stored Credentials</span></h2>" -PostContent "<h4>$descripLSA</h4>" | Out-String
    $frag_DLLSafe = $fragDLLSafe | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>DLL Safe Search Order</span></h2>"  -PostContent "<h4>$descripDLL</h4>"| Out-String
    $frag_DLLHijack = $fragDLLHijack | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Loaded DLL's that are vulnerable to DLL Hijacking</span></h2>" | Out-String
    $frag_DllNotSigned = $fragDllNotSigned | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>All DLL's that aren't signed and user permissions allow write</span></h2>"  -PostContent "<h4>$descriptDLLHijack</h4>"| Out-String
    $frag_Code = $fragCode | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Hypervisor Enforced Code Integrity</span></h2>" -PostContent "<h4>$descripHyper</h4>" | Out-String
    $frag_PCElevate = $fragPCElevate | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Automatically Elevates User Installing Software</span></h2>"  -PostContent "<h4>$descripElev</h4>"| Out-String
    $frag_FilePass = $fragFilePass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Files that Contain the Word PASSWORD</span></h2>" -PostContent "<h4>$descripFilePw</h4>" | Out-String
    $frag_AutoLogon = $fragAutoLogon   | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>AutoLogon Credentials in Registry</span></h2>"  -PostContent "<h4>$descripAutoLogon</h4>"| Out-String
    $frag_UnQu = $fragUnQuoted | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Vectors that Allow UnQuoted Paths Attack</span></h2>" -PostContent "<h4>$DescripUnquoted</h4>" | Out-String
    $frag_LegNIC = $fragLegNIC | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Legacy and Vulnerable Network Protocols</span></h2>" -PostContent "<h4>$DescripLegacyNet</h4>" | Out-String
    $frag_SysRegPerms = $fragReg | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Registry Permissions Allowing User Access - Security Risk if Exist</span></h2>" -PostContent "<h4>$descripRegPer</h4>" | Out-String
    $frag_PSPass = $fragPSPass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Processes where CommandLine Contains a Password</span></h2>" -PostContent "<h4>$Finish</h4>" | Out-String
    $frag_SecOptions = $fragSecOptions | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Security Options to Prevent MitM Attacks </span></h2>" -PostContent "<h4>$descripSecOptions</h4>" | Out-String
    $frag_wFolders = $fragwFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Non System Folders that are Writeable - Security Risk when Executable</span></h2>" -PostContent "<h4>$descripNonFold</h4>"| Out-String
    $frag_SysFolders = $fragsysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Default System Folders that are Writeable - Security Risk if Exist</span></h2>"  -PostContent "<h4>$descripSysFold</h4>"| Out-String
    $frag_CreateSysFold = $fragCreateSysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Default System Folders that Permit Users to Create Files - Security Risk if Exist</span></h2>"  -PostContent "<h4>$descripCreateSysFold</h4>"| Out-String
    $frag_wFile = $fragwFile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>System Files that are Writeable - Security Risk if Exist</span></h2>" -PostContent "<h4>$descripFile</h4>" | Out-String
    $frag_FWProf = $fragFWProfile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Firewall Profile</span></h2>"  -PostContent "<h4>$DescripFirewalls</h4>"| Out-String
    $frag_FW = $fragFW | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Enabled Firewall Rules</span></h2>" | Out-String
    $frag_TaskPerms =  $SchedTaskPerms | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Scheduled Tasks that call on Files on Storage</span></h2>"  -PostContent "<h4>$descripTaskSchPerms</h4>" | Out-String
    $frag_TaskListings = $SchedTaskListings | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Scheduled Tasks that Contain something Encoded</span></h2>"  -PostContent "<h4>$descripTaskSchEncode</h4>" | Out-String
    $frag_DriverQuery = $DriverQuery | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Drivers that aren't Signed</span></h2>" -PostContent "<h4>$descriptDriverQuery</h4>" | Out-String
    $frag_Share = $fragShare | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Shares and their Share Permissions</span></h2>"  | Out-String
    $frag_AuthCodeSig = $fragAuthCodeSig | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Files with an Authenticode Signature HashMisMatch</span></h2>" -PostContent "<h4>$descriptAuthCodeSig</h4>"  | Out-String  
    $frag_CredGuCFG = $fragCredGuCFG | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Credential Guard</span></h2>" -PostContent "<h4>$descripCredGu</h4>" | Out-String
    $frag_LapsPwEna = $fragLapsPwEna | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>LAPS - Local Administrator Password Solution</span></h2>" -PostContent "<h4>$descripLAPS</h4>" | Out-String
    $frag_URA = $fragURA | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>URA - Local Systems User Rights Assignments</span></h2>" -PostContent "<h4>$descripURA</h4>" | Out-String
    $frag_RegPasswords = $fragRegPasswords | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Passwords Embedded in the Registry</span></h2>" -PostContent "<h4>$descripRegPasswords</h4>" | Out-String
    $frag_ASR = $fragASR | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Attack Surface Reduction (ASR)</span></h2>" -PostContent "<h4>$descripASR</h4>" | Out-String
    $frag_WDigestULC = $fragWDigestULC | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>WDigest</span></h2>" -PostContent "<h4>$descripWDigest</h4>" | Out-String
    $frag_NetCredVal = $fragNetCredVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Security Recommendations</span></h2>" -PostContent "<h4>$descripCredRecom</h4>" | Out-String


    #Quick and dirty tidy up and removal of Frags that are $null
    if ($fragAuthCodeSig -eq $null){$frag_AuthCodeSig = ""}
    if ($fragDLLSafe -eq $null){$frag_DLLSafe = ""}
    if ($fragDLLHijack -eq $null){$fragD_LLHijack = ""}
    if ($fragDllNotSigned -eq $null){$fragD_llNotSigned = ""}
    if ($fragPCElevate-eq $null){$frag_PCElevate= ""}
    if ($fragFilePass-eq $null){$frag_FilePass = ""}
    if ($fragAutoLogon -eq $null){$frag_AutoLogon = ""}
    if ($fragUnQuoted -eq $null){$frag_UnQu = ""}
    if ($fragReg -eq $null){$frag_SysRegPerms = ""}
    if ($fragwFold -eq $null){$frag_SysFolders = ""}
    if ($fragwFile -eq $null){$frag_wFile = ""}
    if ($fragFWProfile -eq $null){$frag_FWProf = ""}
    if ($DriverQuery -eq $null){$frag_DriverQuery = ""}
    if ($fragLapsPwEna -eq $null){$frag_LapsPwEna = ""}
    if ($SchedTaskPerms -eq $null){$frag_TaskPerms = ""}
    if ($SchedTaskListings -eq $null){$frag_TaskListings = ""}
    if ($InstallApps16  -eq $null){$fragInstaApps16 = ""}
    if ($fragPSPass -eq $null){$frag_PSPass = ""}
    if ($fragRegPasswords -eq $null){$frag_RegPasswords = ""}
    if ($DriverQuery -eq $null){$frag_DriverQuery = ""}
    if ($SchedTaskPerms -eq $null){$frag_TaskPerms = ""}
    if ($fragWDigestULC -eq $null){$frag_WDigestULC = ""}
    

################################################
############  CREATE HTML REPORT  ##############
################################################
if ($folders -eq "y")
{
    ConvertTo-Html -Head $style -Body "<h1 align=center style='text-align:center'><span style='color:$titleCol;'>TENAKA.NET</span><h1>", 
    $fragDescrip1, 
    $frag_host, 
    $fragOS, 
    $fragbios, 
    $fragcpu, 
    $frag_Share,
    $frag_BitLocker, 
    $FragAccountDetails,
    $FragPassPol,
    $FragGroupDetails,
    $frag_whoamiGroups, 
    $frag_whoamiPriv,
    $frag_URA,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $frag_UnQu,
    $frag_ASR,
    $frag_Msinfo,
    $Frag_descripVirt2,
    $frag_Code,
    $frag_DriverQuery,
    $frag_SecOptions,
    $frag_NetCredVal,
    $frag_LegNIC,
    $frag_LSAPPL,
    $frag_WDigestULC,
    $frag_CredGuCFG,
    $frag_LapsPwEna,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_DllNotSigned,
    $frag_PCElevate,
    $frag_FilePass,
    $frag_RegPasswords,
    $frag_AutoLogon,
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_PSPass,
    $frag_SysRegPerms,
    $frag_SysFolders,
    $frag_CreateSysFold,
    $frag_wFolders,
    $frag_wFile,
    $frag_AuthCodeSig,
    $frag_FWProf,
    $frag_FW,
    $FragDescripFin  | out-file $Report
}
else
{
    ConvertTo-Html -Head $style -Body "<h1 align=center style='text-align:center'><span style='color:$titleCol;'>TENAKA.NET</span><h1>", 
    $fragDescrip1, 
    $frag_host, 
    $fragOS, 
    $fragbios, 
    $fragcpu, 
    $frag_Share,
    $frag_BitLocker, 
    $FragAccountDetails,
    $FragPassPol,
    $FragGroupDetails,
    $frag_whoamiGroups, 
    $frag_whoamiPriv,
    $frag_URA,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $frag_UnQu, 
    $frag_ASR,
    $frag_Msinfo,
    $Frag_descripVirt2,
    $frag_Code,
    $frag_DriverQuery,
    $frag_SecOptions,
    $frag_NetCredVal,
    $frag_LegNIC,
    $frag_LSAPPL,
    $frag_WDigestULC,
    $frag_CredGuCFG,
    $frag_LapsPwEna,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_PCElevate,
    $frag_FilePass,
    $frag_RegPasswords,
    $frag_AutoLogon,
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_PSPass,
    $frag_AuthCodeSig,
    $frag_FWProf,
    $frag_FW,
    $FragDescripFin  | out-file $Report
}

    $HostDomain = ((Get-CimInstance -ClassName win32_computersystem).Domain) + "\" 

    $repDate = (date).Date.ToString("yy-MM-dd:hh:mm").Replace(":","_")

    Get-Content $Report | 
    foreach {$_ -replace "<tr><th>*</th></tr>",""} | 
    foreach {$_ -replace "<tr><td> </td></tr>",""} |

    foreach {$_ -replace "<td>Warning","<td><font color=#ff9933>Warning"} | 
    foreach {$_ -replace "Warning</td>","<font></td>"} |

    foreach {$_ -replace "<td>Review","<td><font color=#ff9933>Review"} | 
    foreach {$_ -replace "Review</td>","<font></td>"}  | 
    
    foreach {$_ -replace "<td>SeImpersonatePrivilege","<td><font color=#ff9933>SeImpersonatePrivilege"} | 
    foreach {$_ -replace "SeImpersonatePrivilege</td>","SeImpersonatePrivilege<font></td>"}  | 

    foreach {$_ -replace "<td>SeAssignPrimaryTokenPrivilege","<td><font color=#ff9933>SeAssignPrimaryTokenPrivilege"} | 
    foreach {$_ -replace "SeAssignPrimaryTokenPrivilege</td>","SeAssignPrimaryTokenPrivilege<font></td>"}  | 

    foreach {$_ -replace "<td>SeBackupPrivilege","<td><font color=#ff9933>SeBackupPrivilege"} | 
    foreach {$_ -replace "SeBackupPrivilege</td>","SeBackupPrivilege<font></td>"}  | 

    foreach {$_ -replace "<td>SeDebugPrivilege","<td><font color=#ff9933>SeDebugPrivilege"} | 
    foreach {$_ -replace "SeDebugPrivilege</td>","SeDebugPrivilege<font></td>"}  | 

    foreach {$_ -replace "<td>SeTakeOwnershipPrivilege ","<td><font color=#ff9933>SeTakeOwnershipPrivilege "} | 
    foreach {$_ -replace "SeTakeOwnershipPrivilege</td>","SeTakeOwnershipPrivilege<font></td>"}  | 

    foreach {$_ -replace "<td>SeNetworkLogonRight","<td><font color=#ff9933>SeNetworkLogonRight"} | 
    foreach {$_ -replace "SeNetworkLogonRight</td>","SeNetworkLogonRight<font></td>"}  | 

    foreach {$_ -replace "<td>SeLoadDriverPrivilege","<td><font color=#ff9933>SeLoadDriverPrivilege"} | 
    foreach {$_ -replace "SeLoadDriverPrivilege</td>","SeLoadDriverPrivilege<font></td>"}  |    

    foreach {$_ -replace "<td>SeTakeOwnershipPrivilege","<td><font color=#ff9933>SeTakeOwnershipPrivilege"} | 
    foreach {$_ -replace "SeTakeOwnershipPrivilege</td>","SeTakeOwnershipPrivilege<font></td>"}  | 
   
    foreach {$_ -replace "<td>SeRestorePrivilege","<td><font color=#ff9933>SeRestorePrivilege"} | 
    foreach {$_ -replace "SeRestorePrivilege</td>","SeRestorePrivilege<font></td>"}  | 

    foreach {$_ -replace '<td>&lt;div title=','<td><div title="'} | 
    foreach {$_ -replace "&gt;",'">'}  | 

    Set-Content "C:\SecureReport\FinishedReport.htm" -Force
   
    }
}
reports

<#
Stuff to Fix.....
$ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage"
Null message warning that security is missing
set warning for secure boot
Expand on explanations - currently of use to non-techies
add filter to report only displaying when items are reported on.
validation for number of folders to check

remove extra blanks when listing progs via registry 

Stuff to Audit.....
Add Server support
    features and roles
Proxy password reg key

FLTMC.exe - mini driver altitude looking for 'stuff' thats at an altitude to bypass security or encryption
report on appX bypass and seriousSam
Remote desktop and permissions
look for %COMSPEC%
Check for impersonation - aimed at servers
snmp
powershell history, stored creds 
Users in the domain that dont pre-authenticate

data streams dir /r

remove powershell commands where performance is an issue, consider replacing with cmd alts

Boot-Start Driver Initialization Policy - Trusted boot \UEFI

####GPO Settings as recommended by MS####
Add mouse over to any item that reports on Reg value

UAC
Microsoft accounts
networks
Updates
Office macros
Accounts and policy



share permissions wont list $IPC

Stuff that wont get fixed.....
Progress bars or screen output will remain limited, each time an output is written to screen the performance degrads



#>
