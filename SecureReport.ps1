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
220710.1 - Added URA Support - uses SecEdit, extracts Rights Assignments and then maps GUID's to User or Group Name
220710.2 - Updated the description tags and added line separators <br>.
220711.1 - Updated the out-file format for the URA
220711.2 - Created if based on Folder audit, if not then the following vars wont be passed to the report, part of the prettification of the output
           $fragwFile           $frag_wFile           
           $fragReg             $frag_SysRegPerms     
           $fragwFold           $frag_wFolders        
           $fragsysFold         $frag_SysFolders      
           $fragcreateSysFold   $frag_CreateSysFold   
           $fragDllNotSigned    $frag_DllNotSigned    
           $fragAuthCodeSig     $frag_AuthCodeSig  
           
              
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
    $Scheme = Read-Host "Type either Tenaka, Dark or Light for choice of colour schemes" 
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
    $hn = Get-CimInstance -ClassName win32_computersystem 
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
        $SecOptName = "$secOpTitle4 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle4 - Disabled Warning"
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
        $SecOptName = "$secOpTitle9 - Enabled"
    }
    else
    {
        $SecOptName = "Warning - $secOpTitle9 - Disabled Warning"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle10 = "Network security: LDAP client signing requirements" # = 2 Required
    $getSecOp10 = get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\parameters' -ErrorAction SilentlyContinue
    $getSecOp10res = $getSecOp10.getvalue("ldapserverintegrity")

    if ($getSecOp9res -eq "2")
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
        $SvcPath = Get-childItem $key -Recurse -Depth 1 -ErrorAction SilentlyContinue | where {$_.Name -notlike "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*"}
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
    #Write-Host $procName -ForegroundColor Green
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
                #Write-Host $dllPath -ForegroundColor Yellow
            }              
     }
}



 
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
    body
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

    $descripSecOptions = "Prevent credential relay with Impacket and Man in the Middle by Digitally Signing for SMB and LDAP connections enforcement. <br> <br>Further information can be found @ https://www.tenaka.net/smb-relay-attack<br>"

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

    $descripLAPS = "Local Administrator Password Solution (LAPS0) is a small program with some GPO settings that randomly sets the local administrator password for clients and servers across the estate. Only Domain Admins by default permission to view the local administrator password via DSA.MSC Access to the LAPS passwords may be delegated unintentionally. This could lead to a serious security breach, leaking all local admin accounts passwords for all computer objects to those that shouldn't have access. <br> <br>Installation guide can be found @ https://www.tenaka.net/post/local-admin-passwords. <br> <br>Security related issue details can be found @ https://www.tenaka.net/post/laps-leaks-local-admin-passwords<br>"

    $descripURA = "User Rights Assignments (URA) control what tasks a user can perform on the local client, server or Domain Controller. For example the ‘Log on as a service’ (SeServiceLogonRight) provides the rights for a service account to Logon as a Service, not Interactively. <br> <br> Access to URA can be abused and attack the system. <br> <br>Both SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege are commonly used by service accounts and vulnerable to escalation of privilege via Juicy Potato exploits.<br> <br>Further details can be found @ https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment<br> <br>Access this computer from the network (SeNetworkLogonRight) allows pass-the-hash when Local Admins share the same password, remove all the default groups and apply named groups, separating client from servers."

################################################
################  FRAGMENTS  ###################
################################################
  
    #Top and Tail
    $FragDescrip1 =  $Descrip1 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Intro</span></h3>" | Out-String
    $FragDescrip2 =  $Descrip2 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Intro2</span></h3>" | Out-String
    $FragDescripFin =  $DescripFin | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:helvetica;>$Finish</span></h3>" | Out-String
    $Frag_descripVirt2 = ConvertTo-Html -as table -Fragment -PostContent "<h4>$descripVirt2</h4>" | Out-String
            
    #Host details    
    $fragHost = $hn | ConvertTo-Html -As List -Property Name,Domain,Model -fragment -PreContent "<h2><span style='color:$titleCol'>Host Details</span></h2>"  | Out-String
    $fragOS = $OS | ConvertTo-Html -As List -property Caption,Version,OSArchitecture,InstallDate -fragment -PreContent "<h2><span style='color:$titleCol'>Windows Details</span></h2>" | Out-String
    $FragAccountDetails = $AccountDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Account Details</span></h2>" | Out-String
    $FragGroupDetails =  $GroupDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Group Members</span></h2>" | Out-String
    $FragPassPol = $PassPol | Select-Object -SkipLast 3 | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Password Policy</span></h2>" | Out-String
    $fragInstaApps  =  $InstallApps | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2><span style='color:$titleCol'>Installed Applications</span></h2>" | Out-String
    $fragHotFix = $HotFix | ConvertTo-Html -As Table -property HotFixID,InstalledOn,Caption -fragment -PreContent "<h2><span style='color:$titleCol'>Latest 10 Installed Updates</span></h2>" | Out-String
    $fragInstaApps16  =  $InstallApps16 | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2><span style='color:$titleCol'>Updates to Office 2016 and older or Updates that create KB's in the Registry</span></h2>" | Out-String
    $fragBios = $bios | ConvertTo-Html -As List -property Name,Manufacturer,SerialNumber,SMBIOSBIOSVersion,ReleaseDate -fragment -PreContent "<h2><span style='color:$titleCol'>Bios Details</span></h2>" | Out-String
    $fragCpu = $cpu | ConvertTo-Html -As List -property Name,MaxClockSpeed,NumberOfCores,ThreadCount -fragment -PreContent "<h2><span style='color:$titleCol'>Processor Details</span></h2>" | Out-String

    #Security Review
    $frag_BitLocker = $fragBitLocker | ConvertTo-Html -As List -fragment -PreContent "<h2><span style='color:$titleCol'>Bitlocker and TPM Details</span></h2>" -PostContent "<h4>$descripBitlocker</h4>" | Out-String
    $frag_Msinfo =  $MsinfoClixml | ConvertTo-Html -As Table -fragment -PreContent "<h2><span style='color:$titleCol'>Virtualization and Secure Boot Details</span></h2>" -PostContent "<h4>$descripVirt</h4>"  | Out-String
    $frag_LSAPPL = $fragLSAPPL | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>LSA Protection for Stored Credentials</span></h2>" -PostContent "<h4>$descripLSA</h4>" | Out-String
    $frag_DLLSafe  =  $fragDLLSafe | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>DLL Safe Search Order</span></h2>"  -PostContent "<h4>$descripDLL</h4>"| Out-String
    $frag_DLLHijack = $fragDLLHijack | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Loaded DLL's that are vulnerable to DLL Hijacking</span></h2>" | Out-String
    $frag_DllNotSigned = $fragDllNotSigned | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>All DLL's that aren't signed and user permissions allow write</span></h2>"  -PostContent "<h4>$descriptDLLHijack</h4>"| Out-String
    $frag_Code  =  $fragCode   | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Hypervisor Enforced Code Integrity</span></h2>" -PostContent "<h4>$descripHyper</h4>" | Out-String
    $frag_PCElevate  =  $fragPCElevate | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Automatically Elevates User Installing Software</span></h2>"  -PostContent "<h4>$descripElev</h4>"| Out-String
    $frag_FilePass  =  $fragFilePass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Files that Contain the Word PASSWORD</span></h2>" -PostContent "<h4>$descripFilePw</h4>" | Out-String
    $frag_AutoLogon  =  $fragAutoLogon   | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>AutoLogon Credentials in Registry</span></h2>"  -PostContent "<h4>$descripAutoLogon</h4>"| Out-String
    $frag_UnQu = $fragUnQuoted | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Vectors that Allow UnQuoted Paths Attack</span></h2>" -PostContent "<h4>$DescripUnquoted</h4>" | Out-String
    $frag_LegNIC = $fragLegNIC | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Legacy and Vulnerable Network Protocols</span></h2>" -PostContent "<h4>$DescripLegacyNet</h4>" | Out-String
    $frag_SysRegPerms = $fragReg | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Registry Permissions Allowing User Access - Security Risk if Exist</span></h2>" -PostContent "<h4>$descripRegPer</h4>" | Out-String
    $frag_PSPass = $fragPSPass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Processes where CommandLine Contains a Password</span></h2>" -PostContent "<h4>$Finish</h4>" | Out-String
    $frag_SecOptions = $fragSecOptions | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Security Options</span></h2>" -PostContent "<h4>$descripSecOptions</h4>" | Out-String
    $frag_wFolders = $fragwFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Non System Folders that are Writeable - Security Risk when Executable</span></h2>" -PostContent "<h4>$descripNonFold</h4>"| Out-String
    $frag_SysFolders = $fragsysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Default System Folders that are Writeable - Security Risk if Exist</span></h2>"  -PostContent "<h4>$descripSysFold</h4>"| Out-String
    $frag_CreateSysFold = $fragCreateSysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Default System Folders that Permit Users to Create Files - Security Risk if Exist</span></h2>"  -PostContent "<h4>$descripCreateSysFold</h4>"| Out-String
    $frag_wFile =  $fragwFile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>System Files that are Writeable - Security Risk if Exist</span></h2>" -PostContent "<h4>$descripFile</h4>" | Out-String
    $frag_FWProf =   $fragFWProfile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Firewall Profile</span></h2>"  -PostContent "<h4>$DescripFirewalls</h4>"| Out-String
    $frag_FW =  $fragFW | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Enabled Firewall Rules</span></h2>" | Out-String
    $frag_TaskPerms =  $SchedTaskPerms | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Scheduled Tasks that call on Files on Storage</span></h2>"  -PostContent "<h4>$descripTaskSchPerms</h4>" | Out-String
    $frag_TaskListings =  $SchedTaskListings | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Scheduled Tasks that Contain something Encoded</span></h2>"  -PostContent "<h4>$descripTaskSchEncode</h4>" | Out-String
    $frag_DriverQuery =  $DriverQuery | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Drivers that aren't Signed</span></h2>" -PostContent "<h4>$descriptDriverQuery</h4>" | Out-String
    $frag_Share = $fragShare | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Shares and their Share Permissions</span></h2>"  | Out-String
    $frag_AuthCodeSig = $fragAuthCodeSig | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Files with an Authenticode Signature HashMisMatch</span></h2>" -PostContent "<h4>$descriptAuthCodeSig</h4>"  | Out-String  
    
    $frag_CredGuCFG = $fragCredGuCFG | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>Credential Guard</span></h2>" -PostContent "<h4>$descripCredGu</h4>" | Out-String
   
    $frag_LapsPwEna = $fragLapsPwEna | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>LAPS - Local Administrator Password Solution</span></h2>" -PostContent "<h4>$descripLAPS</h4>" | Out-String
  
    $frag_URA = $fragURA | ConvertTo-Html -as Table -Fragment -PreContent "<h2><span style='color:$titleCol'>URA - User Rights Assignments</span></h2>" -PostContent "<h4>$descripURA</h4>" | Out-String
  

################################################
############  CREATE HTML REPORT  ##############
################################################
if ($folders -eq "y")
{
    ConvertTo-Html -Head $style -Body "<h1 align=center style='text-align:center'><span style='color:$titleCol;'>TENAKA.NET</span><h1>", 
    $fragDescrip1, 
    $fraghost, 
    $fragOS, 
    $FragAccountDetails,
    $FragGroupDetails,
    $FragPassPol,
    $frag_URA,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $fragbios, 
    $fragcpu, 
    $frag_BitLocker, 
    $frag_Msinfo,
    $Frag_descripVirt2,
    $frag_DriverQuery,
    $frag_Code,
    $frag_SecOptions,
    $frag_LSAPPL,
    $frag_CredGuCFG,
    $frag_LapsPwEna,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_DllNotSigned,
    $frag_PCElevate,
    $frag_FilePass,
    $frag_AutoLogon,
    $frag_UnQu, 
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_PSPass,
    $frag_LegNIC,
    $frag_Share,
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
    $fraghost, 
    $fragOS, 
    $FragAccountDetails,
    $FragGroupDetails,
    $FragPassPol,
    $frag_URA,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $fragbios, 
    $fragcpu, 
    $frag_BitLocker, 
    $frag_Msinfo,
    $Frag_descripVirt2,
    $frag_DriverQuery,
    $frag_Code,
    $frag_SecOptions,
    $frag_LSAPPL,
    $frag_CredGuCFG,
    $frag_LapsPwEna,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_PCElevate,
    $frag_FilePass,
    $frag_AutoLogon,
    $frag_UnQu, 
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_PSPass,
    $frag_LegNIC,
    $frag_Share,
    $frag_AuthCodeSig,
    $frag_FWProf,
    $frag_FW,
    $FragDescripFin  | out-file $Report
}
    $repDate = (date).Date.ToString("yy-MM-dd:hh:mm").Replace(":","_")

    Get-Content $Report | 
    foreach {$_ -replace "<tr><th>*</th></tr>",""} | 
    foreach {$_ -replace "<tr><td> </td></tr>",""} |
    foreach {$_ -replace "<td>Warning","<td><font color=#FF4040>Warning"} | 
    foreach {$_ -replace "Warning</td>","<font></td>"} | Set-Content "C:\SecureReport\FinishedReport.htm" -Force
   
    }
}
reports

<#
Stuff to Fix.....
$ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage"
Password in Registry - slow to get back results 
Null message warning that security is missing
set warning for secure boot
Expand on explanations - currently of use to non-techies
add filter to report only displaying when items are reported on.

remove extra blanks when listing progs via registry 

Stuff to Audit.....
Add Server support
    features and roles
Add warning no user account is available 
UAC 
AutoPlay
Proxy password reg key

FLTMC.exe - mini driver altitude looking for 'stuff' thats at an altitude to bypass security or encryption
report on appX bypass and seriousSam
Remote desktop and permissions
look for %COMSPEC%
Check for impersonation - aimed at servers
snmp
powershell history, stored creds 
USers in the domain that dont pre-authenticate

data streams dir /r


Stuff that wont get fixed.....
Progress bars or screen output will remain limited, each time an output is written to screen the performance degrads

#>
