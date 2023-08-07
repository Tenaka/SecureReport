<#
.Synopsis
Check for common and known security vulnerabilities and create an html report based on the findings

.DESCRIPTION

The report is saved to C:\Securereport\FinishedReport.htm

Before everyone gets critical regarding the script formatting, some are due to how ConvertTo-HTML expects the data, most are to help those that aren't familiar with scripting. There is a conscious decision not to use aliases or abbreviations and where possible to create variables. 

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
"TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then Accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM.
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
Enabling RunAsPPL for LSA Protection allows only digitally signed binaries to load as a protected process preventing credential theft and Access by code injection and memory Access by processes that aren't signed.
Further information can be found @ https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

#DLL Safe Search
When applications do not fully qualify the DLL path and instead allow searching the default behaviour is for the 'Current Working Directory' to be called, then system paths. This allows an easy route to call malicious DLL's. Setting 'DLL Safe Search' mitigates the risk by moving CWD to later in the search order.
Further information can be found @
https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

#DLL Hijacking (Permissions)
DLL Hijacking is when a malicious dll replaces a legitimate dll due to a path vulnerability. A program or service makes a call on that dll gaining the privileges of that program or service. Additionally missing dll's presents a risk where a malicious dll is dropped into a path where no current dll exists but the program or service is making a call to that non-existent dll.
This audit is reliant on programs being launched so that DLL's are loaded. Each process's loaded dll's are checked for permissions issues and whether they are signed.  
The DLL hijacking audit does not currently check for missing dll's being called. Process Monitor filtered for 'NAME NOT FOUND' and path ends with 'DLL' will.


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

For the following Words:
password, credential

Ignore these files as they contain the Word 'Password' by default:
C:\Windows\system32\NarratorControlTemplates.xml
C:\Windows\system32\DDFs\NGCProDDF_v1.2_final.xml
C:\Windows\system32\icsxml\ipcfg.xml
C:\Windows\system32\icsxml\pppcfg.xml
C:\Windows\system32\slmgr\0409\slmgr.ini
C:\Windows\system32\winrm\0409\winrm.ini

#Passwords in the Registry
Searches HKLM and HKCU for the Words 'password' and 'passwd', then displays the password value in the report. 
The search will work with VNC encrypted passwords stored in the registry, from Kali run the following command to decrypt

echo -n PasswordHere | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

​
#Password embedded in Processes
Processes that contain credentials to authenticate and Access applications. Launching Task Manager, Details and add 'Command line' to the view.
​
#AutoLogon
Checks "HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon" for any clear text credentials remaining from a MECM\SCCM\MDT deployment.

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
No user should be allowed to Access the script and make amendments, this is a privilege escalation route.

Checks for encoded scripts, PowerShell or exe's that make calls off box or run within Task Scheduler.

#Shares
Finds all shares and reports on share permissions
Does not show IPC$ and permissions due to Access issues.

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
220411.1 - Added "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" to list x86 install applications
220604.1 - Added Root of drive for permission check Non System Folders
220604.2 - Added | where {$_.displayroot -notlike "*\\*"} to get drive letters and not mounted shares
220605.1 - Added loaded dll hijacking vulnerability scanner
220605.2 - Added READ-HOSTS to prompt to run slow processes.
220606.1 - Added DLL hijacking for dlls not signed and where the user can write.
220606.2 - Tidy up and formatting of script
220607.1 - Password within file search $fragFilePass=@() moved to outside loop as it was dropping previous drives and data
220708.1 - Added depth to Folder and File search to give option to speed up search
220708.2 - Moved DLL not signed and user Access, update to Folder search, not an option to run or not
220708.3 - Added filters to Folder and File search to skip winSXS and LCU folders, time consuming and pointless  - Improves preformance 
220708.4 - DLL not signed and user Access, wrong setting on filter and excluded the files I'm looking for.
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
220724.1 - Added mouse over for URA to show MS recommended settings
220724.1 - Fixed issues with URA
220725.1 - Added 255.255.255.255 wpad to legacy network protocols
220726.1 - Added further Security Options and GPO checked based on ms sec guide
220818.1 - Added MS Edge GPO check
220819.1 - Added Office 2016\365 GPO check
220820.1 - Updated URA to include GPO Path as a mouse over
220825.1 - Added DSQuery to search for accounts that dont pre-auth - Issue requires AD RSAT installed
220830.1 - Added Antivirus Audit - Uses known status codes to report on AV engine and definitions
220831.1 - Updated Get Shares to ignore error for IPC's lack of path and permissions
220901.1 - Added IPv4 and IPv6 Details
220901.2 - Added FSMO Roles
220907.1 - Added Priv Group - DA, EA and Schema
221024.1 - Passwords embedded in files has option as it can crash PowerShell on servers
221024.2 - Added warnings and color to unquoted paths, reg and file permission issues
221024.3 - swapped out get-wmi for cim-instance to support powershell 7
221025.1 - Fixed issue with Unquoted path and not finding .sys files that are unquoted
221025.1 - Added audit for installed Windows Features
221029.1 - Added Compliance Report showing overall status and areas of concern
221029.2 - Fixed issue where Defender cant be detected on Server OS - will assume if WMI fails that its not installed
221031.1 - Added Compliance Report showing overall status and areas of concern - Updated for hyperlinks
221101.1 - Updated Frag titles so reported compliance is an in page link to the reported issue. 
221102.1 - Replaced Net Group will ADSI LDAP for Domain Priv Group Membership - less text formating makes adsi more reliable.
221103.1 - Fixed issue with color schemes not applying swapped out if for ifelse
221106.1 - Firewall profile now warns on misconfiguration
221106.2 - Fixed issues with various links to with Summary
221106.3 - Removed the 'Warning' makes report look neater.
221106.4 - Removed <span style='color:$titleCol'>, not required as CSS applies colour schemes
221112.1 - Fixed issues with href a ID's - Summary links now work
221112.2 - Fixed issue with MSInfo and out-file added additional spaces which translated into spaces in the html output - Out-File $msinfoPathcsv -Encoding utf8 
221112.3 - Added Top to A href, summary links will return to top of page now.
221121.1 - Added Certificate Audit - There is a naughty list that requires key words being added eg a less that desirable company
221123.1 - Fixed issues with MS recommended settings
221129.1 - Added more OS GPO Recommended validation checks
221129.2 - Swapped out “ ” ’ for ' " " - some had sneaked in whilst prepping some settings in MS Word
221208.1 - Added test path and rename to random number for C:\SecureReport if exists
221208.2 - Updated and added further OS GPO settings testing for misconfigurations
221208.3 - Added further Legacy network checks
221210.1 - Updated list of MS Edge checks 
230626.1 - Added kernel-mode hardware-enforced stack protection
230717.1 - Updated look and feel, added fonts and font sizes vars for CSS
230718.1 - Added True and False, true is compliant, false missing a setting
230725.1 - Finised Report is named to hostname and date
230727.1 - Removed 'Warning -'
230802.1 - Certs now warns on Sha1
230802.1 - Updated Installed Apps to warn when installed date is more than 6 months. 
230803.1 - Updated BIOS to warn when installed date is more than 6 months. 
230805.1 - Updated looks and feel of report.
230805.2 - Updated Windows Updates to alert when they are more than 6 months out of date.
230807.1 - Report on supported CipherSuites - Needs explanation to be added


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
    $ptRand = Get-Random -Minimum 100 -Maximum 999
    #$ptRand= (Get-Date).ToString('yy/MM/dd-hh:mm').Replace("/","").Replace(":","")

    if($psise -ne $null)
    {
        $ISEPath = $psise.CurrentFile.FullPath
        $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
        $ISEWork = $ISEPath.TrimEnd("$ISEDisp")

        $tpSecRrpt = test-path $VulnReport
        if ($tpSecRrpt -eq $true)
        {
            Rename-Item $VulnReport -NewName "$VulnReport$($ptRand)" -Force
            New-Item -Path C:\SecureReport -ItemType Directory -Force
        }
        else
        {
            New-Item -Path C:\SecureReport -ItemType Directory -Force
        }
    }
    else
    {
        $PSWork = split-path -parent $MyInvocation.MyCommand.Path
        
        $tpSecRrpt = test-path $VulnReport
        $tpSecRrpt = $VulnReport
        if ($tpSecRrpt -eq $true)
        {
            Rename-Item $VulnReport -NewName "$VulnReport$($ptRand)" -Force
            New-Item -Path C:\SecureReport -ItemType Directory -Force
        }
        else
        {
            New-Item -Path C:\SecureReport -ItemType Directory -Force
        }
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
    Write-Host "Ignore any errors or red messages its due to Administrator being denied Access to parts of the file system." -ForegroundColor Yellow
    Write-Host " "
    Write-Host "Some audits take a long time to complete and do not output progress as this adds to the time taken." -ForegroundColor Yellow
    Write-Host " "
    Write-Host "READ ME - To audit for Dll Hijacking vulnerabilities applications and services must be active, launch programs before continuing." -ForegroundColor Yellow
    Write-Host " "

    $Scheme = Read-Host "Type either Tenaka, Dark, Grey or Light for choice of colour schemes" 
    write-host " "
    $folders = Read-Host "Long running audit - Do you want to audit Files, Folders and Registry for permissions issues....type `"Y`" to audit, any other key for no"

    if ($folders -eq "Y") {$depth = Read-Host "What depth do you wish the folders to be auditied, the higher the number the slower the audit, the default is 2, recommended is 4"}
    write-host " "
    $embeddedpw = Read-Host "Some systems whilst retrieving passwords from within files crash PowerShell....type `"Y`" to audit, any other key for no"
    write-host " "
    $authenticode = Read-Host "Long running audit - Do you want to check that digitally signed files are valid with a trusted hash....type `"Y`" to audit, any other key for no"

    #Summary Frag
    $fragSummary=@()

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
    $TPMSpec = wmic /namespace:\\root\cimv2\Security\microsofttpm path win32_tpm get specversion 
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
        $BitDisabled = "Warning Bitlocker is disabled Warning"
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
    $bios = Get-CimInstance -ClassName win32_bios | Select-Object Name,Manufacturer,SerialNumber,SMBIOSBIOSVersion,ReleaseDate
    $cpu = Get-CimInstance -ClassName win32_processor

    $BiosUEFI=@()

    $BiosName = $bios.Name
    $BiosManufacturer = $bios.Manufacturer
    $BiosSerial = $bios.SerialNumber
    $BiosSMBVersion = $bios.SMBIOSBIOSVersion
    $ReleaseDate = $bios.ReleaseDate

    $date180days = (Get-Date).AddDays(-180)

    if ($date180days -gt $ReleaseDate){$ReleaseDate = "Warning $($ReleaseDate) Warning"}

    $newObjBiosUEFI = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjBiosUEFI -Type NoteProperty -Name BiosName -Value $BiosName
    Add-Member -InputObject $newObjBiosUEFI -Type NoteProperty -Name BiosManufacturer -Value $BiosManufacturer
    Add-Member -InputObject $newObjBiosUEFI -Type NoteProperty -Name BiosSerial -Value $BiosSerial
    Add-Member -InputObject $newObjBiosUEFI -Type NoteProperty -Name BiosSMBVersion -Value $BiosSMBVersion
    Add-Member -InputObject $newObjBiosUEFI -Type NoteProperty -Name ReleaseDate -Value $ReleaseDate
    $BiosUEFI += $newObjBiosUEFI

################################################
##############  ACCOUNT DETAILS  ###############
################################################
#PasWord Policy
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
            $accEnabled = "Warning Enabled Warning"
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

################################################
#########  MEMBERS OF LOCAL GROUPS  ############
################################################
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

################################################
###############  LIST OF DCs  ##################
################################################
#Domain Info
#List of DC's
$fragDCList=@()
[string]$queryDC = netdom /query dc
$dcListQuery = $queryDC.Replace("The command completed successfully.","").Replace("List of domain controllers with accounts in the domain:","").Replace(" ",",").replace(",,","")
$fqdn = ((Get-CimInstance -ClassName win32_computersystem).Domain) + "."
$dcList = $dcListQuery.split(",") | sort 

    foreach ($dcs in $dcList)
    {
        $dcfqdn = $dcs + "." + $fqdn
        $newObjDCList = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjDCList -Type NoteProperty -Name DCList -Value $dcfqdn
        $fragDCList += $newObjDCList
    }

################################################
################  FSMO ROLES  ##################
################################################
    #FSMO Roles
    $fragFSMO=@()
    [string]$fsmolist = netdom /query fsmo
    $fsmoQuery = $fsmolist.Replace("The command completed successfully.","")

    $fsmoQry = $fsmoQuery.replace("master","master,").replace("PDC",",PDC,").Replace("Domain",",Domain").Replace("RID",",RID").Replace("Infra",",Infra").replace("manager","manager,")
    $fsmoSplit = $fsmoQry.Split(",").Trim()

    $schMasterRole = $fsmoSplit[0]
    $schMasterDC = $fsmoSplit[1]

    $DomMasterRole = $fsmoSplit[2]
    $DomMasterDC = $fsmoSplit[3]

    $PDCRole = $fsmoSplit[4]
    $PDCDC = $fsmoSplit[5]

    $RIDRole = $fsmoSplit[6]
    $RIDDC = $fsmoSplit[7]

    $InfraRole = $fsmoSplit[8]
    $InfraDC = $fsmoSplit[9]

    $newObjFsmo = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjFsmo -Type NoteProperty -Name $schMasterRole -Value $schMasterDC
    Add-Member -InputObject $newObjFsmo -Type NoteProperty -Name $DomMasterRole -Value $DomMasterDC
    Add-Member -InputObject $newObjFsmo -Type NoteProperty -Name $PDCRole -Value $PDCDC
    Add-Member -InputObject $newObjFsmo -Type NoteProperty -Name $RIDRole -Value $RIDDC
    Add-Member -InputObject $newObjFsmo -Type NoteProperty -Name $InfraRole -Value $InfraDC
    $fragFSMO += $newObjFsmo

################################################
#########  DOMAIN PRIV GROUPS ##################
################################################
    #Domain Priv Group members
    $Root = [ADSI]"LDAP://RootDSE"
    $rootdse = $Root.rootDomainNamingContext

    $adGroups = 
    "Administrators",
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Guests",
    "Domain Admins",
    "Schema Admins",
    "Enterprise Admins",
    "DnsAdmins",
    "DHCP Administrators",
    "Domain Guests"

    $fragDomainGrps=@()

    foreach ($adGroup in $adGroups)
    {
        try
        {    
            $gpName = [ADSI]"LDAP://CN=$adGroup,CN=Users,$($rootdse)"
            $gpMembers = $gpName.Member    
            $ArgpMem=@()
            if($gpMembers -ne $null)
            {  
            foreach ($gpMem in $gpMembers)
                {
                $gpSting = $gpMem.ToString().split(",").replace("CN=","")[0]
                $ArgpMem += $gpSting
                }
                $joinMem = $ArgpMem -join ", "

                $newObjDomainGrps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjDomainGrps -Type NoteProperty -Name GroupName -Value $adGroup
                Add-Member -InputObject $newObjDomainGrps -Type NoteProperty -Name GroupMembers -Value $joinMem 
                $fragDomainGrps += $newObjDomainGrps   
            }
        }
    finally
        {
            $gpName = [ADSI]"LDAP://CN=$adGroup,CN=builtin,$($rootdse)"
            $gpMembers = $gpName.Member   
            $ArgpMem=@()
                    if($gpMembers -ne $null)
            {  
            foreach ($gpMem in $gpMembers)
                {
                $gpSting = $gpMem.ToString().split(",").replace("CN=","")[0]
                $ArgpMem += $gpSting
                }
                $joinMem = $ArgpMem -join ", "

                $newObjDomainGrps = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjDomainGrps -Type NoteProperty -Name GroupName -Value $adGroup
                Add-Member -InputObject $newObjDomainGrps -Type NoteProperty -Name GroupMembers -Value $joinMem 
                $fragDomainGrps += $newObjDomainGrps   
            }
        }
    }

################################################
########  PRE-AUTHENTICATION  ##################
################################################
    #DSQUERY
    #Pre-Authenticaiton enabled
    #RSAT is requried
    $dsQuery = & dsquery.exe * -limit 0 -filter "&(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -attr samaccountname, distinguishedName, userAccountControl | select -skip 1
    $fragPreAuth=@()

    foreach ($preAuth in $dsQuery)
        {
            $preAuth = $preAuth.trim("").Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            $preAuthSam = "Warning " + $preAuth[0] + " warning" 
            $preAuthOu = "Warning " +$preAuth[1]  + " warning" 
            $preAuthUac = "Warning " +$preAuth[2]  + " warning" 

            $newObjPreAuth = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjPreAuth -Type NoteProperty -Name PreAuth-Account -Value $preAuthSam
            Add-Member -InputObject $newObjPreAuth -Type NoteProperty -Name PreAuth-OUPath -Value $preAuthOu
            Add-Member -InputObject $newObjPreAuth -Type NoteProperty -Name PreAuth-UACValue -Value $preAuthUac
            $fragPreAuth += $newObjPreAuth
        }

################################################
###### PASSWORDS THAT DONT EXPIRE ##############
################################################
    #Accounts that never Expire

    $dsQueryNexpires = & dsquery.exe * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -attr samaccountname, distinguishedName, userAccountControl | select -skip 1
    $fragNeverExpires=@()

    foreach ($NeverExpires in $dsQueryNexpires)
        {
            $NeverExpires = $NeverExpires.trim("").Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            $NeverExpiresSam = "Warning " + $NeverExpires[0] + " warning" 
            $NeverExpiresOu = "Warning " +$NeverExpires[1]  + " warning" 
            $NeverExpiresUac = "Warning " +$NeverExpires[2]  + " warning" 

            $newObjNeverExpires = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjNeverExpires -Type NoteProperty -Name NeverExpires-Account -Value $NeverExpiresSam
            Add-Member -InputObject $newObjNeverExpires -Type NoteProperty -Name NeverExpires-OUPath -Value $NeverExpiresOu
            Add-Member -InputObject $newObjNeverExpires -Type NoteProperty -Name NeverExpires-UACValue -Value $NeverExpiresUac
            $fragNeverExpires += $newObjNeverExpires
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
        "Access Credential Manager as a trusted caller"="SeTrustedCredManAccessPrivilege","Access Credential Manager as a trusted caller | Set Blank"
        "Access this computer from the network" = "SeNetworkLogonRight","Access this computer from the network | Administrators, Remote Desktop Users"
        "Act as part of the operating system"="SeTcbPrivilege","Act as part of the operating system | Set Blank"
        "Add workstations to domain" = "SeMachineAccountPrivilege","Add workstations to domain"
        "Adjust memory quotas for a process" = "SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"
        "Allow log on locally" = "SeInteractiveLogonRight", "Allow log on locally | Administrators, Users | Administrators, Users" 
        "Allow log on through Remote Desktop Services"="SeRemoteInteractiveLogonRight","Allow log on through Remote Desktop Services"
        "Back up files and directories" = "SeBackupPrivilege", "Back up files and directories | Administrators"
        "Bypass traverse checking" = "SeChangeNotifyPrivilege", "Bypass traverse checking"
        "Change the system time" = "SeSystemtimePrivilege", "Change the system time"
        "Change the time zone" = "SeTimeZonePrivilege", "Change the time zone" 
        "Create a pagefile" = "SeCreatePagefilePrivilege", "Create a pagefile | Administrators"
        "Create a token object"="SeCreateTokenPrivilege","Create a token object | Set Blank"
        "Create global objects" = "SeCreateGlobalPrivilege", "Create global objects | Administrators,LOCAL SERVICE,NETWORK SERVICE,SERVICE"
        "Create permanent shared objects"="SeCreatePermanentPrivilege","Create permanent shared objects | Set Blank"
        "Create symbolic links" = "SeCreateSymbolicLinkPrivilege","Create symbolic links" 
        "Debug programs" = "SeDebugPrivilege", "Debug programs | Administrators (Prefer setting Blank)"
        "Deny Access to this computer from the network"   = "SeDenyNetworkLogonRight", "Deny Access to this computer from the network | NT AUTHORITY\Local Account" 
        "Deny log on as a batch job" = "SeDenyBatchLogonRight", "Deny log on as a batch job"
        "Deny log on as a service" = "SeDenyServiceLogonRight", "Deny log on as a service" 
        "Deny log on locally" = "SeDenyInteractiveLogonRight", "Deny log on locally" 
        "Deny log on through Remote Desktop Services" = "SeRemoteInteractiveLogonRight","Deny log on through Remote Desktop Services | NT AUTHORITY\Local Account" 
        "Enable computer and user accounts to be trusted for delegation"="SeEnableDelegationPrivilege","Enable computer and user accounts to be trusted for delegation | Set Blank"
        "Force shutdown from a remote system" = "SeRemoteShutdownPrivilege", "Force shutdown from a remote system | Administrators"
        "Generate security audits" = "SeAuditPrivilege", "Generate security audits" 
        "Impersonate a client after authentication" = "SeImpersonatePrivilege", "Impersonate a client after authentication | Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE" 
        "Increase a process working set" = "SeIncreaseWorkingSetPrivilege","Increase a process working set" 
        "Increase scheduling priority" = "SeIncreaseBasePriorityPrivilege","Increase scheduling priority"
        "Load and unload device drivers" = "SeLoadDriverPrivilege", "Load and unload device drivers | Administrators"
        "Lock pages in memory"="SeLockMemoryPrivilege","Lock pages in memory | Set Blank"
        "Log on as a batch job" = "SeBatchLogonRight", "Log on as a batch job"
        "Log on as a service" = "SeServiceLogonRight", "Log on as a service" 
        "Manage auditing and security log" = "SeSecurityPrivilege", "Manage auditing and security log | Administrators"
        "Modify an object label"="SeRelabelPrivilege","Modify an object label"
        "Modify firmware environment values" = "SeSystemEnvironmentPrivilege","Modify firmware environment values | Administrators"  
        "Obtain an impersonation token for another user in the same session" = "SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session" 
        "Perform volume maintenance tasks" = "SeManageVolumePrivilege", "Perform volume maintenance tasks | Administrators"
        "Profile single process" = "SeProfileSingleProcessPrivilege", "Profile single process  | Administrators" 
        "Profile system performance" = "SeSystemProfilePrivilege", "Profile system performance"
        "Remove computer from docking station" = "SeUndockPrivilege","Remove computer from docking station" 
        "Replace a process level token" = "SeAssignPrimaryTokenPrivilege", "Replace a process level token" 
        "Restore files and directories" = "SeRestorePrivilege","Restore files and directories | Administrators" 
        "Shut down the system" = "SeShutdownPrivilege", "Shut down the system"
        "Synchronize directory service data"="SeSyncAgentPrivilege","Synchronize directory service data"
        "Take ownership of files or other objects" = "SeTakeOwnershipPrivilege", "Take ownership of files or other objects | Administrators"

        }

    $URACommonPath = "Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assingments\" 

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
                   $uraDescripName = $uralookupName.trim()[1].split("|")[0]
                   $uraMSRecom = $uralookupName[1].split("|")[1].trim()
                   #Write-Host $uraDescripName -ForegroundColor Cyan
                   
                   $URAGPOPath = $URACommonPath + $uraDescripName

                   Add-Content $secEditOutPath -Value " " -encoding UTF8

                   $uraDescripName + " " + "`(" +$uraItem.trim()[0] +"`)" | Out-File $secEditOutPath -Append -encoding UTF8
                   $uraDescripName = "<div title=$uraMSRecom>$uraDescripName"

                   $uraTrimDescrip = "<div title=$URAGPOPath>$uraItemTrim"
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
           #Write-Host $objUserName.Value -ForegroundColor Magenta
       
           "   " + $objUserName.Value  | Out-File $secEditOutPath -Append  -encoding UTF8

           [string]$NameURA += $objUserName.Value + ", "
       }
            
       $newObjURA = New-Object -TypeName PSObject
       Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Name -Value $uraDescripName
       Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Priv -Value $uraTrimDescrip
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

$date180days = (Get-Date).AddDays(-180).toString("yyyyMMdd")

    $HotFix=@()
    $getHF = Get-HotFix -ErrorAction SilentlyContinue  | Select-Object HotFixID,InstalledOn,Caption 

    foreach ($hfitem in $getHF)
    {
        $hfid = $hfitem.hotfixid
        $hfdate = $hfitem.installedon
        $hfdate = ($hfdate).Date.ToString("yyyyMMdd")
        $hfurl = $hfitem.caption
        $trueFalse = "True"

        if ($date180days -gt $hfdate)
            {
                $hfdate = "Warning $($hfdate) Warning"
                $trueFalse = "False"
            }

        $newObjHF = New-Object psObject
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name HotFixID -Value $hfid
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name InstalledOn -Value $hfdate
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name Caption -Value $hfurl
        Add-Member -InputObject $newObjHF -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse         
        
        $HotFix += $newObjHF
    }

################################################
##############  INSTALLED APPS  ################
################################################
    $getUninx64 = Get-ChildItem  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
    $getUninx86 = Get-ChildItem  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction SilentlyContinue
    $getUnin = $getUninx64 + $getUninx86
    $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
    $InstallApps =@()
    $date180days = (Get-Date).AddDays(-180).toString("yyyyMMdd")

    
    foreach ($uninItem in  $UninChild)
    {
        $getUninItem = Get-ItemProperty $uninItem -ErrorAction SilentlyContinue | where {$_.displayname -notlike "*kb*"}
    
        #Write-Host $getUninItem.DisplayName
        $UninDisN = $getUninItem.DisplayName -replace "$null",""
        $UninDisVer = $getUninItem.DisplayVersion -replace "$null",""
        $UninPub = $getUninItem.Publisher -replace "$null",""
        $UninDisIcon = ($getUninItem.DisplayIcon -replace "$null","").split(",")[0]
        $UninDate = $getUninItem.InstallDate -replace "$null",""
        $trueFalse = "True"

        if ($date180days -gt $UninDate)
            {
                $UninDate = "Warning $($UninDate) Warning"
                $trueFalse = "False"
            }
    
        $newObjInstApps = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name Publisher -Value  $UninPub 
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayName -Value $UninDisN
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayVersion -Value $UninDisVer
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name DisplayIcon -Value $UninDisIcon
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name InstallDate -Value $UninDate
        Add-Member -InputObject $newObjInstApps -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse 
        $InstallApps += $newObjInstApps
    }
  
################################################
###########  INSTALLED UPDATES  ################
################################################
#MS are making a bit of a mess of udpates, get-hotfix only returns the latest 10 installed
#Office 2019 onwards doesnt register installed KB's
#But for Office 2016 and older installed KB's do create keys in the Uninstall 

    $getUnin16 = Get-ChildItem  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
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
##########  INSTALLED FEATURES #################
################################################
Write-Host " "
Write-Host "Windows Features" -foregroundColor Green
sleep 5

    $VulnReport = "C:\SecureReport"
    $OutFunc = "WindowsFeatures" 
                
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
       New-Item -Path "C:\SecureReport\output\$OutFunc\" -ItemType Directory -Force
    }

    $WinFeaturePathtxt = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"
    $FragWinFeature=@()
    $getWindows = Get-CimInstance win32_operatingsystem | Select-Object caption
        if ($getWindows.caption -notlike "*Server*")
        {
        Dism /online /Get-Features >> $WinFeaturePathtxt
        $getdismCont = (Get-Content $WinFeaturePathtxt | Select-String enabled -Context 1) -replace("  Feature Name : ","") -replace("> State : ",",") | Sort-Object 
    
        foreach ($dismItem in $getdismCont)
            {
                $dismSplit = $dismItem.split(",")
                $dismSplit[0]
                $dismSplit[1]

                $newObjWinFeature = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name WindowsFeature -Value $dismSplit[0]
                Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name InstallState -Value $dismSplit[1]
                $FragWinFeature += $newObjWinFeature
            }
        }
        else
        {
        $WinFeature = Get-WindowsFeature | where {$_.installed -eq "installed"} | Sort-Object name
        foreach ($featureItem in $WinFeature)
            {
                $newObjWinFeature = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name WindowsFeature -Value $featureItem.DisplayName 
                #Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name InstallState -Value $featureItem.Installed
                $FragWinFeature += $newObjWinFeature
            }
        }

################################################
##################  ANTIVIRUS  #################
################################################

#https://stackoverflow.com/questions/33649043/powershell-how-to-get-antivirus-product-details - "borrowed" baulk of script from site

    #$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  
    $AntiVirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct 

    if ($AntiVirusProducts -ne $null)
    {
        if ($AntiVirusProducts.Count -gt "1")
        {$AntiVirusProducts = $AntiVirusProducts | where {$_.displayname -ne "Windows Defender"}}
    
        $newObjAVStatus=@()
        foreach($AntiVirusProduct in $AntiVirusProducts){
            #Switch to determine the status of antivirus definitions and real-time protection.
            switch ($AntiVirusProduct.productState) 
            {
                "262144" {$defstatus = "Up to date" ;$rtstatus = "Warning Disabled warning"}
                "262160" {$defstatus = "Warning Out of date warning" ;$rtstatus = "Warning Disabled warning"}
                "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "266256" {$defstatus = "Warning Out of date warning" ;$rtstatus = "Enabled"}
                "270336" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "393216" {$defstatus = "Up to date" ;$rtstatus = "Warning Disabled warning"}
                "393232" {$defstatus = "Warning Out of date" ;$rtstatus = "Warning Disabled warning"}
                "393488" {$defstatus = "Warning Out of date" ;$rtstatus = "Warning Disabled warning"}
                "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397568" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397328" {$defstatus = "Warning Out of date" ;$rtstatus = "Enabled"}
                "397584" {$defstatus = "Warning Out of date" ;$rtstatus = "Enabled"}   
                "393472" {$defstatus = "Up to date" ;$rtstatus  = "Warning Disabled warning"}
                "401664" {$defstatus = "Up to date" ;$rtstatus  = "Warning Disabled warning"}
                default {$defstatus = "Warning Unknown warning" ;$rtstatus = "Warning Unknown warning"}
            }

            $avDisplay = $AntiVirusProduct.displayName
            $avProduct = $AntiVirusProduct.pathToSignedProductExe 
            $avPath = $AntiVirusProduct.pathToSignedReportingExe 
            $avStatus = $defstatus
            $avReal = $rtstatus

            $AVService = ((get-service | where {$_.DisplayName -like "*$avDisplay*" }).Status)[0]
        
            $newObjAVStatus = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVName -Value $avDisplay
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVProduct -Value $avProduct
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVPathtoExecute -Value $avPath
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVStatus -Value $avStatus 
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVEngine -Value $avReal
            #Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVService -Value $AVService 
            $FragAVStatus += $newObjAVStatus

            }
        }
        Else  #server and Defender cant be detected
        {
            $newObjAVStatus = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVName -Value "Warning Antivirus cant be detected, assume the worst and its not installed warning"
            $FragAVStatus += $newObjAVStatus
        }

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
    
    #Get-CimInstance win32_service
    #gwmi win32_service

    $vulnSvc = Get-CimInstance win32_service | foreach{$_} | 
    where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
    where {-not $_.pathname.startswith("`"")} | 
    where {($_.pathname.substring(0, $_.pathname.indexof(".sys") + 4 )) -match ".* .*" -or ($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 )) -match ".* .*" }
    $fragUnQuoted=@()
    
    foreach ($unQSvc in $vulnSvc)
    {
    $svc = $unQSvc.name
    $SvcReg = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\$svc -ErrorAction SilentlyContinue
    
        if ($SvcReg.imagePath -like "*.exe*")
        {
            $SvcRegSp =  $SvcReg.imagePath -split ".exe"
            $SvcRegSp0 = $SvcRegSp[0]
            $SvcRegSp1 = $SvcRegSp[1]
            $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $qpath -Append
                
            $newObjSvc = New-Object psObject
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning $($SvcReg.PSChildName) warning"
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning $($SvcReg.ImagePath) warning"
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
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning $($SvcReg.PSChildName) warning"
            Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning $($SvcReg.ImagePath) warning"
            $fragUnQuoted += $newObjSvc
        }
    }

Write-Host " "
Write-Host "Finished Searching for UnQuoted Path Vulnerabilities" -foregroundColor Green
      
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
    ($getMsinfo | Select-String "Secure Boot State") -replace "off",";off" -replace "on",";on" |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "Kernel DMA Protection") -replace "off",";off" -replace " on",";on"  |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "Guard Virtualization based") -replace "security	Run","security;	Run" |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "Required Security Properties") -replace "Required Security Properties","Required Security Properties;" |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "Available Security Properties") -replace "Available Security Properties","Available Security Properties;" |Out-File $msinfoPathcsv -Encoding utf8 -Append 
    ($getMsinfo | Select-String "based security services configured") -replace "based security services configured","based security services configured;"  |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "based security services running") -replace "based security services running","based security services running;" |Out-File $msinfoPathcsv -Encoding utf8 -Append
    ($getMsinfo | Select-String "Application Control Policy") -replace "policy	Enforced","policy;	Enforced" -replace "Policy  Audit","Policy;  Audit"|Out-File $msinfoPathcsv -Encoding utf8 -Append 
    ($getMsinfo | Select-String "Application Control User") -replace "off",";off" -replace " on",";on" -replace "policy	Enforced","policy;	Enforced"  -replace "Policy  Audit","Policy;  Audit" |Out-File $msinfoPathcsv -Encoding utf8 -Append 
    ($getMsinfo | Select-String "Device Encryption Support") -replace "Encryption Support","Encryption Support;" |Out-File $msinfoPathcsv -Encoding utf8 -Append

    Import-Csv $msinfoPathcsv -Delimiter ";" | Export-Clixml $msinfoPathXml
    $MsinfoClixml = Import-Clixml $msinfoPathXml 

    #Get-Content $msinfoPathXml 

Write-Host " "
Write-Host "Finished Collecting MSInfo32 data for VBS" -foregroundColor Green

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
            $drvQryItem = "Warning $drvQryItem warning"
        }
    
        $newObjDriverQuery = New-Object PSObject
        Add-Member -InputObject $newObjDriverQuery -Type NoteProperty -Name DriverName -Value $drvQryItem 
        $DriverQuery += $newObjDriverQuery
    }

Write-Host " "
Write-Host "Finished Collectiong DriverQuery data for VBS" -foregroundColor Green

################################################
##############  NETWORK SETTINGS  ##############
################################################
#Going to use the table below for other projects prefix, mask, available addresses, number of hosts
    $IPSubnet =[ordered]@{

    32 = "32","255.255.255.255","1","1"
    31 = "31","255.255.255.254","2","2"
    30 = "30","255.255.255.252","4","2"
    29 = "29","255.255.255.248","8","6"
    28 = "28","255.255.255.240","16","14"
    27 = "27","255.255.255.224","32","30"
    26 = "26","255.255.255.192","64","62"
    25 = "25","255.255.255.128","128","126"
    24 = "24","255.255.255.0","256","254"
    23 = "23","255.255.254.0","512","510"
    22 = "22","255.255.252.0","1024","1022"
    21 = "21","255.255.248.0","2048","2046"
    20 = "20","255.255.240.0","4096","4094"
    19 = "19","255.255.224.0","8192","8190"
    18 = "18","255.255.192.0","16384","16382"
    17 = "17","255.255.128.0","32768","32766"
    16 = "16","255.255.0.0","65536","65534"
    15 = "15","255.254.0.0","131072","131070"
    14 = "14","255.252.0.0","262144","262142"
    13 = "13","255.248.0.0","524288","524286"
    12 = "12","255.240.0.0","1048576","1048574"
    11 = "11","255.224.0.0","2097152","2097150"
    10 = "10","255.192.0.0","4194304","4194302"
    9 = "9","255.128.0.0","8388608","8388606"
    8 = "8","255.0.0.0","16777216","16777214"
    7 = "7","254.0.0.0","33554432","33554430"
    6 = "6","252.0.0.0","67108864","67108862"
    5 = "5","248.0.0.0","134217728","134217726"
    4 = "4","240.0.0.0","268435456","268435454"
    3 = "3","224.0.0.0","536870912","536870910"
    2 = "2","192.0.0.0","1073741824","1073741822"
    1 = "1","128.0.0.0","2147483648","2147483646"
    0 = "0","0.0.0.0","4294967296","4294967294"
    }

$fragNetwork=@()

    $gNetAdp = Get-NetAdapter | where {$_.Status -eq "up"}
    $intAlias = $gNetAdp.InterfaceAlias

    $macAddy = $gNetAdp.MacAddress 

    $gNetIPC = Get-NetIPConfiguration  -InterfaceAlias $gNetAdp.Name
        $IPAddress4 = $gNetIPC.IPv4Address.ipaddress -join ", "
        $IPAddress4 = [string]$IPAddress4 
        
        $IPAddress6 = $gNetIPC.IPv6Address.ipaddress -join ", "
        $IPAddress6 = [string]$IPAddress6

        $Router4 = $gNetIPC.IPv4DefaultGateway.nexthop -join ", "
        $Router4 =[string]$Router4
        
        $Router6 = $gNetIPC.IPv6DefaultGateway.nexthop -join ", "
        $Router6  = [string]$Router6 
        
        $dnsAddress = $gNetIPC.dnsserver.serveraddresses -join ", "
        $dnsAddress = [String]$dnsAddress

    $InterfaceAlias = $gNetAdp.Name
    $gNetIPA4 = Get-NetIPAddress  | where {$_.InterfaceAlias -eq "$InterfaceAlias" -and $_.AddressFamily -eq "IPv4"}
    $IPSubnet4 = $gNetIPA4.PrefixLength

    $gNetIPA6 = Get-NetIPAddress | where {$_.InterfaceAlias -eq "$InterfaceAlias" -and $_.AddressFamily -eq "IPv6"}
    $IPSubnet6 = $gNetIPA6.PrefixLength -join " ,"
    $IPSubnet6 = [string]$IPSubnet6 

    foreach ($IPSubItem in $IPSubnet.Values)
    {
    $subPrefix = $IPSubItem[0]
    $subnet = $IPSubItem[1]
    $subAddress = $IPSubItem[2]
    $subHosts = $IPSubItem[3]
        if ($subPrefix -eq $IPSubnet4)
        {
        $subnetTrans = $subnet
        }
    }

$newObjNetwork4 = New-Object -TypeName PSObject
Add-Member -InputObject $newObjNetwork4 -Type NoteProperty -Name IPv4Address -Value $IPAddress4
Add-Member -InputObject $newObjNetwork4 -Type NoteProperty -Name IPv4Subnet -Value $subnetTrans
Add-Member -InputObject $newObjNetwork4 -Type NoteProperty -Name IPv4Gateway -Value $Router4
Add-Member -InputObject $newObjNetwork4 -Type NoteProperty -Name DNSServers -Value $dnsAddress
Add-Member -InputObject $newObjNetwork4 -Type NoteProperty -Name Mac -Value $macAddy 
$fragNetwork4 += $newObjNetwork4

$newObjNetwork6 = New-Object -TypeName PSObject
Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Address -Value $IPAddress6 
Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Subnet -Value $IPSubnet6
Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Gateway -Value $Router6
Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name DNSServers -Value $dnsAddress
Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name Mac -Value $macAddy 
$fragNetwork6 += $newObjNetwork6

################################################
#############  MISC REG SETTINGS  ##############
################################################
Write-Host " "
Write-Host "Auditing Various Registry Settings" -foregroundColor Green
sleep 5

    #kernel-mode hardware-enforced stack protection
    $getkernelMode = Get-Item 'HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\' -ErrorAction SilentlyContinue
    $getkernelModeVal =  $getkernelMode.GetValue("FeatureSettingsOverride")
    $fragkernelModeVal =@()

    if ($getkernelModeVal -eq "9")
    {
        $kernelModeSet = "Kernel-mode hardware-enforced stack protection key FeatureSettingsOverride is enabled with a value of $getkernelModeVal" 
        $kernelModeReg = "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\"
        $kernelModeCom = "Kernel-mode Hardware-enforced Stack Protection is a security feature of Windows 11 22H2"
        $trueFalse = "True"
    }
    else
    {
        $kernelModeSet = "Warning Kernel-mode hardware-enforced stack protection key FeatureSettingsOverride is disabled with a value of $getkernelModeVal Warning" 
        $kernelModeReg = "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\"
        $kernelModeCom = "Kernel-mode Hardware-enforced Stack Protection is a security feature of Windows 11 22H2"
        $trueFalse = "False"
    }

    $newObjkernelMode = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjkernelMode -Type NoteProperty -Name KernelModeSetting -Value  $kernelModeSet
    Add-Member -InputObject $newObjkernelMode -Type NoteProperty -Name KernelModeRegValue -Value $kernelModeReg 
    Add-Member -InputObject $newObjKernelMode -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    #Add-Member -InputObject $newObjkernelMode -Type NoteProperty -Name kernelModeComment -Value $kernelModeCom
    $fragkernelModeVal += $newObjkernelMode


    #LSA
    $getLSA = Get-Item 'HKLM:\System\CurrentControlSet\Control\lsa\' -ErrorAction SilentlyContinue
    $getLSAPPL =  $getLSA.GetValue("RunAsPPL")
    $fragLSAPPL =@()

    if ($getLSAPPL -eq "1")
    {
        $lsaSet = "LSA is enabled the RunAsPPL is set to $getLSAPPL" 
        $lsaReg = "HKLM:\System\CurrentControlSet\Control\lsa\"
        $lsaCom = "Win10 and above Credential Guard should be used for Domain joined clients"
        $trueFalse = "True"
    }
    else
    {
        $lsaSet = "Warning Secure LSA is disabled set RunAsPPL to 1 Warning" 
        $lsaReg = "HKLM:\System\CurrentControlSet\Control\lsa\"
        $lsaCom = "Required for Win8.1 and below"
        $trueFalse = "False"
    }

    $newObjLSA = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSASetting -Value  $lsaSet
    Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSARegValue -Value $lsaReg 
    Add-Member -InputObject $newObjLSA -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    #Add-Member -InputObject $newObjLSA -Type NoteProperty -Name LSAComment -Value $lsaCom
    $fragLSAPPL += $newObjLSA
 
    #WDigest
    $getWDigest = Get-Item 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\' -ErrorAction SilentlyContinue
    $getWDigestULC =  $getWDigest.GetValue("UseLogonCredential")
    $fragWDigestULC =@()

    if ($getWDigestULC -eq "1")
    {
        $WDigestSet = "Warning WDigest is enabled and plain text passwords are stored in LSASS Warning" 
        $WDigestReg = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\"
        $trueFalse = "False"

    }
    else
    {
        $WDigestSet = "Secure WDigest is disabled" 
        $WDigestReg = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\"
        $trueFalse = "True"
    }

    $newObjWDigest = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWDigest -Type NoteProperty -Name WDigestSetting -Value  $WDigestSet
    Add-Member -InputObject $newObjWDigest -Type NoteProperty -Name WDigestRegValue -Value $WDigestReg 
    Add-Member -InputObject $newObjWDigest -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWDigestULC += $newObjWDigest


    #Credential Guard
    $getCredGu = Get-Item 'HKLM:\System\CurrentControlSet\Control\LSA\' -ErrorAction SilentlyContinue
    $getCredGuCFG =  $getCredGu.GetValue("LsaCfgFlags")
    $fragCredGuCFG =@()

    if ($getCredGuCFG -eq "1")
    {
        $CredGuSet = "Credential Guard is enabled, the LsaCfgFlags value is set to $getCredGuCFG" 
        $CredGuReg = "HKLM:\System\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard is enabled with UEFI persistance."
        $trueFalse = "True"
    }
    elseif ($getCredGuCFG -eq "2")
    {
        $CredGuSet = "Credential Guard is enabled, the LsaCfgFlags value is set to $getCredGuCFG" 
        $CredGuReg = "HKLM:\System\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard is enable without UEFI persistence."
        $trueFalse = "True"
    }
    else
    {
        $CredGuSet = "Warning Secure Credential Guard is disabled, LsaCfgFlags is set to 0 Warning" 
        $CredGuReg = "HKLM:\System\CurrentControlSet\Control\LSA\"
        $CredGuCom = "Credential Guard requires the client to be Domain joined"
        $trueFalse = "False"
    }

    $newObjCredGu = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name CredentialGuardSetting -Value  $CredGuSet
    Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name CredentialGuardRegValue -Value $CredGuReg 
    Add-Member -InputObject $newObjCredGu -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
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
        $trueFalse = "True"

        $newObjLapsPw = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordEnabled -Value $LapsPwSetena
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordComplexity -Value $LapsPwSetcom 
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordLength -Value $LapsPwSetlen
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordDay -Value $LapsPwSetday 
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordReg -Value $LapsPwReg
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
        $fragLapsPwEna += $newObjLapsPw

    }
    else
    {
        $LapsPwSet = "Warning LAPS is not installed or the value is set to 0 Warning" 
        $LapsPwReg = "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" 
        $LapsPwCom = "LAPS is not installed or configured - Ignore if not Domain Joined"
        $trueFalse = "False"

        $newObjLapsPw = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordEnabled -Value  $LapsPwSet
        Add-Member -InputObject $newObjLapsPw -Type NoteProperty -Name LAPSPasswordReg -Value $LapsPwReg
        Add-Member -InputObject $newObjLapsPW -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse         
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
        $trueFalse = "True"
    }
    else
    {
        $dllSet = "Warning DLLSafeSearch is disabled set SafeDLLSearchMode to 1 Warning" 
        $dllReg = "HKLM:\System\CurrentControlSet\Control\Session Manager"
        $dllCom = "Protects against DLL search order hijacking"
        $trueFalse = "False"
    }

    $newObjDLLSafe = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeSetting -Value  $dllSet
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeValue -Value $dllReg 
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name DLLSafeComment -Value $dllCom
    Add-Member -InputObject $newObjDLLSafe -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragDLLSafe += $newObjDLLSafe


    #Code Integrity
    $getCode = Get-Item 'HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
    $getCode =  $getCode.GetValue("Enabled")

    $fragCode =@()
    if ($getCode -eq "1")
    {
        $CodeSet = "Hypervisor Enforced Code Integrity is enabled" 
        $CodeReg = "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        $CodeCom = "Protects against credential theft"
        $trueFalse = "True"
    }
    else
    {
        $CodeSet = "Warning Hypervisor Enforced Code Integrity is disabled set Enabled to 1 Warning" 
        $CodeReg = "HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        #$CodeCom = "Protects against credential theft"
        $trueFalse = "False"
    }

    $newObjCode = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeSetting -Value  $CodeSet
    Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeValue -Value $CodeReg 
    Add-Member -InputObject $newObjCode -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    #Add-Member -InputObject $newObjCode -Type NoteProperty -Name CodeComment -Value $CodeCom
    $fragCode += $newObjCode


    #InstallElevated
    $getPCInstaller = Get-Item HKLM:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    $getUserInstaller = Get-Item HKCU:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
    $PCElevate =  $getUserInstaller.GetValue("AlwaysInstallElevated")
    $UserElevate = $getPCInstaller.GetValue("AlwaysInstallElevated")

    $fragPCElevate =@()
    if ($PCElevate -eq "1")
    {
        $ElevateSet = "Warning Client setting Always Install Elevate is enabled Warning" 
        $ElevateReg = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
        $trueFalse = "False"
    }
    else
    {
        $ElevateSet = "Client setting  Always Install Elevate is disabled" 
        $ElevateReg = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
        $trueFalse = "True"
    }

    $newObjElevate = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateSetting -Value  $ElevateSet
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateRegistry -Value $ElevateReg
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragPCElevate += $newObjElevate 

    if ($UserElevate -eq "1")
    {
        $ElevateSet = "Warning User setting Always Install Elevate is enabled Warning" 
        $ElevateReg = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
        $trueFalse = "False"
    }
    else
    {
        $ElevateSet = "User setting Always Install Elevate is disabled" 
        $ElevateReg = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
        $trueFalse = "True"
    }
       
    $newObjElevate = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateSetting -Value  $ElevateSet
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name AlwaysElevateRegistry -Value $ElevateReg
    Add-Member -InputObject $newObjElevate -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragPCElevate += $newObjElevate 

    #AutoLogon Details in REG inc password   
    $getAutoLogon = Get-Item  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    $AutoLogonDefUser =  $getAutoLogon.GetValue("DefaultUserName")
    $AutoLogonDefPass =  $getAutoLogon.GetValue("DefaultPassword ") 

    $fragAutoLogon =@()

    if ($AutoLogonDefPass  -ne "$null")
    {
        $AutoLPass = "There is no Default Password set for AutoLogon" 
        $AutoLUser = "There is no Default User set for AutoLogon" 
        $AutoLReg = "HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon"
        $trueFalse = "True"
    }
    else
    {
        $AutoLPass = "Warning AutoLogon default password is set with a vaule of $AutoLogonDefPass Warning" 
        $AutoLUser = "Warning AutoLogon Default User is set with a vaule of $AutoLogonDefUser Warning" 
        $AutoLReg = "HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon"
        $trueFalse = "False"
    }

    $newObjAutoLogon = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonUsername -Value $AutoLUser
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonPassword -Value  $AutoLPass
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonRegistry -Value $AutoLReg
    Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
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

    #SMB1 Driver
    cd HKLM:
    $getsmb1drv = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\MrxSmb10" -ErrorAction SilentlyContinue
    $ensmb1drv = $getsmb1drv.Start

    if ($ensmb1drv -eq "4")
    {
        $legProt = "SMB v1 client driver is set to $ensmb1drv in the Registry" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\MrxSmb10.Start"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning SMB v1 client driver is enabled Warning"
        $legReg = "HKLM:\System\CurrentControlSet\Services\MrxSmb10.Start"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #SMB v1 server
    cd HKLM:
    $getsmb1srv = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\" -ErrorAction SilentlyContinue
    $ensmb1srv = $getsmb1srv.SMB1

    if ($ensmb1srv -eq "0")
    {
        $legProt = "SMB v1 Server is set to $ensmb1srv in the Registry" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters.SMB1"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning SMB v1 Server is enabled Warning"
        $legReg = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters.SMB1"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #Insecure logons to an SMB server must be disabled
    cd HKLM:
    $getsmb1srv = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -ErrorAction SilentlyContinue
    $ensmb1srv = $getsmb1srv.AllowInsecureGuestAuth

    if ($ensmb1srv -eq "0")
    {
        $legProt = "Insecure logons to an SMB server is set to $ensmb1srv and disabled" 
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters.AllowInsecureGuestAuth"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Insecure logons to an SMB server is enabled Warning"
        $legReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters.AllowInsecureGuestAuth"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #llmnr = 0 is disabled
    cd HKLM:
    $getllmnrGPO = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $enllmnrGpo = $getllmnrgpo.EnableMulticast

    if ($enllmnrGpo -eq "0" -or $enllmnrReg -eq "0")
    {
        $legProt = "LLMNR (Responder) is disabled GPO = $enllmnrGpo" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient.EnableMulticast"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning LLMNR (Responder) is Enabled Warning" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient.EnableMulticast"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
    
    #NetBIOS over TCP/IP (NetBT) queries = 0 is disabled
    cd HKLM:
    $getNetBTGPO = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
    $enNetBTGPO = $getNetBTGPO.QueryNetBTFQDN

    if ($enNetBTGPO -eq "0")
    {
        $legProt = "NetBios is disabled the Registry = $enNetBTGPO" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient.QueryNetBTFQDN"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning NetBios is enabled Warning" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient.QueryNetBTFQDN"
        $legValue = $enNetBTGPO
        $legWarn = "Incorrect"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #ipv6 0xff (255)
    cd HKLM:
    $getIpv6 = get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -ErrorAction SilentlyContinue
    $getIpv6Int = $getIpv6.DisabledComponents
    
    if ($getIpv6Int -eq "255")
    {
        $legProt = "IPv6 is disabled the Registry = $getIpv6Int" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters.DisabledComponents"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning IPv6 is enabled Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters.DisabledComponents"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #Report on LMHosts file = 1
    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.EnableLMHosts
    
    if ($enLMHostsReg -eq "1")
    {
        $legProt = "LMHosts is disabled the Registry = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.EnableLMHosts"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Disable LMHosts Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.EnableLMHosts"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #NetBios Node Type set to 2 - Only Reg Setting
    cd HKLM:
    $getNetBtNodeReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
    $enNetBTReg = $getNetBtNodeReg.NodeType
    
    if ($enNetBTReg -eq "2")
    {
        $legProt = "NetBios Node Type is set to 2 in the Registry" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.NodeType"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning NetBios Node Type is set to $enNetBTReg is incorrect and should be set to 2 Warning"
        $legReg = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters.NodeType"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #disable netbios
    cd HKLM:
    $getNetBiosInt = Get-ChildItem "HKLM:\System\CurrentControlSet\services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    
    foreach ($inter in $getNetBiosInt)
    {
        $getNetBiosReg = Get-ItemProperty $inter.Name
        $NetBiosValue = $getNetBiosReg.NetbiosOptions
        $NetBiosPath = $getNetBiosReg.PSChildName
        $NEtBiosPara = $NetBiosPath,$NetBiosValue
    
        if ($NetBiosValue -eq "0")
        {
            $legProt = "NetBios is set to $NetBiosValue in the Registry" 
            $legReg = "HKLM:\System\CurrentControlSet\services\NetBT\Parameters\Interfaces.$NetBiosPath"
            $trueFalse = "True"
        }
        else
        {
            $legProt = "Warning NetBios is set to $NetBiosValue, its incorrect and should be set to 0 Warning"
            $legReg = "HKLM:\System\CurrentControlSet\services\NetBT\Parameters\Interfaces.$NetBiosPath"
            $trueFalse = "False"
        }
    
        $newObjLegNIC = New-Object psObject
        Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
        Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
        Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
        $fragLegNIC += $newObjLegNIC
    }

    cd HKLM:

    #Peer Net
    $getPeer = Get-ItemProperty  "HKLM:\Software\policies\Microsoft\Peernet" -ErrorAction SilentlyContinue
    $getPeerDis = $getPeer.Disabled
    
    if ($getPeerDis -eq "1")
    {
        $legProt = "Peer to Peer is set to $getPeerDis and disabled" 
        $legReg = "HKLM:\Software\policies\Microsoft\Peernet"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Peer to Peer is enabled Warning"
        $legReg = "HKLM:\Software\policies\Microsoft\Peernet"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #Enable Font Providers
    cd HKLM:
    $getFont = Get-ItemProperty  "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
    $getFontPr = $getFont.EnableFontProviders
    
    if ( $getFontPr -eq "0")
    {
        $legProt = "Enable Font Providers is set to $getFontPr and is disabled" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\System"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Enable Font Providers is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\System"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #LLTD
    #https://admx.help/HKLM/Software/Policies/Microsoft/Windows/LLTD
    $getNetLLTDInt = Get-item "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -ErrorAction SilentlyContinue

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
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning EnableLLTDIO is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #EnableRspndr
    if ($getRspndr -eq "0")
    {
        $legProt = "EnableRspndr is set to $getRspndr in the Registry" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning EnableRspndr is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #AllowLLTDIOOnDomain
    if ($getOnDomain -eq "0")
    {
        $legProt = "AllowLLTDIOOnDomain is set to $getOnDomain in the Registry" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning AllowLLTDIOOnDomain is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
   
    #AllowLLTDIOOnPublicNet
    if ($getPublicNet -eq "0")
    {
        $legProt = "AllowLLTDIOOnPublicNet is set to $getPublicNet in the Registry" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning AllowLLTDIOOnPublicNet is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
   
    #AllowRspndrOnDomain  
    if ($getRspOnDomain -eq "0")
    {
        $legProt = "AllowRspndrOnDomain is set to $getRspOnDomain in the Registry" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning AllowRspndrOnDomain is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    #AllowRspndrOnPublicNet    
    if ($getRspPublicNet -eq "0")
    {
        $legProt = "AllowRspndrOnPublicNet is set to $getRspPublicNet in the Registry" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning AllowRspndrOnPublicNet is enabled Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
   
    #ProhibitLLTDIOOnPrivateNe
    if ($getLLnPrivateNet -eq "0")
    {
        $legProt = "ProhibitLLTDIOOnPrivateNet is set to $getLLnPrivateNet in the Registry - When EnableLLTDIO is enabled, 1 is the correct setting" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning ProhibitLLTDIOOnPrivateNet is enabled - When EnableLLTDIO is enabled, 1 is the correct setting Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
   
    #ProhibitRspndrOnPrivateNet      $getRspPrivateNet = $getNetLLTDInt.GetValue("ProhibitRspndrOnPrivateNet")
    if ($getRspPrivateNet -eq "0")
    {
        $legProt = "ProhibitLLTDIOOnPrivateNet is set to $getRspPrivateNet in the Registry - When EnableLLTDIO is enabled, 1 is the correct setting" 
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning ProhibitLLTDIOOnPrivateNet is enabled - When EnableLLTDIO is enabled, 1 is the correct setting Warning"
        $legReg = "HKLM:\Software\Policies\Microsoft\Windows\LLTD"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC
  
    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.DisableIpSourceRouting
    
    if ($enLMHostsReg -eq "2")
    {
        $legProt = "IPv6 source routing must be configured to highest protection is enabled = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters.DisableIpSourceRouting"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning IPv6 source routing must be configured to highest protection is disabled or not set Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters.DisableIpSourceRouting"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    
    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.DisableIpSourceRouting
    
    if ($enLMHostsReg -eq "2")
    {
        $legProt = "IPv4 source routing must be configured to highest protection is enabled = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters.DisableIpSourceRouting"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning IPv4 source routing must be configured to highest protection is disabled or not set Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters.DisableIpSourceRouting"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.EnableICMPRedirect
    
    if ($enLMHostsReg -eq "0")
    {
        $legProt = "Allow ICMP redirects to override OSPF generated routes is disabled = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters.EnableICMPRedirect"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Allow ICMP redirects to override OSPF generated routes is enabled Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters.EnableICMPRedirect"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    cd HKLM:
    $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\" -ErrorAction SilentlyContinue
    $enLMHostsReg =  $getLMHostsReg.NoNameReleaseOnDemand
    
    if ($enLMHostsReg -eq "1")
    {
        $legProt = "Allow computer to ignore NetBIOS name release requests except from WINS servers is disabled = $enLMHostsReg" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters.NoNameReleaseOnDemand"
        $trueFalse = "True"
    }
    else
    {
        $legProt = "Warning Allow computer to ignore NetBIOS name release requests except from WINS servers is enabled Warning" 
        $legReg = "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters.NoNameReleaseOnDemand"
        $trueFalse = "False"
    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

    <#
    WPAD
    Web Proxy Auto Discovery protocol

    The Web Proxy Auto Discovery (WPAD) protocol assists with the automatic detection of proxy settings for web browsers. 
    Unfortunately, WPAD has suffered from a number of severe security vulnerabilities. Organisations that do not rely on 
    the use of the WPAD protocol should disable it. This can be achieved by modifying each workstation's host file at

    %SystemDrive%\Windows\System32\Drivers\etc\hosts to create the following entry: 255.255.255.255 wpad

    #>

    cd C:\Windows\System32
    $getwpad = Get-content "C:\Windows\System32\Drivers\etc\hosts\" -ErrorAction SilentlyContinue
    $getwpadstring = $getwpad | Select-String '255.255.255.255 wpad'

    if ($getwpadstring -eq $null)
    {
        $legProt = "Warning There is no '255.255.255.255 wpad' entry Warning" 
        $legReg = "C:\Windows\System32\Drivers\etc\hosts\"
        $trueFalse = "False"
    }
    else
    {
        $legProt = "There's a 255.255.255.255 wpad entry" 
        $legReg = "C:\Windows\System32\Drivers\etc\hosts\"
        $trueFalse = "True"

    }
    
    $newObjLegNIC = New-Object psObject
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyProtocol -Value $legProt
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name LegacyPath -Value $legReg
    Add-Member -InputObject $newObjLegNIC -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragLegNIC += $newObjLegNIC

################################################
############  SECURITY OPTIONS  ################
################################################ 
    $fragSecOptions=@()
    $secOpTitle1 = "Domain member: Digitally encrypt or sign secure channel data (always)" # = 1
    $getSecOp1 = get-item 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue
    $getSecOp1res = $getSecOp1.getvalue("RequireSignOrSeal")

    if ($getSecOp1res -eq "1")
    {
        $SecOptName = "$secOpTitle1 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle1 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions 
    
    $secOpTitle2 = "Microsoft network client: Digitally sign communications (always)" # = 1
    $getSecOp2 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
    $getSecOp2res = $getSecOp2.getvalue("RequireSecuritySignature")

    if ($getSecOp2res -eq "1")
    {
        $SecOptName = "$secOpTitle2 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle2 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle3 = "Microsoft network server: Digitally sign communications (always)" # = 1
    $getSecOp3 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
    $getSecOp3res = $getSecOp3.getvalue("RequireSecuritySignature")

    if ($getSecOp3res -eq "1")
    {
        $SecOptName = "$secOpTitle3 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle3 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle4 = "Microsoft network client: Send unencrypted password to connect to third-party SMB servers" #  = 0
    $getSecOp4 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
    $getSecOp4res = $getSecOp4.getvalue("EnablePlainTextPassword")

    if ($getSecOp4res -eq "0")
    {
        $SecOptName = "$secOpTitle4 - Disabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle4 - Enabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions 

    $secOpTitle5 = "Network security: Do not store LAN Manager hash value on next password change" #  = 1
    $getSecOp5 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp5res = $getSecOp5.getvalue("NoLmHash")

    if ($getSecOp5res -eq "1")
    {
        $SecOptName = "$secOpTitle5 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle5 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle6 = "Network security: LAN Manager authentication level (Send NTLMv2 response only\refuse LM & NTLM)" #  = 5
    $getSecOp6 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp6res = $getSecOp6.getvalue("lmcompatibilitylevel")

    if ($getSecOp6res -eq "5")
    {
        $SecOptName = "$secOpTitle6 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle6 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle7 = "Network Access: Do not allow anonymous enumeration of SAM accounts" #  = 1
    $getSecOp7 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp7res = $getSecOp7.getvalue("restrictanonymoussam")

    if ($getSecOp7res -eq "1")
    {
        $SecOptName = "$secOpTitle7 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle7 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle8 = "Network Access: Do not allow anonymous enumeration of SAM accounts and shares" #  = 1
    $getSecOp8 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp8res = $getSecOp8.getvalue("restrictanonymous")

    if ($getSecOp8res -eq "1")
    {
        $SecOptName = "$secOpTitle8 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle8 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle9 = "Network Access: Let Everyone permissions apply to anonymous users" # = 0
    $getSecOp9 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    $getSecOp9res = $getSecOp9.getvalue("everyoneincludesanonymous")

    if ($getSecOp9res -eq "0")
    {
        $SecOptName = "$secOpTitle9 - Disabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle9 - Enabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle10 = "Network security: LDAP client signing requirements" # = 2 Required
    $getSecOp10 = get-item 'HKLM:\System\CurrentControlSet\Services\NTDS\parameters' -ErrorAction SilentlyContinue
    $getSecOp10res = $getSecOp10.getvalue("ldapserverintegrity")

    if ($getSecOp10res -eq "2")
    {
        $SecOptName = "$secOpTitle10 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle10 - Disabled Warning"
        $trueFalse = "False"
    }
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle15 = "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" 
    $getSecOp15 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' -ErrorAction SilentlyContinue
    $getSecOp15res = $getSecOp15.getvalue("NTLMMinClientSec")

    if ($getSecOp15res -eq "537395200")
    {
        $SecOptName = "$secOpTitle15 - Enabled (Require NTLMv2 session security and Require 128-bit encryption)"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle15 - Disabled set Require NTLMv2 session security and Require 128-bit encryption Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle16 = "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" 
    $getSecOp16 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' -ErrorAction SilentlyContinue
    $getSecOp16res = $getSecOp16.getvalue("NtlmMinServerSec")

    if ($getSecOp16res -eq "537395200")
    {
        $SecOptName = "$secOpTitle16 - Enabled (Require NTLMv2 session security and Require 128-bit encryption)"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle16 - Disabled set Require NTLMv2 session security and Require 128-bit encryption Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
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
    $getSecOp12 = get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' -ErrorAction SilentlyContinue
    $getSecOp12res = $getSecOp12.getvalue("supportedencryptiontypes")

    if ($getSecOp12res -eq "2147483640")
    {
        $SecOptName = "$secOpTitle12 - Enabled, (AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types)"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle12 - Disabled Warning"
        $trueFalse = "False"
    }
    

    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle11 = "Domain member: Require strong (Windows 2000 or later) session key" 
    $getSecOp11 = get-item 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' -ErrorAction SilentlyContinue
    $getSecOp11res = $getSecOp11.getvalue("RequireStrongKey")

    if ($getSecOp11res -eq "1")
    {
        $SecOptName = "$secOpTitle11 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle11 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle13 = "System cryptography: Force strong key protection for user keys stored on the computer" 
    $getSecOp13 = get-item 'HKLM:\Software\Policies\Microsoft\Cryptography\' -ErrorAction SilentlyContinue
    $getSecOp13res = $getSecOp13.getvalue("ForceKeyProtection")

    if ($getSecOp13res -eq "2")
    {
        $SecOptName = "$secOpTitle13 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle13 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions

    $secOpTitle14 = "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" 
    $getSecOp14 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\' -ErrorAction SilentlyContinue
    $getSecOp14res = $getSecOp14.getvalue("Enabled")

    if ($getSecOp14res -eq "1")
    {
        $SecOptName = "$secOpTitle14 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle14 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


    $secOpTitle17 = "Devices: Prevent users from installing printer drivers"
    $getSecOp17 = get-item 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\' -ErrorAction SilentlyContinue
    $getSecOp17res = $getSecOp17.getvalue("AddPrinterDrivers")

    if ($getSecOp17res -eq "1")
    {
        $SecOptName = "$secOpTitle17 - Enabled"
        $trueFalse = "True"
    }
    else
    {
        $SecOptName = "Warning $secOpTitle17 - Disabled Warning"
        $trueFalse = "False"
    }
    
    $newObjSecOptions = New-Object psObject
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name SecurityOptions -Value $SecOptName
    Add-Member -InputObject $newObjSecOptions -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragSecOptions +=  $newObjSecOptions


#Network Access: Restrict anonymous Access to Named Pipes and Shares
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
    
        if ($fwProfileIn -eq "allow")
        {
                $newObjFWProf = New-Object psObject
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Name -Value $fwProfileNa
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Enabled -Value $fwProfileEn
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Inbound -Value "Warning $fwProfileIn warning"
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Outbound -Value $fwProfileOut
                $fragFWProfile += $newObjFWProf 
        }
        else
        {
                $newObjFWProf = New-Object psObject
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Name -Value $fwProfileNa
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Enabled -Value $fwProfileEn
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Inbound -Value $fwProfileIn
                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Outbound -Value $fwProfileOut
                $fragFWProfile += $newObjFWProf 
        }
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
    where {$_.enabled -eq "true" -and $_.Direction -eq "Inbound"} | 
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
##############  SCHEDULED TasKS  ###############
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
            
            if ($syfoldAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
            {
                $taskUSerPers = "Warning User are allowed to WRITE or MODIFY $taskArgs Warning"
            }

            if ($syfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $taskUSerPers = "Warning Everyone are allowed to WRITE or MODIFY $taskArgs Warning"
            }

            if ($syfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $taskUSerPers = "Warning Authenticated User are allowed to WRITE or MODIFY $taskArgs Warning"
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
            where {$_.Accesstostring -like "*Users Allow  Write*" `
                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
            
            {
                $cfile | Out-File $hpath -Append
                #Write-Host $cfile -ForegroundColor Yellow
            }

            if ($cfileAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfile | Out-File $hpath -Append
                #Write-Host $cfile -ForegroundColor Yellow
            }
    
            if ($cfileAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
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
            Add-Member -InputObject $newObjwFile -Type NoteProperty -Name WriteableFiles -Value "Warning $($wFileItems) warning"
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
    $HKLMSvc = 'HKLM:\System\CurrentControlSet\Services'
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
            Add-Member -InputObject $newObjReg -Type NoteProperty -Name RegWeakness -Value "Warning $($regItems) warning"
            $fragReg += $newObjReg    
        }
   }

Write-Host " "
Write-Host "Finished Searching for Writeable Registry Hive Vulnerabilities" -foregroundColor Green

################################################
#############  WRITEABLE FOLDERS  ##############
############  NON System FOLDERS  ##############
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

            if ($cfoldAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
            {
                $cfold | Out-File $fpath -Append
                #Write-Host $cfold -ForegroundColor red
            }

            if ($cfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfold | Out-File $fpath -Append
                #Write-Host $cfold -ForegroundColor red
            }

            if ($cfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
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
###############  System FOLDERS  ###############
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
            if ($syfoldAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
            {
                $syfold | Out-File $sysPath -Append
                #Write-Host $syfold -ForegroundColor red
            }

            if ($syfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $syfold | Out-File $sysPath -Append
                #Write-Host $syfold -ForegroundColor red
            }

            if ($syfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})

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
###############  System FOLDERS  ###############
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

            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Users Allow  CreateFiles*"})
            {
                $createSyfold | Out-File $createSysPath -Append
                #Write-Host $createSyfold -ForegroundColor red
            }

            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  CreateFiles*"})
            {
                $createSyfold | Out-File $createSysPath -Append
                #Write-Host $createSyfold -ForegroundColor red
            }

            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  CreateFiles*"})
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
              where {$_.Accesstostring -like "*Users Allow  Write*" `
              -or $_.Accesstostring -like "*Users Allow  Modify*" `
              -or $_.Accesstostring -like "*Users Allow  FullControl*" `
              -or $_.Accesstostring -like "*Everyone Allow  Write*" `
              -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
              -or $_.Accesstostring -like "*Everyone Allow  FullControl*" `
              -or $_.Accesstostring -like "*Authenticated Users Allow  Write*" `
              -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
              -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"} 
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
        Add-Member -InputObject $newObjDllNotSigned -Type NoteProperty -Name CreateFiles -Value "Warning $($dllNotSigned) warning"
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
#Warning Very long running process - enable only when required
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
                Add-Member -InputObject $newObjAuthSig -Type NoteProperty -Name PathAuthCodeSig -Value "Warning $($authPath) warning"
                Add-Member -InputObject $newObjAuthSig -Type NoteProperty -Name StatusAuthCodeSig -Value "Warning $($authStatus) warning"
                $fragAuthCodeSig += $newObjAuthSig
            }
        }
    }

Write-Host " "
Write-Host "Completed searching for authenticode signature hashmismatch" -foregroundColor Green
#END OF IF
}

################################################
##########  CERTIFICATE DETAILS  ###############
################################################
    $getCert = (Get-ChildItem Cert:\LocalMachine).Name
    $fragCertificates=@()
    $certIssuer=@()
    $dateToday = get-date
    foreach($certItem in $getCert)
    {
    $getCertItems = (Get-ChildItem "Cert:\LocalMachine\$($certItem)" )  #| where {$_.Subject -notlike "*microsoft*"}) 

        foreach ($allCertInfo in $getCertItems)
        {
            $certThumb = $allCertInfo.Thumbprint
            $certPath = ($allCertInfo.PSPath).replace("Microsoft.PowerShell.Security\Certificate::","").replace("$certThumb","")
            $certIssuer = $allCertInfo.Issuer
            $count = ($certIssuer.split(",")).count
            $certDns = $allCertInfo.DnsNameList
            $certSub = $allCertInfo.Subject
            $certExpire = $allCertInfo.NotAfter
            $certName = $allCertInfo.FriendlyName
            $certKey = $allCertInfo.HasPrivateKey
            $certkeysize = $allCertInfo.PublicKey.Key.KeySize
            $certSigAlgor =  $allCertInfo.SignatureAlgorithm.FriendlyName

            $dateDiff = (get-date $certExpire) -lt (get-date $dateToday)
            $dateShort = $certExpire.ToShortDateString()

            #Added for a naughty list of CN=, Domain Names or words
            $newObjCertificates = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertIssuer -Value $certIssuer
            Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertSha1 -Value "$certSigAlgor" -force
            Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertExpired -Value $dateShort
            Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertSelfSigned -Value False
            Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertPrivateKey -Value False


            if 
            (
                $certDns -like "*somexxx*" `
                -or $certDns -like "*thingxxx*" 
            )
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertDNS -Value "Warning $($certDns) warning" -Force             
            }
            if
            (
                $certIssuer -like "*somexxx*" `
                -or $certIssuer -like "*thingxxx*" 
             )
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertIssuer -Value "Warning $($certIssuer) warning" -Force
            }

            if ($certSigAlgor -match "sha1")
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertSha1 -Value "Warning $($certSigAlgor) Warning" -force
            }

            if ($dateDiff -eq "false")
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertExpired -Value "Expired - $($dateShort) expired" -Force
            }

            if ($certSub -eq $certIssuer -and $count -eq 1)
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertSelfSigned -Value "SelfSigned - True SelfSigned" -force
            }

            if ($certKey -eq "true")
            {
                Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertPrivateKey -Value "privateKey - True privatekey" -force
            }
                                   
             #Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertIssuer -Value $certIssuer
             #Add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertExpired -Value $certExpire
             #add-Member -InputObject $newObjCertificates -Type NoteProperty -Name CertDNS -Value $certDns
             $fragCertificates += $newObjCertificates
        }
    }

################################################
##############  CIPHER SUITS  ##############
################################################

$gtCipherSuit = Get-TlsCipherSuite
$fragCipherSuit=@()
foreach($CipherItem in $gtCipherSuit)
    {
        $cipherName = $CipherItem.name
        $cipherCert = $CipherItem.certificate
        $cipherhash = $CipherItem.hash
        $cipherExch = $CipherItem.Exchange
        $trueFalse = "True"   

        if ($cipherhash -match "sha1")
            {
            $cipherhash = "Warning $cipherhash is vulnerable to MitM Warning"
            $cipherName = "Warning $cipherName Warning"
            $trueFalse = "False"  
            }
                    
        $newObjCipherSuite = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjCipherSuite -Type NoteProperty -Name CipherName -Value $cipherName
        Add-Member -InputObject $newObjCipherSuite -Type NoteProperty -Name CipherCert -Value $cipherCert
        Add-Member -InputObject $newObjCipherSuite -Type NoteProperty -Name CipherHash -Value $cipherhash
        Add-Member -InputObject $newObjCipherSuite -Type NoteProperty -Name CipherExchange -Value $cipherExch
        Add-Member -InputObject $newObjCipherSuite -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
        
        $fragCipherSuit += $newObjCipherSuite 
        
    }

################################################
##############  SHARES AND PERMS  ##############
################################################ 

Write-Host " "
Write-Host "Auditing Shares and permissions" -foregroundColor Green
sleep 3

    $getShr = Get-SmbShare #| where {$_.name -ne "IPC$"}
    $Permarray=@()
    $fragShare=@()

    foreach($shr in $getShr)
    {
        $Permarray=@()
        $shrName = $Shr.name
        $shrPath = $Shr.path
        $shrDes = $Shr.description

        $getShrPerms = Get-FileShareAccessControlEntry -Name $shr.Name -ErrorAction SilentlyContinue
    
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
############  EMBEDDED PASSWordS  ##############
################################################  

Write-Host " "
Write-Host "Now progress will slow whilst the script enumerates all files for passwords, be patient" -foregroundColor Green
Write-Host " "
Write-Host "Searching for Embedded Password in Files" -foregroundColor Green
sleep 7
  
#Passwords in Processes
    #$getPSPass = gwmi win32_process -ErrorAction SilentlyContinue | 

    $getPSPass = Get-CimInstance win32_process -ErrorAction SilentlyContinue |
    Select-Object Caption, Description,CommandLine | 
    where {$_.commandline -like "*pass*" -or $_.commandline -like "*credential*" -or $_.commandline -like "*username*"  }

    $fragPSPass=@()
    foreach ($PStems in $getPSPass)
    {
        $PSCap = $PStems.Caption
        $PSDes = $PStems.Description
        $PSCom = $PStems.CommandLine

        $newObjPSPass = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessCaption -Value "Warning $($PSCap) - warning"
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessDescription -Value "Warning $($PSDes) - warning"
        Add-Member -InputObject $newObjPSPass -Type NoteProperty -Name ProcessCommandLine -Value "Warning $($PSCom) - warning"
        $fragPSPass += $newObjPSPass
    }

#passwords embedded in files
#findstr /si password *.txt - alt
if ($embeddedpw -eq "y")
    {
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
    }

Write-Host " "
Write-Host "Finished Searching for Embedded Password in Files" -foregroundColor Green

################################################
#####  SEARCHING FOR REGISTRY PASSWordS   ######
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

    #Enter list of Words to search
    $regSearchWords = "password", "passwd"

    foreach ($regSearchItems in $regSearchWords){
        #swapped to native tool, Powershell is too slow
        reg query HKLM\Software /f $regSearchItems /t REG_SZ /s >> $secEditPath
        reg query HKCU\Software /f $regSearchItems /t REG_SZ /s >> $secEditPath
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
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPath -Value "Warning $($regPassPath) warning"
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryValue -Value "Warning $($regSearchItems) warning"
            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPassword -Value "Warning $($regPassword) warning"
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

        if ($dllFileAcl | where {$_.Accesstostring -like "*Users Allow  Write*" -or `
        $_.Accesstostring -like "*Users Allow  Modify*" -or `
        $_.Accesstostring -like "*Users Allow  FullControl*" -or `
        $_.Accesstostring -like "*Everyone Allow  Write*" -or `
        $_.Accesstostring -like "*Everyone Allow  Modify*" -or `
        $_.Accesstostring -like "*Everyone Allow  FullControl*" -or `
        $_.Accesstostring -like "*Authenticated Users Allow  Write*" -or `
        $_.Accesstostring -like "*Authenticated Users Allow  Modify*" -or `
        $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $getAuthCodeSig = get-authenticodesignature -FilePath $dllPath 
                $dllStatus = $getAuthCodeSig.Status

                $newObjDLLHijack = New-Object psObject
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLProcess -Value "Warning $($procName) warning"
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLPath -Value "Warning $($dllPath) warning"
                Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLSigStatus -Value "Warning $($dllStatus) warning"
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
$getASRGuids = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ErrorAction SilentlyContinue

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
            $ASRGuidObj = "Warning ASR Guid $asrGuiditem is not set Warning" 
            }
        
        if ($asrGuidSetting -eq "1")
            {
            $asrGuidSetObj = "ASR = 1"    
            }
        else
            {
            $asrGuidSetObj = "Warning ASR is disabled Warning"
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
    $DomAWarn = "Warning " + $HostDomain + "Domain Admins" + "  Warning"

    $EntA = $HostDomain + "Enterprise Admins"
    $EntAWarn = "Warning " + $HostDomain + "Enterprise Admins" + "  Warning"

    $SchA = $HostDomain + "Schema Admins"
    $SchAWarn = "Warning " + $HostDomain + "Schema Admins" + "  Warning"

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

#CERTS GO HERE - When its working correctly   

################################################
#######  RECOMMENDED SECURITY SETTINGS  ########
################  WINDOWS OS  ##################
################################################

#Here's 3000 lines of fun ;(
#Unable to extract GPO spreadsheet due to the numbers involved and the amount of work getting the spreadsheet into a workable format
#Lastly some of the MS recommend settings are mental and would destroy the system when following blindly eg Kerberos Armouring 
# Here are the settings that should either be set or at least acknowledged

    $fragWindowsOSVal=@()

    <#
    Boot-Start Driver Initialization Policy

    Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware

    This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:
    - Good: The driver has been signed and has not been tampered with.
    - Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
    - Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
    - Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.

    If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.
    If you disable or do not configure this policy setting, the boot start drivers determined to be Good, Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be Bad is skipped.
    If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.

    #>
    $WindowsOSDescrip = "Boot-Start Driver Initialization Policy"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Early Launch Antimalware\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Policies\EarlyLaunch\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DriverLoadPolicy"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "8")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled good only boot-start drivers that can be initialized" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    elseif ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled good and unknown only boot-start drivers that can be initialized" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    elseif ($getWindowsOSVal -eq "3")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Good, unknown and bad but critical boot-start drivers that can be initialized warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }
    else
    {
        #Else assume all boot-start drivers are allowed this is normally have a value of 7
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled all boot-start drivers that can be initialized warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

     if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse 
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Safe Mode

    An adversary with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with 
    Command Prompt options may be able to bypass system protections and security functionality. To reduce this risk, users with standard credentials 
    should be prevented from using Safe Mode options to log in.

    The following registry entry can be implemented using Group Policy preferences to prevent non-administrators from using Safe Mode options.

    #>
    $WindowsOSDescrip = "Prevent SafeMode for Non Admins"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "SafeModeBlockNonAdmins"   
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is not set warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

     if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse 
    $fragWindowsOSVal += $newObjWindowsOS

    <#

    Do not display network selection UI Enabled

    Computer Configuration\Policies\Administrative Templates\System\Logon\Do not display network selection UI Enabled

    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.
    If you enable this policy setting, the PC's network connectivity state cannot be changed without signing into Windows.
    If you disable or don't configure this policy setting, any user can disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
    #>

    $WindowsOSDescrip = "Do not display network selection UI Enabled"
    $gpopath = "Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DontDisplayNetworkSelectionUI"

    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal=@()
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is Enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }

     if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting  -Value $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    
    <#
    Enumerate local users on domain-joined computers

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows local users to be enumerated on domain-joined computers.
    If you enable this policy setting, Logon UI will enumerate all local users on domain-joined computers.
    If you disable or do not configure this policy setting, the Logon UI will not enumerate local users on domain-joined computers.
    #>
    
    $WindowsOSDescrip = "Enumerate local users on domain-joined computers"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnumerateLocalUsers"

    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal=@()
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is Enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip is Disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, 
    and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence 
    in case the system or network is compromised. Collecting this data is essential for analyzing the security of information 
    assets and detecting signs of suspicious and unexpected behavior. Enabling "Include command line data for process creation events"
     will record the command line information with the process creation events in the log. This can provide additional detail when 
     malware has run on a system.

    Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    #>
    $WindowsOSDescrip = "Include command line in process creation events"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Audit Process Creation\$WindowsOSDescrip"
    $RegKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ProcessCreationIncludeCmdLine_Enabled"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.
    If you enable this policy setting or if you do not configure this policy setting the SMB client will 
    allow insecure guest logons.If you disable this policy setting the SMB client will reject insecure guest logons.
    Insecure guest logons are used by file servers to allow unauthenticated access to shared folders. While uncommon 
    in an enterprise environment insecure guest logons are frequently used by consumer 
    Network Attached Storage (NAS) appliances acting as file servers. Windows file servers require authentication 
    and do not use insecure guest logons by default. Since insecure guest logons are unauthenticated important security 
    features such as SMB Signing and SMB Encryption are disabled. As a result clients that allow insecure guest logons 
    are vulnerable to a variety of man-in-the-middle attacks that can result in data loss data corruption and exposure to malware. 
    Additionally any data written to a file server using an insecure guest logon is potentially accessible to anyone on the network. 
    Microsoft recommends disabling insecure guest logons and configuring file servers to require authenticated access."      

    #>
    $WindowsOSDescrip = "Enable insecure guest logons"
    $gpopath ="Computer Configuration\Administrative Templates\Network\Lanman Workstation\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowInsecureGuestAuth"   
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is not set warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off picture password sign-in

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows you to control whether a domain user can sign in using a picture password.
    If you enable this policy setting, a domain user can't set up or sign in with a picture password.
    If you disable or don't configure this policy setting, a domain user can set up and use a picture password.
    Note that the user's domain password will be cached in the system vault when using this feature.

    #>
    $WindowsOSDescrip = "Turn off picture password sign-in"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "BlockDomainPicturePassword"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn on convenience PIN sign-in

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows you to control whether a domain user can sign in using a convenience PIN.
    If you enable this policy setting, a domain user can set up and sign in with a convenience PIN.
    If you disable or don't configure this policy setting, a domain user can't set up and use a convenience PIN.
    Note: The user's domain password will be cached in the system vault when using this feature.
    To configure Windows Hello for Business, use the Administrative Template policies under Windows Hello for Business.

    #>
    $WindowsOSDescrip = "Turn on convenience PIN sign-in"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowDomainPINLogon"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

 <#
    Allow users to select when a password is required when resuming from connected standby

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows you to control whether a user can change the time before a password is required when a Connected Standby device screen turns off.
    If you enable this policy setting, a user on a Connected Standby device can change the amount of time after the device's screen turns off before a password is required when waking the device. The time is limited by any EAS settings or Group Policies that affect the maximum idle time before a device locks. Additionally, if a password is required when a screensaver turns on, the screensaver timeout will limit the options the user may choose.
    If you disable this policy setting, a user cannot change the amount of time after the device's screen turns off before a password is required when waking the device. Instead, a password is required immediately after the screen turns off.

    #>
    $WindowsOSDescrip = "Allow users to select when a password is required when resuming from connected standby"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowDomainDelayLock"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Turn off app notifications on the lock screen

    Computer Configuration\Policies\Administrative Templates\System\Logon

    #>
    $WindowsOSDescrip = "Turn off app notifications on the lock screen"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableLockScreenAppNotifications"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS



<#
    Prevent the computer from joining a homegroup

    Computer Configuration\Policies\Administrative Templates\Windows Components\HomeGroup

    This policy setting specifies whether users can add computers to a homegroup. By default, users can add their computer to a homegroup on a private network.
    If you enable this policy setting, users cannot add computers to a homegroup. This policy setting does not affect other network sharing features.
    If you disable or do not configure this policy setting, users can add computers to a homegroup. However, data on a domain-joined computer is not shared with the homegroup.
    This policy setting is not configured by default.
    You must restart the computer for this policy setting to take effect.

    #>
    $WindowsOSDescrip = "Prevent the computer from joining a homegroup"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\HomeGroup\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\HomeGroup\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableHomeGroup"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


  <#
    Allow Windows Ink Workspace

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace

    #>
    $WindowsOSDescrip = "Allow Windows Ink Workspace"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowWindowsInkWorkspace"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Show lock in the user tile menu

    Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    #>
    $WindowsOSDescrip = "Show lock in the user tile menu"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ShowLockOption"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Enable screen saver

    User Configuration\Policies\Administrative Templates\Control Panel\Personalization

    #>
    $WindowsOSDescrip = "Enable screen saver"
    $gpopath ="User Configuration\Policies\Administrative Templates\Control Panel\Personalization\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ScreenSaveActive"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Password protect the screen saver

    User Configuration\Policies\Administrative Templates\Control Panel\Personalization

    #>
    $WindowsOSDescrip = "Password protect the screen saver"
    $gpopath ="User Configuration\Policies\Administrative Templates\Control Panel\Personalization\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ScreenSaverIsSecure"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Screen saver timeout

    User Configuration\Policies\Administrative Templates\Control Panel\Personalization

    #>
    $WindowsOSDescrip = "Screen saver timeout"
    $gpopath ="User Configuration\Policies\Administrative Templates\Control Panel\Personalization\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ScreenSaveTimeOut"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "900")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Turn off toast notifications on the lock screen

    User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications

    #>
    $WindowsOSDescrip = "Turn off toast notifications on the lock screen"
    $gpopath ="User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoToastApplicationNotificationOnLockScreen"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Do not suggest third-party content in Windows spotlight

    User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content

    #>
    $WindowsOSDescrip = "Do not suggest third-party content in Windows spotlight"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\CloudContent\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableThirdPartySuggestions"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent enabling lock screen camera

    Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization

    #>
    $WindowsOSDescrip = "Prevent enabling lock screen camera"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoLockScreenCamera"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent enabling lock screen slide show

    Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization

    #>
    $WindowsOSDescrip = "Prevent enabling lock screen camera"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Control Panel\Personalization\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Personalization\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoLockScreenSlideshow"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent users from sharing files within their profile.

    User Configurations\Policies\Administrative Templates\Windows Components\Network Sharing

    By default users are allowed to share files within their profile to other users on their network once an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.
    If you enable this policy, users will not be able to share files within their profile using the sharing wizard. Also, the sharing wizard will not create a share at %root%\users and can only be used to create SMB shares on folders.
    If you disable or don't configure this policy, then users will be able to share files out of their user profile once an administrator has opted in the computer.

    #>
    $WindowsOSDescrip = "Prevent users from sharing files within their profile"
    $gpopath ="User Configurations\Policies\Administrative Templates\Windows Components\Network Sharing\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoInplaceSharing"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Do not display the password reveal button

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.
    If you enable this policy setting, the password reveal button will not be displayed after a user types a password in the password entry text box.
    If you disable or do not configure this policy setting, the password reveal button will be displayed after a user types a password in the password entry text box.
    By default, the password reveal button is displayed after a user types a password in the password entry text box. To display the password, click the password reveal button.
    The policy applies to all Windows components and applications that use the Windows system controls, including Internet Explorer.
    
    #>

    $WindowsOSDescrip = "Do not display the password reveal button"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\CredUI\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisablePasswordReveal"
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal=@()
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


   <#
    Enumerate administrator accounts on elevation

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\

    This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application. By default, administrator accounts are not displayed when the user attempts to elevate a running application.
    If you enable this policy setting, all local administrator accounts on the PC will be displayed so the user can choose one and enter the correct password.
    If you disable this policy setting, users will always be required to type a user name and password to elevate.
    #>

    $WindowsOSDescrip = "Enumerate administrator accounts on elevation"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnumerateAdministrators"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Require trusted path for credential entry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface

    This policy setting requires the user to enter Microsoft Windows credentials using a trusted path, to prevent a Trojan horse or other types of malicious code from stealing the user's Windows credentials.
    Note: This policy affects nonlogon authentication tasks only. As a security best practice, this policy should be enabled.
    If you enable this policy setting, users will be required to enter Windows credentials on the Secure Desktop by means of the trusted path mechanism.
    If you disable or do not configure this policy setting, users will enter Windows credentials within the user's desktop session, potentially allowing malicious code Access to the user's Windows credentials.
    #>

    $WindowsOSDescrip = "Require trusted path for credential entry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableSecureCredentialPrompting"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse 
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent the use of security questions for local accounts

    Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface

    If you turn this policy setting on, local users won't be able to set up and use security questions to reset their passwords.    
    #>

    $WindowsOSDescrip = "Prevent the use of security questions for local accounts"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoLocalPasswordResetQuestions"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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

    $WindowsOSDescrip = "Disable or enable software Secure Attention Sequence"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "SoftwareSASGeneration"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq $null)
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is Enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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
    $WindowsOSDescrip = "Sign-in last interactive user automatically after a system-initiated restart"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableAutomaticRestartSignOn"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1" -or $getWindowsOSVal -eq $null)
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled or not Set Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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

    Note: passing ctrl, alt and Del through multiple RDP wont work
    #>

    $WindowsOSDescrip = "Interactive logon: Do not require CTRL+ALT+DEL"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "disablecad"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is Enabled or not defined Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Interactive logon: Machine inactivity limit

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    #>
    $WindowsOSDescrip = "Interactive logon: Machine inactivity limit"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "InactivityTimeoutSecs"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "900")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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

    $WindowsOSDescrip = "Interactive logon: Number of previous logons to cache"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\'
    $WindowsOSVal=@()
    $WindowsOSVal = "CachedLogonsCount"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -lt "2")
    {
        $WindowsOSSet = "$WindowsOSDescrip caches $getWindowsOSVal previous logons, ideally this should be set to 1" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is $getWindowsOSVal, ideally this should be set to 1 Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Network Access: Do not allow storage of passwords and credentials for network authentication

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
    $WindowsOSDescrip = "Network Access: Do not allow storage of passwords and credentials for network authentication"
    $gpopath ="Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Windows Logon Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "disabledomaincreds"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS
 

    <#
    Apply UAC restrictions to local accounts on network logons

    This setting controls whether local accounts can be used for remote administration via network logon 
    (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the 
    same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.

    Enabled (recommended): Applies UAC token-filtering to local accounts on network logons. Membership in 
    powerful group such as Administrators is disabled and powerful privileges are removed from the resulting 
    Access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.

    Disabled: Allows local accounts to have full administrative rights when authenticating via network logon, 
    by configuring the LocalAccountTokenFilterPolicy registry value to 1.

    For more information about local accounts and credential theft, see "Mitigating Pass-the-Hash (PtH) 
    Attacks and Other Credential Theft Techniques": http://www.microsoft.com/en-us/download/details.aspx?id=36036.

    For more information about LocalAccountTokenFilterPolicy, see http://support.microsoft.com/kb/951016.

    #>
    $WindowsOSDescrip = "Apply UAC restrictions to local accounts on network logons"
    $gpopath ="No GPO Setting available"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "LocalAccountTokenFilterPolicy"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled, mitigates Pass-the-Hash Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

       <#
    Hardened UNC Paths

    Computer Configuration\Policies\Administrative Templates\Network\Network Provider

    Not applicable to non-domain joined systems

    When enabled ensures only domain joined systems can download and Access policies


    #>
    $WindowsOSDescrip = "Hardened UNC Paths"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Network\Network Provider\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\'
    $WindowsOSVal=@()
    $WindowsOSVal = "HardenedPaths"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
   # $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 
     $getWindowsOSVal = $getWindowsOS.Property

    if ($getWindowsOSVal -eq "\\*\SYSVOL" -and "\\*\NETLOGON")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled, \\*\SYSVOL and \\*\NETLOGON are missing Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    
   <#
    Configure registry policy processing

    Computer Configuration\Policies\Administrative Templates\System\Group Policy

    The "Process even if the Group Policy objects have not changed" option updates and reapplies the policies even if the policies 
    have not changed. Many policy implementations specify that they are updated only when changed. However, you might want to update 
    unchanged policies, such as reapplying a desired policy setting in case a user has changed it.

    #>
    $WindowsOSDescrip = "Configure registry policy processing"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Group Policy\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoGPOListChanges"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

       <#
    Configure security policy processing

    Computer Configuration\Policies\Administrative Templates\System\Group Policy

    The "Process even if the Group Policy objects have not changed" option updates and reapplies the policies even if the policies 
    have not changed. Many policy implementations specify that they are updated only when changed. However, you might want to update 
    unchanged policies, such as reapplying a desired policy setting in case a user has changed it.

    reboot for reg to be created and gpo to apply

    #>
    $WindowsOSDescrip = "Configure security policy processing"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Group Policy\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoBackgroundPolicy"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Turn off background refresh of Group Policy

    Computer Configuration\Policies\Administrative Templates\System\Group Policy

    This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users, and domain controllers.
    If you enable this policy setting, the system waits until the current user logs off the system before updating the computer and user settings.
    If you disable or do not configure this policy setting, updates can be applied while users are working. The frequency of updates is determined by the "Set Group Policy refresh interval for computers" and "Set Group Policy refresh interval for users" policy settings.


    #>
    $WindowsOSDescrip = "Turn off background refresh of Group Policy"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Group Policy\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableBkGndGroupPolicy"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Local Group Policy Objects processing

    Computer Configuration\Policies\Administrative Templates\System\Group Policy

    This policy setting prevents Local Group Policy Objects (Local GPOs) from being applied.
    By default, the policy settings in Local GPOs are applied before any domain-based GPO policy settings. These policy settings can apply to both users and the local computer. You can disable the processing and application of all Local GPOs to ensure that only domain-based GPOs are applied.
    If you enable this policy setting, the system does not process and apply any Local GPOs.
    If you disable or do not configure this policy setting, Local GPOs continue to be applied.
    Note: For computers joined to a domain, it is strongly recommended that you only configure this policy setting in domain-based GPOs. This policy setting will be ignored on computers that are joined to a workgroup.

    #>
    $WindowsOSDescrip = "Turn off Local Group Policy Objects processing"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Group Policy\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableLGPOProcessing"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Network Access: Allow anonymous SID/Name translation

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting enables or disables the ability of an anonymous user to request security identifier (SID) attributes for another user.
    If this policy setting is enabled, a user might use the well-known Administrators SID to get the real name of the built-in Administrator account, even if the account has been renamed. That person might then use the account name to initiate a brute-force password-guessing attack.
    Misuse of this policy setting is a common error that can cause data loss or problems with data Access or security.

    #>
    $WindowsOSDescrip = "Network Access: Allow anonymous SID/Name translation"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AnonymousNameLookup"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Network Access: Let Everyone permissions apply to anonymous users

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting determines what additional permissions are granted for anonymous connections to the device. 
    If you enable this policy setting, anonymous users can enumerate the names of domain accounts and shared folders and 
    perform certain other activities. This capability is convenient, for example, when an administrator wants to grant 
    Access to users in a trusted domain that does not maintain a reciprocal trust.

    By default, the token that is created for anonymous connections does not include the Everyone SID. Therefore, permissions 
    that are assigned to the Everyone group do not apply to anonymous users.

    #>
    $WindowsOSDescrip = "Network Access: Let Everyone permissions apply to anonymous users"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "everyoneincludesanonymous"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Network Access: Do not allow anonymous enumeration of SAM accounts

    RestrictAnonymousSAM (Sam accounts)

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting determines which additional permissions will be assigned for anonymous connections to the 
    device. Windows allows anonymous users to perform certain activities, such as enumerating the names of domain 
    accounts and network shares. This is convenient, for example, when an administrator wants to give Access to users 
    in a trusted domain that does not maintain a reciprocal trust. However, even with this policy setting enabled,
     anonymous users will have Access to resources with permissions that explicitly include the built-in group, ANONYMOUS LOGON.
    This policy setting has no impact on domain controllers. Misuse of this policy setting is a common error that 
    can cause data loss or problems with data Access or security.

    #>
    $WindowsOSDescrip = "Network Access: Do not allow anonymous enumeration of SAM accounts"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RestrictAnonymousSAM"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Network Access: Do not allow anonymous enumeration of SAM accounts and shares

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    RestrictAnonymous (Sam accounts and shares)

    This policy setting determines which additional permissions will be assigned for anonymous connections to the device. 
    Windows allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares. 
    This is convenient, for example, when an administrator wants to give Access to users in a trusted domain that does not 
    maintain a reciprocal trust. However, even with this policy setting enabled, anonymous users will have Access to resources 
    with permissions that explicitly include the built-in group, ANONYMOUS LOGON.
    This policy setting has no impact on domain controllers. Misuse of this policy setting is a common error that can cause data 
    loss or problems with data Access or security.

    #>
    $WindowsOSDescrip = "Network Access: Do not allow anonymous enumeration of SAM accounts and shares"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RestrictAnonymous"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Network Access: Restrict anonymous Access to Named Pipes and Shares

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    This policy setting enables or disables the restriction of anonymous Access to only those shared folders and 
    pipes that are named in the Network Access: Named pipes that can be Accessed anonymously and Network Access: 
    Shares that can be Accessed anonymously settings. The setting controls null session Access to shared folders 
    on your computers by adding RestrictNullSessAccess with the value 1 in the registry key 
    HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters. This registry value toggles null session 
    shared folders on or off to control whether the Server service restricts unauthenticated clients' Access to named resources.
    Null sessions are a weakness that can be exploited through the various shared folders on the devices in your environment.


    #>
    $WindowsOSDescrip = "Network Access: Restrict anonymous Access to Named Pipes and Shares"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RestrictNullSessAccess"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Network Access: Restrict clients allowed to make remote calls to SAM

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-Access-restrict-clients-allowed-to-make-remote-sam-calls
    O:BAG:BAD:(A;;RC;;;BA) = Administrator
    #>
    $WindowsOSDescrip = "Network Access: Restrict clients allowed to make remote calls to SAM"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RestrictRemoteSam"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "O:BAG:BAD:(A;;RC;;;BA)")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled to allow Administrator remote Access (O:BAG:BAD:(A;;RC;;;BA))" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"

    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled or not set Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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
    which is a session with a server in which no user authentication is performed; and therefore, anonymous Access is allowed.)
    
    #>
    $WindowsOSDescrip = "Network security: Allow Local System to use computer identity for NTLM"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "UseMachineId"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

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
    $WindowsOSDescrip = "Network security: Allow LocalSystem NULL session fallback"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0\'
    $WindowsOSVal=@()
    $WindowsOSVal = "allownullsessionfallback"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS   

    <#
    Accounts: Limit local account use of blank passwords to console logon only

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    #>
    $WindowsOSDescrip = "Accounts: Limit local account use of blank passwords to console logon only"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Lsa\'
    $WindowsOSVal=@()
    $WindowsOSVal = "LimitBlankPasswordUse"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS



<#
    Disallow Autoplay for non-volume devices - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Disallow Autoplay for non-volume devices"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoAutoplayfornonVolume"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Disallow Autoplay for non-volume devices - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Disallow Autoplay for non-volume devices"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoAutoplayfornonVolume"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Set the default behavior for AutoRun - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Set the default behavior for AutoRun"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoAutorun"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Set the default behavior for AutoRun - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Set the default behavior for AutoRun"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoAutorun"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Autoplay - Machine

    Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Turn off Autoplay"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoDriveTypeAutoRun"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "255")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Autoplay - Users

    User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies

    #>
    $WindowsOSDescrip = "Turn off Autoplay"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\AutoPlay Policies\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoDriveTypeAutoRun"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "255")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

<#
    Prevent Access to the command prompt

    User Configuration\Policies\Administrative Templates\System

    This policy setting prevents users from running the interactive command prompt Cmd.exe.

    This policy setting also determines whether batch files (.cmd and .bat) can run on the computer.
    If you enable this policy setting and the user tries to open a command window, the system displays a message explaining that a setting prevents the action. .
    If you disable this policy setting or don't configure it, users can run Cmd.exe and batch files normally.

    #>
    $WindowsOSDescrip = "Prevent Access to the Command Prompt"
    $gpopath ="User Configuration\Policies\Administrative Templates\System\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableCMD"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent Access to registry editing tools

    User Configuration\Policies\Administrative Templates\System

    #>
    $WindowsOSDescrip = "Prevent Access to Registry Editing Tools"
    $gpopath ="User Configuration\Policies\Administrative Templates\System\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableRegistryTools"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "2")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn on PowerShell Script Block Logging

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell

    #>
    $WindowsOSDescrip = "Turn on PowerShell Script Block Logging"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableScriptBlockLogging"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn on Script Execution

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell

    #>
    $WindowsOSDescrip = "Turn on Script Execution - Execution Policy: Allow only signed scripts"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows PowerShell\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ExecutionPolicy"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS
    
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
    $WindowsOSDescrip = "Configure Windows Defender SmartScreen (File Explorer)"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableSmartScreen"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled to Warn and prevent bypass" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is set warn and allow bypass Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

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
    $WindowsOSDescrip = "Configure Windows Defender SmartScreen (Windows Defender SmartScreen)"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender SmartScreen\Explorer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableSmartScreen"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled to Warn and prevent bypass" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is set warn and allow bypass Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    
    <#
    Allow user control over installs

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, some of the security features of Windows Installer are bypassed. It permits installations to 
    complete that otherwise would be halted due to a security violation.
        If you disable or do not configure this policy setting, the security features of Windows Installer prevent users from changing 
        installation options typically reserved for system administrators, such as specifying the directory to which files are installed.

    #>
    $WindowsOSDescrip = "Allow user control over installs"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Installer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableUserControl"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Always install with elevated privileges - Computer

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, privileges are extended to all programs. These privileges are usually reserved for programs 
    that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available 
    in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require Access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    If you disable or do not configure this policy setting, the system applies the current user's permissions when it installs programs 
    that a system administrator does not distribute or offer.
    Note: This policy setting appears both in the Computer Configuration and User Configuration folders. To make this policy setting 
    effective, you must enable it in both folders.

    #>
    $WindowsOSDescrip = "Always install with elevated privileges"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Installer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AlwaysInstallElevated"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Always install with elevated privileges - User

    User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer

    This policy setting permits users to change installation options that typically are available only to system administrators.

    If you enable this policy setting, privileges are extended to all programs. These privileges are usually reserved for programs 
    that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available 
    in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require Access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    If you disable or do not configure this policy setting, the system applies the current user's permissions when it installs programs 
    that a system administrator does not distribute or offer.
    Note: This policy setting appears both in the Computer Configuration and User Configuration folders. To make this policy setting 
    effective, you must enable it in both folders.

    #>
    $WindowsOSDescrip = "Always install with elevated privileges"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\Windows Installer\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\Installer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AlwaysInstallElevated"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Devices: Prevent users from installing printer drivers

    Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options

    #>
    $WindowsOSDescrip = "Devices: Prevent users from installing printer drivers"
    $gpopath ="Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\$WindowsOSDescrip"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AddPrinterDrivers"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled, only Admin can install printer drivers" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }
    
    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Do not process the legacy run list

    Computer Configuration\Policies\Administrative Templates\System\Logon

    Once malicious code has been copied to a workstation, an adversary with registry Access can remotely schedule it 
    to execute (i.e. using the run once list) or to automatically execute each time Microsoft Windows starts (i.e. using the legacy run list). 
    To reduce this risk, legacy and run once lists should be disabled. This may interfere with the operation of legitimate applications that 
    need to automatically execute each time Microsoft Windows starts. In such cases, the Run these programs at user logon Group Policy 
    setting can be used to perform the same function in a more secure manner when defined at a domain level; however, if not used this Group Policy 
    setting should be disabled rather than left in its default undefined state.

    #>
    $WindowsOSDescrip = "Do not process the legacy run list"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableCurrentUserRun"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Do not process the legacy run list

    Computer Configuration\Policies\Administrative Templates\System\Logon

    Once malicious code has been copied to a workstation, an adversary with registry Access can remotely schedule it 
    to execute (i.e. using the run once list) or to automatically execute each time Microsoft Windows starts (i.e. using the legacy run list). 
    To reduce this risk, legacy and run once lists should be disabled. This may interfere with the operation of legitimate applications that 
    need to automatically execute each time Microsoft Windows starts. In such cases, the Run these programs at user logon Group Policy 
    setting can be used to perform the same function in a more secure manner when defined at a domain level; however, if not used this Group Policy 
    setting should be disabled rather than left in its default undefined state.

    #>
    $WindowsOSDescrip = "Do not process the run once list"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableLocalMachineRunOnce"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Run these programs at user logon

    Computer Configuration\Policies\Administrative Templates\System\Logon

    This policy setting specifies additional programs or documents that Windows starts automatically when a user logs on to the system.
    If you enable this policy setting, you can specify which programs can run at the time the user logs on to this computer that has this policy applied.
    To specify values for this policy setting, click Show. In the Show Contents dialog box in the Value column, type the name of the executable program (.exe) 
    file or document file. To specify another name, press ENTER, and type the name. Unless the file is located in the %Systemroot% directory, you must specify 
    the fully qualified path to the file.
    If you disable or do not configure this policy setting, the user will have to start the appropriate programs after logon

    #>
    $WindowsOSDescrip = "Run these programs at user logon"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Logon\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\'
    $WindowsOSVal=@()
    $WindowsOSVal = "1"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq 1)
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "$WindowsOSDescrip disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

<#
    Do not preserve zone information in file attachments

    User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager

    The Attachment Manager within Microsoft Windows works in conjunction with applications such as the Microsoft Office suite and Internet Explorer to 
    help protect workstations from attachments that have been received via email or downloaded from the internet. The Attachment Manager classifies files 
    as high, medium or low risk based on the zone they originated from and the type of file. Based on the risk to the workstation, the Attachment Manager 
    will either issue a warning to a user or prevent them from opening a file. If zone information is not preserved, or can be removed, it can allow an 
    adversary to socially engineer a user to bypass protections afforded by the Attachment Manager. To reduce this risk, the Attachment Manager should 
    be configured to preserve and protect zone information for files.


    #>
    $WindowsOSDescrip = "Do not preserve zone information in file attachments"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\'
    $WindowsOSVal=@()
    $WindowsOSVal = "SaveZoneInformation"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "2")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Hide mechanisms to remove zone information

    User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager

    This policy setting allows you to manage whether users can manually remove the zone information from saved file attachments by 
    clicking the Unblock button in the file's property sheet or by using a check box in the security warning dialog. Removing the zone 
    information allows users to open potentially dangerous file attachments that Windows has blocked users from opening.
    If you enable this policy setting, Windows hides the check box and Unblock button.
    If you disable this policy setting, Windows shows the check box and Unblock button.
    If you do not configure this policy setting, Windows hides the check box and Unblock button.

    #>
    $WindowsOSDescrip = "Hide mechanisms to remove zone information"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\'
    $WindowsOSVal=@()
    $WindowsOSVal = "HideZoneInfoOnProperties"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


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
    $WindowsOSDescrip = "Restrict Unauthenticated RPC clients"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RestrictRemoteClients"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled - Not to be applied against DCs Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

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
    $WindowsOSDescrip = "Enable RPC Endpoint Mapper Client Authentication"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\'
    $WindowsOSVal=@()
    $WindowsOSVal = "EnableAuthEpResolution"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Disallow Digest authentication

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Digest authentication.
    If you enable this policy setting, the WinRM client does not use Digest authentication.
    If you disable or do not configure this policy setting, the WinRM client uses Digest authentication.

    #>
    $WindowsOSDescrip = "Disallow Digest authentication"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowDigest"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

<#
    Allow Basic authentication

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.
    If you enable this policy setting, the WinRM service accepts Basic authentication from a remote client.
    If you disable or do not configure this policy setting, the WinRM service does not accept Basic authentication from a remote client.

    #>
    $WindowsOSDescrip = "Allow Basic authentication"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\service\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowBasic"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Allow unencrypted traffic

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.

    #>
    $WindowsOSDescrip = "Allow unencrypted traffic"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowUnencryptedTraffic"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Allow Basic authentication

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.
    If you enable this policy setting, the WinRM service accepts Basic authentication from a remote client.
    If you disable or do not configure this policy setting, the WinRM service does not accept Basic authentication from a remote client.

    #>
    $WindowsOSDescrip = "Allow Basic authentication"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowBasic"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Allow unencrypted traffic

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.

    #>
    $WindowsOSDescrip = "Allow unencrypted traffic"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowUnencryptedTraffic"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Disallow WinRM from storing RunAs credentials

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Service
    
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.
    If you enable this policy setting, the WinRM service will not allow the RunAsUser or RunAsPassword configuration values to be set for any plug-ins. If a plug-in 
    has already set the RunAsUser and RunAsPassword configuration values, the RunAsPassword configuration value will be erased from the credential store on this 
    computer

    #>
    $WindowsOSDescrip = "Disallow WinRM from storing RunAs credentials"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Management (WinRM)\WinRM Client\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableRunAs"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Allow Remote Shell Access

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Shell
    
    This policy setting configures Access to remote shells.
    If you enable or do not configure this policy setting, new remote shell connections are accepted by the server.
    If you set this policy to 'disabled', new remote shell connections are rejected by the server.

    #>
    $WindowsOSDescrip = "Allow Remote Shell Access"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Remote Shell\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowRemoteShellAccess"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Prohibit connection to non-domain networks when connected to domain authenticated network

    "Computer Configuration\Administrative Templates\Network\Windows Connection Manager\"

    This policy setting prevents computers from connecting to both a domain based network and a non-domain based network 
    at the same time.If this policy setting is enabled the computer responds to automatic and manual network connection 
    attempts based on the following circumstances:Automatic connection attempts- When the computer is already connected 
    to a domain based network all automatic connection attempts to non-domain networks are blocked.- When the computer 
    is already connected to a non-domain based network automatic connection attempts to domain based networks are blocked.
    Manual connection attempts- When the computer is already connected to either a non-domain based network or a domain based 
    network over media other than Ethernet and a user attempts to create a manual connection to an additional network in 
    violation of this policy setting the existing network connection is disconnected and the manual connection is allowed.- 
    When the computer is already connected to either a non-domain based network or a domain based network over Ethernet 
    and a user attempts to create a manual connection to an additional network in violation of this policy setting the 
    existing Ethernet connection is maintained and the manual connection attempt is blocked.If this policy setting is 
    not configured or is disabled computers are allowed to connect simultaneously to both domain and non-domain networks.      
    
    #>
    $WindowsOSDescrip = "Prohibit connection to non-domain networks when connected to domain authenticated network"
    $gpopath ="Computer Configuration\Administrative Templates\Network\Windows Connection Manager\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\'
    $WindowsOSVal=@()
    $WindowsOSVal = "fBlockNonDomain"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disbled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Prohibit use of Internet Connection Sharing on your DNS domain network

    "Computer Configuration\Administrative Templates\Network\Network Connections"

    Determines whether administrators can enable and configure the Internet Connection Sharing (ICS) feature of an Internet 
    connection and if the ICS service can run on the computer.ICS lets administrators configure their system as an Internet 
    gateway for a small network and provides network services such as name resolution and addressing through DHCP to the local 
    private network.If you enable this setting ICS cannot be enabled or configured by administrators and the ICS service cannot 
    run on the computer. The Advanced tab in the Properties dialog box for a LAN or remote access connection is removed. The Internet 
    Connection Sharing page is removed from the New Connection Wizard. The Network Setup Wizard is disabled.If you disable this setting 
    or do not configure it and have two or more connections administrators can enable ICS. The Advanced tab in the properties dialog 
    box for a LAN or remote access connection is available. In addition the user is presented with the option to enable Internet Connection 
    Sharing in the Network Setup Wizard and Make New Connection Wizard. (The Network Setup Wizard is available only in Windows XP 
    Professional.)By default ICS is disabled when you create a remote access connection but administrators can use the Advanced tab to 
    enable it. When running the New Connection Wizard or Network Setup Wizard administrators can choose to enable ICS.Note: Internet 
    Connection Sharing is only available when two or more network connections are present.Note: When the "Prohibit access to properties 
    of a LAN connection" "Ability to change properties of an all user remote access connection" or "Prohibit changing properties of a 
    private remote access connection" settings are set to deny access to the Connection Properties dialog box the Advanced tab for the 
    connection is blocked.Note: Nonadministrators are already prohibited from configuring Internet Connection Sharing regardless of this 
    setting.Note: Disabling this setting does not prevent Wireless Hosted Networking from using the ICS service for DHCP services. 
    To prevent the ICS service from running on the Network Permissions tab in the network's policy properties select the "Don't use 
    hosted networks" check box.
    
    #>

    $WindowsOSDescrip = "Prohibit use of Internet Connection Sharing on your DNS domain network"
    $gpopath ="Computer Configuration\Administrative Templates\Network\Network Connections\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Network Connections\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NC_ShowSharedAccessUI"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

 
    <#
    Allow Windows to automatically connect to suggested open hotspots to networks shared by contacts and to hotspots offering paid services
    
    "Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN SettingsAllow Windows to automatically connect to suggested open hotspots to networks shared by contacts and to hotspots offering paid services"

    This policy setting determines whether users can enable the following WLAN settings: "Connect to suggested open hotspots" 
    "Connect to networks shared by my contacts" and "Enable paid services"."Connect to suggested open hotspots" enables Windows 
    to automatically connect users to open hotspots it knows about by crowdsourcing networks that other people using Windows have 
    connected to."Connect to networks shared by my contacts" enables Windows to automatically connect to networks that the user's 
    contacts have shared with them and enables users on this device to share networks with their contacts."Enable paid services" 
    enables Windows to temporarily connect to open hotspots to determine if paid services are available.If this policy setting is 
    disabled both "Connect to suggested open hotspots" "Connect to networks shared by my contacts" and "Enable paid services" will 
    be turned off and users on this device will be prevented from enabling them.If this policy setting is not configured or is enabled 
    users can choose to enable or disable either "Connect to suggested open hotspots"  or "Connect to networks shared by my contacts".      
    #>

    $WindowsOSDescrip = "Allow Windows to automatically connect to suggested open hotspots to networks shared by contacts and to hotspots offering paid services"
    $gpopath ="Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN Settings\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AutoConnectAllowedOEM"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Remote host allows delegation of non-exportable credentials
    
    "Computer Configuration\Administrative Templates\System\Credentials Delegation\Remote host allows delegation of non-exportable credentials"

    Remote host allows delegation of non-exportable credentialsWhen using credential delegation devices provide an exportable version of 
    credentials to the remote host. This exposes users to the risk of credential theft from attackers on the remote host.If you enable 
    this policy setting the host supports Restricted Admin or Remote Credential Guard mode.If you disable or do not configure this policy 
    setting Restricted Administration and Remote Credential Guard mode are not supported. User will always need to pass their credentials 
    to the host.   
    #>

    $WindowsOSDescrip = "Remote host allows delegation of non-exportable credentials"
    $gpopath ="Computer Configuration\Administrative Templates\System\Credentials Delegation\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowProtectedCreds"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Encryption Oracle Remediation
        
    "Computer Configuration\Administrative Templates\System\Credentials Delegation"

    Encryption Oracle RemediationThis policy setting applies to applications using the CredSSP component (for example: Remote Desktop Connection).
    Some versions of the CredSSP protocol are vulnerable to an encryption oracle attack against the client.  This policy controls 
    compatibility with vulnerable clients and servers.  This policy allows you to set the level of protection desired for the 
    encryption oracle vulnerability.If you enable this policy setting CredSSP version support will be selected based on the 
    following options:Force Updated Clients: Client applications which use CredSSP will not be able to fall back to the insecure 
    versions and services using CredSSP will not accept unpatched clients. Note: this setting should not be deployed until all 
    remote hosts support the newest version.Mitigated: Client applications which use CredSSP will not be able to fall back to the 
    insecure version but services using CredSSP will accept unpatched clients. See the link below for important information about 
    the risk posed by remaining unpatched clients.Vulnerable: Client applications which use CredSSP will expose the remote servers to 
    attacks by supporting fall back to the insecure versions and services using CredSSP will accept unpatched clients.For more information 
    about the vulnerability and servicing requirements for protection see https://go.microsoft.com/fwlink/?linkid=866660   
    #>

    $WindowsOSDescrip = "Encryption Oracle Remediation"
    $gpopath ="Computer Configuration\Administrative Templates\System\Credentials Delegation\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowEncryptionOracle"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled Force Updated Clients" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


  
      <#
    Allow Cortana

    Computer Configuration\Policies\Administrative Templates\Windows Components\Search
    
    This policy setting specifies whether Cortana is allowed on the device.
    If you enable or don't configure this setting, Cortana will be allowed on the device. If you disable this setting, Cortana will be turned off.

    #>
    $WindowsOSDescrip = "Allow Cortana"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Search\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowCortana"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Don't search the web or display web results in Search

    Computer Configuration\Policies\Administrative Templates\Windows Components\Search
    
    This policy setting allows you to control whether or not Search can perform queries on the web, and if the web results are displayed in Search.
    If you enable this policy setting, queries won't be performed on the web and web results won't be displayed when a user performs a query in Search.
    If you disable this policy setting, queries will be performed on the web and web results will be displayed when a user performs a query in Search.
    If you don't configure this policy setting, a user can choose whether or not Search can perform queries on the web, and if the web results are displayed in Search

    #>
    $WindowsOSDescrip = "Don't search the web or display web results in Search"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Search\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsSearch\'
    $WindowsOSVal=@()
    $WindowsOSVal = "ConnectedSearchUseWeb"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider

    Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool

    #>
    $WindowsOSDescrip = "Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableQueryRemoteServer"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip enabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Inventory Collector

    Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility

    The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft. 
    This information is used to help diagnose compatibility problems.
    If you enable this policy setting, the Inventory Collector will be turned off and data will not be sent to Microsoft. Collection of
     installation data through the Program Compatibility Assistant is also disabled.
    If you disable or do not configure this policy setting, the Inventory Collector will be turned on.

    #>
    $WindowsOSDescrip = "Turn off Inventory Collector"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableInventory"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Steps Recorder

    Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility
    Steps Recorder keeps a record of steps taken by the user. The data generated by Steps Recorder can be used in feedback systems 
    such as Windows Error Reporting to help developers understand and fix problems. The data includes user actions such as keyboard 
    input and mouse input, user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.

    #>
    $WindowsOSDescrip = "Turn off Steps Recorder"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableUAR"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Prevent Access to 16-bit applications

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
    $WindowsOSDescrip = "Prevent Access to 16-bit applications"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Application Compatibility\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat\'
    $WindowsOSVal=@()
    $WindowsOSVal = "VDMDisallowed"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Allow Telemetry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds

    Diagnostic data is categorized into four levels, as follows:
    - 0 (Security). Information that's required to help keep Windows, Windows Server, and System Center secure, including data about the Connected User Experiences and Telemetry component settings, the Malicious Software Removal Tool, and Windows Defender.
    - 1 (Required). Basic device info, including: quality-related data, app compatibility, and data from the Security level.
    - 2 (Enhanced). Additional insights, including: how Windows, Windows Server, System Center, and apps are used, how they perform, advanced reliability data, and data from both the Required and the Security levels.
    - 3 (Optional). All data necessary to identify and help to fix problems, plus data from the Security, Required, and Enhanced levels.

    #>
    $WindowsOSDescrip = "Allow Telemetry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowTelemetry"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled for Enterprise Only - Computer" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


        <#
    Allow Telemetry

    Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds

    Diagnostic data is categorized into four levels, as follows:
    - 0 (Security). Information that's required to help keep Windows, Windows Server, and System Center secure, including data about the Connected User Experiences and Telemetry component settings, the Malicious Software Removal Tool, and Windows Defender.
    - 1 (Required). Basic device info, including: quality-related data, app compatibility, and data from the Security level.
    - 2 (Enhanced). Additional insights, including: how Windows, Windows Server, System Center, and apps are used, how they perform, advanced reliability data, and data from both the Required and the Security levels.
    - 3 (Optional). All data necessary to identify and help to fix problems, plus data from the Security, Required, and Enhanced levels.

    #>
    $WindowsOSDescrip = "Allow Telemetry"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection\'
    $WindowsOSVal=@()
    $WindowsOSVal = "AllowTelemetry"
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled for Enterprise Only - User" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip disabled warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Configure Corporate Windows Error Reporting

    Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings

    This policy setting specifies a corporate server to which Windows Error Reporting sends reports (if you do not want to send error reports to Microsoft).
    If you enable this policy setting, you can specify the name or IP address of an error report destination server on your organization's network. 
    You can also select Connect using SSL to transmit error reports over a Secure Sockets Layer (SSL) connection, and specify a port number on the destination 
    server for transmission.

    #>
    $WindowsOSDescrip = "Configure Corporate Windows Error Reporting"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Error Reporting\Advanced Error Reporting Settings\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsErrorReporting\'
    $WindowsOSVal=@()
    $WindowsOSVal = "CorporateWerUseSSL"   #query for SSL to be enabled
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is not set warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

    <#
    Turn off Data Execution Prevention for Explorer

    Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.

    #>
    $WindowsOSDescrip = "Turn off Data Execution Prevention for Explorer"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoDataExecutionPrevention"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Enabled Structured Exception Handling Overwrite Protection (SEHOP)

    Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    If this setting is enabled, SEHOP is enforced. For more information, see 
    https://support.microsoft.com/en-us/help/956607/how-to-enable-structured-exception-handling-overwrite-protection-sehop-in-windows-operating-systems.
    If this setting is disabled or not configured, SEHOP is not enforced for 32-bit processes.

    https://support.microsoft.com/en-us/topic/how-to-enable-structured-exception-handling-overwrite-protection-sehop-in-windows-operating-systems-8d4595f7-827f-72ee-8c34-fa8e0fe7b915

    #>
    $WindowsOSDescrip = "Enabled Structured Exception Handling Overwrite Protection (SEHOP)"
    $gpopath ="Create manually or via GPO Preferences"
    $RegKey = 'HKLM:\System\CurrentControlSet\Control\Session Manager\kernel\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableExceptionChainValidation"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
    Remove Security tab

    User Configuration\Policies\Administrative Templates\Windows Components\File Explorer

    #>
    $WindowsOSDescrip = "Remove Security tab - User"
    $gpopath ="User Configuration\Policies\Administrative Templates\Windows Components\File Explorer\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoSecurityTab"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

   <#
    Turn off location

    Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors

    #>
    $WindowsOSDescrip = "Turn off location"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableLocationScripting"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS
    

       <#
   Turn off Windows Location Provider

    Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors\Windows Location Provider

    #>
    $WindowsOSDescrip = "Turn off Windows Location Provider"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors\Windows Location Provider\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DisableWindowsLocationProvider"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


    <#
   Turn off Access to the Store

    Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings

    Pointless setting, I dont know anyone who uses the Windows Store or at least own up to using it ;)

    #>
    $WindowsOSDescrip = "Turn off Access to the Store"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\Windows\Explorer\'
    $WindowsOSVal=@()
    $WindowsOSVal = "NoUseStoreOpenWith"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


   <#
   Turn off the Store application

    Computer Configuration\Policies\Administrative Templates\Windows Components\Store

    Pointless setting, I dont know anyone who uses the Windows Store or at least own up to using it ;)

    #>
    $WindowsOSDescrip = "Turn off the Store application"
    $gpopath ="Computer Configuration\Policies\Administrative Templates\Windows Components\Store\$WindowsOSDescrip"
    $RegKey = 'HKLM:\Software\Policies\Microsoft\WindowsStore\'
    $WindowsOSVal=@()
    $WindowsOSVal = "RemoveWindowsStore"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "1")
    {
        $WindowsOSSet = "$WindowsOSDescrip is Enabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is disabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value  $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS

   <#
   Determine if interactive users can generate Resultant Set of Policy data

    User Configuration\Policies\Administrative Templates\System\Group Policy - Users

    Allows user to interrogate gpos for system weaknesses

    #>
    $WindowsOSDescrip = "Determine if interactive users can generate RSOP"
    $gpopath ="User Configuration\Policies\Administrative Templates\System\Group Policy\$WindowsOSDescrip"
    $RegKey = 'HKCU:\Software\Policies\Microsoft\Windows\System\'
    $WindowsOSVal=@()
    $WindowsOSVal = "DenyRsopToInteractiveUser"  
    $getWindowsOSVal=@()
    $getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue
    $getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal") 

    if ($getWindowsOSVal -eq "0")
    {
        $WindowsOSSet = "$WindowsOSDescrip is disabled" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "True"
    }
    else
    {
        $WindowsOSSet = "Warning $WindowsOSDescrip is enabled Warning" 
        $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
        $trueFalse = "False"
    }

    if ([string]::IsNullorEmpty($getWindowsOSVal) -eq $true){$WindowsOSSet = "DefaultGPO $WindowsOSDescrip is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjWindowsOS = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsGPONameSetting -Value $WindowsOSSet
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
    Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
    $fragWindowsOSVal += $newObjWindowsOS


################################################
#######  RECOMMENDED SECURITY SETTINGS  ########
###################  EDGE  #####################
################################################

<#
"TyposquattingChecker" , 
"Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","   ","

"Configure Edge TyposquattingChecker",

"Enabled","HKLM:\Software\Policies\Microsoft\Edge\",

"TyposquattingCheckerEnabled",

"This policy setting lets you configure whether to turn on Edge TyposquattingChecker. Edge TyposquattingChecker provides warning messages to help protect your users from potential typosquatting sites. By default Edge TyposquattingChecker is turned on.If you enable this policy Edge TyposquattingChecker is turned on.If you disable this policy Edge TyposquattingChecker is turned off.If you don't configure this policy Edge TyposquattingChecker is turned on but users can choose whether to use Edge TyposquattingChecker."}

#>

$EdgePolicies =[ordered]@{
#stig
"SSLVersionMin"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Minimum TLS version enabled","SSLVersionMin","tls1.2","HKLM:\Software\Policies\Microsoft\Edge\"
"SyncDisabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Disable synchronization of data using Microsoft sync services","SyncDisabled","1","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportBrowserSettings"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of browser settings","ImportBrowserSettings","0","HKLM:\Software\Policies\Microsoft\Edge\"
"DeveloperToolsAvailability"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Control where developer tools can be used","DeveloperToolsAvailability","2","HKLM:\Software\Policies\Microsoft\Edge\"
"PromptForDownloadLocation"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Ask where to save downloaded files","PromptForDownloadLocation","1","HKLM:\Software\Policies\Microsoft\Edge\"
"PreventSmartScreenPromptOverride"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","SmartScreen settings/Prevent bypassing Microsoft Defender SmartScreen prompts for sites","PreventSmartScreenPromptOverride","1","HKLM:\Software\Policies\Microsoft\Edge\"
"PreventSmartScreenPromptOverrideForFiles"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","SmartScreen settings/Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads","PreventSmartScreenPromptOverrideForFiles","1","HKLM:\Software\Policies\Microsoft\Edge\"
"InPrivateModeAvailability"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Configure InPrivate mode availability","InPrivateModeAvailability","1","HKLM:\Software\Policies\Microsoft\Edge\"
"AllowDeletingBrowserHistory"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable deleting browser and download history","AllowDeletingBrowserHistory","0","HKLM:\Software\Policies\Microsoft\Edge\"
"BackgroundModeEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Continue running background apps after Microsoft Edge closes","BackgroundModeEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"DefaultPopupsSetting"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Content settings","Default pop-up window setting","DefaultPopupsSetting","2","HKLM:\Software\Policies\Microsoft\Edge\"
"NetworkPredictionOptions"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Enable network prediction","Don't predict network actions on any network connection","NetworkPredictionOptions","2","HKLM:\Software\Policies\Microsoft\Edge\"
"SearchSuggestEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable search suggestions","SearchSuggestEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportAutofillFormData"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of autofill form data","ImportAutofillFormData","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportCookies"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of cookies","ImportCookies","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportExtensions"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of extensions","ImportExtensions","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportHistory"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of browsing history","ImportHistory","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportHomepage"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of home page settings","ImportHomepage","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportOpenTabs"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of open tabs","ImportOpenTabs","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportPaymentInfo"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of payment info","ImportPaymentInfo","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportSavedPasswords"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of saved passwords","ImportSavedPasswords","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportSearchEngine"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of search engine settings","ImportSearchEngine","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ImportShortcuts"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow importing of shortcuts","ImportShortcuts","0","HKLM:\Software\Policies\Microsoft\Edge\"
"AutoplayAllowed"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow media autoplay for websites","AutoplayAllowed","0","HKLM:\Software\Policies\Microsoft\Edge\"
"EnableMediaRouter"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Cast\","Enable Google Cast","EnableMediaRouter","0","HKLM:\Software\Policies\Microsoft\Edge\"
"AutofillCreditCardEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable AutoFill for credit cards","AutofillCreditCardEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"AutofillAddressEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable AutoFill for addresses","AutofillAddressEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"PersonalizationReportingEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow personalization of ads, search and news by sending browsing history to Microsoft","PersonalizationReportingEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"DefaultGeolocationSetting"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Content settings/Default geolocation setting\","Don't allow any site to track users' physical location","DefaultGeolocationSetting","2","HKLM:\Software\Policies\Microsoft\Edge\"
"PasswordManagerEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Password manager and protection/Enable saving passwords to the password manager","PasswordManagerEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
#"IsolateOrigins"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable site isolation for every site","IsolateOrigins","1","HKLM:\Software\Policies\Microsoft\Edge\"
"SmartScreenEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\SmartScreen settings\","Configure Microsoft Defender SmartScreen","SmartScreenEnabled","1","HKLM:\Software\Policies\Microsoft\Edge\"
"SmartScreenPuaEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\SmartScreen settings\","Configure Microsoft Defender SmartScreen to block potentially unwanted apps","SmartScreenPuaEnabled","1","HKLM:\Software\Policies\Microsoft\Edge\"
"PaymentMethodQueryEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow websites to query for available payment methods","PaymentMethodQueryEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"AlternateErrorPagesEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Suggest similar pages when a webpage can't be found","AlternateErrorPagesEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"UserFeedbackAllowed"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow user feedback","UserFeedbackAllowed","0","HKLM:\Software\Policies\Microsoft\Edge\"
"EdgeCollectionsEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable the Collections feature","EdgeCollectionsEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"ConfigureShare"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Configure the Share experience\","Don't allow using the Share experience","ConfigureShare","1","HKLM:\Software\Policies\Microsoft\Edge\"
"BrowserGuestModeEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable guest mode","BrowserGuestModeEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"BuiltInDnsClientEnabled"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Use built-in DNS client","BuiltInDnsClientEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"SitePerProcess"="Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Enable site isolation for every site\","Enable site isolation for every site","SitePerProcess","1","HKLM:\Software\Policies\Microsoft\Edge\"
#MS
"InternetExplorerIntegrationReloadInIEModeAllowed" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Allow unconfigured sites to be reloaded in Internet Explorer mode","InternetExplorerIntegrationReloadInIEModeAllowed","0","HKLM:\Software\Policies\Microsoft\Edge\"
"TripleDESEnabled" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable 3DES cipher suites in TLS","TripleDESEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"BrowserLegacyExtensionPointsBlockingEnabled" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Enable browser legacy extension point blocking","BrowserLegacyExtensionPointsBlockingEnabled","1","HKLM:\Software\Policies\Microsoft\Edge\"
"InternetExplorerModeToolbarButtonEnabled" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Show the Reload in Internet Explorer mode button in the toolbar","InternetExplorerModeToolbarButtonEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"SharedArrayBufferUnrestrictedAccessAllowed" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Specifies whether SharedArrayBuffers can be used in a non cross-origin-isolated context","SharedArrayBufferUnrestrictedAccessAllowed","0","HKLM:\Software\Policies\Microsoft\Edge\"
"DisplayCapturePermissionsPolicyEnabled" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\","Specifies whether the display-capture permissions-policy is checked or skipped","DisplayCapturePermissionsPolicyEnabled","1","HKLM:\Software\Policies\Microsoft\Edge\"
"ExtensionInstallBlocklist" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Extensions\","Control which extensions cannot be installed","1","*","HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\"
"BasicAuthOverHttpEnabled" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\HTTP authentication\","Allow Basic authentication for HTTP","BasicAuthOverHttpEnabled","0","HKLM:\Software\Policies\Microsoft\Edge\"
"NativeMessagingUserLevelHosts" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Native Messaging\","Allow user-level native messaging hosts (installed without admin permissions)","NativeMessagingUserLevelHosts","0","HKLM:\Software\Policies\Microsoft\Edge\"
"InsecurePrivateNetworkRequestsAllowed" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Private Network Request Settings\","Specifies whether to allow insecure websites to make requests to more-private network endpoints","InsecurePrivateNetworkRequestsAllowed","0","HKLM:\Software\Policies\Microsoft\Edge\"
"TyposquattingChecker" = "Computer Configuration\Policies\Administrative Templates\Microsoft Edge\TyposquattingChecker settings\","Configure Edge TyposquattingChecker","TyposquattingCheckerEnabled","1","HKLM:\Software\Policies\Microsoft\Edge\"

}

$fragEdgeVal=@()

foreach ($EdgePolItems in $EdgePolicies.values)
{
$EdgeVal=@()
$getEdgeValue=@()
$EdgeDescrip=@()
$regpath=@()

$edgeGPOPath = $EdgePolItems[0]    #Computer Configuration\Policies\Administrative Templates\Microsoft Edge\Allow download restrictions\
$edgeGPOName = $EdgePolItems[1]    #Block potentially dangerous or unwanted downloads
$edgeRegName = $EdgePolItems[2]    #DownloadRestrictions
$edgeRegValue = $EdgePolItems[3]   #1
$edgeRegPath = $EdgePolItems[4]    #HKLM:\Software\Policies\Microsoft\Edge\
#$edgeHelp = $EdgePolItems[5]

if ($edgeRegValue -eq "1"){$edgeGPOValue = "Enabled"}
if ($edgeRegValue -eq "0"){$edgeGPOValue = "Disabled"}

$gpopath = $edgeGPOPath + $edgeGPOName
$regpath = $edgeRegPath + $edgeRegName

$getEdgePath = Get-Item $edgeRegPath -ErrorAction SilentlyContinue
$getEdgeValue = $getEdgePath.GetValue("$edgeRegName") 

    if ($getEdgeValue -eq "$edgeRegValue")
    {
        $EdgeSet = "$edgeGPOName is correctly set to $edgeGPOValue" 
        $EdgeReg = "<div title=$gpoPath>$regpath"
        $edgeTrue = "True"
    }
    else
    {
        $EdgeSet = "Warning $edgeGPOName is misconfigured with a value of $edgeGPOValue Warning" 
        $EdgeReg = "<div title=$gpoPath>$regpath"
        $edgeTrue = "False"
    }

    if ([string]::IsNullorEmpty($getEdgeValue) -eq $true){$EdgeSet = "DefaultGPO $edgeGPOName is not explicitly set in GPO and the default setting is applied DefaultGPO"}

    $newObjEdge = New-Object -TypeName PSObject
    Add-Member -InputObject $newObjEdge -Type NoteProperty -Name EdgeGPONameSetting -Value $EdgeSet
    Add-Member -InputObject $newObjEdge -Type NoteProperty -Name EdgeRegValue -Value $EdgeReg 
    Add-Member -InputObject $newObjEdge -Type NoteProperty -Name TrueIsCompliant -Value $edgeTrue 
    $fragEdgeVal += $newObjEdge

}


################################################
#######  RECOMMENDED SECURITY SETTINGS  ########
#################  Office  #####################
################################################

$OfficePolicies =[ordered]@{


#NO GPO
"DataConnectionWarnings"="MS Security - No GPO create Registry keys with preferences","DataConnectionWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","DataConnectionWarnings"
"RichDataConnectionWarnings"="MS Security - No GPO create Registry keys with preferences","RichDataConnectionWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","RichDataConnectionWarnings"
"WorkbookLinkWarnings"="MS Security - No GPO create Registry keys with preferences","WorkbookLinkWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","WorkbookLinkWarnings"
"ppPackagerPrompt"="MS Security - No GPO create Registry keys with preferences","WorkbookLinkWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security","PackagerPrompt"
"wwPackagerPrompt"="MS Security - No GPO create Registry keys with preferences","WorkbookLinkWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","PackagerPrompt"
"PackagerPrompt"="MS Security - No GPO create Registry keys with preferences","WorkbookLinkWarnings","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","PackagerPrompt"


#High Risk
#Office
"disableallactivex"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Disable All ActiveX","1","HKCU:\Software\Policies\Microsoft\Office\common\security","disableallactivex"
"includescreenshot"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Allow users to include screenshots and attachments when they submit feedback to Microsoft","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\feedback","includescreenshot"
#office dont share with MS
"updatereliabilitydata"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Automatically receive small updates to improve reliability","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common","updatereliabilitydata"
"sendtelemetry"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Configure the level of client software diagnostic data sent by Office to Microsoft","3","HKCU:\Software\Policies\Microsoft\Office\common\clienttelemetry","sendtelemetry"
"shownfirstrunoptin"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Disable Opt-in Wizard on first run","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\general","shownfirstrunoptin"
"qmenable"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Enable Customer Experience Improvement Program","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common","qmenable"
"enabled"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Allow users to submit feedback to Microsoft","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback","enabled"
"sendcustomerdata"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Privacy\Trust Center","Send personal information","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common","sendcustomerdata"
#lower risk
"uficontrols"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","ActiveX Control Initialization","6","HKCU:\Software\Policies\Microsoft\Office\Common\Security","uficontrols"
"allowvbaintranetreferences"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Allow VBA to load typelib references by path from untrusted intranet locations","0","HKCU:\Software\Policies\Microsoft\vba\Security","allowvbaintranetreferences"
"automationsecurity"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Automation Security","2","HKCU:\Software\Policies\Microsoft\Office\Common\Security","automationsecurity"
"disablestrictvbarefssecurity"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Disable additional security checks on VBA library references that may refer to unsafe locations on the local machine","0","HKCU:\Software\Policies\Microsoft\vba\Security","disablestrictvbarefssecurity"
"trustbar"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Disable all Trust Bar notifications for security issues","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\trustcenter","trustbar"
"defaultencryption12"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Encryption type for password protected Office 97-2003 files","Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security","defaultencryption12"
"openxmlencryption"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Encryption type for password protected Office Open XML files","Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security","openxmlencryption"
"loadcontrolsinforms"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Load Controls in Forms3","1","HKCU:\Software\Policies\Microsoft\vba\Security","loadcontrolsinforms"
"macroruntimescanscope"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Macro Runtime Scan Scope","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security","macroruntimescanscope"
"drmencryptproperty"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings","Protect document metadata for rights managed Office Open XML Files","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security","drmencryptproperty"
"allow user locations"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Security Settings\Trust Center","Allow mix of policy and user locations","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security\Trusted Locations","allow user locations"
"linkpublishingdisabled"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Server Settings","Disable the Office client from polling the SharePoint Server for published links","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Common\portal","linkpublishingdisabled"
"neverloadmanifests"="User Configuration\Policies\Administrative Templates\Microsoft Office 2016\Smart Documents (Word  Excel)","Disable Smart Document's use of manifests","1","HKCU:\Software\Policies\Microsoft\Office\Common\smart tag","neverloadmanifests"


#Access
"Accblockcontentexecutionfrominternet"="User Configuration\Policies\Administrative Templates\Microsoft Access 2016\Application Settings\Security\Trust Center","Block macros from running in Office files from the Internet","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Access\Security","blockcontentexecutionfrominternet"
"acdisabletrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Access 2016\Access Options\Security\Trust Center","Turn off trusted documents","1","HKCU:\software\policies\microsoft\office\16.0\access\security\trusted documents","disabletrusteddocuments"
"acdisablenetworktrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Access 2016\Excel Options\Security\Trust Center","Turn off Trusted Documents on the network","1","HKCU:\software\policies\microsoft\office\16.0\Access\security\trusted documents","disablenetworktrusteddocuments"
"allownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft Access 2016\Application Settings\Security\Trust Center\Trusted Locations","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Access\Security\Trusted Locations","allownetworklocations"


#word
"wwdontupdatelinks"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Advanced","Update automatic links at Open","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\options","dontupdatelinks"
"woblockcontentexecutionfrominternet"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","Block macros from running in Office files from the Internet","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","blockcontentexecutionfrominternet"
"vbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft Access 2016\Application Settings\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Access\Security","vbawarnings"
"wovbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","vbawarnings"
#When gpo is set to disabled the allowdde value is removed
"woallowdde"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","Dynamic Data Exchange","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","allowdde"
"wonotbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins and block them","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","notbpromptunsignedaddin"
"worequireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","requireaddinsig"
"woopeninprotectedview"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Set default file block behavior","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","openinprotectedview"
"Word2files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 2 and earlier binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word2files"
"Word2000files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 2000 binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word2000files"
"Word2003files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 2003 binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word2003files"
"Word2007files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 2007 and later binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word2007files"
"Word60files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 6.0 binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word60files"
"Word95files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 95 binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word95files"
"Word97files"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word 97 binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Word97files"
"Wordxpfiles"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\File Block Settings","Word XP binary documents and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\fileblock","Wordxpfiles"
#reg enable = 0 disable = 1
"woenableonload"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security","Turn off file validation","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\filevalidation","enableonload"
"wodisableinternetfilesinpv"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\Protected View","Do not open files from the Internet zone in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\protectedview","disableinternetfilesinpv"
"wodisableunsafelocationsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\Protected View","Do not open files in unsafe locations in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\protectedview","disableunsafelocationsinpv"
"wodisableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\Protected View","Turn off Protected View for attachments opened from Outlook","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\protectedview","disableattachmentsinpv"
"wwdisableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Powerpoint Options\Security\Trust Center\Protected View","Set document behaviour if file validation fails","0","HKCU:\Software\Policies\Microsoft\office\16.0\Word\security\filevalidation","openinprotectedview"
"showmarkupopensave"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security","Make hidden markup visible","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\options","showmarkupopensave"
"wwdisabletrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\PowerPoint Options\Security\Trust Center","Turn off trusted documents","1","HKCU:\software\policies\microsoft\office\16.0\Visio\security\trusted documents","disabletrusteddocuments"
"wwdisablenetworktrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\PowerPoint Options\Security\Trust Center","Turn off Trusted Documents on the network","1","HKCU:\software\policies\microsoft\office\16.0\Word\security\trusted documents","disablenetworktrusteddocuments"
"Wordbypassencryptedmacroscan"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center","Scan encrypted macros in Word Open XML documents","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security","Wordbypassencryptedmacroscan"
"woallownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft Word 2016\Word Options\Security\Trust Center\Trusted Locations","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security\Trusted Locations","allownetworklocations"

#excel
"enableblockunsecurequeryfiles"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\External Content","Always prevent untrusted Microsoft Query files from opening","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\external content","enableblockunsecurequeryfiles"
"disableddeserverlaunch"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\External Content","Don't allow Dynamic Data Exchange (DDE) server launch in Excel","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\external content","disableddeserverlaunch"
"disableddeserverlookup"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\External Content","Don't allow Dynamic Data Exchange (DDE) server lookup in Excel","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\external content","disableddeserverlookup"
"Execblockcontentexecutionfrominternet"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Block macros from running in Office files from the Internet","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","blockcontentexecutionfrominternet"
"notbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins and block them","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","notbpromptunsignedaddin"
"requireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","requireaddinsig"
"extensionhardening"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security","Force file extension to match file type","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","extensionhardening"
"dbasefiles"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","dBase III / IV files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","dbasefiles"
"difandsylkfiles"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Dif and Sylk files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","difandsylkfiles"
"xl2macros"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 2 macrosheets and add-in files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl2macros"
"xl2worksheets"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 2 worksheets","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl2worksheets"
"xl3macros"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 3 macrosheets and add-in files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl3macros"
"xl3worksheets"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 3 worksheets","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl3worksheets"
"xl4macros"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 4 macrosheets and add-in files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl4macros"
"xl4workbooks"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 4 workbooks","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl4workbooks"
"xl4worksheets"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 4 worksheets","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl4worksheets"
"xl95workbooks"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 95 workbooks","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl95workbooks"
"xl9597workbooksandtemplates"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 95-97 workbooks and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl9597workbooksandtemplates"
"xl97workbooksandtemplates"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Excel 97-2003 workbooks and templates","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","xl97workbooksandtemplates"
"openinprotectedview"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Set default file block behavior","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","openinprotectedview"
"htmlandxmlssfiles"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\File Block Settings","Web pages and Excel 2003 XML spreadsheets","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\fileblock","htmlandxmlssfiles"
#reg enable = 0 disable = 1
"enableonload"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security","Turn off file validation","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\Filevalidation","enableonload"
"enabledatabasefileprotectedview"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\Protected View","Always open untrusted database files in Protected View","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\protectedview","enabledatabasefileprotectedview"
"disableinternetfilesinpv"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\Protected View","Do not open files from the Internet zone in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\protectedview","disableinternetfilesinpv"
"disableunsafelocationsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\Protected View","Do not open files in unsafe locations in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\protectedview","disableunsafelocationsinpv"
"disableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\Protected View","Turn off Protected View for attachments opened from Outlook","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\protectedview","disableattachmentsinpv"
"exdisableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Powerpoint Options\Security\Trust Center\Protected View","Set document behaviour if file validation fails","0","HKCU:\Software\Policies\Microsoft\office\16.0\excel\security\filevalidation","openinprotectedview"
"exdisabletrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Turn off trusted documents","1","HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted documents","disabletrusteddocuments"
"exdisablenetworktrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Turn off Trusted Documents on the network","1","HKCU:\software\policies\microsoft\office\16.0\excel\security\trusted documents","disablenetworktrusteddocuments"
"donotloadpictures"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Advanced\Web Options...\General","Load pictures from Web pages not created in Excel","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\internet","donotloadpictures"
"disableautorepublish"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Save","Disable AutoRepublish","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\options","disableautorepublish"
"disableautorepublishwarning"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Save","Do not show AutoRepublish warning alert","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\options","disableautorepublishwarning"
"Excelbypassencryptedmacroscan"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security","Scan encrypted macros in Excel Open XML workbooks","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","Excelbypassencryptedmacroscan"
"webservicefunctionwarnings"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security","WEBSERVICE Function Notification Settings","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","webservicefunctionwarnings"
"xl4macrooff"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center","Prevent Excel from running XLM macros","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security","xl4macrooff"
"Exceallownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Security\Trust Center\Trusted Locations","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security\Trusted Locations","allownetworklocations"
"extractdatadisableui"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Data Recovery","Do not show data extraction options when opening corrupt workbooks","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\options","extractdatadisableui"
#reg enable = 0 disable = 1
"fupdateext_78_1"="User Configuration\Policies\Administrative Templates\Microsoft Excel 2016\Excel Options\Advanced","Ask to update automatic links","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\options\binaryoptions","fupdateext_78_1"

#powerpoint
"blockcontentexecutionfrominternet"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center","Block macros from running in Office files from the Internet","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","blockcontentexecutionfrominternet"
"ppvbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","vbawarnings"
"ppnotbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins and block them","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","notbpromptunsignedaddin"
"pprequireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","requireaddinsig"
"binaryfiles"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\File Block Settings","PowerPoint 97-2003 presentations  shows  templates and add-in files","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\fileblock","binaryfiles"
"ppopeninprotectedview"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\File Block Settings","Set default file block behavior","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\fileblock","openinprotectedview"
#reg enable = 0 disable = 1
"ppenableonload"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security","Turn off file validation","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\filevalidation","enableonload"
"runprograms"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security","Run Programs","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","runprograms"
"ppdisableinternetfilesinpv"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\Protected View","Do not open files from the Internet zone in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\protectedview","disableinternetfilesinpv"
"ppdisableunsafelocationsinpv"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\Protected View","Do not open files in unsafe locations in Protected View","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\protectedview","disableunsafelocationsinpv"
"ppdisableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\Protected View","Turn off Protected View for attachments opened from Outlook","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\protectedview","disableattachmentsinpv"
"pdisableattachmentsinpv"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\Protected View","Set document behaviour if file validation fails","0","HKCU:\Software\Policies\Microsoft\office\16.0\Powerpoint\security\filevalidation","openinprotectedview"
"markupopensave"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\PowerPoint Options\Security","Make hidden markup visible","1","HKCU:\Software\Policies\Microsoft\Office\16.0\powerpoint\options","markupopensave"
"ppdisabletrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\PowerPoint Options\Security\Trust Center","Turn off trusted documents","1","HKCU:\software\policies\microsoft\office\16.0\Powerpoint\security\trusted documents","disabletrusteddocuments"
"ppdisablenetworktrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\PowerPoint Options\Security\Trust Center","Turn off Trusted Documents on the network","1","HKCU:\software\policies\microsoft\office\16.0\Powerpoint\security\trusted documents","disablenetworktrusteddocuments"
#reg enable = 0 disable = 1
"powerpointbypassencryptedmacroscan"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security","Scan encrypted macros in PowerPoint Open XML presentations","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security","powerpointbypassencryptedmacroscan"
"ppallownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft PowerPoint 2016\Powerpoint Options\Security\Trust Center\Trusted Locations","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Powerpoint\Security\Trusted Locations","allownetworklocations"

#outlook
"authenticationservice"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Account Settings\Exchange","Authentication with Exchange Server","16","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","authenticationservice"
"enablerpcencryption"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Account Settings\Exchange","Enable RPC encryption","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\rpc","enablerpcencryption"
"publicfolderscript"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Outlook Options\Other\Advanced","Do not allow Outlook object model scripts to run for public folders","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","publicfolderscript"
"sharedfolderscript"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Outlook Options\Other\Advanced","Do not allow Outlook object model scripts to run for shared folders","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","sharedfolderscript"
"msgformat"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Outlook Options\Other\Advanced","Use Unicode format when dragging e-mail message to file system","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\options\general","msgformat"
"junkmailprotection"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Outlook Options\Preferences\Junk E-mail","Junk E-mail protection level","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\options\mail","junkmailprotection"
"allowactivexoneoffforms"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security","Allow Active X One Off Forms","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","allowactivexoneoffforms"
"disallowattachmentcustomization"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security","Prevent users from customizing attachment security settings","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook","disallowattachmentcustomization"
"internet"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Automatic Picture Download Settings","Include Internet in Safe Zones for Automatic Picture Download","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\options\mail","internet"
"minenckey"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Cryptography","Minimum encryption settings","168","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","minenckey"
"warnaboutinvalid"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Cryptography","Signature Warning","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","warnaboutinvalid"
"usecrlchasing"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Cryptography\Signature Status dialog box","Retrieving CRLs (Certificate Revocation Lists)","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","usecrlchasing"
"adminsecuritymode"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings","Outlook Security Mode","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","adminsecuritymode"
"allowuserstolowerattachments"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Attachment Security","Allow users to demote attachments to Level 2","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","allowuserstolowerattachments"
"showlevel1attach"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Attachment Security","Display Level 1 attachments","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","showlevel1attach"
"fileextensionsremovelevel1"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Attachment Security","Remove file extensions blocked as Level 1",";","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","fileextensionsremovelevel1"
"fileextensionsremovelevel2"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Attachment Security","Remove file extensions blocked as Level 2",";","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","fileextensionsremovelevel2"
"enableoneoffformscripts"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Custom Form Security","Allow scripts in one-off Outlook forms","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","enableoneoffformscripts"
"promptoomcustomaction"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Custom Form Security","Set Outlook object model custom actions execution prompt","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomcustomaction"
"promptoomaddressbookAccess"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt when Accessing an address book","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomaddressbookAccess"
"promptoomformulaAccess"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt When Accessing the Formula property of a UserProperty object","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomformulaAccess"
"promptoomsaveas"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt when executing Save As","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomsaveas"
"promptoomaddressinformationAccess"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt when reading address information","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomaddressinformationAccess"
"promptoommeetingtaskrequestresponse"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt when responding to meeting and task requests","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoommeetingtaskrequestresponse"
"promptoomsend"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Security Form Settings\Programmatic Security","Configure Outlook object model prompt when sending mail","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","promptoomsend"
"junkmailenablelinks"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Trust Center","Allow hyperlinks in suspected phishing e-mail messages","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\options\mail","junkmailenablelinks"
"level"="User Configuration\Policies\Administrative Templates\Microsoft Outlook 2016\Security\Trust Center","Security setting for macros","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security","level"

#publisher
"puvbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft Publisher 2016\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\publisher\Security","vbawarnings"
"punotbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft Publisher 2016\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins","1","HKCU:\Software\Policies\Microsoft\Office\16.0\publisher\Security","notbpromptunsignedaddin"
"purequireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft Publisher 2016\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\office\16.0\publisher\security","requireaddinsig"
"puautomationsecuritypublisher"="User Configuration\Policies\Administrative Templates\Microsoft Publisher 2016\Security","Publisher Automation Security Level","2","HKCU:\Software\Policies\Microsoft\Office\Common\Security","automationsecuritypublisher"

#Project
"prvbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft Project 2016\Project Options\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\MS Project\Security","vbawarnings"
"prnotbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft Project 2016\Project Options\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins and block them","1","HKCU:\Software\Policies\Microsoft\Office\16.0\MS Project\Security","notbpromptunsignedaddin"
"prrequireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft Project 2016\Project Options\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\Office\16.0\MS Project\Security","requireaddinsig"
"prallownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft Project 2016\Project Options\Security\Trust Center","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\MS Project\Security\Trusted Locations","allownetworklocations"

#visio
"viblockcontentexecutionfrominternet"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center","Block macros from running in Office files from the Internet","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security","blockcontentexecutionfrominternet"
"vivbawarnings"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center","VBA Macro Notification Settings","3","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security","vbawarnings"
"vinotbpromptunsignedaddin"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center","Disable Trust Bar Notification for unsigned application add-ins and block them","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security","notbpromptunsignedaddin"
"virequireaddinsig"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center","Require that application add-ins are signed by Trusted Publisher","1","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security","requireaddinsig"
"Visio2000files"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center\File Block Settings","Visio 2000-2002 Binary Drawings  Templates and Stencils","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security\fileblock","Visio2000files"
"Visio2003files"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center\File Block Settings","Visio 2003-2010 Binary Drawings  Templates and Stencils","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security\fileblock","Visio2003files"
"Visio50andearlierfiles"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center\File Block Settings","Visio 5.0 or earlier Binary Drawings  Templates and Stencils","2","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security\fileblock","Visio50andearlierfiles"
"vvdisabletrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\PowerPoint Options\Security\Trust Center","Turn off trusted documents","1","HKCU:\software\policies\microsoft\office\16.0\Visio\security\trusted documents","disabletrusteddocuments"
"vvdisablenetworktrusteddocuments"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\PowerPoint Options\Security\Trust Center","Turn off Trusted Documents on the network","1","HKCU:\software\policies\microsoft\office\16.0\Visio\security\trusted documents","disablenetworktrusteddocuments"
"viallownetworklocations"="User Configuration\Policies\Administrative Templates\Microsoft Visio 2016\Visio Options\Security\Trust Center","Allow Trusted Locations on the network","0","HKCU:\Software\Policies\Microsoft\Office\16.0\Visio\Security\Trusted Locations","allownetworklocations"

#Lync
"enablesiphighsecuritymode"="Computer Configuration\Policies\Administrative Templates\Skype for Business 2016\Microsoft Lync Feature Policies","Configure SIP security mode","0","HKLM:\Software\Policies\Microsoft\Office\16.0\Lync","enablesiphighsecuritymode"
"disablehttpconnect"="Computer Configuration\Policies\Administrative Templates\Skype for Business 2016\Microsoft Lync Feature Policies","Disable HTTP fallback for SIP connection","1","HKLM:\Software\Policies\Microsoft\Office\16.0\Lync","disablehttpconnect"

}


$fragOfficeVal=@()

foreach ($OfficePolItems in $OfficePolicies.values)
{
    $OfficeVal=@()
    $getOfficeValue=@()
    $OfficeDescrip=@()
    $regPath=@()

    $OfficeGPOPath = $OfficePolItems[0]
    $OfficeGPOName = $OfficePolItems[1]
    $OfficeRegValue = $OfficePolItems[2]
    $OfficeRegPath = $OfficePolItems[3]
    $OfficeRegName = $OfficePolItems[4]
    $OfficeHelp = $OfficePolItems[5]

    # write-host $OfficeGPOPath -ForegroundColor Red
    # write-host $OfficeGPOName -ForegroundColor Red
    # write-host $OfficeRegPath  -ForegroundColor Green
    # write-host $OfficeRegName -ForegroundColor Yellow
    # Write-Host $OfficeRegValue -ForegroundColor White

    #MS cant decided if 1 is enabled or disabled, compounded with double negs and positives, so this is of little use, updated the above table with the correct numerical values
    #if ($OfficeRegValue -eq "Enabled"){$OfficeRegValue = "1"}
    #if ($OfficeRegValue -eq "Disabled"){$OfficeRegValue = "0"}

    $gpopath = $OfficeGPOPath +"\"+ $OfficeGPOName
    $regPath = $OfficeRegPath  +"\"+ $OfficeRegName

    $getOfficePath = Get-Item $OfficeRegPath -ErrorAction SilentlyContinue
    $getOfficeValue = $getOfficePath.GetValue("$OfficeRegName") 

    #defaulf behaviour is disabled even with gpo set so reg value is not created
    if ($OfficeRegName -eq "allowdde" -and $getOfficeValue -eq $null){$getOfficeValue = "0"}
    if ($OfficeRegName -eq "runprograms" -and $getOfficeValue -eq $null){$getOfficeValue = "0"}

   # Write-Host $getOfficeValue -ForegroundColor Cyan

        if ($getOfficeValue -eq "$OfficeRegValue")
        {
            $OfficeSet = "$OfficeGPOName is set correctly with a value of $getOfficeValue" 
            $OfficeReg = "<div title=$gpoPath>$regPath"
            $trueFalse = "True"
        }
        else
        {
            $OfficeSet = "Warning $OfficeGPOName is not set or has the wrong setting with value of $getOfficeValue Warning" 
            $OfficeReg = "<div title=$gpoPath>$regPath"
            $trueFalse = "False"
        }

        if ([string]::IsNullorEmpty($getOfficeValue) -eq $true){$OfficeSet = "DefaultGPO $OfficeGPOName is not explicitly set in GPO and the default setting is applied DefaultGPO"}

        $newObjOffice = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjOffice -Type NoteProperty -Name OfficeGPONameSetting -Value $OfficeSet
        Add-Member -InputObject $newObjOffice -Type NoteProperty -Name OfficeRegValue -Value $OfficeReg 
        Add-Member -InputObject $newObjOffice -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
        $fragOfficeVal += $newObjOffice

}

################################################
#################  SUMMARY  ####################
################################################
   if ($BiosUEFI -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#BiosUEFI">Out of date BIOS or UEFI</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }

   if ($HotFix -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Hotfix">Windows Updates are out of date</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragInstaApps -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#InstalledApps">Out of date Applications</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }
    
    if ($MsinfoClixml -eq $null)
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#vbs">Virtualised Based Security</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragCode -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#HECI">Hypervisor Enforced Code Integrity</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragBitLocker -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Bitlockerisnotenabled">Bitlocker</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Very High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragPreAuth -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#PreAuth">There are AD accounts that dont Pre-Authenticated</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    
    if ($fragkernelModeVal -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#KernelMode">Kernel-mode Hardware-enforced Stack Protection is not enabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }


    if ($fragNeverExpires -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#PassExpire">There are AD accounts that dont Expire their Passwords</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragLSAPPL -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#LSA">LSA is Disabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragCredGuCFG -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#CredGuard">Credential Guard is Disabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragWDigestULC -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#WDigest">WDigest is Enabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragLapsPwEna -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#LAPS">LAPS is not Configured</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($FragAVStatus -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#AV">There are issues with AntiVirus</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

   if ($fragPSPass -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#ProcPW">Processes have been found that contain Embedded Passwords</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragFilePass -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#FilePW">Files have been found that contain Embedded Passwords</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }  

   if ($fragRegPasswords -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#RegPW">Found Embedded Passwords in the Registry</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   } 

    if ($fragAutoLogon -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#AutoLogon">The Registry contains Autologon credentials</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragPCElevate -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#SoftElevation">Installation of Software will Auto Elevate</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

    if ($fragDLLSafe -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#DLLSafe">DLL Safe Search is not Enabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
    }

   if ($fragDllNotSigned -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#DLLSign">Dlls that are Not Signed and User Permissions Allow Write</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragDLLHijack -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#DLLHigh">Loaded  dlls that are Vulnerable to dll Hijacking by the User</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragAuthCodeSig -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#AuthentiCode">Found Authenticode Signature Hash Mismatch</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragCertificates -like "*Warning*" -or $fragCertificates -like "*selfsigned*" -or $fragCertificates -like "*Expired*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Certs">Installed Certificate Issues</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragCipherSuit -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#CipherSuites">SHA1 Cipher Suites are Supported</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }
   
   if ($fragUnQuoted -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#unquoted">Unquoted Paths Vulnerability</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Very High Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragReg -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#RegWrite">Registry Keys that are Writeable</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragsysFold -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#SysDirWrite">Program Files or Windows Directories are Writeable</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium to High Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragcreateSysFold -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#sysDirExe">Users can both Execute and Write to Program Files or Windows Directories</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium to High Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragwFile -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#sysFileWrite">File in Program Files or Windows Directories are Writeable</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragwFold -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#nonSysDirWrite">Directories that are Writeable and Non System</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Low Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragShare -like "*C$*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#shares">There are System Shares available</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Informational"
       $fragSummary += $newObjSummary
   }

   if ($fragLegNIC -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#LegNetProt">Legacy Network Protocols are Enabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium to High Risk"
       $fragSummary += $newObjSummary
   } 

   if ($SchedTaskPerms -ne $null)
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#schedDir">Scheduled Tasks with Scripts and Permissions are Weak</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   } 

      if ($SchedTaskListings -ne $null)
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#schedTask">Scheduled Tasks Contain Base64 or Commands that Require Reviewing</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   } 


    if ($DriverQuery -like "*warning*")
    {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#drivers">There are Drivers that Arent Signed</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
    }

      if ($fragSecOptions -like "*warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#secOptions">Security Options that Pevent MitM Attack are Enabled</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   } 

   if ($fragASR -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#asr">Attack Surface Reduction GPOs have not been Set</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
       $fragSummary += $newObjSummary
   }

      if ($fragWindowsOSVal -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#WinSSLF">Windows Hardening Policies Recommended by Microsoft are Missing</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }

   if ($fragEdgeVal -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#EdgeSSLF">Edge Hardening Policies Recommended by Microsoft are Missing</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }


   if ($fragOfficeVal -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#OfficeSSLF">Office Hardening Policies Recommended by Microsoft are Missing</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
   }
       
   #if ($fragFWProfile| % {$_.inbound -eq "Allow"})
    if ($fragFWProfile -like "*Warning*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#FirewallProf">The Firewall Profile Allows Inbound Traffic</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Very High Risk"
       $fragSummary += $newObjSummary      
   }

   
   if ($getFw -like "*Inbound*")
   {
       $newObjSummary = New-Object psObject
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#InFirewall">There are Firewall rules Allowing Inbound Firewall Traffic</a>'
       Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
       $fragSummary += $newObjSummary
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

    #$VulnReport = "C:\SecureReport"
    #$OutFunc = "scheme" 
                
    #$tpScheme = Test-Path "C:\SecureReport\output\$OutFunc\"
    #$SchemePath = "C:\SecureReport\output\$OutFunc\" + "$OutFunc.txt"

    #$Scheme = Get-Content $SchemePath

#$font = "helvetica"
$font = "Raleway"
$FontTitle_H1 = "175%"
$FontSub_H2 = "130%"
$FontBody_H3 = "105%"
$FontHelps_H4 = "100%"

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
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#B87333;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:$FontTitle_H1;
        font-family:$font;
        margin:0,0,10px,0;
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h2
    {
        background-color:#250F00; 
        color:#4682B4
        font-size:$FontSub_H2;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h3
    {
        background-color:#250F00; 
        color:#B87333;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#250F00; 
        color:#766A6A;
        font-size:$FontHelps_H4;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#B87333;
        background-color:#250F00
    }
    td
    {
        border-width: 1px;
        padding:7px;
        font-size:$FontBody_H3;
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

    a:link {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:visited {
    color:#ff9933;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:hover {
    color:#B87333;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:active {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    </Style>
"@
}

elseif ($Scheme -eq "Dark")
{
$titleCol = "#4682B4"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#FFF9EC;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:$FontTitle_H1;
        font-family:$font;
        margin:0,0,10px,0;
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h2
    {
        background-color:#06273A; 
        color:#4682B4;
        font-size:$FontSub_H2;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h3
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#06273A; 
        color:#766A6A;
        font-size:$FontHelps_H4;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#FFF9EC;
        background-color:#06273A
    }
    td
    {
        border-width: 1px;
        padding:7px;
        font-size:$FontBody_H3;
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

    a:link {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:visited {
    color:#ff9933;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:hover {
    color:#FFF9EC;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:active {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    </Style>
"@
}

elseif ($Scheme -eq "Light")
{
$titleCol = "#000000"

#HTML GENERATOR CSS
$style = @"
    <Style>
    body
    {
        background-color:#EBEAE7; 
        color:#79253D;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    table
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#FFF9EC;
        border-collapse:collapse;
        width:auto
    }
    h1
    {
        background-color:#EBEAE7 
        color:#79253D;
        font-size:$FontTitle_H1;
        font-family:$font;
        margin:0,0,10px,0;
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h2
    {
        background-color:#EBEAE7; 
        color:#000000;
        font-size:$FontSub_H2;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h3
    {
        background-color:#EBEAE7; 
        color:#79253D;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#EBEAE7; 
        color:#877F7D;
        font-size:$FontHelps_H4;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#79253D;
        background-color:#EBEAE7
    }
    td
    {
        border-width: 1px;
        padding:7px;
        font-size:$FontBody_H3;
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

    a:link {
    color:#000000;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:visited {
    color:#ff9933;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:hover {
    color:#79253D;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:active {
    color:#000000;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    </Style>
"@
}

elseif ($Scheme -eq "Grey")
{
$titleCol = "#D3BAA9"

#HTML GENERATOR CSS
$style = @"
    <Style>
    
    body
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
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
        font-size:$FontTitle_H1;
        font-family:$font;
        margin:0,0,10px,0;
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h2
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:$FontSub_H2;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h3
    {
        background-color:#454545; 
        color:#A88F7E;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal;
        width:auto
    }
        h4
    {
        background-color:#454545; 
        color:#D3BAA9;
        font-size:$FontHelps_H4;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#D3BAA9;
        background-color:#454545
    }
    td
    {
        border-width: 1px;
        padding:7px;
        font-size:$FontBody_H3;
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

    a:link {
    color:#D3BAA9;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:visited {
    color:#ff9933;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:hover {
    color:#A88F7E;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:active {
    color:#D3BAA9;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }    

    </Style>
"@
}

#4682B4 - blue
#FFF9EC - white

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
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
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
        font-size:$FontTitle_H1;
        font-family:$font;
        margin:0,0,10px,0;
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h2
    {
        background-color:#06273A; 
        color:#4682B4;
        font-size:$FontSub_H2;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word
    }
    h3
    {
        background-color:#06273A; 
        color:#FFF9EC;
        font-size:$FontBody_H3;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal;
        width:auto
    }
    h4
    {
        background-color:#06273A; 
        color:#9f9696;
        font-size:$FontHelps_H4;
        font-family:$font;
        margin:0,0,10px,0; 
        Word-break:normal; 
        Word-wrap:break-Word;
        font-weight: normal
    }
    th
    {
        border-width: 1px;
        padding: 7px;
        font-size:$FontBody_H3;
        border-style: solid;
        border-color:#FFF9EC;
        background-color:#06273A
    }
    td
    {
        border-width: 1px;
        padding:7px;
        font-size:$FontBody_H3;
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

    a:link {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:visited {
    color:#ff9933;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:hover {
    color:#FFF9EC;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
    }

    a:active {
    color:#4682B4;
    font-size:$FontBody_H3;
    background-color: transparent;
    text-decoration: none;
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

    $Intro = "Thanks for using the vulnerability report written by Tenaka.net, please show your support and visit my site, it's non-profit and Ad-free. <br> <br>Any issues with the report's accuracy please do let me know and I'll get it fixed asap. The results in this report are a guide and not a guarantee that the tested system is not without further defects or vulnerability.<br>
    <br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail.<br><br>The html output can be imported into Excel for further analysis and uses the True and False values as a drop-down filter.<br>Open Excel, Data, Import from Web. Enter the file path in the following format file:///C:/SecureReport/NameOfReport.htm, then Select multiple items and click on Load and select 'Load To', click on Table.<br><br>Further support for this report can be found @ https://www.tenaka.net/windowsclient-vulnscanner"

    #$Intro2 = "The results in this report are a guide and not a guarantee that the tested system is not without further defect or vulnerability.<br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail.<br><br>The html output can be imported into Excel for further analysis and uses the True and False values as a drop-down filter.<br><br>Open Excel, Data, Import from Web. Enter the file path in the following format file:///C:/SecureReport/NameOfReport.htm, then Select multiple items and click on Load and select 'Load To', click on Table.<br>"

    $Finish = "This script has been provided by Tenaka.net, if it's beneficial, please provide feedback and any additional feature requests gratefully received. "

    $descripBitlocker = "TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then Accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM. <br> <br>Further information can be found @ https://www.tenaka.net/bitlocker<br>"

    $descripVirt = "Secure Boot is a security standard to ensure only trusted OEM software is allowed at boot. At startup the UEFi and boot software's digital signatures are validated preventing rootkits. <br> <br>More on Secure Boot can be found here @ https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF<br>"

    $descripVirt2 = "Virtualization-based security (VBS), isolates core system resources to create secure regions of memory. Enabling VBS allows for Hypervisor-Enforced Code Integrity (HVCI), Device Guard and Credential Guard. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs<br> <br>https://www.tenaka.net/deviceguard-vs-rce and https://www.tenaka.net/pass-the-hash <br>"

    $descripSecOptions = "<br>GPO settings can be found @ Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options<br><br>Prevent credential relay with Impacket and Man in the Middle by Digitally Signing for SMB and LDAP connections enforcement. <br> <br>Further information can be found @ https://www.tenaka.net/smb-relay-attack<br> <br>System cryptography: Force strong key protection for user keys stored on the computer should only be set on clients and not Servers<br>"

    $descripLSA = "Enabling RunAsPPL for LSA Protection allows only digitally signed binaries to load as a protected process preventing credential theft and Access by code injection and memory Access by processes that aren't signed. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection<br>"

    $descripDLL = "Loading DLL's default behaviour is to call the dll from the current working directory of the application, then the directories listed in the environmental variable. Setting 'DLL Safe Search' mitigates the risk by moving CWD to later in the search order. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order<br>"

    $descripHyper = "Hypervisor Enforced Code Integrity prevents the loading of unsigned kernel-mode drivers and system binaries from being loaded into system memory. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity<br>"

    $descripElev = "Auto Elevate User is a setting that elevates users allowing them to install software without being an administrator. "

    $descripFilePw = "Files that contain password or credentials"

    $descripAutoLogon = "MECM\SCCM\MDT could leave Autologon credentials including a clear text password in the Registry."

    $descripUnquoted = "The Unquoted paths vulnerability is when a Windows Service's 'Path to Executable' contains spaces and not wrapped in double-quotes providing a route to System. <br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripProcPw = "Processes that contain credentials to authenticate and Access applications. Launching Task Manager, Details and add 'Command line' to the view."

    $descripLegacyNet = "LLMNR and other legacy network protocols can be used to steal password hashes. <br> <br>Further information can be found @https://www.tenaka.net/responder<br>"

    $descripRegPer ="Weak Registry permissions allowing users to change the path to launch malicious software.<br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths"

    $descripSysFold = "Default System Folders that allow a User the Write permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br> Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripCreateSysFold = "Default System Folders that allows a User the CreateFile permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripNonFold = "A vulnerability exists when enterprise software has been installed on the root of C:\. The default permissions allow a user to replace approved software binaries with malicious binaries. <br> <br>Further information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripFile = "System files that allow users to write can be swapped out for malicious software binaries. <br> <br>Further  information can be found @ https://www.tenaka.net/unquotedpaths<br>"

    $descripFirewalls = "Firewalls should always block inbound and exceptions should be to a named IP and Port.<br> <br>Further  information can be found @ https://www.tenaka.net/whyhbfirewallsneeded<br>" 

    $descripTaskSchPerms = "Checks for Scheduled Tasks excluding any that reference System32 as a directory. These potential user-created tasks are checked for scripts and their directory permissions are validated. No user should be allowed to Access the script and make amendments, this is a privilege escalation route." 

    $descripTaskSchEncode = "Checks for encoded scripts, PowerShell or exe's that make calls off box or run within Task Scheduler" 

    $descriptDriverQuery = "All Drivers should be signed with a digital signature to verify the integrity of the packages. 64bit kernel Mode drivers must be signed without exception"

    $descriptAuthCodeSig = "Checks that digitally signed files have a valid and trusted hash. If any Hash Mis-Matches then the file could have been altered"

    $descriptDLLHijack = "DLL Hijacking is when a malicious dll replaces a legitimate dll due to a path vulnerability. A program or service makes a call on that dll gaining the privileges of that program or service. Additionally missing dll's presents a risk where a malicious dll is dropped into a path where no current dll exists but the program or service is making a call to that non-existent dll. This audit is reliant on programs being launched so that DLL's are loaded. Each process's loaded dll's are checked for permissions issues and whether they are signed. The DLL hijacking audit does not currently check for missing dll's being called. Process Monitor filtered for 'NAME NOT FOUND' and path ends with 'DLL' will."

    $descripCredGu = "Credential Guard securely isolating the LSA process preventing the recovery of domain hashes from memory. Credential Guard only works for Domain joined clients and servers.<br> <br>Further information can be found @ https://www.tenaka.net/pass-the-hash<br>"

    $descripLAPS = "Local Administrator Password Solution (LAPS) is a small program with some GPO settings that randomly sets the local administrator password for clients and servers across the estate. Domain Admins have default permission to view the local administrator password via DSA.MSC. Access to the LAPS passwords may be delegated unintentionally, this could lead to a serious security breach, leaking all local admin accounts passwords for all computer objects to those that shouldn't have Access. <br> <br>Installation guide can be found @ https://www.tenaka.net/post/local-admin-passwords. <br> <br>Security related issue details can be found @ https://www.tenaka.net/post/laps-leaks-local-admin-passwords<br>"

    $descripURA = "User Rights Assignments (URA) control what tasks a user can perform on the local client, server or Domain Controller. For example the 'Log on as a service' (SeServiceLogonRight) provides the rights for a service account to Logon as a Service, not Interactively. <br> <br> Access to URA can be abused and attack the system. <br> <br>Both SeImpersonatePrivilege (Impersonate a client after authentication) and SeAssignPrimaryTokenPrivilege (Replace a process level token) are commonly used by service accounts and vulnerable to escalation of privilege via Juicy Potato exploits.<br> <br>SeBackupPrivilege (Back up files and directories), read Access to all files including SAM Database, Registry and NTDS.dit (AD Database). <br> <br>SeRestorePrivilege (Restore files and directories), Write Access to all files. <br> <br>SeDebugPrivilege (Debug programs), allows the ability to dump and inject into process memory inc kernel. Passwords are stored in memory in the clear and can be dumped and easily extracted. <br> <br>SeTakeOwnershipPrivilege (Take ownership of files or other objects), take ownership of file regardless of Access.<br> <br>SeNetworkLogonRight (Access this computer from the network) allows pass-the-hash when Local Admins share the same password, remove all the default groups and apply named groups, separating client from servers.<br><br>SeCreateGlobalPrivilege (Create global objects), do not assign any user or group other than Local System as this will allow system takeover<br><br>Further details can be found @ <br>https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment<br>https://www.microsoft.com/en-us/download/details.aspx?id=55319<br><br>**UserRightAssignment-Name - Mouse over to show Microsofts recommended setting"

    $descripRegPasswords = "Searches HKLM and HKCU for the Words 'password' and 'passwd', then displays the password value in the report.<br><br>The search will work with VNC encrypted passwords stored in the registry, from Kali run the following command<br> <br>echo -n PasswordHere | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv<br>"

    $descripASR = "Attack Surface Reduction (ASR) requires Windows Defender Real-Time Antivirus and works in conjunction with Exploit Guard to prevent malware abusing legitimate MS Office functionality<br> <br>Further information can be found @ https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide<br>"

    $descripWDigest = "WDigest was introduced with Windows XP\2003 and has been enabled by default until and including Windows 8 and Server 2012. Enabling allows clear text passwords to be recoverable from LSASS with Mimikatz"

    $descripDomainGroups = "Group membership of the user executing this script. Local admins are required, the account should not have Domain Admins as this can result in privilege escalation."

    $descripDomainPrivs = "Reference User Rights Assignment (USR) section below for further details"

    $descripLocalAccounts = "Local accounts should be disabled when the client or server is part of a Domain. LAPS should be deployed to ensure all local account passwords are unique"

    $descripWindowsOS = "Warning: Absence of a GPO setting will raise an issue as the default setting is not assumed<br>These are recommended GPO settings to secure Windows by Microsoft, do NOT implement without the correct research and testing. Some settings could adversely affect your system.<br> <br>Due to the sheer number of settings, the script contains details and the equivalent GPO settings, search for RECOMMENDED SECURITY SETTINGS section<br><br>MS Security Compliance Toolkit can be found @ <br>https://admx.help/?Category=security-compliance-toolkit<br>https://www.microsoft.com/en-us/download/details.aspx?id=55319<br><br>**WindowsRegValue - Mouse over to show Reg Key to GPO path translation" 

    $descripOffice2016 = "These are recommended GPO settings to secure Office 2016-365 by Microsoft, do NOT implement without the correct research and testing. Some settings could adversely affect your system.<br> Its recommended that Attack Surface Reduction (ASR) is enabled but requires Windows Defender Real-Time Antivirus and works in conjunction with Exploit Guard to prevent malware abusing legitimate MS Office functionality"

    $descripPreAuth = "READ ME - Requires the installation of the AD RSAT tools for this to work.<br><br>Pre-authentication is when the user sends the KDC an Authentication Service Request (AS_REQ) with an encrypted Timestamp. The KDC replies with an Authentication Service Reply (AS_REP) with the TGT and a logon session. The issue arises when the user's account doesn't require pre-authentication, it's a check box on the user's account settings. An attacker is then able to request a DC, and the DC dutifully replies with user encrypted TGT using the user's own NTLM password hash. An offline brute force attack is then possible in the hope of extracting the clear text password, known as AS-REP Roasting <br> <br>Further information @<br><br>https://www.tenaka.net/kerberos-armouring<br>https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx"

    $descripAV = ""

    $descripDomainPrivsGps = "Review and minimise members of privileged groups and delegate as much as possible. Don't nest groups into Domain Admins, add direct user accounts only. Deploy User Rights Assignments to explicitly prevent Domain Admins from logging on to Member Servers and Clients more information can be found here @<br><br>https://www.tenaka.net/post/deny-domain-admins-logon-to-workstations<br><br>Dont add privilged groups to Guests or Domain Guests and yes I've seen Domain Guests added to Domain Admins"

    $descripCerts = ""

    $decripCipher = ""

    $descripKernelMode = "Enabed with Windwos 11 22H2 - For code running in kernel mode, the CPU confirms requested return addresses with a second copy of the address stored in the shadow stack to prevent attackers from substituting an address that runs malicious code. Not all drivers are compatiable with this security feature. More information can be found here @<br><br>https://techcommunity.microsoft.com/t5/windows-os-platform-blog/understanding-hardware-enforced-stack-protection/ba-p/1247815"

    $descripInstalledApps = "Will assume any installed program older than 6 months is out of date"

    $descripBios = "Will assume any UEFI\BIOS is out of date if its older than 6 months"

    $descripWinUpdates = "Will assume any Windows Updates are out of date if older than 6 months"

################################################
################  FRAGMENTS  ###################
################################################
  
    #Top and Tail
    $FragDescrip1 =  $Descrip1 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Intro</span></h3>" | Out-String
    #$FragDescrip2 =  $Descrip2 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Intro2</span></h3>" | Out-String
    $FragDescripFin =  $DescripFin | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Finish</span></h3>" | Out-String
    $Frag_descripVirt2 = ConvertTo-Html -as table -Fragment -PostContent "<h4>$descripVirt2</h4>" | Out-String
    
    #Summary
    $frag_Summary = $fragSummary | ConvertTo-Html -As Table -fragment -PreContent "<h2>Overall Compliance Status</span></h2>"  | Out-String
            
    #Host details    
    $frag_Host = $fragHost | ConvertTo-Html -As List -Property Name,Domain,Model -fragment -PreContent "<h2>Host Details</span></h2>"  | Out-String
    $fragOS = $OS | ConvertTo-Html -As List -property Caption,Version,OSArchitecture,InstallDate -fragment -PreContent "<h2>Windows Details</span></h2>" | Out-String
    $FragAccountDetails = $AccountDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2>Local Account Details</span></h2>" -PostContent "<h4>$descripLocalAccounts</h4>" | Out-String 
    $frag_DCList  = $fragDCList | ConvertTo-Html -As Table -fragment -PreContent "<h2>List of Domain Controllers</span></h2>" | Out-String 
    $frag_FSMO = $fragFSMO | ConvertTo-Html -As Table -fragment -PreContent "<h2>FSMO Roles</span></h2>" | Out-String 
    $frag_DomainGrps = $fragDomainGrps | ConvertTo-Html -As Table -fragment -PreContent "<h2>Members of Privilege Groups</span></h2>" -PostContent "<h4>$descripDomainPrivsGps</h4>" | Out-String 
    $frag_PreAuth = $fragPreAuth | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"PreAuth`"><a href=`"#TOP`">Domain Accounts that DO NOT Pre-Authenticate</a></span></h2>" -PostContent "<h4>$descripPreAuth</h4>" | Out-String
    $frag_NeverExpires = $fragNeverExpires | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"PassExpire`"><a href=`"#TOP`">Domain Accounts that Never Expire their Password</a></span></h2>"  | Out-String
    $FragGroupDetails =  $GroupDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2>Local System Group Members</span></h2>" | Out-String
    $FragPassPol = $PassPol | Select-Object -SkipLast 3 | ConvertTo-Html -As Table -fragment -PreContent "<h2>Local Password Policy</span></h2>" | Out-String
    $fragInstaApps  =  $InstallApps | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2><a name=`"InstalledApps`"><a href=`"#TOP`">Installed Applications</a></span></h2>" -PostContent "<h4>$descripInstalledApps</h4>" | Out-String
    $fragHotFix = $HotFix | ConvertTo-Html -As Table -property HotFixID,InstalledOn,Caption -fragment -PreContent "<h2><a name=`"Hotfix`"><a href=`"#TOP`">Installed Windows Updates</a></span></h2>" -PostContent "<h4>$descripWinUpdates</h4>"| Out-String   
    $fragInstaApps16  =  $InstallApps16 | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2>Updates to Office 2016 and older or Updates that create KB's in the Registry</span></h2>" | Out-String
    $fragBios = $BiosUEFI | ConvertTo-Html -As List -fragment -PreContent "<h2><a name=`"BiosUEFI`"><a href=`"#TOP`">Bios Details</a></span></h2>" -PostContent "<h4>$descripBios</h4>"| Out-String
    $fragCpu = $cpu | ConvertTo-Html -As List -property Name,MaxClockSpeed,NumberOfCores,ThreadCount -fragment -PreContent "<h2>Processor Details</span></h2>" | Out-String
    $frag_whoamiGroups =  $whoamiGroups | ConvertTo-Html -As Table -fragment -PreContent "<h2>Current Users Group Membership</span></h2>" -PostContent "<h4>$descripDomainGroups</h4>" | Out-String
    $frag_whoamiPriv =  $whoamiPriv | ConvertTo-Html -As Table -fragment -PreContent "<h2>Current Users Local Privileges</span></h2>" -PostContent "<h4>$descripDomainPrivs</h4>" | Out-String
    $frag_Network4 = $fragNetwork4 | ConvertTo-Html -As List -fragment -PreContent "<h2>IPv4 Address Details</span></h2>"  | Out-String
    $frag_Network6 = $fragNetwork6 | ConvertTo-Html -As List -fragment -PreContent "<h2>IPv4 Address Details</span></h2>"  | Out-String
    $Frag_WinFeature = $FragWinFeature | ConvertTo-Html -As table -fragment -PreContent "<h2>Installed Windows Features</span></h2>"  | Out-String
    
    #Security Review
    $Frag_AVStatus = $FragAVStatus | ConvertTo-Html -As Table  -fragment -PreContent "<h2><a name=`"AV`"><a href=`"#TOP`">AntiVirus Engine and Definition Status</a></span></h2>" -PostContent "<h4>$descripAV</h4>" | Out-String
    $frag_BitLocker = $fragBitLocker | ConvertTo-Html -As List -fragment -PreContent "<h2><a name=`"Bitlockerisnotenabled`"><a href=`"#TOP`">Bitlocker and TPM Details</a></span></h2>" -PostContent "<h4>$descripBitlocker</h4>" | Out-String
    $frag_Msinfo = $MsinfoClixml | ConvertTo-Html -As Table -fragment -PreContent "<h2><a name=`"VBS`"><a href=`"#TOP`">Virtualization and Secure Boot Details</a></span></h2>" -PostContent "<h4>$descripVirt</h4>"  | Out-String
    $frag_kernelModeVal = $fragkernelModeVal | ConvertTo-Html -As Table -fragment -PreContent "<h2><a name=`"KernelMode`"><a href=`"#TOP`">Kernel-mode Hardware-enforced Stack Protection</a></span></h2>" -PostContent "<h4>$descripKernelMode</h4>"  | Out-String
    $frag_LSAPPL = $fragLSAPPL | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"LSA`"><a href=`"#TOP`">LSA Protection for Stored Credentials</a></span></h2>" -PostContent "<h4>$descripLSA</h4>" | Out-String
    $frag_DLLSafe = $fragDLLSafe | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"DLLSafe`"><a href=`"#TOP`">DLL Safe Search Order</a></span></h2>"  -PostContent "<h4>$descripDLL</h4>"| Out-String
    $frag_DLLHijack = $fragDLLHijack | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"DLLHigh`"><a href=`"#TOP`">Loaded DLL's that are vulnerable to DLL Hijacking</a></span></h2>" | Out-String
    $frag_DllNotSigned = $fragDllNotSigned | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"DLLSign`"><a href=`"#TOP`">All DLL's that aren't signed and user permissions allow write</a></span></h2>"  -PostContent "<h4>$descriptDLLHijack</h4>"| Out-String
    $frag_Code = $fragCode | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"HECI`"><a href=`"#TOP`">Hypervisor Enforced Code Integrity</a></span></h2>" -PostContent "<h4>$descripHyper</h4>" | Out-String
    $frag_PCElevate = $fragPCElevate | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"SoftElevation`"><a href=`"#TOP`">Automatically Elevates User Installing Software</a></span></h2>"  -PostContent "<h4>$descripElev</h4>"| Out-String
    $frag_FilePass = $fragFilePass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"FilePW`"><a href=`"#TOP`">Files that Contain the Word PASSWord</a></span></h2>" -PostContent "<h4>$descripFilePw</h4>" | Out-String
    $frag_AutoLogon = $fragAutoLogon   | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"AutoLogon`"><a href=`"#TOP`">AutoLogon Credentials in Registry</a></span></h2>"  -PostContent "<h4>$descripAutoLogon</h4>"| Out-String
    $frag_UnQu = $fragUnQuoted | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"unquoted`"><a href=`"#TOP`">UnQuoted Paths Attack</a></span></h2>" -PostContent "<h4>$DescripUnquoted</h4>" | Out-String
    $frag_LegNIC = $fragLegNIC | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"LegNetProt`"><a href=`"#TOP`">Legacy and Vulnerable Network Protocols</a></span></h2>" -PostContent "<h4>$DescripLegacyNet</h4>" | Out-String
    $frag_SysRegPerms = $fragReg | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"RegWrite`"><a href=`"#TOP`">Registry Permissions Allowing User Access - Security Risk if Exist</a></span></h2>" -PostContent "<h4>$descripRegPer</h4>" | Out-String
    $frag_PSPass = $fragPSPass | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"ProcPW`"><a href=`"#TOP`">Processes where CommandLine Contains a Password</a></span></h2>" -PostContent "<h4>$Finish</h4>" | Out-String
    $frag_SecOptions = $fragSecOptions | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"secOptions`"><a href=`"#TOP`">Security Options to Prevent MitM Attacks</a></span></h2>" -PostContent "<h4>$descripSecOptions</h4>" | Out-String
    $frag_wFolders = $fragwFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"sysFileWrite `"><a href=`"#TOP`">Non System Folders that are Writeable - Security Risk when Executable</span></a></h2>" -PostContent "<h4>$descripNonFold</h4>"| Out-String
    $frag_SysFolders = $fragsysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"SysDirWrite`"><a href=`"#TOP`">Default System Folders that are Writeable - Security Risk if Exist</span></a></h2>"  -PostContent "<h4>$descripSysFold</h4>"| Out-String
    $frag_CreateSysFold = $fragCreateSysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"sysDirExe`"><a href=`"#TOP`">Default System Folders that Permit Users to Create Files - Security Risk if Exist</a></span></h2>"  -PostContent "<h4>$descripCreateSysFold</h4>"| Out-String
    $frag_wFile = $fragwFile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"sysFileWrite`"><a href=`"#TOP`">System Files that are Writeable - Security Risk if Exist</a></span></h2>" -PostContent "<h4>$descripFile</h4>" | Out-String
    $frag_FWProf = $fragFWProfile | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"FirewallProf`"><a href=`"#TOP`">Firewall Profile</a></span></h2>"  -PostContent "<h4>$DescripFirewalls</h4>"| Out-String
    $frag_FW = $fragFW | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"InFirewall`"><a href=`"#TOP`">Enabled Firewall Rules</a></span></h2>" | Out-String
    $frag_TaskPerms =  $SchedTaskPerms | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"schedDir`"><a href=`"#TOP`">Scheduled Tasks with Scripts Stored on Disk</a></span></h2>"  -PostContent "<h4>$descripTaskSchPerms</h4>" | Out-String
    $frag_TaskListings = $SchedTaskListings | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"schedTask`"><a href=`"#TOP`">Scheduled Tasks that Contain something Encoded</a></span></h2>"  -PostContent "<h4>$descripTaskSchEncode</h4>" | Out-String
    $frag_DriverQuery = $DriverQuery | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"drivers`"><a href=`"#TOP`">Drivers that aren't Signed</a></span></h2>" -PostContent "<h4>$descriptDriverQuery</h4>" | Out-String
    $frag_Share = $fragShare | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"shares`"><a href=`"#TOP`">Shares and their Share Permissions</a></span></h2>"  | Out-String
    $frag_AuthCodeSig = $fragAuthCodeSig | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"AuthentiCode`"><a href=`"#TOP`">Files with an Authenticode Signature HashMisMatch</a></span></h2>" -PostContent "<h4>$descriptAuthCodeSig</h4>"  | Out-String  
    $frag_CredGuCFG = $fragCredGuCFG | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"CredGuard`"><a href=`"#TOP`">Credential Guard</a></span></h2>" -PostContent "<h4>$descripCredGu</h4>" | Out-String
    $frag_LapsPwEna = $fragLapsPwEna | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"LAPS`"><a href=`"#TOP`">LAPS - Local Administrator Password Solution</a></span></h2>" -PostContent "<h4>$descripLAPS</h4>" | Out-String
    $frag_URA = $fragURA | ConvertTo-Html -as Table -Fragment -PreContent "<h2>URA - Local Systems User Rights Assignments</a></span></h2>" -PostContent "<h4>$descripURA</h4>" | Out-String
    $frag_RegPasswords = $fragRegPasswords | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"RegPW`"><a href=`"#TOP`">Passwords Embedded in the Registry</a></span></h2>" -PostContent "<h4>$descripRegPasswords</h4>" | Out-String
    $frag_ASR = $fragASR | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"asr`"><a href=`"#TOP`">Attack Surface Reduction (ASR)</a></span></h2>" -PostContent "<h4>$descripASR</h4>" | Out-String
    $frag_WDigestULC = $fragWDigestULC | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"WDigest`"><a href=`"#TOP`">WDigest</a></span></h2>" -PostContent "<h4>$descripWDigest</h4>" | Out-String
    $frag_Certificates = $fragCertificates | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"Certs`"><a href=`"#TOP`">Installed Certificates</a></span></h2>" -PostContent "<h4>$descripCerts</h4>" | Out-String
    
    $frag_CipherSuit = $fragCipherSuit | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"CipherSuites`"><a href=`"#TOP`">Supported Cipher Suites</a></span></h2>" -PostContent "<h4>$decripCipher</h4>" | Out-String
    
      
    #MS Recommended Secuirty settings (SSLF)
    $frag_WindowsOSVal = $fragWindowsOSVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"WinSSLF`"><a href=`"#TOP`">Windows OS Security Recommendations</a></span></h2>" -PostContent "<h4>$descripWindowsOS</h4>" | Out-String
    $frag_EdgeVal = $fragEdgeVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"EdgeSSLF`"><a href=`"#TOP`">MS Edge Security Recommendations</a></span></h2>" | Out-String
    $frag_OfficeVal = $fragOfficeVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2><a name=`"OfficeSSLF`"><a href=`"#TOP`">MS Office Security Recommendations</a></span></h2>" -PostContent "<h4>$descripOffice2016</h4>" | Out-String
    
    #Quick and dirty tidy up and removal of Frags that are $null
    if ($fragAuthCodeSig -eq $null){$frag_AuthCodeSig = ""}
    if ($fragDLLSafe -eq $null){$frag_DLLSafe = ""}
    if ($fragDLLHijack -eq $null){$frag_DLLHijack = ""}
    if ($fragDllNotSigned -eq $null){$frag_DllNotSigned = ""}
    if ($fragPCElevate-eq $null){$frag_PCElevate= ""}
    if ($fragFilePass-eq $null){$frag_FilePass = ""}
    if ($fragAutoLogon -eq $null){$frag_AutoLogon = ""}
    if ($fragUnQuoted -eq $null){$frag_UnQu = ""}
    if ($fragReg -eq $null){$frag_SysRegPerms = ""}
    if ($fragwFold -eq $null){$frag_SysFolders = ""}
    if ($fragwFile -eq $null){$frag_wFile = ""}
    if ($fragFWProfile -eq $null){$frag_FWProf = ""}
    if ($DriverQuery -eq $null){$frag_DriverQuery = ""}
    if ($SchedTaskPerms -eq $null){$frag_TaskPerms = ""}
    if ($SchedTaskListings -eq $null){$frag_TaskListings = ""}
    if ($InstallApps16  -eq $null){$fragInstaApps16 = ""}
    if ($fragPSPass -eq $null){$frag_PSPass = ""}
    if ($fragRegPasswords -eq $null){$frag_RegPasswords = ""}
    if ($DriverQuery -eq $null){$frag_DriverQuery = ""}
    if ($SchedTaskPerms -eq $null){$frag_TaskPerms = ""}
    if ($fragPSPass -eq $null){$frag_PSPass = ""}
    if ($fragFilePass -eq $null){$frag_FilePass = ""}
    if ($fragRegPasswords -eq $null){$frag_RegPasswords = ""}
    if ($fragDomainGrps -eq $null){$frag_DomainGrps = ""}
    if ($fragDCList -eq $null){$frag_DCList = ""}
    if ($fragFSMO -eq $null){$frag_FSMO = ""}
    if ($fragPreAuth -eq $null){$frag_PreAuth = ""}

################################################
############  CREATE HTML REPORT  ##############
################################################
if ($folders -eq "y")
{
    ConvertTo-Html -Head $style -Body "<h1 align=center style='text-align:center'><span style='color:$titleCol;'>TENAKA.NET</span><h1>", 
    $fragDescrip1, 
    $frag_Summary,
    $frag_host, 
    $fragOS, 
    $fragbios, 
    $fragcpu, 
    $frag_Network4,
    $frag_Network6,
    $frag_Share,
    $FragPassPol,
    $FragAccountDetails,
    $frag_DomainGrps,
    $frag_DCList,
    $frag_FSMO,
    $frag_PreAuth,
    $frag_NeverExpires,
    $FragGroupDetails,
    $frag_whoamiGroups, 
    $frag_whoamiPriv,
    $frag_URA,
    $Frag_WinFeature,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $Frag_AVStatus,
    $frag_UnQu,
    $frag_Msinfo,
    $frag_BitLocker, 
    $Frag_descripVirt2,
    $frag_Code,
    $frag_LSAPPL,
    $frag_WDigestULC,
    $frag_CredGuCFG,
    $frag_kernelModeVal,
    $frag_LapsPwEna,
    $frag_Certificates,
    $frag_CipherSuit,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_DllNotSigned,
    $frag_PCElevate,
    $frag_PSPass,
    $frag_FilePass,
    $frag_RegPasswords,
    $frag_AutoLogon,
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_SysRegPerms,
    $frag_SysFolders,
    $frag_CreateSysFold,
    $frag_wFolders,
    $frag_wFile,
    $frag_DriverQuery,
    $frag_AuthCodeSig,
    $frag_ASR,
    $frag_LegNIC,
    $frag_SecOptions,
    $frag_WindowsOSVal,
    $frag_EdgeVal,
    $frag_OfficeVal,
    $frag_FWProf,
    $frag_FW,
    $FragDescripFin  | out-file $Report
}
else
{
    ConvertTo-Html -Head $style -Body "<h1 align=center style='text-align:center'><span style='color:$titleCol;'>TENAKA.NET</span><h1>", 
    $fragDescrip1, 
    $frag_Summary,
    $frag_host, 
    $fragOS, 
    $fragbios, 
    $fragcpu, 
    $frag_Network4,
    $frag_Network6,
    $frag_Share,
    $FragPassPol,
    $FragAccountDetails,
    $frag_DomainGrps,
    $frag_DCList,
    $frag_FSMO,
    $frag_PreAuth,
    $frag_NeverExpires,
    $FragGroupDetails,
    $frag_whoamiGroups, 
    $frag_whoamiPriv,
    $frag_URA,
    $Frag_WinFeature,
    $fragInstaApps,
    $fragHotFix,
    $fragInstaApps16,
    $Frag_AVStatus,
    $frag_UnQu, 
    $frag_Msinfo,
    $frag_BitLocker, 
    $Frag_descripVirt2,
    $frag_Code,
    $frag_LSAPPL,
    $frag_WDigestULC,
    $frag_CredGuCFG,
    $frag_kernelModeVal,
    $frag_LapsPwEna,
    $frag_Certificates,
    $frag_CipherSuit,
    $frag_DLLSafe,
    $frag_DLLHijack,
    $frag_PCElevate,
    $frag_PSPass,
    $frag_FilePass,
    $frag_RegPasswords,
    $frag_AutoLogon,
    $frag_TaskPerms,
    $frag_TaskListings,
    $frag_DriverQuery,
    $frag_AuthCodeSig,
    $frag_LegNIC,
    $frag_SecOptions,
    $frag_ASR,
    $frag_WindowsOSVal,
    $frag_EdgeVal,
    $frag_OfficeVal,
    $frag_FWProf,
    $frag_FW,
    $FragDescripFin  | out-file $Report
}

    $HostDomain = ((Get-CimInstance -ClassName win32_computersystem).Domain) + "\" 
    $repDate = (Get-Date).Date.ToString("yy-MM-dd").Replace(":","_")

    Get-Content $Report | 
    foreach {$_ -replace "<tr><th>*</th></tr>",""} | 
    foreach {$_ -replace "<tr><td> </td></tr>",""} |

    foreach {$_ -replace "<td>expired","<td><font color=#ff9933>expired"} | 
    foreach {$_ -replace "expired</td>","<font></td>"} |

    foreach {$_ -replace "<td>Selfsigned","<td><font color=#ff9933>selfsigned"} | 
    foreach {$_ -replace "selfsigned</td>","<font></td>"} |

    foreach {$_ -replace "<td>privateKey","<td><font color=#ff9933>privateKey"} | 
    foreach {$_ -replace "privateKey</td>","<font></td>"} |
    
    foreach {$_ -replace "<td>Warning","<td><font color=#ff9933>Warning"} | 
    foreach {$_ -replace "#ff9933>Warning ","#ff9933>"} |
    foreach {$_ -replace "Warning</td>","<font></td>"} |

    foreach {$_ -replace "<td>DefaultGPO","<td><font color=#ffd633>DefaultGPO"} | 
    foreach {$_ -replace "#ffd633>DefaultGPO ","#ffd633>"} |
    foreach {$_ -replace "DefaultGPO</td>","<font></td>"} |

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

    foreach {$_ -replace "<td>SeCreateGlobalPrivilege","<td><font color=#ff9933>SeCreateGlobalPrivilege"} | 
    foreach {$_ -replace "SeCreateGlobalPrivilege</td>","SeCreateGlobalPrivilege<font></td>"}  | 

    foreach {$_ -replace '<td>&lt;div title=','<td><div title="'} | 
    foreach {$_ -replace "&gt;",'">'}  | 
    
    foreach {$_ -replace ">Take ownership of files or other objects </td><td><div",">Take ownership of files or other objects</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Load and unload device drivers </td><td><div",">Load and unload device drivers</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Back up files and directories </td><td><div",">Back up files and directories</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Restore files and directories </td><td><div",">Restore files and directories</td><td><font color=#ff9933><div"}|

    foreach {$_ -replace ">Impersonate a client after authentication </td><td><div",">Impersonate a client after authentication</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Create global objects </td><td><div",">Create global objects</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Replace a process level token</td><td><div",">Replace a process level token</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Debug programs</td><td><div",">Debug programs</td><td><font color=#ff9933><div"} |
    foreach {$_ -replace ">Debug programs </td><td><div",">Debug programs</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace ">Access this computer from the network </td><td><div",">Access this computer from the network</td><td><font color=#ff9933><div"} |

    foreach {$_ -replace "<td>Very High Risk","<td><font color=#e60000>Very High Risk"} | 
    foreach {$_ -replace "<td>High Risk","<td><font color=#ff471a>High Risk"} | 
    foreach {$_ -replace "<td>Medium to High Risk","<td><font color=#ff751a>Medium to High Risk"} | 
    foreach {$_ -replace "<td>Medium Risk","<td><font color=#ffb366>Medium Risk"} | 
    foreach {$_ -replace "<td>Low to Medium Risk","<td><font color=#a6ff4d>Low to Medium Risk"} | 
    foreach {$_ -replace "<td>Low Risk","<td><font color=#ffff66>Low Risk"} | 
    foreach {$_ -replace "<td>Informational","<td><font color=#80ff80>Informational"} | 

    foreach {$_ -replace '&lt;a href=&quot;','<a href="'} | 
    foreach {$_ -replace '&lt;/a">','</a>'} |
    foreach {$_ -replace '&quot;">','">'} |

    foreach {$_ -replace 'Warning ',''} |
    foreach {$_ -replace 'expired - ',''} |
    foreach {$_ -replace 'selfsigned - ',''} |
    foreach {$_ -replace 'privateKey - ',''} |
           
    Set-Content "C:\SecureReport\$($repDate)-$($env:COMPUTERNAME)-Report.htm" -Force
    
    invoke-item 'C:\SecureReport'   

    }
}
reports

<#
Stuff to Fix.....


$ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage"
Null message warning that security is missing
set warning for secure boot
Expand on explanations - currently of use to non-techies

remove extra blanks when listing progs via registry 

Stuff to Audit.....

Proxy password reg key

FLTMC.exe - mini driver altitude looking for 'stuff' thats at an altitude to bypass security or encryption
report on appX bypass and seriousSam
Remote desktop and permissions
look for %COMSPEC%
snmp

data streams dir /r
Get-Item   -Stream * | where {$_.stream -notmatch "$DATA"}

netstat -ano
Find network neighbours and accessible shares
dated or old drivers
wifi passwords
    netsh wlan show profile
    netsh wlan show profile name="wifi name" key=clear

credential manager
    %Systemdrive%\Users\<Username>\AppData\Local\Microsoft\Credentials
    cmdkey /list 
powershell passwords, history, transcript, creds
Services and svc accounts
GPO and GPP's that apply
Browser security
DNS
Auditing Wec\wef - remote collection point
Interesting events
wevtutil "Microsoft-Windows-Wcmsvc/Operational"
Add Applocker audit
Add WDAC audit
File hash database
Performance tweaks audit client and hyper v
warn on stuff thats older than 6 months - apps, updates etc
Warn Bios\uefi version and date


remove powershell commands where performance is an issue, consider replacing with cmd alts

####GPO Settings as recommended by MS####

UAC
networks
Updates

Audit Settings - ms rec

Chrome GPOs
Add further MS Edge GPO checks

Report on Windows defender and memory protections

Allign look and feel for all Reg and gpo queries inc mouse over effect

Stuff that wont get fixed.....
Progress bars or screen output will remain limited, each time an output is written to screen the performance degrads


#>

