﻿<#
Tenaka.net

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
  
.Versioning has been move to the end of the script

#>


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

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
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Working Directory C:\SecureReport
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    #Enable detection of PowerShell or ISE, enable to run from both
    #Script name has been defined and must be saved as that name.
    $secureReport = "C:\SecureReport"
    $secureReporOutPut = "$($secureReport)\output\"
    $secureReportError = "$($secureReporOutPut)\Errorlog.log" 
    
    $ptRand = Get-Random -Minimum 100 -Maximum 999
    $tpSecRrpt = test-path $secureReport
        if ($tpSecRrpt -eq $true)
            {
                Rename-Item $secureReport -NewName "$secureReport$($ptRand)" -Force
                New-Item -Path $secureReport -ItemType Directory -Force
                #New-Item -path $secureReportLog -ItemType File -Force
                New-Item -path $secureReportError -ItemType File -Force
            }
        else
            {
                New-Item -Path $secureReport -ItemType Directory -Force
                #New-Item -path $secureReportLog -ItemType File -Force
                New-Item -path $secureReportError -ItemType File -Force
            }

    #Current working path
        if($psise -ne $null)
            {
                $ISEPath = $psise.CurrentFile.FullPath
                $ISEDisp = $psise.CurrentFile.DisplayName.Replace("*","")
                $pwdPath = $ISEPath.TrimEnd("$ISEDisp")
            }
        else
            {
                $pwdPath = split-path -parent $MyInvocation.MyCommand.Path
            }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   Functions
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    function SecureReportError
        {
            Write-Host "$($SecCheck)" -foregroundColor yellow
            Write-Host "$($SecErrorComment)" -ForegroundColor Cyan
            if ([string]::IsNullorEmpty($exceptionMessage) -ne "$true")
                {
                    Add-Content -Path $secureReportError -value $SecCheck
                    Add-Content -Path $secureReportError -value "     Error: $exceptionMessage"
                    Write-Host "Error: $exceptionMessage" -ForegroundColor Cyan
                }

            if ([string]::IsNullorEmpty($exceptionCMD) -ne "$true")
                {
                    Add-Content -Path $secureReportError -value $exceptionCMD
                    Add-Content -Path $secureReportError -value "     Error: $exceptionCMD"
                    write-Host $exceptionCMD -ForegroundColor Cyan   
                }          
        }

    function TestConfigOutputPath
        {
            try
                {
                    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
                    Get-Item -path $SecureReportConfig -ErrorAction Stop                
                }
            catch
                {
                    New-Item -Path $SecureReportConfig -ItemType Directory -Force
                }           
        }
    
    function splatVariables
        {
           $SecCheck=@()
           $exceptionMessage=@() 
           $exceptionCMD=@()
           $fragSQLSvc=@()
           $fragCISSQL=@() 
        }

    function splatAutoRunsVar
        {
            $hkuRunComment=@()
            $hkuRunPath=@()
            $hkuRunItem=@()
            $gthkuRunValue=@()
            $tphkuRunPath=@()
        }

    function splatSQLChecks
        {
            $SQLCIS_Title=@() 
            $SQLCIS_Check=@()
            $SQLCIS_Secure=@()
            $SQLCIS_res=@()
            $SQLCIS_Config=@()
            $SQLCIS_InUse=@()        
        }
    
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Audit Functions and Tests
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    $psver4 = $psversiontable.PSVersion 
    if ($psver4 -le "4.0")
    {
        write-host " " 
        Write-Host "PowerShell version 4 is installed (Windows8.1\Server 2012 R2), the Get-ChildItem -Depth is not supported, don't waste your time selecting audit Files, Folders and Registry for permissions issues" -ForegroundColor Red
        write-host " "
    }

        #Start Message
        Write-Host " "
        Write-warning "The report requires at least 20 minutes to run, depending on hardware and amount of data on the system, it could take much longer"
        Write-Host " "
        Write-Warning "READ ME - To audit for Dll Hijacking vulnerabilities applications and services must be active, launch programs before continuing." 
        Write-Host " "

        $folders = Read-Host "Long running audit - Do you want to audit Files, Folders and Registry for permissions issues....type `"Y`" to audit, any other key for no"

        if ($folders -eq "Y") {$depth = Read-Host "What depth do you wish the folders to be auditied, the higher the number the slower the audit, the default is 2, recommended is 4"}
        write-host " "
        $embeddedpw = Read-Host "Some systems whilst retrieving passwords from within files crash PowerShell....type `"Y`" to audit, any other key for no"
        write-host " "
        $authenticode = Read-Host "Long running audit - Do you want to check that digitally signed files are valid with a trusted hash....type `"Y`" to audit, any other key for no"

        #Summary Frag
        $fragSummary=@()
        #Queries
        $gtCIM_OS = (Get-CimInstance -ClassName win32_operatingsystem | Select-Object caption).caption

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  MDT Buid Details
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables    
    $SecCheck = "Auditing MDT Task Sequence"
    $fragMDTBuild =@()
        try 
            {        
                $mdtBuild = gwmi -Class microsoft_BDD_info -ErrorAction stop
                    $mdtID =  $mdtBuild.TaskSequenceID 
                    $mdtTS = $mdtBuild.TaskSequenceName
                    $mdtVer = $mdtBuild.TaskSequenceVersion
                    $mdtDate = $mdtBuild.DeploymentTimestamp.Split(".")[0] 
                    $mdtActDate = [datetime]::ParseExact($mdtDate,'yyyyMMddHHmmss', $null)

                $newObjMDTBuild = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjMDTBuild -Type NoteProperty -Name TaskSequenceID -Value $mdtID
                    Add-Member -InputObject $newObjMDTBuild -Type NoteProperty -Name TaskSequenceName -Value $mdtTS
                    Add-Member -InputObject $newObjMDTBuild -Type NoteProperty -Name TaskSequenceVersion -Value $mdtVer
                    Add-Member -InputObject $newObjMDTBuild -Type NoteProperty -Name DeploymentTime -Value $mdtActDate
                $fragMDTBuild += $newObjMDTBuild
                $fragMDTBuild | Out-File "$($secureReporOutPut)\MDTBuild.log"
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage) 
                
                $mdtID = "Client not deployed by MDT"
                $newObjMDTBuild = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjMDTBuild -Type NoteProperty -Name TaskSequenceID -Value $mdtID
                $fragMDTBuild += $newObjMDTBuild
                $fragMDTBuild | Out-File "$($secureReporOutPut)\MDTBuild.log"       
            }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          BITLOCKER
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Bitlocker"

        #Bitlocker Details
        $fragBitLocker=@()
        try
            {
                $GetTPM = Get-Tpm -ErrorAction stop
                $getBit = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop | Select-Object * 
            
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

                        $fragBitLocker | Out-File "$($secureReporOutPut)\Bitlocker.log"
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
           
                $BitDisabled = "Warning Bitlocker is disabled Warning"
                $newObjBit = New-Object psObject
                    Add-Member -InputObject $newObjBit -Type NoteProperty -Name BitLockerDisabled -Value $BitDisabled
                $fragBitLocker += $newObjBit               
                $fragBitLocker | Out-File "$($secureReporOutPut)\Bitlocker.log"                   
            }
    
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          OS Details
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Gathering Host and Account Details"
    $exceptionMessage="No errors gathered"
    SecureReportError($SecCheck,$exceptionMessage)

    #OS Details
    $fragHost = Get-CimInstance -ClassName win32_computersystem -ErrorAction SilentlyContinue
    $OS = Get-CimInstance -ClassName win32_operatingsystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName win32_bios  -ErrorAction SilentlyContinue | Select-Object Name,Manufacturer,SerialNumber,SMBIOSBIOSVersion,ReleaseDate
    $cpu = Get-CimInstance -ClassName win32_processor -ErrorAction SilentlyContinue

    $fragPatchversion=@()
    #$OSBuildNumber = (Get-ItemProperty HKLM:\system\Software\Microsoft\BuildLayers\OSClient).buildnumber
    #$OSPatchNumber = (Get-ItemProperty HKLM:\system\Software\Microsoft\BuildLayers\OSClient).BuildQfe
    [string]$OSPatchversion = & cmd.exe /c ver.exe
    $OSPatchverSpace = [string]$OSPatchversion.Replace(" Microsoft","Microsoft")

    $newObjPatchversion = New-Object -TypeName PSObject
        Add-Member -InputObject $newObjPatchversion -Type NoteProperty -Name WindowsPatchVersion -Value $OSPatchverSpace
    $fragPatchversion += $newObjPatchversion

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
    $BiosUEFI | Out-File "$($secureReporOutPut)\OSHostDetails.log" 

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Password Policy
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Password Policy"
    $exceptionMessage="No errors gathered"
    SecureReportError($SecCheck,$exceptionMessage)

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
            $PassPol | Out-File "$($secureReporOutPut)\AccountDetails.log" 
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Local Accounts
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Local Accounts"
    $exceptionMessage="No errors gathered"
    SecureReportError($SecCheck,$exceptionMessage)

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
        $AccountDetails | Out-File "$($secureReporOutPut)\AccountDetails.log" -Append
    }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
              Members of Built-in and Local Groups
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Local Group Members"
    $exceptionMessage="No errors gathered"
    SecureReportError($SecCheck,$exceptionMessage)

    $getLGrp = Get-LocalGroup 
    $GroupDetails=@()
    foreach ($LGpItem in $getLGrp)
    {
        $grpName = $LGpItem.Name 
        $grpMember = Get-LocalGroupMember -Group $LGpItem.ToString() -ErrorAction SilentlyContinue
        $groupMemberA=@()
        $groupMemberString=@()
        #Members of Group
        foreach ($grpMemberitem in $grpMember)
            {
                $groupMemberA += ("$($grpMemberitem.name),")
                $groupMemberString = [string]$groupMemberA
            }
           if ([string]::IsNullOrWhiteSpace($groupMemberString) -eq $true){$groupMemberString = "No Group Members"}

            $newObjGroup = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjGroup -Type NoteProperty -Name GroupName -Value $grpName
                Add-Member -InputObject $newObjGroup -Type NoteProperty -Name GroupMembers -Value $groupMemberString.TrimEnd(",")
            $GroupDetails += $newObjGroup 
            $GroupDetails | Out-File "$($secureReporOutPut)\AccountDetails.log" -Append
       }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
   Reports on the credentials of the user running this report
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Current User Privs"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "DomainUser" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $WinFeaturePathtxt = "$($SecureReportConfig)\$($OutConfigDir).txt"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    $HostDomain = ((Get-CimInstance -ClassName win32_computersystem -ErrorAction SilentlyContinue).Domain).split(".")[0] + "\" 

    $DomA = $HostDomain + "Domain Admins"
    $DomAWarn = "Warning " + $HostDomain + "Domain Admins" + "  Warning"

    $EntA = $HostDomain + "Enterprise Admins"
    $EntAWarn = "Warning " + $HostDomain + "Enterprise Admins" + "  Warning"

    $SchA = $HostDomain + "Schema Admins"
    $SchAWarn = "Warning " + $HostDomain + "Schema Admins" + "  Warning"

    #WHOAMI /User /FO CSV /NH > C:\SecureReport\output\DomainUser\User.csv
    WHOAMI /Groups /FO CSV /NH > "$($SecureReportConfig)\Groups.csv"
    WHOAMI /Priv /FO CSV /NH > "$($SecureReportConfig)\Priv.csv"

        try #parse Groups and tidy plus warn if the current user has Pri Groups
            {
                (Get-Content -ErrorAction Stop "$($SecureReportConfig)\Groups.csv") `
                    -replace("Mandatory group,","")    `
                    -replace("Enabled by default,","") `
                    -replace("Enabled group,","")      `
                    -replace("Enabled group","")       `
                    -replace("Group owner","")         `
                    -replace(',"Attributes"',"")       `
                    -replace(',"  "',"") -replace(',""',"") `
                    -replace($EntA,$EntAWarn)          `
                    -replace($DomA,$DomAWarn)          `
                    -replace($SchA,$SchAWarn) | 
                    Out-File "$($SecureReportConfig)\Groups.csv" -ErrorAction Stop
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)    
            }

        try #parse for privs aka User Rights
            {                    
                (Get-Content -ErrorAction Stop "$($SecureReportConfig)\Priv.csv") -replace("Enabled","Review - Enabled Review") | 
                    Out-File "$($SecureReportConfig)\Priv.csv" -ErrorAction Stop       
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #Export csv and re-import as CliXML
        try 
            {
                import-csv "$($SecureReportConfig)\Groups.csv" -Delimiter "," -ErrorAction Stop | Export-Clixml "$($SecureReportConfig)\Groups.xml" -ErrorAction Stop
                $whoamiGroups = Import-Clixml "$($SecureReportConfig)\Groups.xml" -ErrorAction Stop
             }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        try 
            {
                import-csv "$($SecureReportConfig)\Priv.csv" -Delimiter "," -ErrorAction Stop | Export-Clixml "$($SecureReportConfig)\Priv.xml" -ErrorAction Stop
                $whoamiPriv = Import-Clixml "$($SecureReportConfig)\Priv.xml" -ErrorAction Stop
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }
 
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   List Domain Controllers
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Domain Controllers" 
    $exceptionMessage=""

    $fragDCList=@()
    try 
        {
            [string]$queryDC = & netdom /query dc

            $dcListQuery = $queryDC.Replace("The command completed successfully.","").Replace("List of domain controllers with accounts in the domain:","").Replace(" ",",").replace(",,","")
            $fqdn = ((Get-CimInstance -ClassName win32_computersystem  -ErrorAction SilentlyContinue).Domain) + "."
            $dcList = $dcListQuery.split(",") | sort 

                foreach ($dcs in $dcList)
                {
                    $dcfqdn = $dcs + "." + $fqdn
                    $newObjDCList = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjDCList -Type NoteProperty -Name DCList -Value $dcfqdn
                    $fragDCList += $newObjDCList
                    $fragDCList | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                     FSMO Roles
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing FSMO Roles"
    $exceptionMessage=""

    try
        {
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
            $fragFSMO | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append                
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   Domain Priv Gropus
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Domain Privilege Groups"
    $exceptionMessage="No errors gathered"
    SecureReportError($SecCheck,$exceptionMessage)
    try
        {
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
                            $fragDomainGrps  | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append                    
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
                                $fragDomainGrps | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append  
                            }
            }
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
           Domain Accounts that DON'T Pre-Authenticate
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Domain Accounts that dont Pre-Authenticate"
    $exceptionMessage=""

    try
        {
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
                    $fragPreAuth  | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   Domain Priv Gropus
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Domain Accounts that Dont Expire" 
    $exceptionMessage="No errors gathered"

    try
        {
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
                    $fragNeverExpires  | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                   Service Principal Names (SPNs)
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Service Principal Names (SPNs)"
    $exceptionMessage="No errors gathered"
    #list all spns
    try
        {    
            $gtUserSPNList = Get-ADUser -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select SamAccountName, ServicePrincipalName
            $fragListUserSPNs=@()
            foreach ($ListUserSPNs in $gtUserSPNList)
                {
                    $ListUserSPNsName = $ListUserSPNs.samaccountName
                    $ListUserSPNsUPN = [string]$ListUserSPNs.ServicePrincipalName

                    $newObjListUserSPNs = New-Object psObject
                        Add-Member -InputObject $newObjListUserSPNs -Type NoteProperty -Name SamAccountName -Value $ListUserSPNsName
                        Add-Member -InputObject $newObjListUserSPNs -Type NoteProperty -Name ServicePrincipalName -Value $ListUserSPNsUPN
                    $fragListUserSPNs += $newObjListUserSPNs
                    $fragListUserSPNs | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
            }
    catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    #list all computer spn - loop spn and split 
    try
        {                   
                $gtComputerSPN = Get-ADComputer -Filter { ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | select DNSHostname, ServicePrincipalName
                $fragListComputerSPNs=@()
                foreach ($ListComputerSPNs in $gtComputerSPN)
                    {
                        $ListComputerSPNsName = $ListComputerSPNs.DNSHostname
                        $ListComputerSPNsUPN = [string]$ListComputerSPNs.ServicePrincipalName

                        $newObjListComputerSPNs = New-Object psObject
                            Add-Member -InputObject $newObjListComputerSPNs -Type NoteProperty -Name Hostname -Value $ListComputerSPNsName
                            Add-Member -InputObject $newObjListComputerSPNs -Type NoteProperty -Name ServicePrincipalName -Value $ListComputerSPNsUPN
                        $fragListComputerSPNs += $newObjListComputerSPNs
                        $fragListComputerSPNs | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                    }                
            }
    catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    #Accounts unconstrained delegation eg Admins that can delegate and their services
    try
        {     
            $gtUserTrusted4Delegate = Get-ADUser -filter {TrustedForDelegation -eq $true} -Properties Name,DistinguishedName,UserPrincipalName,TrustedForDelegation
            $fragTrusted4Delegate=@()
            foreach ($Trusted4Delegate in $gtUserTrusted4Delegate)
                {
                    $allowDelegateName = $Trusted4Delegate.Name
                    $allowDelegateDN = $Trusted4Delegate.DistinguishedName
                    $allowDelegateUPN = $Trusted4Delegate.UserPrincipalName
                    $allowDelegateTo = [string]$Trusted4Delegate.TrustedForDelegation

                    $newObjTrusted4Delegate = New-Object psObject
                        Add-Member -InputObject $newObjTrusted4Delegate -Type NoteProperty -Name Name -Value "Warning $($allowDelegateName) Warning"
                        Add-Member -InputObject $newObjTrusted4Delegate -Type NoteProperty -Name DistinguishedName -Value "Warning $($allowDelegateDN) Warning"
                        Add-Member -InputObject $newObjTrusted4Delegate -Type NoteProperty -Name UserPrincipalName -Value "Warning $($allowDelegateUPN) Warning"
                        Add-Member -InputObject $newObjTrusted4Delegate -Type NoteProperty -Name Trusted4Delegateto -Value "Warning $($allowDelegateTo) Warning"
                    $fragTrusted4Delegate += $newObjTrusted4Delegate 
                    $fragTrusted4Delegate | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
            }
    catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    #Accounts constrained delegation eg Admins that can delegate and their services
    try
        {    
            $gtUserAllowed2Delegate = Get-ADUser -filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties * 
            $fragAllowed2Delegate=@()
            foreach ($Allowed2Delegate in $gtUserAllowed2Delegate)
                {
                    $allowDelegateName = $Allowed2Delegate.Name
                    $allowDelegateDN = $Allowed2Delegate.DistinguishedName
                    $allowDelegateUPN = $Allowed2Delegate.UserPrincipalName
                    $allowDelegateTo = [string]$Allowed2Delegate.'msDS-AllowedToDelegateTo'

                    $newObjAllowed2Delegate = New-Object psObject
                        Add-Member -InputObject $newObjAllowed2Delegate -Type NoteProperty -Name Name -Value "Warning $($allowDelegateName) Warning"
                        Add-Member -InputObject $newObjAllowed2Delegate -Type NoteProperty -Name DistinguishedName -Value "Warning $($allowDelegateDN) Warning"
                        Add-Member -InputObject $newObjAllowed2Delegate -Type NoteProperty -Name UserPrincipalName -Value "Warning $($allowDelegateUPN) Warning"
                        Add-Member -InputObject $newObjAllowed2Delegate -Type NoteProperty -Name Allowed2Delegateto -Value "Warning $($allowDelegateTo) Warning"
                    $fragAllowed2Delegate += $newObjAllowed2Delegate 
                    $fragAllowed2Delegate | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
            }
    catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    #Computers UnConstrained delegation
    try
        {    
            $gtUnConstrained = Get-ADComputer -filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation, TrustedToAuthForDelegation,msDS-AllowedToActOnBehalfOfOtherIdentity,msDS-AllowedToDelegateTo,PrincipalsAllowedToDelegateToAccount,serviceprincipalname 
            $fragUnConstrained=@()
            foreach ($UnConstrained in $gtUnConstrained)
                {
                    $unconstrainDN = $UnConstrained.DistinguishedName
                    $unconstrainSPN = [string]$UnConstrained.serviceprincipalname
                    $unconstrainTrusted = $UnConstrained.TrustedForDelegation 

                    if ($unconstrainDN -notmatch "OU=Domain Controllers"){$unconstrainDN = "Warning $($unconstrainDN) Warning" }else{$unconstrainDN = $unconstrainDN}

                    $newObjUnConstrained = New-Object psObject
                        Add-Member -InputObject $newObjUnConstrained -Type NoteProperty -Name DN -Value $unconstrainDN
                        Add-Member -InputObject $newObjUnConstrained -Type NoteProperty -Name SPN -Value $unconstrainSPN
                        Add-Member -InputObject $newObjUnConstrained -Type NoteProperty -Name TrustedForDelegation -Value $unconstrainTrusted
                    $fragUnConstrained += $newObjUnConstrained
                    $fragUnConstrained | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }
            }
    catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    #Computers constained delegation            
    try
        {  
            $gtConstrained = Get-ADComputer -filter {TrustedToAuthForDelegation -eq $true} -Property TrustedForDelegation, TrustedToAuthForDelegation,msDS-AllowedToActOnBehalfOfOtherIdentity,msDS-AllowedToDelegateTo,PrincipalsAllowedToDelegateToAccount,serviceprincipalname 
            $fragConstrained=@()
            foreach ($Constrained in $gtConstrained)
                {
                    $constrainDN = $Constrained.DistinguishedName
                    $constrainSPN = [string]$Constrained.serviceprincipalname
                    $constrainTrusted = $Constrained.TrustedToAuthForDelegation

                    $newObjConstrained = New-Object psObject
                        Add-Member -InputObject $newObjConstrained -Type NoteProperty -Name DN -Value $constrainDN
                        Add-Member -InputObject $newObjConstrained -Type NoteProperty -Name SPN -Value $constrainSPN
                        Add-Member -InputObject $newObjConstrained -Type NoteProperty -Name TrustedToAuthForDelegation -Value $constrainTrusted
                    $fragConstrained += $newObjConstrained
                    $fragConstrained | Out-File "$($secureReporOutPut)\DomainDetails.log" -Append 
                }

         }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          User Rights Assignments (URA)
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "User Rights Assignments (URA)"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "URA"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    $secEditPath = "$($SecureReportConfig)\$OutFunc.Inf"
    $secEditOutPath = "$($SecureReportConfig)\URAOut.txt"
    $secEditImpPath = "$($SecureReportConfig)\URAImport.txt"
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
            $uraItem = $uraLine.ToString().split(",").split("=").replace("*","").replace(" ","") #.replace(",","")
            #write-host $uraItem -ForegroundColor Yellow

            foreach ($uralookupName in $URALookup.Values)
                {
                    $uraItemTrim = $uraItem[0].trim()
                    $uralookupTrim = $uralookupName.trim()[0]

                        if ($uralookuptrim -eq $uraItemTrim)
                            {
                               try
                                   {
                                       $uraDescripName = $uralookupName.trim()[1].split("|")[0]
                                       $uraMSRecom = $uralookupName[1].split("|")[1].trim()
                                       $URAGPOPath = $URACommonPath + $uraDescripName
                                   }catch{}

                               Add-Content $secEditOutPath -Value " " -encoding UTF8

                               $uraDescripName + " " + "`(" +$uraItem.trim()[0] +"`)" | Out-File $secEditOutPath -Append -encoding UTF8
                               $uraDescripName = "<div title=$uraMSRecom>$uraDescripName"

                               $uraTrimDescrip = "<div title=$URAGPOPath>$uraItemTrim"
                            }
                    }
           $uraItemTrimStart = ($uraItem | where {$_ -ne "$uraItemTrim"}).replace(",","")

           $objSid=@()
     
           Set-Content -Path $secEditImpPath -Value " "
           $NameURA=@()
           foreach($uraSidItems in $uraItemTrimStart)
               {
                    if ($uraSidItems -match "S-1-")
                        {
                            $objSid = New-Object System.Security.Principal.SecurityIdentifier("$uraSidItems")
                            $objUserName = $objSID.Translate([System.Security.Principal.NTAccount])  
                            "   " + $objUserName.Value  | Out-File $secEditOutPath -Append  -encoding UTF8  
                            [string]$NameURA += $objUserName.Value + ", "
                        }
                    else
                        {
                            $objUserName = $uraSidItems
                            "   " + $objUserName | Out-File $secEditOutPath -Append  -encoding UTF8 
                            [string]$NameURA += $objUserName + ", "   
                        }                                       
               }
            
            $newObjURA = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Name -Value $uraDescripName
                Add-Member -InputObject $newObjURA -Type NoteProperty -Name UserRightAssignment-Priv -Value $uraTrimDescrip
                Add-Member -InputObject $newObjURA -Type NoteProperty -Name URA-GroupName -Value $NameURA
            $fragURA += $newObjURA
        }
    
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                         Windows Updates
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Windows Updates"
    $exceptionMessage="No errors gathered"

    $date180days = (Get-Date).AddDays(-180).toString("yyyyMMdd")
    try
        {
            $HotFix=@()
            $getHF = Get-HotFix -ErrorAction Stop  | Select-Object HotFixID,InstalledOn,Caption 

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
                    $HotFix | Out-File "$($secureReporOutPut)\WindowsUpdates.log" -Append 
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Installed Applications
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Installed Applications"
    $exceptionMessage="No errors gathered"

    try
        {
            $getUninx64 = Get-ChildItem  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction Stop
            $getUninx86 = Get-ChildItem  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"  -ErrorAction Stop
                $getUnin = $getUninx64 + $getUninx86
                $UninChild = $getUnin.Name.Replace("HKEY_LOCAL_MACHINE","HKLM:")
                $InstallApps =@()
                $date180days = (Get-Date).AddDays(-180).toString("yyyyMMdd")
    
            foreach ($uninItem in  $UninChild)
            {
                $getUninItem = Get-ItemProperty $uninItem -ErrorAction Stop | where {$_.displayname -notlike "*kb*"}  
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
                $InstallApps | Out-File "$($secureReporOutPut)\InstalledApplications.log" -Append 
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
  
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Installed Applications kbs
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Installed Applications KB's"
    $exceptionMessage="No errors gathered"
        #MS are making a bit of a mess of updates, get-hotfix only returns the latest 10 installed
        #Office 2019 onwards doesnt register installed KB's
        #But for Office 2016 and older installed KB's do create keys in the Uninstall 
    try
        {
            $getUnin16 = Get-ChildItem  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction Stop
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
                $InstallApps16 | Out-File "$($secureReporOutPut)\InstalledApplications.log" -Append 
            }    
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
       
 
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Installed Winodws Features
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Windows Features"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "WindowsFeatures" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $WinFeaturePathtxt = "$($SecureReportConfig)\$($OutConfigDir).txt"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)
    
    $FragWinFeature=@()
    try
        {
            $getWindows = Get-CimInstance win32_operatingsystem -ErrorAction Stop | Select-Object caption
                if ($getWindows.caption -notlike "*Server*")
                    {
                    Dism /online /Get-Features >> $WinFeaturePathtxt
                    $getdismCont = (Get-Content $WinFeaturePathtxt -ErrorAction Stop | 
                        Select-String enabled -Context 1) -replace("  Feature Name : ","") -replace("> State : ",",") | Sort-Object 
   
                        foreach ($dismItem in $getdismCont)
                            {
                                $dismSplit = $dismItem.split(",")
                                $dismSplit[0]
                                $dismSplit[1]

                                $newObjWinFeature = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name WindowsFeature -Value $dismSplit[0]
                                    Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name InstallState -Value $dismSplit[1]
                                $FragWinFeature += $newObjWinFeature
                                $FragWinFeature | Out-File "$($secureReporOutPut)\InstalledApplications.log" -Append
                            }
                    }

                if($getdismCont -eq $null)
                    {           
                        $getWindows  = Get-WindowsOptionalFeature -online -ErrorAction Stop | where {$_.state -eq "enabled"}
                            foreach($feature in $getWindows)
                                {
                                    $featureName = $feature.featurename
                                    $featureState = $feature.state

                                    $newObjWinFeature = New-Object -TypeName PSObject
                                        Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name WindowsFeature -Value $featureName
                                        Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name InstallState -Value $featureState
                                    $FragWinFeature += $newObjWinFeature   
                                    $FragWinFeature | Out-File "$($secureReporOutPut)\InstalledWindowsFeatures.log" -Append     
                                }
                    }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Installed Appx Packages
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing AppX Packages"
    $exceptionMessage="No errors gathered"            
            
    $FragAppx=@()
    try
        {
            $gtAppxPackage  = Get-AppxPackage -ErrorAction Stop
                foreach($AppxPackageItem in $gtAppxPackage)
                    {
                        $appxName = $AppxPackageItem.name
                        $appxStatus = $AppxPackageItem.status

                        $newObjWinAppx = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjWinAppx -Type NoteProperty -Name WindowsFeature -Value $appxName
                            Add-Member -InputObject $newObjWinAppx -Type NoteProperty -Name InstallState -Value $appxStatus
                        $FragAppx += $newObjWinAppx 
                        $FragAppx | Out-File "$($secureReporOutPut)\InstalledWindowsFeatures.log" -Append       
                    }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
               Server - Installed Winodws Features
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Server Windows Features"
    $exceptionMessage="No errors gathered"

    $FragSrvWinFeature=@()
    try
        {
            if($getWindows.caption -like "*Server*")
                {
                $WinFeature = Get-WindowsFeature -ErrorAction Stop | where {$_.installed -eq "installed"} | Sort-Object name
                foreach ($featureItem in $WinFeature)
                    {
                        $newObjSrvWinFeature = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjSrvWinFeature -Type NoteProperty -Name WindowsSrvFeature -Value $featureItem.DisplayName 
                        #Add-Member -InputObject $newObjWinFeature -Type NoteProperty -Name InstallState -Value $featureItem.Installed
                        $FragSrvWinFeature += $newObjSrvWinFeature
                        $FragSrvWinFeature | Out-File "$($secureReporOutPut)\InstalledWindowsServerFeatures.log" -Append  
                    }
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                       Antivirus
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Antivirus"
    $exceptionMessage="No errors gathered"

    #https://stackoverflow.com/questions/33649043/powershell-how-to-get-antivirus-product-details - "borrowed" baulk of script from site
    try
        {
            #$AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  
            $AntiVirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop

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
                                $FragAVStatus | Out-File "$($secureReporOutPut)\Antivirus.log" -Append 

                        }
                }
            Else  #server and Defender cant be detected
                {
                    $newObjAVStatus = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVName -Value "Warning Antivirus cant be detected, assume the worst and its not installed warning"
                    $FragAVStatus += $newObjAVStatus
                    $FragAVStatus | Out-File "$($secureReporOutPut)\Antivirus.log" -Append 
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage) 
            
            $newObjAVStatus=@()
            $FragAVStatus=@()
            $newObjAVStatus = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjAVStatus -Type NoteProperty -Name AVName -Value "Warning Antivirus cant be detected, assume the worst and its not installed warning"
            $FragAVStatus += $newObjAVStatus       
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  UnQuoted Path Vulnerabilities
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Searching for UnQuoted Path Vulnerabilities"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "UnQuoted" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $UnQuotedPathLog = "$($SecureReportConfig)\$($OutConfigDir).log"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    #Unquoted paths
    $vulnSvc = Get-CimInstance win32_service  -ErrorAction SilentlyContinue | foreach{$_} | 
    where {($_.pathname -ne $null) -and ($_.pathname.trim() -ne "")} | 
    where {-not $_.pathname.startswith("`"")} |
    where {($_.pathname.substring(0, $_.pathname.indexof(".sys") + 4 )) -match ".* .*" -or ($_.pathname.substring(0, $_.pathname.indexof(".exe") + 4 ))  -match ".* .*" -or ($_.pathname.substring(0, $_.pathname.indexof(".SYS") + 4 )) -match ".* .*" -or ($_.pathname.substring(0, $_.pathname.indexof(".EXE") + 4 ))  -match ".* .*"}

    $fragUnQuoted=@()
    try
        {    
            foreach ($unQSvc in $vulnSvc)
                {
                    $svc = $unQSvc.name
                    $SvcReg = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\$svc -ErrorAction Stop
    
                        if ($SvcReg.imagePath -like "*.exe*")
                        {
                            $SvcRegSp =  $SvcReg.imagePath -split ".exe"
                            $SvcRegSp0 = $SvcRegSp[0]
                            $SvcRegSp1 = $SvcRegSp[1]
                            $image = "`"$SvcRegSp0" + ".exe`""+  " " + $SvcRegSp1
                            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $UnQuotedPathLog -Append -ErrorAction Stop
                
                            $newObjSvc = New-Object psObject
                                Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning $($SvcReg.PSChildName) warning"
                                Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning $($SvcReg.ImagePath) warning"
                            $fragUnQuoted += $newObjSvc
                            $fragUnQuoted | Out-File "$($secureReporOutPut)\UnQuoted.log" -Append 
                        }
    
                        if ($SvcReg.imagePath -like "*.sys*")
                        {
                            $SvcRegSp =  $SvcReg.imagePath -split ".sys"
                            $SvcRegSp0 = $SvcRegSp[0]
                            $SvcRegSp1 = $SvcRegSp[1]
                            $image = "`"$SvcRegSp0" + ".sys`""+   " $SvcRegSp1"
                            $SvcReg |Select-Object PSChildName,ImagePath  | out-file $UnQuotedPathLog -Append -ErrorAction Stop
                       
                            $newObjSvc = New-Object psObject
                                Add-Member -InputObject $newObjSvc -Type NoteProperty -Name ServiceName -Value "Warning $($SvcReg.PSChildName) warning"
                                Add-Member -InputObject $newObjSvc -Type NoteProperty -Name Path -Value "Warning $($SvcReg.ImagePath) warning"
                            $fragUnQuoted += $newObjSvc
                            $fragUnQuoted | Out-File "$($secureReporOutPut)\UnQuoted.log" -Append 
                        }
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      MSInfo32
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Starting MSInfo32 and Outputting to File"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "MSInfo"
    $wdacEnforce = "wdacEnforce"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
   
    $msinfoPath = "$($SecureReportConfig)\$($OutConfigDir).txt"
    $msinfoPathcsv = "$($SecureReportConfig)\$($OutConfigDir).csv"
    $msinfoPathXml = "$($SecureReportConfig)\$($OutConfigDir).xml"

    $wdacEnforcecsv = "$($SecureReportConfig)\$($wdacEnforce).csv"
    $wdacEnforceXml = "$($SecureReportConfig)\$($wdacEnforce).xml"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    & cmd /c msinfo32 /nfo $SecureReportConfig /report $msinfoPath 2>&1 | Out-String -OutVariable exceptionCMD 
    SecureReportError($SecCheck,$exceptionCMD)
    try
        {
            $getMsinfo = Get-Content $msinfoPath -ErrorAction stop | select -First 50

            <#
                Device Guard Virtualization based security	Running	
                Device Guard Required Security Properties	Base Virtualization Support, Secure Boot, DMA Protection	
                Device Guard Available Security Properties	Base Virtualization Support, Secure Boot, DMA Protection, UEFI Code Readonly	
                Device Guard Security Services Configured	Credential Guard, Hypervisor enforced Code Integrity	
                Device Guard Security Services Running	Credential Guard, Hypervisor enforced Code Integrity
                A hypervisor has been detected. Features required for Hyper-V will not be displayed.
            #>

            Set-Content -Path $msinfoPathcsv -Value 'Virtualization;On\Off'
                ($getMsinfo | Select-String "Secure Boot State") -replace "off",";off" -replace "on",";on" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "Kernel DMA Protection") -replace "off",";off" -replace " on",";on" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "Guard Virtualization based") -replace "security	Run","security;	Run" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "Required Security Properties") -replace "Required Security Properties","Required Security Properties;" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "Available Security Properties") -replace "Available Security Properties","Available Security Properties;" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop  
                ($getMsinfo | Select-String "based security services configured") -replace "based security services configured","based security services configured;" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "based security services running") -replace "based security services running","based security services running;" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 
                ($getMsinfo | Select-String "Application Control Policy") -replace "policy	Enforced","policy;	Enforced" -replace "Policy  Audit","Policy;  Audit" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop  
                ($getMsinfo | Select-String "Application Control User") -replace "off",";off" -replace " on",";on" -replace "policy	Enforced","policy;	Enforced"  -replace "Policy  Audit","Policy;  Audit" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop  
                ($getMsinfo | Select-String "Device Encryption Support") -replace "Encryption Support","Encryption Support;" | Out-File $msinfoPathcsv -Encoding utf8 -Append -ErrorAction stop 

            Import-Csv $msinfoPathcsv -Delimiter ";" | Export-Clixml $msinfoPathXml -ErrorAction Stop
            $MsinfoClixml = Import-Clixml $msinfoPathXml -ErrorAction Stop

            #Import-Clixml $msinfoPathXml | select-string "Windows Defender Application Control policy"

            Set-Content -Path $wdacEnforcecsv -Value 'WDAC\DeviceGuard;Enforced\Audit' -ErrorAction Stop
                ($getMsinfo | Select-String "Application Control Policy") -replace "policy	Enforced","policy;	Enforced" -replace "Policy  Audit","Policy;  Audit"| Out-File $wdacEnforcecsv -Encoding utf8 -Append -ErrorAction stop  
                ($getMsinfo | Select-String "Application Control User") -replace "off",";off" -replace " on",";on" -replace "policy	Enforced","policy;	Enforced"  -replace "Policy  Audit","Policy;  Audit" | Out-File $wdacEnforcecsv -Encoding utf8 -Append -ErrorAction stop  

            Import-Csv $wdacEnforcecsv -Delimiter ";" -ErrorAction Stop | Export-Clixml $wdacEnforceXml -ErrorAction Stop
                $fragwdacClixml = Import-Clixml $wdacEnforceXml -ErrorAction Stop
                $fragwdacClixml | Out-File "$($secureReporOutPut)\msinfo.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                     WDAC\Device Guard
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing WDAC aka Device Guard Policies"
    $exceptionMessage="No errors gathered"

    try
        {
            $osBuild = (Get-CimInstance -ClassName win32_operatingsystem -ErrorAction Stop).buildnumber 
            $fragWDACCIPolicy=@()
            if ($osBuild -ge "22621")
                {
                    $ciPolicyTool =  (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object {$_.IsEnforced -eq "True"} | Select-Object -Property * 

                    Foreach($ciPolicy in $ciPolicyTool)
                        {
                            $ciPolName = $ciPolicy.FriendlyName
                            $ciPolID = $ciPolicy.PolicyID
                            $ciPolsys = $ciPolicy.IsSystemPolicy
                            $ciPolDisk = $ciPolicy.IsOnDisk
                            $ciPolEnforced = $ciPolicy.IsEnforced
                            $ciPolEnforced = if ($ciPolicy.IsEnforced -match "False"){"Warning $($ciPolicy.IsEnforced) Warning"}else{$ciPolicy.IsEnforced}
                            $ciPolAuthorised = $ciPolicy.IsAuthorized

                            $newObjWdac = New-Object PSObject
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicyName -Value $ciPolName
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicyID -Value $ciPolID 
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicySystemPol -Value $ciPolsys
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicyOnDisk -Value $ciPolDisk                        
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicyEnforced -Value $ciPolEnforced             
                                Add-Member -InputObject $newObjWdac -Type NoteProperty -Name CIPolicyAuthorised -Value $ciPolAuthorised            
                            $fragWDACCIPolicy += $newObjWdac 
                            $fragWDACCIPolicy | Out-File "$($secureReporOutPut)\msinfo.log" -Append        
                        }
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      DRIVERQRY
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Starting DriverQuery and Outputting to File"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "DriverQuery"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    $devQryPathtxt = "$($SecureReportConfig)\$OutConfigDir.txt"
    $devQryPathcsv = "$($SecureReportConfig)\$OutConfigDir.csv"
    $devQryPathXml = "$($SecureReportConfig)\$OutConfigDir.xml"   

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    try
        {
            $drvSign = driverquery.exe /SI >>  $devQryPathtxt
            $getdrvQry = Get-Content $devQryPathtxt -ErrorAction Stop | Select-String "FALSE" 

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
                                $DriverQuery | Out-File "$($secureReporOutPut)\DeviceQuery.log" -Append
                        }
                }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      Networking
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing network an dip settings"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "networking"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)
 
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

    $fragNetwork4=@()
    $fragNetwork6=@()

    try
        {
            $gNetAdapter = Get-NetAdapter -erroraction stop | where {$_.Status -eq "up"}
            $gNetAdapter | Out-File "$($secureReporOutPut)\networking.log" -Append
            foreach($gNetAdp in $gNetAdapter)
                {

                    $intAlias = $gNetAdp.InterfaceAlias
                    $macAddy = [string]$gNetAdp.MacAddress 

                    $gNetIPC = Get-NetIPConfiguration -InterfaceAlias $gNetAdp.Name
                        $IPAddress4 = $gNetIPC.IPv4Address.ipaddress 
                        $IPAddress4 = [string]$IPAddress4 
        
                        $IPAddress6 = $gNetIPC.IPv6Address.ipaddress 
                        $IPAddress6 = [string]$IPAddress6

                        $Router4 = $gNetIPC.IPv4DefaultGateway.nexthop 
                        $Router4 =[string]$Router4
        
                        $Router6 = $gNetIPC.IPv6DefaultGateway.nexthop 
                        $Router6  = [string]$Router6 
        
                        $dnsAddress = $gNetIPC.dnsserver.serveraddresses 
                        $dnsAddress = [String]$dnsAddress

                        $InterfaceAlias = $gNetAdp.Name
                        $gNetIPA4 = Get-NetIPAddress  -erroraction stop  | where {$_.InterfaceAlias -eq "$InterfaceAlias" -and $_.AddressFamily -eq "IPv4"}
                        $IPSubnet4 = $gNetIPA4.PrefixLength

                        $gNetIPA6 = Get-NetIPAddress -erroraction stop | where {$_.InterfaceAlias -eq "$InterfaceAlias" -and $_.AddressFamily -eq "IPv6"}
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
                        $fragNetwork4 | Out-File "$($secureReporOutPut)\networking.log" -Append

                        $newObjNetwork6 = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Address -Value $IPAddress6 
                            Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Subnet -Value $IPSubnet6
                            Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name IPv6Gateway -Value $Router6
                            Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name DNSServers -Value $dnsAddress
                            Add-Member -InputObject $newObjNetwork6 -Type NoteProperty -Name Mac -Value $macAddy 
                        $fragNetwork6 += $newObjNetwork6
                        $fragNetwork6 | Out-File "$($secureReporOutPut)\networking.log" -Append

                    }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      Local Shares and Permissions
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = Local "Shares and Permissions"
    $exceptionMessage="No errors gathered"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

try
    {
        $getShr = Get-SmbShare -errorAction Stop
        $Permarray=@()
        $fragShare=@()

        foreach($shr in $getShr)
        {
            $Permarray=@()
            $shrName = $Shr.name
            $shrPath = $Shr.path
            $shrDes = $Shr.description

            $getShrPerms = Get-FileShareAccessControlEntry -Name $shr.Name -ErrorAction Stop
        
            foreach($perms in $getShrPerms)
                {
                    $Permarray += $perms.AccountName
                }
                    $arrayjoin = $Permarray -join ",  "
    
                    $newObjShare = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjShare -Type NoteProperty -Name Name -Value $shrName
                        Add-Member -InputObject $newObjShare -Type NoteProperty -Name Path -Value $shrPath
                        Add-Member -InputObject $newObjShare -Type NoteProperty -Name Permissions -Value $arrayjoin
                    $fragShare += $newObjShare
                    $fragShare | Out-File "$($secureReporOutPut)\Shares.log" -Append
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
            
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Misc Registry Settings
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing various registry settings"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "MiscRegSettings"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)

    try
        {
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
            $fragkernelModeVal += $newObjkernelMode
            $fragkernelModeVal | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    try
        {
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
            $fragLSAPPL += $newObjLSA
            $fragLSAPPL | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {         
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
            $fragWDigestULC | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragCredGuCFG += $newObjCredGu
            $fragCredGuCFG | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #LAPS is installed
            $getLapsPw = Get-Item "HKLM:\Software\Policies\Microsoft Services\AdmPwd\" -ErrorAction SilentlyContinue
            try{$getLapsPwEna =  $getLapsPw.GetValue("AdmPwdEnabled")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try{$getLapsPwCom =  $getLapsPw.GetValue("PasswordComplexity")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try{$getLapsPwLen =  $getLapsPw.GetValue("PasswordLength")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try{$getLapsPwDay =  $getLapsPw.GetValue("PasswordAgeDays")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
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
                        $fragLapsPwEna  | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append

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
                        $fragLapsPwEna += $newObjLapsPw
                        $fragLapsPwEna | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
                    }
 `      }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {            
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
            $fragDLLSafe | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragCode += $newObjCode
            $fragCode | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #InstallElevated
            $getPCInstaller = Get-Item HKLM:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
            $getUserInstaller = Get-Item HKCU:\Software\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue
            try{$PCElevate =  $getUserInstaller.GetValue("AlwaysInstallElevated")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try{$UserElevate = $getPCInstaller.GetValue("AlwaysInstallElevated")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }

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
            $fragPCElevate | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append

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
            $fragPCElevate | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #AutoLogon Details in REG inc password   
            $getAutoLogon = Get-Item  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
            $AutoLogonDefUser =  $getAutoLogon.GetValue("DefaultUserName")
            $AutoLogonDefPass =  $getAutoLogon.GetValue("DefaultPassword") 

            $fragAutoLogon =@()
            if ([string]::IsNullorEmpty($AutoLogonDefPass) -eq "$true")
                {
                    $AutoLPass = "There is no Default Password set for AutoLogon" 
                    $AutoLUser = "There is no Default User set for AutoLogon" 
                    $AutoLReg = "HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon"
                    $trueFalse = "True"
                }
            else
                {
                    $AutoLPass = "Warning AutoLogon default password is set with a value of $AutoLogonDefPass Warning" 
                    $AutoLUser = "Warning AutoLogon Default User is set with a value of $AutoLogonDefUser Warning" 
                    $AutoLReg = "HKLM:\Software\Microsoft\Windows NT\Currentversion\Winlogon"
                    $trueFalse = "False"
                }

            $newObjAutoLogon = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonUsername -Value $AutoLUser
                Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonPassword -Value  $AutoLPass
                Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name AutoLogonRegistry -Value $AutoLReg
                Add-Member -InputObject $newObjAutoLogon -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragAutoLogon += $newObjAutoLogon
            $fragAutoLogon | Out-File "$($secureReporOutPut)\MiscRegSettings.log" -Append
 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        } 

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Legacy Network Protocols
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Legacy Network Protocols"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "llmnr" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $llnmrpath = "$($SecureReportConfig)\$($OutConfigDir).log"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)
        
    $fragLegNIC=@()
    try
        {
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #llmnr = 0 is disabled
            cd HKLM:
            $getllmnrGPO = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
            $enllmnrGpo = $getllmnrgpo.EnableMulticast

            if ($enllmnrGpo -eq "0" -or $enllmnrReg -eq "0")
                {
                    $legProt = "LLMNR (Responder) is disabled in GPO = $enllmnrGpo" 
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {         
            #NetBIOS over TCP/IP (NetBT) queries = 0 is disabled
            cd HKLM:
            $getNetBTGPO = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue
            $enNetBTGPO = $getNetBTGPO.QueryNetBTFQDN

            if ($enNetBTGPO -eq "0")
                {
                    $legProt = "NetBios is disabled in the Registry = $enNetBTGPO" 
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #ipv6 0xff (255)
            cd HKLM:
            $getIpv6 = get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters" -ErrorAction SilentlyContinue
            $getIpv6Int = $getIpv6.DisabledComponents
    
            if ($getIpv6Int -eq "255")
                {
                    $legProt = "IPv6 is disabled in the Registry = $getIpv6Int" 
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #Report on LMHosts file = 1
            cd HKLM:
            $getLMHostsReg = Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters" -ErrorAction SilentlyContinue
            $enLMHostsReg =  $getLMHostsReg.EnableLMHosts
    
            if ($enLMHostsReg -eq "1")
                {
                    $legProt = "LMHosts is disabled in the Registry = $enLMHostsReg" 
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
                $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }

    cd HKLM:
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            #LLTD
            #https://admx.help/HKLM/Software/Policies/Microsoft/Windows/LLTD
            $getNetLLTDInt = Get-item "HKLM:\Software\Policies\Microsoft\Windows\LLTD" -ErrorAction SilentlyContinue

            try {$getLTDIO =  $getNetLLTDInt.GetValue("EnableLLTDIO")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getRspndr = $getNetLLTDInt.GetValue("EnableRspndr")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getOnDomain =  $getNetLLTDInt.GetValue("AllowLLTDIOOnDomain")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getPublicNet = $getNetLLTDInt.GetValue("AllowLLTDIOOnPublicNet")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getRspOnDomain = $getNetLLTDInt.GetValue("AllowRspndrOnDomain")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getRspPublicNet = $getNetLLTDInt.GetValue("AllowRspndrOnPublicNet")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getLLnPrivateNet = $getNetLLTDInt.GetValue("ProhibitLLTDIOOnPrivateNet")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }
            try {$getRspPrivateNet = $getNetLLTDInt.GetValue("ProhibitRspndrOnPrivateNet")}catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)  
                }

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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {        
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {        
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {        
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {        
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
         }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {   
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {         
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

    try
        {     
            <#
            WPAD
            Web Proxy Auto Discovery protocol

            The Web Proxy Auto Discovery (WPAD) protocol assists with the automatic detection of proxy settings for web browsers. 
            Unfortunately, WPAD has suffered from a number of severe security vulnerabilities. Organisations that do not rely on 
            the use of the WPAD protocol should disable it. This can be achieved by modifying each workstation's host file at

            %SystemDrive%\Windows\System32\Drivers\etc\hosts to create the following entry: 255.255.255.255 wpad

            #>

            cd C:\Windows\System32
            $getwpad = Get-content "C:\Windows\System32\Drivers\etc\hosts\" -ErrorAction Sstop
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
            $fragLegNIC | Out-File "$($secureReporOutPut)\LegacyNetwork.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Security Options
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Security Options"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "SecurityOptions" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
 
    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)   

    try
        {    
            $fragSecOptions=@()
            $secOpTitle1 = "Domain member: Digitally encrypt or sign secure channel data (always)" # = 1
            $getSecOp1 = get-item 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {    
            $secOpTitle2 = "Microsoft network client: Digitally sign communications (always)" # = 1
            $getSecOp2 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle3 = "Microsoft network server: Digitally sign communications (always)" # = 1
            $getSecOp3 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle4 = "Microsoft network client: Send unencrypted password to connect to third-party SMB servers" #  = 0
            $getSecOp4 = get-item 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle5 = "Network security: Do not store LAN Manager hash value on next password change" #  = 1
            $getSecOp5 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle6 = "Network security: LAN Manager authentication level (Send NTLMv2 response only\refuse LM & NTLM)" #  = 5
            $getSecOp6 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle7 = "Network Access: Do not allow anonymous enumeration of SAM accounts" #  = 1
            $getSecOp7 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle8 = "Network Access: Do not allow anonymous enumeration of SAM accounts and shares" #  = 1
            $getSecOp8 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle9 = "Network Access: Let Everyone permissions apply to anonymous users" # = 0
            $getSecOp9 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle10 = "Network security: LDAP client signing requirements" # = 2 Required
            $getSecOp10 = get-item 'HKLM:\System\CurrentControlSet\Services\NTDS\parameters' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {

            $secOpTitle15 = "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" 
            $getSecOp15 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle16 = "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" 
            $getSecOp16 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            <#
            All allows the AES encryption types aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96, as well as the RC4 encryption type rc4-hmac. 
            AES takes precedence if the server supports AES and RC4 encryption types.

            * Strong or leaving it unset allows only the AES types.
            * Legacy allows only the RC4 type. RC4 is insecure. It should only be needed in very specific circumstances. 

            If possible, reconfigure the server to support AES encryption.
    
            Caution - removing RC4 can break trusts between parent\child where rc4 is configured
    
            Also see https://wiki.samba.org/index.php/Samba_4.6_Features_added/changed#Kerberos_client_encryption_types.
            #>
    
            $secOpTitle12 = "Network security: Configure encryption types allowed for Kerberos" 
            $getSecOp12 = get-item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' -ErrorAction Stop
            try{$getSecOp12res = $getSecOp12.getvalue("supportedencryptiontypes")}catch{}

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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle11 = "Domain member: Require strong (Windows 2000 or later) session key" 
            $getSecOp11 = get-item 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle13 = "System cryptography: Force strong key protection for user keys stored on the computer" 
            $getSecOp13 = get-item 'HKLM:\Software\Policies\Microsoft\Cryptography\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle14 = "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" 
            $getSecOp14 = get-item 'HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
    
    try
        {
            $secOpTitle17 = "Devices: Prevent users from installing printer drivers"
            $getSecOp17 = get-item 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\' -ErrorAction Stop
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
            $fragSecOptions | Out-File "$($secureReporOutPut)\SecurityOptions.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

#Network Access: Restrict anonymous Access to Named Pipes and Shares
#Network security: Do not store LAN Manager hash value on next password change

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Firewall Profiles
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Firewall Profiles"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "FirewallProfiles" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)   

    try
        {
            $getFWProf = Get-NetFirewallProfile -PolicyStore activestore -ErrorAction Stop
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
                            $fragFWProfile | Out-File "$($secureReporOutPut)\Firewall.log" -Append 
                    }
                else
                    {
                            $newObjFWProf = New-Object psObject
                                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Name -Value $fwProfileNa
                                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Enabled -Value $fwProfileEn
                                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Inbound -Value $fwProfileIn
                                Add-Member -InputObject $newObjFWProf  -Type NoteProperty -Name Outbound -Value $fwProfileOut
                            $fragFWProfile += $newObjFWProf 
                            $fragFWProfile | Out-File "$($secureReporOutPut)\Firewall.log" -Append 
                    }
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Firewall Rules
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Firewall Rules"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "FirewallRules" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $fwpath  = "$($SecureReportConfig)\$($OutConfigDir).log"
    $fwpathcsv = "$($SecureReportConfig)\$OutConfigDir.csv"
    $fwpathxml = "$($SecureReportConfig)\$OutConfigDir.xml"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir) 

    [System.Text.StringBuilder]$fwtxt = New-Object System.Text.StringBuilder

    try
        {
            $getFw = Get-NetFirewallRule -PolicyStore activestore -errorAction Stop | 
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

                Set-Content -Path $fwpath -Value 'DisplayName,Direction,Protocol,LocalIP,LocalPort,RemoteIP,RemotePort,Program' -ErrorAction Stop
            }

            Add-Content -Path $fwpath -Value $fwtxt -ErrorAction stop
            Get-Content $fwpath | Out-File $fwpathcsv -ErrorAction Stop
            $fwCSV = Import-Csv $fwpathcsv -Delimiter "," -ErrorAction Stop | Export-Clixml $fwpathxml -ErrorAction Stop
            $fragFW = Import-Clixml $fwpathxml -ErrorAction Stop
            $fragFW | Out-File "$($secureReporOutPut)\Firewall.log" -Append 
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
  Scheduled Tasks Stores on local drive and weak permissions
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Scheduled Tasks and Permissions"
    $exceptionMessage="No errors gathered"

    try 
        {
            $getScTask = Get-ScheduledTask -erroraction Stop
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
                                try
                                    {
                                        $getAclArgs = Get-Acl $taskArgs -ErrorAction Stop
                                        $getAclArgs.Path.Replace("Microsoft.PowerShell.Core\FileSystem::","")
                                        $taskUser = $getAclArgs.Access.IdentityReference
                                        $taskPerms = $getAclArgs.Access.FileSystemRights
        
                                        $getTaskCon = Get-Content $taskArgs -ErrorAction Stop
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
                                        $SchedTaskPerms | Out-File "$($secureReporOutPut)\ScheduledTaskPerms.log" -Append 
                                    }
                                catch
                                    {
                                        $exceptionMessage = $_.Exception.message
                                        SecureReportError($SecCheck,$exceptionMessage)        
                                    }
                                }
                        }  
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }
<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
       Scheduled Tasks Calling on EXEs and Embedded Code
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Scheduled Tasks EXEs"
    $exceptionMessage="No errors gathered"
 
    try
        { 
         $getScTask = Get-ScheduledTask -errorAction Stop
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
                        $SchedTaskListings += $newObjSchedTaskListings
                        $SchedTaskListings | Out-File "$($secureReporOutPut)\ScheduledTasksEXE.log" -Append
                    }
                }
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
           Auditing Windows Services
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Windows Services"
    $exceptionMessage="No errors gathered"
    try
        {
        $gtServices = Get-Service -ErrorAction Stop | where {$_.StartType -ne "Disabled"} | 
        Select-Object Displayname,ServiceName,Status,StartType | 
        Sort-Object displayname 

        $fragRunServices=@()
        foreach ($runService in $gtServices)
            {
                $runSvcDisName = $runService.displayName
                $runSvcName = $runService.ServiceName
                $runSvcStatus = $runService.Status
                $runSvcStart = $runService.StartType

                $newObjRunningSvc= New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjRunningSvc -Type NoteProperty -Name DisplayName -Value $runSvcDisName
                    Add-Member -InputObject $newObjRunningSvc -Type NoteProperty -Name ServiceName -Value $runSvcName
                    Add-Member -InputObject $newObjRunningSvc -Type NoteProperty -Name Status -Value $runSvcStatus
                    Add-Member -InputObject $newObjRunningSvc -Type NoteProperty -Name StartType -Value $runSvcStart
                $fragRunServices += $newObjRunningSvc
                $fragRunServices | Out-File "$($secureReporOutPut)\Windows Services.log" -Append
            }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
           Auditing Windows Printer Services - Servers
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Printer Spooler Service - Servers only"
    $exceptionMessage="No errors gathered"
    try
        {
            if ($gtCIM_OS -match "Server" )
                {
                    $gtSpoolerSvc = Get-Service -ErrorAction Stop | where {$_.StartType -ne "Disabled" -and $_.name -eq "spooler"} | 
                    Select-Object Displayname,ServiceName,Status,StartType | 
                    Sort-Object displayname   
        
                    $fragRunSpoolerSvc=@()
                    foreach ($runSpoolerSvc in $gtSpoolerSvc)
                    {
                        $runSpoolerSvcDisName = $runSpoolerSvc.displayName
                        $runSpoolerSvcName = $runSpoolerSvc.ServiceName
                        $runSpoolerSvcStatus = $runSpoolerSvc.Status
                        $runSpoolerSvcStart = $runSpoolerSvc.StartType

                        $newObjSpoolerSvc = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSpoolerSvc -Type NoteProperty -Name DisplayName -Value "Warning $runSpoolerSvcDisName Warning"
                            Add-Member -InputObject $newObjSpoolerSvc -Type NoteProperty -Name ServiceName -Value "Warning $runSpoolerSvcName Warning"
                            Add-Member -InputObject $newObjSpoolerSvc -Type NoteProperty -Name Status -Value "Warning $runSpoolerSvcStatus Warning"
                            Add-Member -InputObject $newObjSpoolerSvc -Type NoteProperty -Name StartType -Value "Warning $runSpoolerSvcStart Warning"
                        $fragRunSpoolerSvc += $newObjSpoolerSvc
                        $fragRunSpoolerSvc | Out-File "$($secureReporOutPut)\Printer Services.log" -Append
                    }
                }
        }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)        
        }


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
              FILES, FOLDERS, REG AUDITS
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

#START OF IF
if ($folders -eq "y")
    {
    if ($depth -eq $null){$depth = "2"}
    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
             Searching for Writeable Registry Vulnerabilities
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Writeable Registry Hive Vulnerabilities"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "WriteableReg"  

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $rpath = "$($SecureReportConfig)\$OutConfigDir.log"    	

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 
 
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
                        try
                            {
                                $acl = Get-Acl $regPath -ErrorAction Stop
                                $acc = $acl.AccessToString

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
                            catch
                                {
                                    $exceptionMessage = $_.Exception.message
                                    SecureReportError($SecCheck,$exceptionMessage)        
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
                            $fragReg | Out-File "$($secureReporOutPut)\WriteableRegistry.log" -Append    
                        }
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
             Searching for Writeable Files Vulnerabilities (*.exe, *.dll)
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Writeable Files Vulnerabilities (*.exe, *.dll)"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "WriteableFiles" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $hpath = "$($SecureReportConfig)\$OutConfigDir.log"    	

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

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
                        try
                            {
                                $cfileAcl = Get-Acl $cfile -ErrorAction Stop

                                if ($cfileAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                                    -or $_.Accesstostring -like "*Users Allow  Modify*" `
                                    -or $_.Accesstostring -like "*Users Allow  FullControl*"})
                                    {
                                        $cfile | Out-File $hpath -Append
                                    }

                                if ($cfileAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                                    -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                                    -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
                                    {
                                        $cfile | Out-File $hpath -Append
                                    }
    
                                if ($cfileAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                                    -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                                    -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
                                    {
                                        $cfile | Out-File $hpath -Append
                                    }
                            }
                        catch
                            {
                                $exceptionMessage = $_.Exception.message
                                SecureReportError($SecCheck,$exceptionMessage)        
                            }
                    }
    
                $wFileDetails = Get-Content $hpath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
                $fragwFile =@()
    
                foreach ($wFileItems in $wFileDetails)
                    {
                        $newObjwFile = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjwFile -Type NoteProperty -Name WriteableFiles -Value "Warning $($wFileItems) warning"
                        $fragwFile += $newObjwFile
                        $fragwFile | Out-File "$($secureReporOutPut)\WriteableFiles.log" -Append
                    }
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
       Searching for Writeable Non System Folders Vulnerabilities

            NOT the following Directories
             
                where {$_.Name -ne "PerfLogs" -and ` 
                $_.Name -ne "Program Files" -and `
                $_.Name -ne "Program Files (x86)" -and `
                $_.Name -ne "Users" -and `
                $_.Name -ne "Windows"}

    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Writeable Non System Folder Vulnerabilities"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "WriteableNonSysFolders" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $fpath = "$($SecureReportConfig)\$OutConfigDir.log"  
        
        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 
    
        $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
        $drvRoot = $drv.root 
        $getRoot = Get-Item $drvRoot -ErrorAction SilentlyContinue

        foreach ($rt in $drvRoot)
        {
            $ffolders =  Get-ChildItem $rt -ErrorAction SilentlyContinue  | 
            where {$_.Name -ne "PerfLogs" -and ` 
                $_.Name -ne "Program Files" -and `
                $_.Name -ne "Program Files (x86)" -and `
                $_.Name -ne "Users" -and `
                $_.Name -ne "Windows"}
    
            $foldhash = @()
            foreach ($ffold in $ffolders.fullname)
                {
                    $subfl = Get-ChildItem -Path $ffold -Depth $depth -Directory -Recurse -Force -ErrorAction SilentlyContinue
                    $foldhash+=$ffolders
                    $foldhash+=$subfl
                    $foldhash+=$getRoot 
                }
    
            foreach ($cfold in $foldhash.fullname)
            {
                try {
                        $cfoldAcl = Get-Acl $cfold -ErrorAction stop

                            if ($cfoldAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
                                {
                                    $cfold | Out-File $fpath -Append
                                }

                            if ($cfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
                                {
                                    $cfold | Out-File $fpath -Append
                                }

                            if ($cfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})
                                {
                                    $cfold | Out-File $fpath -Append
                                } 
                    }
                catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }
            }
        
            Get-Content $fpath -ErrorAction SilentlyContinue | Sort-Object -Unique | Set-Content $fpath -ErrorAction SilentlyContinue

            #Get content and remove the first 3 lines
            $wFolderDetails = Get-Content $fpath  -ErrorAction SilentlyContinue   #|  where {$_ -ne ""} |select -skip 3
            $fragwFold =@()
    
            foreach ($wFoldItems in $wFolderDetails)
                {
                    $newObjwFold = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjwFold -Type NoteProperty -Name FolderWeakness -Value $wFoldItems
                    $fragwFold += $newObjwFold
                    $fragwFold | Out-File "$($secureReporOutPut)\WriteableNonSysFolders.log" -Append
                }       
        }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
       Searching for Writeable System Folders Vulnerabilities

            IS the following Directories
             
                where {$_.Name -ne "PerfLogs" -and ` 
                $_.Name -eq "Program Files" -and `
                $_.Name -eq "Program Files (x86)" -and `
                $_.Name -eq "Users" -and `
                $_.Name -eq "Windows"}

    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Writeable System Folder Vulnerabilities" 
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "SystemFolders" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $sysPath = "$($SecureReportConfig)\$OutConfigDir.log"  
        
        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir)      

        $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
        $drvRoot = $drv.root
        $getRoot = Get-Item $drvRoot -ErrorAction SilentlyContinue

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
                    $subsysfl = Get-ChildItem -Path $sysfold -Depth $depth -Directory -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"}

                    $sysfoldhash+=$subsysfl
                }
    
            foreach ($syfold in $sysfoldhash.fullname)
                {
                    try
                        {
                            $syfoldAcl = Get-Acl $syfold -ErrorAction Stop
                            if ($syfoldAcl | where {$_.Accesstostring -like "*Users Allow  Write*" `
                                -or $_.Accesstostring -like "*Users Allow  Modify*" `
                                -or $_.Accesstostring -like "*Users Allow  FullControl*"})
                                {
                                    $syfold | Out-File $sysPath -Append
                                }

                            if ($syfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  Write*" `
                                -or $_.Accesstostring -like "*Everyone Allow  Modify*" `
                                -or $_.Accesstostring -like "*Everyone Allow  FullControl*"})
                                {
                                    $syfold | Out-File $sysPath -Append
                                }

                            if ($syfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  Write*" `
                                -or $_.Accesstostring -like "*Authenticated Users Allow  Modify*" `
                                -or $_.Accesstostring -like "*Authenticated Users Allow  FullControl*"})

                                {
                                    $syfold | Out-File $sysPath -Append
                                }
                        }
                    catch
                        {
                            $exceptionMessage = $_.Exception.message
                            SecureReportError($SecCheck,$exceptionMessage)        
                        }
                }
    
            Get-Content $sysPath | Sort-Object -Unique | Set-Content $sysPath 

            #Get content and remove the first 3 lines
            $sysFolderDetails = Get-Content $sysPath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
            $fragsysFold =@()
    
            foreach ($sysFoldItems in $sysFolderDetails)
            {
                $newObjsysFold = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjsysFold -Type NoteProperty -Name FolderWeakness -Value "Warning $($sysFoldItems) Warning"
                $fragsysFold += $newObjsysFold
                $fragsysFold | Out-File "$($secureReporOutPut)\WriteableSystemFolders.log" -Append
            }
        }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
       Searching for Writeable System Folders Vulnerabilities

            IS the following Directories
             
                where {$_.Name -ne "PerfLogs" -and ` 
                $_.Name -eq "Program Files" -and `
                $_.Name -eq "Program Files (x86)" -and `
                $_.Name -eq "Users" -and `
                $_.Name -eq "Windows"}

    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for CreateFile Permissions Vulnerabilities within System Directories"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "CreateFileSystemFolders" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $createSysPath = "$($SecureReportConfig)\$OutConfigDir.log"  
        
        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

        $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
        $drvRoot = $drv.root
        $getRoot = Get-Item $drvRoot -ErrorAction SilentlyContinue

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
                }

            foreach ($createSyfold in $createSysfoldhash.fullname)
                {
                    try 
                        {
                            $createSyfoldAcl = Get-Acl $createSyfold -ErrorAction Stop

                            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Users Allow  CreateFiles*"})
                                {
                                    $createSyfold | Out-File $createSysPath -Append
                                }

                            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Everyone Allow  CreateFiles*"})
                                {
                                    $createSyfold | Out-File $createSysPath -Append
                                }

                            if ($createSyfoldAcl | where {$_.Accesstostring -like "*Authenticated Users Allow  CreateFiles*"})
                                {
                                    $createSyfold | Out-File $createSysPath -Append
                                }
                        }
                     catch
                        {
                            $exceptionMessage = $_.Exception.message
                            SecureReportError($SecCheck,$exceptionMessage)        
                        }
                 }

                Get-Content $createSysPath | Sort-Object -Unique | Set-Content $createSysPath 

                #Get content and remove the first 3 lines
                $createSysFolderDetails = Get-Content $createSysPath -ErrorAction SilentlyContinue #|  where {$_ -ne ""} |select -skip 3
                $fragcreateSysFold=@()
        
                foreach ($createSysFoldItems in $createSysFolderDetails)
                    {
                        $newObjcreateSysFold = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjcreateSysFold -Type NoteProperty -Name CreateFiles -Value "Warning $($createSysFoldItems) Warning"
                        $fragcreateSysFold += $newObjcreateSysFold
                        $fragcreateSysFold | Out-File "$($secureReporOutPut)\CreateFileSystemFolders.log" -Append
                    }
            }
    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
           Auditing DLLs that a User can Write and not signed
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Auditing DLLs that a User can Write and not signed"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "DLLNotSigned"  

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $dllLogPath = "$($SecureReportConfig)\$OutConfigDir.log" 
        $dllLogPathtxt = "$($SecureReportConfig)\$OutConfigDir.txt" 
        
        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

        $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) |  where {$_.displayroot -notlike "*\\*"}
        $drvRoot = $drv.root 
        $getRoot = Get-Item $drvRoot -ErrorAction SilentlyContinue

        foreach ($rt in $drvRoot)
        {
            $dllFolders =  Get-ChildItem $rt -ErrorAction SilentlyContinue  |
            where {$_.fullName -match "Program Files" -or `
                $_.fullName -match "(x86)" -or `
                $_.fullName -match "Windows"}
      
            ForEach ($dllFold in $dllFolders.fullname)
                {
                    try
                        {
                            $dllSigned = Get-ChildItem -Path $dllFold -Recurse -depth $depth -force -ErrorAction SilentlyContinue | 
                                  where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"} |
                                  where {$_.Extension -eq ".dll"} | Get-AuthenticodeSignature | 
                                  where {$_.status -ne "valid"} | get-acl -ErrorAction Stop | 
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
                      catch
                        {
                            $exceptionMessage = $_.Exception.message
                            SecureReportError($SecCheck,$exceptionMessage)        
                        }
                 }
        }

        Get-Content $dllLogPath  | 
            foreach {$_ -replace "Microsoft.PowerShell.Core",""} |
            foreach {$_ -replace 'FileSystem::',""} |
            foreach {$_.substring(1)} |
            Set-Content $dllLogPathtxt -Force

        $fragDllNotSigned=@()
        $getDllPath = get-content $dllLogPathtxt -ErrorAction SilentlyContinue

        foreach ($dllNotSigned in $getDllPath)
            {
                $newObjDllNotSigned = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjDllNotSigned -Type NoteProperty -Name CreateFiles -Value "Warning $($dllNotSigned) warning"
                $fragDllNotSigned += $newObjDllNotSigned
                $fragDllNotSigned | Out-File "$($secureReporOutPut)\DLLsNotSignedUserWrite.log" -Append
            }  

    #END OF IF
    }


    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Auditing Authenticode Signatures
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    if ($authenticode -eq "y")
        {
                splatVariables
                $SecCheck = "Auditing Authenticode Signatures"
                $exceptionMessage="No errors gathered"

                $OutConfigDir = "AuthenticodeSignatures"

                $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        
                #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
                TestConfigOutputPath($OutConfigDir) 

                $fragAuthCodeSig=@()
                $newObjAuthSig=@()

                $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
                $drvRoot = $drv.root
 
                    foreach ($rt in $drvRoot)
                        {
                            $getAuthfiles = Get-ChildItem -Path $rt -Recurse -depth $depth -force -ErrorAction SilentlyContinue | 
                            where {$_.FullName -notMatch "winsxs" -and $_.FullName -notmatch "LCU"} |
                            where { ! $_.PSIsContainer `
                                -and $_.extension -ne ".log" `
                                -and $_.extension -ne ".hve" `
                                -and $_.extension -ne ".txt" `
                                -and $_.extension -ne ".evtx" `
                                -and $_.extension -ne ".elt"}

                            foreach($file in $getAuthfiles)
                                {
                                    try
                                        {
                                            $getAuthCodeSig = Get-AuthenticodeSignature -FilePath $file.FullName | where {$_.Status -eq "hashmismatch"}
                                        }        
                                    catch
                                        {
                                            $exceptionMessage = $_.Exception.message
                                            SecureReportError($SecCheck,$exceptionMessage)        
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
                                                     $fragAuthCodeSig | Out-File "$($secureReporOutPut)\AuthenticodeSignatures.log" -Append
                                                }
                                }
                            }
           }#END OF IF

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Auditing Certificates
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Installed Certificates"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "Certificates" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)  

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
                     $fragCertificates | Out-File "$($secureReporOutPut)\Certificates.log" -Append
                }
        }

<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  Auditing Cipher Suits
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing Cipher Suits"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "CipherSuits" 

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)  

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
            $fragCipherSuit | Out-File "$($secureReporOutPut)\CipherSuit.log" -Append        
        }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                Searching for Embedded Password in Processes
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Embedded Password in Processes"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "PasswordsEmbedded" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 
  
        $getPSPass = Get-CimInstance win32_process -ErrorAction SilentlyContinue |
            Select-Object Caption, Description,CommandLine | 
            where {$_.commandline -like "*pass*" -or $_.commandline -like "*credential*" -or $_.commandline -like "*user*" }

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
                $fragPSPass | Out-File "$($secureReporOutPut)\PasswordsEmbeddedProcesses.log" -Append  
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                Searching for Embedded Password in Files
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        #passwords embedded in files
        #findstr /si password *.txt - alt
        if ($embeddedpw -eq "y")
            {
                splatVariables
                $SecCheck = "Searching for Embedded Password in Files"
                $exceptionMessage="No errors gathered"

                $OutConfigDir = "PasswordsEmbedded" 

                $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	

                #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
                TestConfigOutputPath($OutConfigDir) 

                $drv = (psdrive | where {$_.root -match "^[a-zA-Z]:"}) | where {$_.displayroot -notlike "*\\*"}
                $drvRoot = $drv.root
                $fragFilePass=@()
                if ($depth -eq $null){$depth = "2"}
                $depthExtra = [int]$depth + 2
                    foreach ($rt in $drvRoot)
                        {
                            try
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
                                        -and $_.FullName -notmatch "SystemApps" `
                                        -and $_.FullName -notmatch "servicing" `
                                        -and $_.FullName -notmatch "Microsoft.NET" `
                                        -and $_.FullName -notmatch "SoftwareDistribution" `
                                        -and $_.FullName -notmatch "DriverStore" `
                                        -and $_.FullName -notmatch "spool" `
                                        -and $_.FullName -notmatch "icsxm" `
                                        -and $_.FullName -notmatch "PSPa55words" `
                                        -and $_.FullName -notmatch "Report.AD.xml"} |
                                    where {$_.Extension -eq ".txt"`
                                        -or $_.Extension -eq ".ini" `
                                        -or $_.Extension -eq ".xml"}  #xml increase output, may break report
                                }
                            catch
                                {
                                    $exceptionMessage = $_.Exception.message
                                    SecureReportError($SecCheck,$exceptionMessage)        
                                }

                            foreach ($PassFile in $getUserFolder)
                                {
                                    try
                                        {
                                            #Write-Host $PassFile.fullname -ForegroundColor Yellow
                                            [string]$SelectPassword  = Get-Content $PassFile.FullName -ErrorAction Stop | Select-String -Pattern password, credential

                                                if ($SelectPassword -like "*password*" -or $SelectPassword -like "*credential*")
                                                    {
                                                        $newObjFilePass = New-Object -TypeName PSObject
                                                            Add-Member -InputObject $newObjFilePass -Type NoteProperty -Name FilesContainingPassword -Value $PassFile.FullName 
                                                            Add-Member -InputObject $newObjFilePass -Type NoteProperty -Name Value -Value "Warning $SelectPassword warning"
                                                        $fragFilePass += $newObjFilePass
                                                        $fragFilePass | Out-File "$($secureReporOutPut)\PasswordsEmbeddedFiles.log" -Append  
                                                    }
                                        }
                                    catch
                                        {
                                            $exceptionMessage = $_.Exception.message
                                            SecureReportError($SecCheck,$exceptionMessage)        
                                        }
                                }
                        }
            }#END OF IF

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Searching for Registry Passwords
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for Embedded Password in Processes"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "RegPasswords" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $secEditPath = "$($SecureReportConfig)\$OutConfigDir.txt"	

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir)   

        #Enter list of Words to search
        $regSearchWords = "password", "passwd","DefaultPassword"

        foreach ($regSearchItems in $regSearchWords)
            {
                #swapped to native tool, Powershell is too slow
                reg query HKLM\Software /f $regSearchItems /t REG_SZ /s >> $secEditPath
                reg query HKCU\Software /f $regSearchItems /t REG_SZ /s >> $secEditPath
                reg query HKLM\SYSTEM\CurrentControlSet\Services /f $regSearchItems /t REG_SZ /s >> $secEditPath
            }

        $getRegPassCon = (get-content $secEditPath | 
        where {$_ -notmatch "classes" -and $_ -notmatch "ClickToRun" -and $_ -notmatch "}" -and $_ -notmatch "PolicyManager" -and $_ -notmatch "Internet" -and $_ -notmatch "WSMAN" -and $_ -notmatch "PasswordEnrollmentManager" -and $_ -notmatch "FirewallPolicy"  -and $_ -notmatch "NetworkController"} | Select-String -Pattern "hkey_", "hkcu_")# -and $_ -notmatch "microsoft" -and $_ -notmatch "default"} | 

        $fragRegPasswords=@()
        foreach ($getRegPassItem in $getRegPassCon)
            {
                if ($getRegPassItem -match "HKEY_LOCAL_MACHINE"){$getRegPassItem = $getRegPassItem.tostring().replace("HKEY_LOCAL_MACHINE","HKLM:")}
                if ($getRegPassItem -match "HKEY_CURRENT_USER"){$getRegPassItem = $getRegPassItem.tostring().replace("HKEY_CURRENT_USER","HKCU:")}

                $gtItemPasskey = (Get-Item $getRegPassItem).property | where {$_ -match "passd" -or $_ -match "password"-or $_ -match "user" -or $_ -match "cred" -or $_ -match "unlock" -and $_ -notmatch "PasswordExpiryWarning"}

                foreach ($gtItemPasskeyitem in $gtItemPasskey)
                    {
                        $gtItemPassValue = (Get-ItemProperty $getRegPassItem -Name $gtItemPasskeyitem).$gtItemPasskeyitem

                        $newObjRegPasswords = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPath -Value "Warning $($getRegPassItem) warning"
                            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryValue -Value "Warning $($gtItemPasskeyitem) warning"
                            Add-Member -InputObject $newObjRegPasswords -Type NoteProperty -Name RegistryPassword -Value "Warning $($gtItemPassValue) warning"
                        $fragRegPasswords += $newObjRegPasswords  
                        $fragRegPasswords | Out-File "$($secureReporOutPut)\PasswordsEmbeddedRegistry.log" -Append  
                    }           
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Auditing Powershell History for Passwords
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Auditing Powershell History for Passwords"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "PSPa55words"

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $PSPa55wordsOutput = "$($SecureReportConfig)\$OutConfigDir.txt"	
        $PSPa55wordsParsed = "$($SecureReportConfig)\$($OutConfigDir)_Parsed.txt"	

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir)   

        $fragPSPa55words=@()

        foreach ($CachedProfiles in $gtCachedProfiles)
            {
            $tpHistory = test-path "$($CachedProfiles)\Appdata\roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                if ($tpHistory -eq $true)
                    {
                        [array]$gtPSPa55words = get-content "$($CachedProfiles)\Appdata\roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | where {$_ -match "password" -or $_ -match "user" -or $_ -match "ConvertTo-SecureString" }
                        foreach ($psHistory in $gtPSPa55words)
                        {
                            $gtPSPa55words
                            $newObjPSPa55words = New-Object -TypeName PSObject
                                Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSHistoryPath -Value $CachedProfiles
                                Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSWordsOfInterest -Value "Warning $($psHistory) warning"
                            $fragPSPa55words += $newObjPSPa55words
                            $fragPSPa55words | Out-File "$($secureReporOutPut)\PasswordsEmbeddedPowershell.log" -Append 
                        }
                    }
                else {}
            }
        
            $shellPSHistory = history
            Start-Transcript -Path $PSPa55wordsOutput -Force
            foreach ($psHistory in $shellPSHistory)
                {
                    $pshistoutQuery = $psHistory | where {$_.CommandLine -like "*password*" -or $_.CommandLine -like "*user*" -or $_.CommandLine -like "ConvertTo-SecureString"} 
                    Write-Host $pshistoutQuery
                }
        
            Stop-Transcript
            Get-Content -Path $PSPa55wordsOutput | Select-Object -skip 22 |  Select-String -Pattern "user","password","ConvertTo-SecureString"  | Out-File $PSPa55wordsParsed
            $gtPSPa55wordsPattern = Get-Content $PSPa55wordsParsed
        
            if ($gtPSPa55wordsPattern.Count -gt "30")
                {
                    $newObjPSPa55words = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSHistoryPath -Value "C:\SecureReport\output\PSPa55words\PSPa55words_Parsed.txt"
                        Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSWordsOfInterest -Value "Warning Too many matches found go to file warning"
                    $fragPSPa55words += $newObjPSPa55words
                    $fragPSPa55words | Out-File "$($secureReporOutPut)\PasswordsEmbeddedPowershell.log" -Append 
                }
            else
                {
                    foreach ($gtPSPa55wordsitem in $gtPSPa55wordsPattern)
                        {
                            $newObjPSPa55words = New-Object -TypeName PSObject
                                Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSHistoryPath -Value "Extracted from C:\SecureReport\output\PSPa55words\PSPa55words_Parsed.txt"
                                Add-Member -InputObject $newObjPSPa55words -Type NoteProperty -Name PSWordsOfInterest -Value "Warning $gtPSPa55wordsitem warning"
                            $fragPSPa55words += $newObjPSPa55words
                            $fragPSPa55words | Out-File "$($secureReporOutPut)\PasswordsEmbeddedPowershell.log" -Append 
                        }
               }
                
    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Auditing Applocker
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Auditing Applocker"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "Applocker"

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir)   

        $fragApplockerSvc=@()
        $AppLockerSvc = get-service appidsvc
        $newObjApplockerSvc = New-Object -TypeName PSObject
            Add-Member -InputObject $newObjApplockerSvc -Type NoteProperty -Name Path $AppLockerSvc.DisplayName
            Add-Member -InputObject $newObjApplockerSvc -Type NoteProperty -Name PubExcep $AppLockerSvc.Name
            Add-Member -InputObject $newObjApplockerSvc -Type NoteProperty -Name PubPathExcep $AppLockerSvc.StartType
        $fragApplockerSvc += $newObjApplockerSvc
        $fragApplockerSvc | Out-File "$($secureReporOutPut)\Applocker.log" -Append 

        $gtAppLRuleCollection = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollections 
        $gtAppLCollectionTypes = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollectionTypes

        #Enforcment mode
        $fragApplockerEnforcement=@()
        $gtApplockerEnforce = (Get-AppLockerPolicy -Effective).rulecollections | Select-Object -Property RuleCollectionType,EnforcementMode,ServiceEnforcementMode,SystemAppAllowMode,Count 

        foreach($appEnforcement in $gtApplockerEnforce)
            {
                $applockerEnforceColl = $appEnforcement.RuleCollectionType
                $applockerEnforceMode = $appEnforcement.EnforcementMode
                $applockerEnforceSvc = $appEnforcement.ServiceEnforcementMode
                $applockerEnforceSys = $appEnforcement.SystemAppAllowMode
                $applockerEnforceCount = $appEnforcement.Count 

                    $newObjApplockerEnforce= New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjApplockerEnforce -Type NoteProperty -Name CollectionType $applockerEnforceColl
                        Add-Member -InputObject $newObjApplockerEnforce -Type NoteProperty -Name EnforceMode $applockerEnforceMode
                        Add-Member -InputObject $newObjApplockerEnforce -Type NoteProperty -Name ServiceMode $applockerEnforceSvc 
                        Add-Member -InputObject $newObjApplockerEnforce -Type NoteProperty -Name SysAppAllow $applockerEnforceSys
                        Add-Member -InputObject $newObjApplockerEnforce -Type NoteProperty -Name NumerofRules $applockerEnforceCount              
                    $fragApplockerEnforcement += $newObjApplockerEnforce 
                    $fragApplockerEnforcement | Out-File "$($secureReporOutPut)\Applocker.log" -Append    
            }

        #Path Conditions
        $fragApplockerPath=@()
        foreach ($appLockerRule in $gtAppLCollectionTypes)
            {
                $appLockerRuleType = ($gtAppLRuleCollection | where {$_.RuleCollectionType -eq "$appLockerRule"}) | select-object PathConditions,PathExceptions,PublisherExceptions,HashExceptions,action,UserOrGroupSid,id,name
                $appLockerPathAllow = $appLockerRuleType | where {$_.action -eq "allow" -and $_.pathconditions -ne $null}
                $appLockerPathDeny = $appLockerRuleType | where {$_.action -eq "deny" -and $_.pathconditions -ne $null} 

                    foreach ($allowitem in $appLockerPathAllow)
                        {
                            $alPathName = [string]$allowitem.name
                            $alPathCon = [string]$allowitem.pathconditions
                            $alPublishExcep = [string]$allowitem.PublisherExceptions
                            $alPublishPathExcep = [string]$allowitem.PathExceptions
                            $alPublishHashExcep = [string]$allowitem.HashExceptions
                            $alUserGroup = [string]$allowitem.UserOrGroupSid
                            $alAction = [string]$allowitem.action
                            $alID = [string]$allowitem.ID
                            $alRule = [string]$appLockerRule

                            $newObjApplocker = New-Object -TypeName PSObject
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Name $alPathName
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Path $alPathCon
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubExcep $alPublishExcep
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubPathExcep $alPublishPathExcep
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubHashExcep $alPublishHashExcep
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Action -Value $alAction 
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Rule -Value $alRule
                            #Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name ID -Value $alID
                            $fragApplockerPath += $newObjApplocker    
                            $fragApplockerPath | Out-File "$($secureReporOutPut)\Applocker.log" -Append 
                        }

                    foreach ($denyitem in $appLockerPathDeny)
                        {
                            $alPathName = [string]$denyitem.name
                            $alPathCon = [string]$denyitem.pathconditions
                            $alPublishExcep = [string]$denyitem.PublisherExceptions
                            $alPublishPathExcep = [string]$denyitem.PathExceptions
                            $alPublishHashExcep = [string]$denyitem.HashExceptions
                            $alUserGroup = [string]$denyitem.UserOrGroupSid
                            $alAction = [string]$denyitem.action
                            $alID = [string]$denyitem.ID
                            $alRule = [string]$appLockerRule

                            $newObjApplocker = New-Object -TypeName PSObject
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Name $alPathName
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Path $alPathCon
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubExcep $alPublishExcep
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubPathExcep $alPublishPathExcep
                                Add-Member -InputObject $newObjAppLocker -Type NoteProperty -Name PubHashExcep $alPublishHashExcep
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Action -Value $alAction 
                                Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name Rule -Value $alRule
                            #Add-Member -InputObject $newObjApplocker -Type NoteProperty -Name ID -Value $alID
                            $fragApplockerPath += $newObjApplocker
                            $fragApplockerPath | Out-File "$($secureReporOutPut)\Applocker.log" -Append 
                        }
            }


        #Publisher Rules
        $gtAppLRuleCollection = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollections 
        $gtAppLCollectionTypes = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollectionTypes

        #$appLockerRule  = "exe"
        #Path Conditions
        $fragApplockerPublisher=@()
        foreach ($appLockerRule in $gtAppLCollectionTypes)
        {
            $appLockerRuleType = ($gtAppLRuleCollection | where {$_.RuleCollectionType -eq "$appLockerRule"}) | select-object PublisherConditions, PublisherExceptions, PathExceptions, HashExceptions, action,UserOrGroupSid,id,name
            $ApplockerPublisherAllow = $appLockerRuleType | where {$_.action -eq "allow" -and $_.PublisherConditions -ne $null}
            $ApplockerPublisherDeny = $appLockerRuleType | where {$_.action -eq "deny" -and $_.PublisherConditions -ne $null} 

                foreach ($allowitem in $ApplockerPublisherAllow)
                    {
                        $alPublishName = [string]$allowitem.name
                        $alPublishCon = [string]$allowitem.PublisherConditions
                        $alPublishExcep = [string]$allowitem.PublisherExceptions
                        $alPublishPathExcep = [string]$allowitem.PathExceptions
                        $alPublishHashExcep = [string]$allowitem.HashExceptions
                        $alUserGroup = [string]$allowitem.UserOrGroupSid
                        $alAction = [string]$allowitem.action
                        $alID = [string]$allowitem.ID
                        $alRule = [string]$appLockerRule

                        $newObjAppLockPublisher = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PublisherName $alPublishName
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PublisherConditions $alPublishCon
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubExcep $alPublishExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubPathExcep $alPublishPathExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubHashExcep $alPublishHashExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name Action -Value $alAction 
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name Rule -Value $alRule
                            #Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name ID -Value $alID
                        $fragApplockerPublisher += $newObjAppLockPublisher  
                        $fragApplockerPublisher | Out-File "$($secureReporOutPut)\Applocker.log" -Append   
                    }

                foreach ($denyitem in $ApplockerPublisherDeny)
                    {
                        $alPublishName = [string]$denyitem.name
                        $alPublishCon = [string]$denyitem.PublisherConditions
                        $alPublishExcep = [string]$denyitem.PublisherExceptions
                        $alPublishPathExcep = [string]$denyitem.PathExceptions
                        $alPublishHashExcep = [string]$denyitem.HashExceptions
                        $alUserGroup = [string]$denyitem.UserOrGroupSid
                        $alAction = [string]$denyitem.action
                        $alID = [string]$denyitem.ID
                        $alRule = [string]$appLockerRule

                        $newObjAppLockPublisher = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PublisherName $alPublishName
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PublisherConditions $alPublishCon
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubExcep $alPublishExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubPathExcep $alPublishPathExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name PubHashExcep $alPublishHashExcep
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name Action -Value $alAction 
                            Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name Rule -Value $alRule
                        #Add-Member -InputObject $newObjAppLockPublisher -Type NoteProperty -Name ID -Value $alID
                        $fragApplockerPublisher += $newObjAppLockPublisher
                        $fragApplockerPublisher | Out-File "$($secureReporOutPut)\Applocker.log" -Append 
                    }
        }


        #hash conditions
        $gtAppLRuleCollection = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollections 
        $gtAppLCollectionTypes = Get-ApplockerPolicy -Effective | select -ExpandProperty RuleCollectionTypes

        #Path Conditions
        $fragApplockerHash=@()
        foreach ($appLockerRule in $gtAppLCollectionTypes)
        {
            $appLockerRuleType = ($gtAppLRuleCollection | where {$_.RuleCollectionType -eq "$appLockerRule"}) | select-object HashConditions, action, UserOrGroupSid, id, name
            $ApplockerHashAllow = $appLockerRuleType | where {$_.action -eq "allow" -and $_.HashConditions -ne $null}
            $ApplockerHashDeny = $appLockerRuleType | where {$_.action -eq "deny" -and $_.HashConditions -ne $null} 

                foreach ($allowitem in $ApplockerHashAllow)
                    {
                        $alHashCon = [string]$allowitem.HashConditions #.split(";")[0]
                        $alHashCon = $alHashCon.split(";")[0]
                        $alUserGroup = [string]$allowitem.UserOrGroupSid
                        $alAction = [string]$allowitem.action
                        $alName = [string]$allowitem.name
                        $alID = [string]$allowitem.ID
                        $alRule = [string]$appLockerRule

                        $newObjAppLockHash = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Name $alName
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Hash $alHashCon
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Action -Value $alAction 
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Rule -Value $alRule
                        #Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name ID -Value $alID
                        $fragApplockerHash += $newObjAppLockHash    
                        $fragApplockerHash | Out-File "$($secureReporOutPut)\Applocker.log" -Append 
                    }

                foreach ($denyitem in $ApplockerHashDeny)
                    {
                        $alHashCon = [string]$denyitem.HashConditions #.split(";")[0]
                        $alHashCon = $alHashCon.split(";")[0]
                        $alUserGroup = [string]$denyitem.UserOrGroupSid
                        $alAction = [string]$denyitem.action
                        $alName = [string]$denyitem.name
                        $alID = [string]$denyitem.ID
                        $alRule = [string]$appLockerRule

                        $newObjAppLockHash = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Name $alName
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Hash $HashCon
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name UserorGroup -Value $alUserGroup                 
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Action -Value $alAction 
                            Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name Rule -Value $alRule
                        #Add-Member -InputObject $newObjAppLockHash -Type NoteProperty -Name ID -Value $alID
                        $fragApplockerHash += $newObjAppLockHash
                        $fragApplockerHash | Out-File "$($secureReporOutPut)\Applocker.log" -Append 
                    }
        }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
        Loaded  dll's that are vulnerable to dll hijacking
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Searching for active processes that are vulnerable to dll hijacking"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "LoadedDLLsHijacking" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

        $getDll = Get-Process
        $fragDLLHijack=@()
        foreach ($dll in $getDll)
            {
                $procName = $dll.Name
                try 
                    {
                        $dllMods = $dll | Select-Object -ExpandProperty modules -ErrorAction Stop
                    }
                catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }

                $dllFilename = $dllMods.filename

                foreach ($dllPath in $dllFilename)
                    {
                        try
                            {
                                $dllFileAcl = Get-Acl $dllPath -ErrorAction Stop
                            }     
                        catch
                            {
                                $exceptionMessage = $_.Exception.message
                                SecureReportError($SecCheck,$exceptionMessage)        
                            }

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
                                    try
                                        {
                                            $getAuthCodeSig = Get-AuthenticodeSignature -FilePath $dllPath -ErrorAction Stop
                                            $dllStatus = $getAuthCodeSig.Status
                                        }
                                    catch
                                        {
                                            $exceptionMessage = $_.Exception.message
                                            SecureReportError($SecCheck,$exceptionMessage)        
                                        }

                                    $newObjDLLHijack = New-Object psObject
                                        Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLProcess -Value "Warning $($procName) warning"
                                        Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLPath -Value "Warning $($dllPath) warning"
                                        Add-Member -InputObject $newObjDLLHijack -Type NoteProperty -Name DLLSigStatus -Value "Warning $($dllStatus) warning"
                                    $fragDLLHijack += $newObjDLLHijack
                                    $fragDLLHijack | Out-File "$($secureReporOutPut)\DLLHijack.log" -Append 
                                }              
                     }
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                     Attack Surface Reduction (ASR)
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Attack Surface Reduction (ASR)"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "ASR" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $ASRPathtxt = "$($SecureReportConfig)\$OutConfigDir.txt"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

        try
            {        
                $getASRGuids = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ErrorAction Stop
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
             }
        <#
            - 1 (Block)
            - 0 (Off)
            - 2 (Audit)
            - 5 (Not Configured)
            - 6 (Warn)
        #>

        if ($getASRGuids -eq $null)
            {
                Set-Content -Path $ASRPathtxt -Value "ASP Policy is not set: 0"
                $getASRCont = Get-Content $ASRPathtxt | Select-String -Pattern ": 1", ": 0"
            }
        else
            {
              $getASRGuids | Out-File $ASRPathtxt
              $getASRCont = Get-Content $ASRPathtxt | Select-String -Pattern ": 1", ": 0",": 2",": 6",": 5"
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
             
                        if ($asrGuidSetting -eq "1")
                            {
                                $asrGuidSetObj = "ASR (Block) = 1"    
                            }
       
                       if ($asrGuidSetting -eq "2")
                            {
                                $asrGuidSetObj = "Warning ASR (Audit) = 2 Warning"
                            }

                       if ($asrGuidSetting -eq "5")
                            {
                                $asrGuidSetObj = "Warning ASR (Not Configured) = 5 Warning"
                            }
                       if ($asrGuidSetting -eq "6")
                            {
                                $asrGuidSetObj = "Warning ASR (Warn) = 6 Warning"
                            }
       
                       if ($asrGuidSetting -eq "0")
                            {
                                $asrGuidSetObj = "Warning ASR is disabled Warning"

                            }
                       if ($asrGuidSetting -eq $null)
                            {
                                $asrGuidSetObj = "Warning ASR is disabled Warning"
                            }

                           $ASRDescripObj = $asrDescription | Select-String -Pattern $asrGuid

                           $newObjASR = New-Object -TypeName PSObject
                               Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRGuid -Value $asrGuid
                               Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRSetting -Value $asrGuidSetObj
                               Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRDescription -Value $ASRDescripObj
                           $fragASR += $newObjASR
                           $fragASR | Out-File "$($secureReporOutPut)\ASR.log" -Append 

            }

            <# fix this compare to add missing settings that exist in the above table
            $ASRContentGuid = $getASRCont.ToString().split(":").replace(" ","")[0]
            $missingASRs = (Compare-Object $ASRList $ASRContentGuid | ?{$_.sideIndicator -eq '<='}).InputObject


            foreach ($ASRmissingItem in $missingASRs)
            {
                       $ASRDescripObj = $asrDescription | Select-String -Pattern $ASRmissingItem

                       $newObjASR = New-Object -TypeName PSObject
                       Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRGuid -Value "Warning $ASRmissingItem Warning"
                       Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRSetting -Value "Warning Is not Set Warning "
                       Add-Member -InputObject $newObjASR -Type NoteProperty -Name ASRDescription -Value "Warning $ASRDescripObj Warning"
                       $fragASR += $newObjASR

            }
            #>

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                            AutoRuns
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Auditing AutoRuns"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "Autoruns" 

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        $ASRPathtxt = "$($SecureReportConfig)\$OutConfigDir.txt"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

        $fragAutoRunsVal=@()  
        <#-------------------------------------------------
        File System
        --------------------------------------------------#>
        splatAutoRunsVar
        $hkuRunComment="Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp."

        $gtCachedProfiles = (Get-ChildItem c:\Users\ -Force -Directory).fullname
        foreach ($CachedProfiles in $gtCachedProfiles)
            {

             try
                {
                    $gtAppDataStartup = Get-ChildItem "$($CachedProfiles)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -Recurse -Force -Exclude desktop.ini -ErrorAction Stop
                }
             catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)        
                }

                foreach($AppDataStartup in $gtAppDataStartup)
                    {
                        $gthkuRunValue=""
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value ($AppDataStartup.Directory).FullName
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value ($AppDataStartup.Name) 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns 
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                    }                    
            }

            try
                {
                    $gtProgDataStartup = Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Recurse -Force -Exclude desktop.ini -ErrorAction Stop
                }
             catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)        
                }

                foreach($AppDataStartup in $gtAppDataStartup)
                    {
                        $gthkuRunValue=""
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value ($AppDataStartup.Directory).FullName
                            add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value ($AppDataStartup.Name) 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                    }

        <#-------------------------------------------------
        HK USERS
        --------------------------------------------------#>

        
        try{New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop}
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }
        $gtHKUSid = (Get-childItem HKU:\).Name 

        foreach ($HKUSidItem in $gtHKUSid)
            {
            #$HKUSidItem = "HKEY_USERS\S-1-5-21-4000739697-4006183653-2191022337-1360"

                $hkuKey = ($HKUSidItem.Split("\")[0]).replace("HKEY_USERS","HKU")
                $hkuSID = $HKUSidItem.Split("\")[1]

                splatAutoRunsVar
                $hkuRunComment="Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp."
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\run"

                try
                    {
                    $hkuRun = Get-Item $hkuRunPath  -ErrorAction Stop | select -ExpandProperty property
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem | Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append                            
                            }
                    }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }

                splatAutoRunsVar
                $hkuRunComment="Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp."
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\runonce"

                try
                    {
                        $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue| Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                            }
                    }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }


                #HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
                #$hkuUserShellFolders = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                splatAutoRunsVar
                $hkuRunComment="The following Registry keys can be used to set startup folder items for persistence: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders and HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

                try
                    {
                        $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction stop).startup #| select -ExpandProperty property 

                        $hkuRunPath = $hkuRunPath
                        $hkuRunItem = "startup"
                        $gthkuRunValue = $hkuRun

                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append                   
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }


                #HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
                #$hkuShellFolders = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                splatAutoRunsVar
                $hkuRunComment="The following Registry keys can be used to set startup folder items for persistence: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders and HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

                try
                    {
                        $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).startup #| select -ExpandProperty property 

                        $hkuRunPath = $hkuRunPath
                        $hkuRunItem = "startup"
                        $gthkuRunValue = $hkuRun

                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }
         
                #$hkuRunServiceOnce = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
                splatAutoRunsVar
                $hkuRunComment="The following Registry keys can control automatic startup of services during boot: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce and HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"

                try
                    {
                        $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem | Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider -ErrorAction SilentlyContinue).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                            }
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }
         
                #$hkuRunServices = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\RunServices"
                splatAutoRunsVar
                $hkuRunComment="The following Registry keys can control automatic startup of services during boot: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce and HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices"
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Software\Microsoft\Windows\CurrentVersion\RunServices"

                try
                    {
                        $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue | Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                            }
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }

                #HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
                #$hkuExplorRun = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                splatAutoRunsVar
                $hkuRunComment="Using policy settings to specify startup programs creates corresponding values in either of Registry key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                $hkuRunPath = "$($hkuKey):\$($hkuSID)\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

                try
                    {
                        $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue | Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                            }
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }

                #$hkuWindows = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Microsoft\Windows NT\CurrentVersion\Windows"
                splatAutoRunsVar
                $hkuRunComment="Programs listed in the load value of the registry key: HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows run when any user logs on."
                try
                    {
                        $hkuRunPath = Get-ItemProperty "$($hkuKey):\$($hkuSID)\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction Stop
                        $hkuRun = Get-Item $hkuRunPath | select -ExpandProperty property -ErrorAction SilentlyContinue
                        foreach($hkuRunItem in $hkuRun)
                            {
                                $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue | Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                                $newObjAutoRuns = New-Object -TypeName PSObject
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                                $fragAutoRunsVal += $newObjAutoRuns
                                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                            }
                     }
                 catch
                    {
                        $exceptionMessage = $_.Exception.message
                        SecureReportError($SecCheck,$exceptionMessage)        
                    }
            }

        <#-------------------------------------------------
        HK Local Machine
        --------------------------------------------------#>
        try{New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -ErrorAction Stop}
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #$hklmCVRun = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run") 
        splatAutoRunsVar
        $hkuRunComment="Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp."
        $hkuRunPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        try
            {
                $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem  -ErrorAction SilentlyContinue| Select -Property *  -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                    }
            }
            catch
                {
                    $exceptionMessage = $_.Exception.message
                    SecureReportError($SecCheck,$exceptionMessage)        
                }

        #$hklmCVRunOnce = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")
        splatAutoRunsVar
        $hkuRunComment="Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp."
        $hkuRunPath = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        try
            {
                $hkuRun = Get-Item $hkuRunPath -ErrorAction Stop | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem  -ErrorAction SilentlyContinue| Select -Property * -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                    }
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }    
    
        #Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
        splatAutoRunsVar
        $hkuRunComment="Run keys may exist under multiple hives. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a Depend key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d C:\temp\evil[.]dll"
        try
            {
            $hkuRunPath = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" -ErrorAction Stop
            $hkuRun = Get-Item $hkuRunPath | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem  -ErrorAction SilentlyContinue| Select -Property *  -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                        $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append
                    }
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }
      
        #$hklExplorShellFolders = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "common startup").'Common Startup'
        splatAutoRunsVar
        $hkuRunComment="The following Registry keys can be used to set startup folder items for persistence: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders and HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $hkuRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

        try
            {
                $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).startup #| select -ExpandProperty property 

                $hkuRunPath = $hkuRunPath
                $hkuRunItem = "startup"
                $gthkuRunValue = $hkuRun

                $newObjAutoRuns = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                $fragAutoRunsVal += $newObjAutoRuns
                $fragAutoRunsVal | Out-File "$($secureReporOutPut)\AutoRuns.log" -Append

            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }
    
        #$hklExplorShell = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "common startup").'Common Startup'
        splatAutoRunsVar
        $hkuRunComment="The following Registry keys can be used to set startup folder items for persistence: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders and HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

        $hkuRunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

        try
            {
                $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).startup #| select -ExpandProperty property 

                $hkuRunPath = $hkuRunPath
                $hkuRunItem = "startup"
                $gthkuRunValue = $hkuRun

                $newObjAutoRuns = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                $fragAutoRunsVal += $newObjAutoRuns
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #$hklmCVRunSvcOnce = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")
        splatAutoRunsVar
        $hkuRunComment="The following Registry keys can control automatic startup of services during boot:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"
        try
            {
                $hkuRunPath = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ErrorAction Stop
                
                $hkuRun = Get-Item $hkuRunPath -ErrorAction SilentlyContinue | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem  -ErrorAction SilentlyContinue| Select -Property *  -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                    }
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #$hklmCVRunSvc = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices")
        splatAutoRunsVar
        $hkuRunComment="The following Registry keys can control automatic startup of services during boot:HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices"

        try
            {
                $hkuRunPath = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" -ErrorAction Stop
                $hkuRun = Get-Item $hkuRunPath -ErrorAction SilentlyContinue | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue | Select -Property *  -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                        $newObjAutoRuns = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                            Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                        $fragAutoRunsVal += $newObjAutoRuns
                    }
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }
    
        #$hklmCVPolRun = (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
        splatAutoRunsVar
        $hkuRunComment="Using policy settings to specify startup programs creates corresponding values in either of two Registry keys: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        try
            {
                $hkuRunPath = Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -ErrorAction Stop
                $hkuRun = Get-Item $hkuRunPath -ErrorAction SilentlyContinue | select -ExpandProperty property
                foreach($hkuRunItem in $hkuRun)
                    {
                        $gthkuRunValue = (Get-ItemProperty $hkuRunPath -Name $hkuRunItem -ErrorAction SilentlyContinue | Select -Property *  -ExcludeProperty pspath,PSParentPath,PSChildName,psdrive,psprovider).$hkuRunItem 
            
                         $newObjAutoRuns = New-Object -TypeName PSObject
                             Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                             Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                             Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                             Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                         $fragAutoRunsVal += $newObjAutoRuns
                    }
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }


        #Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" 
        splatAutoRunsVar
        $hkuRunComment="The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell subkeys can automatically launch programs."
        $hkuRunPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

        try
            {
                $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).Userinit #| select -ExpandProperty property 
                $hkuRunPath = $hkuRunPath
                $hkuRunItem = "Userinit "
                $gthkuRunValue = $hkuRun

                if ($gthkuRunValue -notmatch "userinit.exe"){$gthkuRunValue = "Warning $gthkuRunValue Warning"}
    
                $newObjAutoRuns = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                $fragAutoRunsVal += $newObjAutoRuns

            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
        splatAutoRunsVar
        $hkuRunComment="The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit and HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell subkeys can automatically launch programs."
        $hkuRunPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

        try
            {
                $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).Shell #| select -ExpandProperty property 

                $hkuRunPath = $hkuRunPath
                $hkuRunItem = "Shell"
                $gthkuRunValue = $hkuRun

                if ($gthkuRunValue -notmatch "explorer.exe" ){$gthkuRunValue = "Warning $gthkuRunValue Warning"}

                $newObjAutoRuns = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                $fragAutoRunsVal += $newObjAutoRuns
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

        #(Get-ItemProperty "HKLM:\\System\CurrentControlSet\Control\Session Manager").BootExecute
        splatAutoRunsVar
        $hkuRunComment="By default, the multistring BootExecute value of the registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot."
        $hkuRunPath = "HKLM:\System\CurrentControlSet\Control\Session Manager"

        try
            {
                $hkuRun = (Get-ItemProperty $hkuRunPath -ErrorAction Stop).BootExecute #| select -ExpandProperty property 

                $hkuRunPath = $hkuRunPath
                $hkuRunItem = "BootExecute"
                $gthkuRunValue = [string]$hkuRun

                if ($gthkuRunValue -notmatch "autocheck autochk *" ){$gthkuRunValue = "Warning $gthkuRunValue Warning"}

                $newObjAutoRuns = New-Object -TypeName PSObject
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsPath -Value $hkuRunPath
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsKey -Value $hkuRunItem 
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsValue -Value $gthkuRunValue
                    Add-Member -InputObject $newObjAutoRuns -Type NoteProperty -Name AutoRunsComment -Value $hkuRunComment
                $fragAutoRunsVal += $newObjAutoRuns
            }
        catch
            {
                $exceptionMessage = $_.Exception.message
                SecureReportError($SecCheck,$exceptionMessage)        
            }

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    Windows OS SCM GPO Secuity Settings
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    #Here's 4000 lines of fun ;(
    #Unable to extract GPO settings from the SCM spreadsheet due to the numbers of inconsistencies and effort getting the spreadsheet into a workable format
    #Lastly some of the MS recommend settings are mental and would destroy the system when following blindly eg Kerberos Armouring 
    #Here are the settings that should either be set or at least acknowledged

        splatVariables
        $SecCheck = "Windows OS SCM GPO Secuity Settings"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "WindowsSCMGPOSettings"

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir)   

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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

        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
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

        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        $getWindowsOSVal=@()
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
       # try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}
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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

        if ($getWindowsOSVal -eq "0")
                {
                    $WindowsOSSet = "Zero is set for $WindowsOSDescrip allowing only Security telemtry for clients Enterprise Only - User" 
                    $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
                    $trueFalse = "True"
                }
            elseif ($getWindowsOSVal -eq "1")
                {
                    $WindowsOSSet = "One is set for $WindowsOSDescrip and the minimum for non-enterprise clients" 
                    $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
                    $trueFalse = "True"
                }
        else
                {
                    $WindowsOSSet = "Warning A setting other than 1 or 0 is set for $WindowsOSDescrip warning" 
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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

        if ($getWindowsOSVal -eq "0")
                {
                    $WindowsOSSet = "Zero is set for $WindowsOSDescrip allowing only Security telemtry for clients Enterprise Only - User" 
                    $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
                    $trueFalse = "True"
                }
            elseif ($getWindowsOSVal -eq "1")
                {
                    $WindowsOSSet = "One is set for $WindowsOSDescrip and the minimum for non-enterprise clients" 
                    $WindowsOSReg = "<div title=$gpoPath>$RegKey" +"$WindowsOSVal"
                    $trueFalse = "True"
                }
        else
                {
                    $WindowsOSSet = "Warning A setting other than 1 or 0 is set for $WindowsOSDescrip warning" 
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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
        try{$getWindowsOS = Get-Item $RegKey -ErrorAction SilentlyContinue}catch{}
        try{$getWindowsOSVal = $getWindowsOS.GetValue("$WindowsOSVal")}catch{}

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
            Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsSetting -Value $WindowsOSSet
            Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name WindowsRegValue -Value $WindowsOSReg 
            Add-Member -InputObject $newObjWindowsOS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
        $fragWindowsOSVal += $newObjWindowsOS
        $fragWindowsOSVal | Out-File "$($secureReporOutPut)\WindowsOSGPOSettings.log" -Append

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    MS Edge STIG and MS GPO Secuity Settings
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "MS Edge GPO Secuity Settings"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "MSEdgeGPOSettings"

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

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

                try {$getEdgePath = Get-Item $edgeRegPath -ErrorAction SilentlyContinue}catch{}
                try {$getEdgeValue = $getEdgePath.GetValue("$edgeRegName")}catch{} 

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
            $fragEdgeVal | Out-File "$($secureReporOutPut)\MSEdgeGPOSettings.log" -Append

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                    MS Office SCM GPO Secuity Settings
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        splatVariables
        $SecCheck = "Windows Office SCM GPO Secuity Settings"
        $exceptionMessage="No errors gathered"

        $OutConfigDir = "MSOfficeSCMGPOSettings"

        $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"

        #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
        TestConfigOutputPath($OutConfigDir) 

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
                try{$getOfficeValue = $getOfficePath.GetValue("$OfficeRegName")}catch{}

                #defaulf behaviour is disabled even with gpo set so reg value is not created
                if ($OfficeRegName -eq "allowdde" -and $getOfficeValue -eq $null){$getOfficeValue = "0"}
                if ($OfficeRegName -eq "runprograms" -and $getOfficeValue -eq $null){$getOfficeValue = "0"}

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
        $fragOfficeVal | Out-File "$($secureReporOutPut)\MSOfficeGPOSettings.log" -Append


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
            SERVER SPECIFIC TESTS
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                  "Auditing SQL Server"
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    splatVariables
    $SecCheck = "Auditing SQL Server"
    $exceptionMessage="No errors gathered"

    $OutConfigDir = "SQLAudit"

    $SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"	
    $UnQuotedPathLog = "$($SecureReportConfig)\$($OutConfigDir).log"

    $SQLAuditPath = "$($secureReporOutPut)\$($OutConfigDir)"

    #$SecureReportConfig = "$($secureReporOutPut)\$($OutConfigDir)"
    TestConfigOutputPath($OutConfigDir)         
    
    try
        {
            $MSSlSvc = Get-Service -ErrorAction Stop | where {$_.Name -like "*SQL*"}
            $SQLSrvVersion = (& sqlcmd -W -Q "set NOCOUNT ON;select  @@VERSION as [SQL Server version]")[2] }
    catch
        {
            $exceptionMessage = $_.Exception.message
            SecureReportError($SecCheck,$exceptionMessage)   
            Write-host "SQL Server may not be present or is inaccessible" -ForegroundColor Cyan                 
        }

    if ($MSSlSvc -match "SQL" -and $SQLSrvVersion -ne $null)
        {
            $secureReport = "C:\SecureReport"
            $OutConfigDir = "SQLAudit"  

            $tpSec10 = Test-Path "C:\SecureReport\output\$OutConfigDir\"
    
            if ($tpSec10 -eq $false)
                {
                    New-Item -Path "C:\SecureReport\output\$OutConfigDir\" -ItemType Directory -Force
                }
    
            $SQLAuditPath = "C:\SecureReport\output\$OutConfigDir\"

            $fragSQLVer=@()
            $fragSQLDB =@()
            $fragSQLSvc=@()
            $fragCISSQL=@()
            #Get Basic SQL Version data
            $SQLSrvVersion = (& sqlcmd -W -Q "set NOCOUNT ON;select  @@VERSION as [SQL Server version]")[2]
            $SQLSrvEdt = (& sqlcmd -W -Q "set NOCOUNT ON;select SERVERPROPERTY('EDITION') as [SQL Server Edition]")[2]
            $SQLSrvSp = (& sqlcmd -W -Q "set NOCOUNT ON;select SERVERPROPERTY('PRODUCTLEVEL') as [Service Pack]")[2]
            $SQLSrvProdVer = (& sqlcmd -W -Q "set NOCOUNT ON;select SERVERPROPERTY('PRODUCTVERSION') as [Version]")[2]
            $SQLSrvColl = (& sqlcmd -W -Q "set NOCOUNT ON;select SERVERPROPERTY('COLLATION') as [Collation]")[2]

            $newObjSQLVer = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLVer -Type NoteProperty -Name SQLSrvVersion -Value $SQLSrvVersion
                Add-Member -InputObject $newObjSQLVer -Type NoteProperty -Name SQLSrvEdition -Value $SQLSrvEdt
                Add-Member -InputObject $newObjSQLVer -Type NoteProperty -Name SQLSrvSP -Value $SQLSrvSp
                Add-Member -InputObject $newObjSQLVer -Type NoteProperty -Name SQLSrvProdVersion -Value $SQLSrvProdVer
                Add-Member -InputObject $newObjSQLVer -Type NoteProperty -Name SQLSrvCollation -Value $SQLSrvColl
            $fragSQLVer +=  $newObjSQLVer

            #Get SQL Path Locations
            $SQLDB_Path = & sqlcmd -s"," -W -Q "set NOCOUNT ON;SELECT
	            mdf.type_desc,
	            mdf.name,
	            mdf.physical_name as data_file,
	            ldf.physical_name as log_file,
	            db_size = CAST((mdf.size * 8.0)/1024 AS DECIMAL(8,2)),
	            log_size = CAST((ldf.size * 8.0)/1024 AS DECIMAL(8,2)),
	            mdf.state_desc
            FROM (SELECT * FROM sys.master_files WHERE type_desc = 'ROWS') mdf
            join (SELECT * FROM sys.master_files WHERE type_desc = 'LOG') ldf
            on mdf.database_id = ldf.database_id"

            $SQLDB_Info = ($SQLDB_Path.replace("-","").replace(",,,,,,","").replace("type_desc,name,data_file,log_file,db_size,log_size,state_desc","")) | ?{$_.trim() -ne ""}

            foreach ($SQLDB_Item in $SQLDB_Info)
                {
                    $SQLDB_Name = $SQLDB_Item.split(",")[1]
                    $SQLDB_MDF = if ($SQLDB_Item.split(",")[2] -match 'c:'){"Warning $($SQLDB_Item.split(",")[2]) Warning"}else{"$($SQLDB_Item.split(",")[2])"}
                    $SQLDB_LDF = if ($SQLDB_Item.split(",")[3] -match 'c:'){"warning $($SQLDB_Item.split(",")[3]) Warning"}else{"$($SQLDB_Item.split(",")[3])"}
                    $SQLDB_DBSize = $SQLDB_Item.split(",")[4]
                    $SQLDB_LDFSize = $SQLDB_Item.split(",")[5]
                    $SQLDB_Status = $SQLDB_Item.split(",")[6]   
        
                    $newObjSQLDB = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseName -Value $SQLDB_Name
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseMDF -Value $SQLDB_MDF
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseLDF -Value $SQLDB_LDF
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseDBSize -Value $SQLDB_DBSize
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseLDFSize -Value $SQLDB_LDFSize
                        Add-Member -InputObject $newObjSQLDB -Type NoteProperty -Name DataBaseStatus -Value $SQLDB_Status
                    $fragSQLDB +=  $newObjSQLDB             
                }

    <#
           SQL SERVICE ACCOUNTS
    #>
            $SQLDBSvc = Get-Service | where {$_.DisplayName -like "*SQL*"} 

            foreach($SQLDBSvcItem in $SQLDBSvc)
                {
                    $SQLSvcName = $SQLDBSvcItem.Name
                    $SQLSvcDetails = gwmi Win32_service -Filter "name='$SQLSvcNAme'" | Select-Object Name,PathName,StartMode,Caption,startName,State
                    $SQLSvc_name = $SQLSvcDetails.Name
                    $SQLSvc_pathname = if ($SQLSvcDetails.PathName -match "c:" `
                         -and $SQLSvcDetails.PathName -notmatch "sqlwriter.exe" `
                         -and $SQLSvcDetails.PathName -notmatch "sqlbrowser.exe")
                         {"Warning $($SQLSvcDetails.PathName) Warning"}else{"$($SQLSvcDetails.PathName)"}
                    $SQLSvc_startmode = $SQLSvcDetails.StartMode
                    $SQLSvc_caption = $SQLSvcDetails.Caption
                    $SQLSvc_state = $SQLSvcDetails.State

                    $newObjSQLSvc = New-Object -TypeName PSObject
                        Add-Member -InputObject $newObjSQLSvc -Type NoteProperty -Name SQLSvcName -Value $SQLSvc_name
                        Add-Member -InputObject $newObjSQLSvc -Type NoteProperty -Name SQLSvcPath -Value $SQLSvc_pathname
                        Add-Member -InputObject $newObjSQLSvc -Type NoteProperty -Name SQLSvcStartMode -Value $SQLSvc_startmode
                        Add-Member -InputObject $newObjSQLSvc -Type NoteProperty -Name SQLSvcCaption -Value $SQLSvc_caption 
                        Add-Member -InputObject $newObjSQLSvc -Type NoteProperty -Name SQLSvcState -Value $SQLSvc_state
                    $fragSQLSvc += $newObjSQLSvc
                }
     <#
           SQL SERVER CIS BENCHMARKS
    #>

            #list all databases by name
            $SQLDB_Names = (& sqlcmd -s"," -W -Q "set NOCOUNT ON;SELECT mdf.name FROM (SELECT * FROM sys.master_files WHERE type_desc = 'ROWS') mdf") #[7..10000]
            $SQLDB_Names = $SQLDB_Names | where {$_ -ne "MSDBData" -and $_ -ne "master" -and $_ -ne "tempdev" -and $_ -ne "temp2" -and $_ -ne "temp3" -and $_ -ne "modeldev" -and $_ -ne "name" -and $_ -ne "----"}

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"

            $SQLCIS_Comment = "This feature can be used to remotely access and exploit vulnerabilities on remote SQL Server instances andto run unsafe Visual Basic for Application functions"
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure}
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$SQLCIS_res have been found" 
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title 
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'CLR Enabled' Server Configuration Option is set to '0' - per Database "
            <#--------------------------------------#>
                Foreach($DBName_item in $SQLDB_Names)
                    {
                       $sqlVuln = "set NOCOUNT ON; use $DBName_item;SELECT name AS Assembly_Name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1;"

                        $SQLCIS_Comment = "If CLR assemblies are in use, applications may need to be rearchitected to eliminate their usage before disabling this setting. Alternatively, some organizations may allow this setting to be enabled 1 for assemblies created with the SAFE permission set, but disallow assemblies created with the riskier UNSAFE and EXTERNAL_ACCESS permission sets"
                        $SQLCIS_Secure = "Doesn't return 1"

                        $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                        $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match "1"}

                            if ($SQLCIS_res -match "1" -and $SQLCIS_res -like "*context to '*'")
                                {
                                    $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                    #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                    $SQLCIS_Config = $DBName_item + " is " + $SQLCIS_res  
                                    $SQLCIS_InUse = $DBName_item + " is " + $SQLCIS_res 
                                    $SQLCIS_Secure = $SQLCIS_Secure
                                    $SQLCIS_Comment = $SQLCIS_Comment
                                    $trueFalse = "False"  
                                }
                            else
                                {
                                    $SQLCIS_Title = $SQLCIS_Title
                                    #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                    $SQLCIS_Config = ("$($DBName_item) with value of $($SQLCIS_res ) (can be null)").Replace("Changed database context to '$($DBName_item)'.","")
                                    $SQLCIS_InUse = ("$($DBName_item) with value of $($SQLCIS_res ) (can be null)").Replace("Changed database context to '$($DBName_item)'.","")
                                    $SQLCIS_Secure = $SQLCIS_Secure
                                    $SQLCIS_Comment = $SQLCIS_Comment
                                    $trueFalse = "True"  
                                 }
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'clr strict security' Server Configuration Option is set to '1'"
            <#--------------------------------------#>

                $sqlVuln = "set NOCOUNT ON; SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'clr strict security';"

                $SQLCIS_Comment = "Enabling use of CLR assemblies widens the attack surface of SQL Server and puts it at risk from both inadvertent and malicious assemblies. f clr strict securityis set to 1this recommendation is not applicable. By default, clr strict securityis enabled and treats SAFEand EXTERNAL_ACCESSassemblies as if they were marked UNSAFE."
                $SQLCIS_Secure = "1,1"

                $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln)
                $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                    if ($SQLCIS_res -match $SQLCIS_Secure)
                        {
                            $SQLCIS_Title = $SQLCIS_Title
                            #$SQLCIS_Vuln = "'clrstrict security' Server Configuration is enabled"
                            $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                            $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                            $trueFalse = "True"  
                        }
                    elseif ($SQLCIS_res -eq $null)
                        {
                            $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                            #$SQLCIS_Vuln = "'clrstrict security' Server Configuration is enabled"
                            $SQLCIS_Config = "Null"
                            $SQLCIS_InUse = "Null"
                            $trueFalse = "False" 
                        }
                    else
                        {
                             $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                             #$SQLCIS_Vuln = "'clrstrict security' Server Configuration is enabled"
                             $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                             $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                             $trueFalse = "False"  
                        }
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
        

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'CLR Enabled' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'CLR Enabled';"
 
            $SQLCIS_Comment = "Enabling use of CLR assemblies widens the attack surface of SQL Server and puts it at risk from both inadvertent and malicious assemblies. Both value columns must show 0 to be compliant"
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = $SQLCIS_Check[2]
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $($SQLCIS_Title) Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining';"
 
            $SQLCIS_Comment = "When enabled, this option allows a member of the db_owner role in a database to gain access to objects owned by a login in any other database, causing an unnecessary information disclosure. When required, cross-database ownership chaining should only be enabled for the specific databases requiring it instead of at the instance level for all databases by using the ALTER DATABASE<database_name>SET DB_CHAINING ON command. This database option may not be changed on the master, model, or tempdbsystem databases"
            $SQLCIS_Secure = "0,0"

            "Test - EXECUTE sp_configure 'cross db ownership chaining', 0;RECONFIGURE;GO"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln)
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure}  
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        $SQLCIS_Vuln = $SQLCIS_res
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        $SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Database Mail XPs' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs';"
 
            $SQLCIS_Comment = "Disabling the Database Mail XPs option reduces the SQL Server surface, eliminates a DOS attack vector and channel to exfiltrate data from the database server to a remote host"
            $SQLCIS_Secure = "0,0"

            "Test - EXECUTE sp_configure 'cross db ownership chaining', 0;RECONFIGURE;GO"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0' "
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
 
            $SQLCIS_Comment = "Enabling this option will increase the attack surface of SQL Server and allow users to execute functions in the security context of SQL Server"
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Remote Access' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote access';"
 
            $SQLCIS_Comment = "Functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target."
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else 
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res
                        $SQLCIS_InUse = $SQLCIS_res
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote admin connections'AND SERVERPROPERTY('IsClustered') = 0;"
 
            $SQLCIS_Comment = "The Dedicated Administrator Connection (DAC) lets an administrator access a running server to execute diagnostic functions or Transact-SQL statements, or to troubleshoot problems on the server, even when the server is locked or running in an abnormal state and not responding to a SQL Server Database Engine connection. In a cluster scenario, the administrator may not actually be logged on to the same node that is currently hosting the SQL Server instance and thus is considered remote. Therefore, this setting should usually be enabled (1) for SQL Server failover clusters; otherwise, it should be disabled (0) which is the default"
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure -or $SQLCIS_Check -match "1,1"} 
                if ($SQLCIS_Check -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = [string]$SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = [string]$SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "True"        
                    }
                elseif ($SQLCIS_Check -match "1,1")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = [string]$SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = [string]$SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "False"
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = [string]$SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = [string]$SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'scan for startup procs';"
 
            $SQLCIS_Comment = "The scan for startup procs option, if enabled, causes SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Enforcing this control reduces the threat of an entity leveraging these facilities for malicious purposes."
            $SQLCIS_Secure = "0,0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = [string]$SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = [string]$SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = [string]$SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = [string]$SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Trustworthy' Database Property is set to 'Off'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';"
 
            $SQLCIS_Comment = "The TRUSTWORTHY database option allows database objects to access objects in other databases under certain circumstances. Provides protection from malicious CLR assemblies or extended procedures."
            $SQLCIS_Secure = "0"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        $SQLCIS_Vuln = $SQLCIS_Check[2..1000] -join ", " 
                        $SQLCIS_Config = $SQLCIS_Check[2..1000] -join ", " 
                        $SQLCIS_InUse = $SQLCIS_Check[2..1000] -join ", " 
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        $SQLCIS_Vuln = ""
                        $SQLCIS_Config = "$($SQLCIS_Check[2])"
                        $SQLCIS_InUse = "$($SQLCIS_Check[2])"
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure SQL Server is configured to use non-standard ports"
            <#--------------------------------------#>

            $sqlVuln = "SELECT registry_key, value_name, value_data FROM sys.dm_server_registry WHERE value_name like '%Tcp%';" # and value_data='1433';"
 
            $SQLCIS_Comment = "Using a non-default port helps protect the database from attacks directed to the default port."
            $SQLCIS_Secure = "No port should equal 1433"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check -match "1433")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        [string]$SQLCIS_Vuln = "$($SQLCIS_Check[2].split("\")[8]) ;$($SQLCIS_Check[3].split("\")[8]); $($SQLCIS_Check[4].split("\")[8]); $($SQLCIS_Check[5].split("\")[8]); $($SQLCIS_Check[6].split("\")[8]); $($SQLCIS_Check[6].split("\")[8])" 
                        [string]$SQLCIS_Config = "$($SQLCIS_Check[2].split("\")[8]) ;$($SQLCIS_Check[3].split("\")[8]); $($SQLCIS_Check[4].split("\")[8]); $($SQLCIS_Check[5].split("\")[8]); $($SQLCIS_Check[6].split("\")[8]); $($SQLCIS_Check[6].split("\")[8])"  
                        [string]$SQLCIS_InUse = "$($SQLCIS_Check[2].split("\")[8]) ;$($SQLCIS_Check[3].split("\")[8]); $($SQLCIS_Check[4].split("\")[8]); $($SQLCIS_Check[5].split("\")[8]); $($SQLCIS_Check[6].split("\")[8]); $($SQLCIS_Check[6].split("\")[8])" 
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        $SQLCIS_Vuln = ""
                        $SQLCIS_Config = "$($SQLCIS_Check[2].split("\")[8]) ;$($SQLCIS_Check[3].split("\")[8]); $($SQLCIS_Check[4].split("\")[8]); $($SQLCIS_Check[5].split("\")[8]); $($SQLCIS_Check[6].split("\")[8]); $($SQLCIS_Check[6].split("\")[8])"  
                        $SQLCIS_InUse = "$($SQLCIS_Check[2].split("\")[8]) ;$($SQLCIS_Check[3].split("\")[8]); $($SQLCIS_Check[4].split("\")[8]); $($SQLCIS_Check[5].split("\")[8]); $($SQLCIS_Check[6].split("\")[8]); $($SQLCIS_Check[6].split("\")[8])"  
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;DECLARE @getValue INT;
            EXEC master.sys.xp_instance_regread
            @rootkey = N'HKEY_LOCAL_MACHINE',
            @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
            @value_name = N'HideInstance',
            @value = @getValue OUTPUT;SELECT @getValue;"
 
            $SQLCIS_Comment = "Non-clustered SQL Server instances within production environments should be designated as hidden to prevent advertisement by the SQL Server Browser service. Designating production SQL Server instances as hidden leads to a more secure installation because they cannot be enumerated. However, clustered instances may break if this option is selected"
            $SQLCIS_Secure = "1"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure the 'sa' Login Account is set to 'Disabled'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01"
 
            $SQLCIS_Comment = "An is_disabled value of 0indicates the login is currently enabled and therefore needs remediation. The sa account is a widely known and often widely used SQL Server account with sysadmin privileges. This is the original login created during installation and always has the principal_id=1and sid=0x01.Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal"
            $SQLCIS_Secure = "sa,1"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[0]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[1]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = ""
                        try{$SQLCIS_Config = $SQLCIS_res.split(",")[0]}catch{}
                        try{$SQLCIS_InUse = $SQLCIS_res.split(",")[1]}catch{}
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure the 'sa' Login Account has been renamed"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name FROM sys.server_principals WHERE sid = 0x01;"
 
            $SQLCIS_Comment = "It is more difficult to launch password-guessing and brute-force attacks against the salogin if the name is not known."
            $SQLCIS_Secure = "Not sa"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match "sa"} 
                if ($SQLCIS_res -match "sa")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[0]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[1]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[0]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[1]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure no login exists with the name 'sa'"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT principal_id, name FROM sys.server_principals WHERE name = 'sa';"
            $SQLCIS_Comment = "The sa login (e.g. principal) is a widely known and often widely used SQL Server account. Therefore, there should not be a login called saeven when the original salogin (principal_id = 1) has been renamed"

            $SQLCIS_Secure = "Not sa"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match "sa"} 
                if ($SQLCIS_res -match "sa")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2].split(",")[1]) has been found"
                        $SQLCIS_Config = $SQLCIS_res.split(",")[0]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[1]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_res.split(",")[0]
                        $SQLCIS_InUse = $SQLCIS_res.split(",")[1]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, containment, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 and is_auto_close_on = 1;"
 
            $SQLCIS_Comment = "Because authenticationof users for contained databases occurs within the database not at the server\instance level, the database must be opened every time to authenticate a user. The frequent opening/closing of the database consumes additional server resources and may contribute to a denial of service"
            $SQLCIS_Secure = "contained = 1, auto_close = 0 - null is acceptable"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        $SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure CONNECT permissions on the 'guest' user is Revoked within all SQL Server databases"
            <#--------------------------------------#>
                $SQLCIS_Comment = "A login assumes the identity of the guestuser when a login has access to SQL Server but does not have access to a database through its own account and the database has a guestuser account. Revoking the CONNECTpermission for the guestuser will ensure that a login is not able to access database information without explicit access to do so" 
                $SQLCIS_Secure = "Null"

                Foreach($DBName_item in $SQLDB_Names)
                    {
                       $sqlVuln = "set NOCOUNT ON; use $DBName_item;
                        Go
                        Select DB_Name() as DatabaseName, 'guest' as Database_User,
                        [permission_name], [state_desc]
                        from sys.database_permissions
                        where [grantee_principal_id] = Database_Principal_id('guest')
                        and [state_desc] like 'grant%'
                        and [permission_name] = 'connect'
                        and DB_Name() not in ('master','tempdb','msdb','MSDBData')";

                        $SQLCIS_Secure = "Null"
                               $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                                if ($SQLCIS_Check[3] -ne $null)
                                    {
                                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                        #$SQLCIS_Vuln = "Guest is granted connect permissions to $DBName_item"
                                        $SQLCIS_Config = "$($DBName_item) $($SQLCIS_Check[3])" 
                                        $SQLCIS_InUse = "$($DBName_item) $($SQLCIS_Check[3])" 
                                        #$SQLCIS_Secure = "should return null"
                                        $trueFalse = "False"  
                                    }
                                else
                                    {
                                        $SQLCIS_Title = $SQLCIS_Title
                                        #$SQLCIS_Vuln = "Guest is revoked connect permissions to $DBName_item "
                                        $SQLCIS_Config = "$($DBName_item) $($SQLCIS_Check[3])" 
                                        $SQLCIS_InUse = "$($DBName_item) $($SQLCIS_Check[3])" 
                                        #$SQLCIS_Secure = "should return null"
                                        $trueFalse = "True"  
                                     }
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode' "
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];"

            $SQLCIS_Comment = "Windows provides a more robust authentication mechanism than SQL Server authentication."
            $SQLCIS_Secure = "1"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
            $SQLCIS_res = ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure} 
                if ($SQLCIS_res -match $SQLCIS_Secure)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        $SQLCIS_Vuln = "$($SQLCIS_Check[2]) has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[2])"
                        $SQLCIS_InUse = "$($SQLCIS_Check[2])"
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        $SQLCIS_Vuln = "Windows Authentiacation is set"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Orphaned Users' are Dropped From SQL Server Databases"
            <#--------------------------------------#>
            #not tested as working
                Foreach($DBName_item in $SQLDB_Names)
                    {
                        $sqlVuln = "set NOCOUNT ON; use $DBName_item; 
                        EXEC sp_change_users_login @Action='Report';"

                        $SQLCIS_Comment = "A database user for which the corresponding SQL Server login is undefined or is incorrectly defined on a server instance cannot log in to the instance and is referred to as orphaned and should be removed. Orphan users should be removed to avoid potential misuse of those broken users in any way."
                        $SQLCIS_Secure = "Null"

                            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                            if ($SQLCIS_Check[3] -ne $null)
                                {
                                    $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                    #$SQLCIS_Vuln = "'Orphaned Users' are available on $DBName_item"
                                    $SQLCIS_Config = "$($DBName_item) $($SQLCIS_Check[3])"
                                    $SQLCIS_InUse = "$($DBName_item) $($SQLCIS_Check[3])"
                                    $trueFalse = "False"  
                                }
                            else
                                {
                                    $SQLCIS_Title = $SQLCIS_Title
                                    #$SQLCIS_Vuln = "'Orphaned Users' aren't available on $DBName_item "
                                    $SQLCIS_Config = "$($DBName_item) $($SQLCIS_Check[3])"
                                    $SQLCIS_InUse = "$($DBName_item) $($SQLCIS_Check[3])"
                                    $trueFalse = "True"  
                                 }
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure SQL Authentication is not used in contained databases"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name AS DBUser FROM sys.database_principals WHERE name NOT IN ('dbo','Information_Schema','sys','guest') AND type IN ('U','S','G') AND authentication_type = 2;"

            $SQLCIS_Comment = "Contained databases do not enforce password complexity rules for SQL Authenticated users.The absence of an enforced password policy may increase the likelihood of a weak credential being established in a contained database"
            $SQLCIS_Secure = "1"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2]) has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[2])"
                        $SQLCIS_InUse = "$($SQLCIS_Check[2])"
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "SQL Authentication is not used in contained databases"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure only the default permissions specified by Microsoft are granted to the public server role"
            <#--------------------------------------#>
            <#
            use master
            go
            grant create database to public;
            go
            #>

            $sqlVuln = "set NOCOUNT ON;SELECT * FROM master.sys.server_permissions WHERE (grantee_principal_id= SUSER_SID(N'public') and state_desc LIKE 'GRANT%')AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2)AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3)AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4)AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);"

            $SQLCIS_Comment = "Every SQL Server login belongs to the publicrole and cannot be removed from this role. Therefore, any permissions granted to this role will be available to all logins unless they have beenexplicitly denied to specific logins or user-defined server roles"
            $SQLCIS_Secure = "Null"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "$($SQLCIS_Check[2]) has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[3])"
                        $SQLCIS_InUse = "$($SQLCIS_Check[4])"
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = "Public has the default read permissions"
                        $SQLCIS_Config = "Null"
                        $SQLCIS_InUse = "Null"
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure Windows BUILTIN groups are not SQL Logins"
            <#--------------------------------------#>
            $hn = "'$($env:COMPUTERNAME)%'"

            $sqlVuln = "SELECT pr.[name], pe.[permission_name], pe.[state_desc] 
            FROM sys.server_principals pr JOIN sys.server_permissions pe ON pr.principal_id = pe.grantee_principal_id WHERE pr.name like $hn;"

            $SQLCIS_Comment = "Local or builtin accounts shouldn't have access to SQL"
            $SQLCIS_Secure = "Null"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2].split(",")[1] -ne $null -and $SQLCIS_Check[1].split(",")[1] -ne "----------")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = $SQLCIS_Check[2].Split('\')[1] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2].Split('\')[1]
                        $SQLCIS_InUse = $SQLCIS_Check[2].Split('\')[1]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title 
                        #$SQLCIS_Vuln = "Local or builtin accounts don't have access to SQL"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure Windows local groups are not SQL Logins"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT pr.[name] AS LocalGroupName, 
            pe.[permission_name], 
            pe.[state_desc]FROM sys.server_principals pr
            JOIN sys.server_permissions pe
            ON pr.[principal_id] = pe.[grantee_principal_id]WHERE pr.[type_desc] = 'WINDOWS_GROUP';"
 
            $SQLCIS_Comment = "Local Windows groups should not be used as logins for SQL Server instances. Allowing local Windows groups as SQL Logins provides a loophole whereby anyone with OS level administrator rights (and no SQL Server rights) could add users to the local Windows groups and thereby give themselves or others access to the SQL Server instance"
            $SQLCIS_Secure = "contained = 1, auto_close = 0 - null is acceptable"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                       # $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[2]); $($SQLCIS_Check[3]);$($SQLCIS_Check[2]); $($SQLCIS_Check[4]); $($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7]);"
                        $SQLCIS_InUse = "$($SQLCIS_Check[2]); $($SQLCIS_Check[3]);$($SQLCIS_Check[2]); $($SQLCIS_Check[4]); $($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7]);"
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse 
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure the public role in the msdb database is not granted access to SQL Agent proxies"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;USE [msdb];
            SELECT sp.name AS proxyname
            FROM dbo.sysproxylogin spl
            JOIN sys.database_principals dp
            ON dp.sid = spl.sid
            JOIN sysproxies sp
            ON sp.proxy_id = spl.proxy_id
            WHERE principal_id = USER_ID('public');
            "
 
            $SQLCIS_Comment = "Granting access to SQL Agent proxies for the publicrole would allow all users to utilize the proxy which may have high privileges. This would likely break the principle of least privileges."
            $SQLCIS_Secure = "Null"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[3] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                       # $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[3]
                        $SQLCIS_InUse = $SQLCIS_Check[3]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[3]
                        $SQLCIS_InUse = $SQLCIS_Check[3]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name ,CAST(LOGINPROPERTY(log.name, N'IsMustChange') AS bit) AS [MustChangePassword]FROM sys.server_principals AS log WHERE type = 'S';"
 
            $SQLCIS_Comment = "Enforcing a password change after a reset or new login creation will prevent the account administrators or anyone accessing the initial password from misuse of the SQL login created without being noticed"
            $SQLCIS_Secure = "Null - shows the first 3 only"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2..10] -match "0")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                       # $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7])"  #filtered out ##MS_PolicyEventProcessingLogin##,0 ##MS_PolicyTsqlExecutionLogin##,0
                        $SQLCIS_InUse = "$($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7])"
                        $trueFalse = "False"        
                    }
                 else 
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = "$($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7])" #-match "0"
                        $SQLCIS_InUse = "$($SQLCIS_Check[5]); $($SQLCIS_Check[6]); $($SQLCIS_Check[7])"
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role"
            <#--------------------------------------#>

            $sqlVuln = "SELECT l.[name], 'sysadmin membership' AS 'Access_Method'FROM sys.sql_logins AS l 
            WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1 AND l.is_expiration_checked <> 1
            UNION ALL SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
            FROM sys.sql_logins AS l JOIN sys.server_permissions AS p
            ON l.principal_id = p.grantee_principal_id WHERE p.type = 'CL' AND p.state IN ('G', 'W')AND l.is_expiration_checked <> 1;"
 
            $SQLCIS_Comment = "Ensuring SQL logins comply with the secure password policy applied by the Windows Server Benchmark will ensure the passwords for SQL logins with sysadminprivileges are changed on a frequent basis to help prevent compromise via a brute force attack. CONTROL SERVERis an equivalent permission to sysadminand logins with that permission should also be required to have expiring passwords."
            $SQLCIS_Secure = "null, shows only the first 3 accounts"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"        
                    }
                 else 
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins"
            <#--------------------------------------#>

            $sqlVuln = "set NOCOUNT ON;SELECT name, is_disabled FROM sys.sql_logins WHERE is_policy_checked = 0;"
 
            $SQLCIS_Comment = "Ensure SQL authenticated login passwords comply with the secure password policy applied by the Windows Server Benchmark so that they cannot be easily compromised via brute force attack"
            $SQLCIS_Secure = "null, shows only the first 3 accounts"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2] -ne $null)
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                       # $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = "$($SQLCIS_Check[2]); $($SQLCIS_Check[3]); $($SQLCIS_Check[4])"
                        $SQLCIS_InUse = "$($SQLCIS_Check[2]); $($SQLCIS_Check[3]); $($SQLCIS_Check[4])"
                        $trueFalse = "False"        
                    }
                 else 
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS


            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Maximum number of error log files' is set to greater than or equal to '12' "
            <#--------------------------------------#>

            $sqlVuln = "DECLARE @NumErrorLogs int;
            EXEC master.sys.xp_instance_regread
            N'HKEY_LOCAL_MACHINE',
            N'Software\Microsoft\MSSQLServer\MSSQLServer',
            N'NumErrorLogs',
            @NumErrorLogs OUTPUT;
            SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];"
 
            $SQLCIS_Comment = "SQL Server error log files must be protected from loss. The log files must be backed up before they are overwritten. Retaining more error logs helps prevent loss from frequent recycling before backups can occur.The SQL Server error log contains important information about major server events and login attempt information as well."
            $SQLCIS_Secure = "12 or greater than 12 log files"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                #when not configured with explicit number of logs, RegQueryValueEx() returned error 2, 'The system cannot find the file specified is returned in line 0. 
                #This would idicate the default number of logs is configured of 6 
                if ($SQLCIS_Check[2] -le "12" -or $SQLCIS_Check -match "-1")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                       # $SQLCIS_Vuln = $SQLCIS_Check[2] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[3]
                        $SQLCIS_InUse = $SQLCIS_Check[3]
                        $trueFalse = "False"        
                    }
                 else 
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = ""
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Default Trace Enabled' Server Configuration Option is set to '1'"
            <#--------------------------------------#>

            $sqlVuln = "SELECT name, 
                CAST(value as int) as value_configured,       
                CAST(value_in_use as int) as value_in_use 
                FROM sys.configurations 
                WHERE name = 'default trace enabled'; "
 
            $SQLCIS_Comment = "The default trace provides audit logging of database activity including account creations, privilege elevation and execution of DBCC commands. Default trace provides valuable audit information regarding security-related activities on the server."
            $SQLCIS_Secure = "1,1"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if (ForEach-Object {$SQLCIS_Check -match $SQLCIS_Secure})
                    {
                        $SQLCIS_Title = "$SQLCIS_Title"
                        #$SQLCIS_Vuln = $SQLCIS_Check[2].Split('\')[1] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2].split(",")[1]
                        $SQLCIS_InUse = $SQLCIS_Check[2].split(",")[2]
                        $trueFalse = "True"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "Local or builtin accounts don't have access to SQL"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Login Auditing' is set to 'failed logins'"
            <#--------------------------------------#>

            $sqlVuln = "EXEC xp_loginconfig 'audit level';"
 
            $SQLCIS_Comment = "At a minimum, we want to ensure failed logins are captured in order to detect if an adversary is attempting to brute force passwords or otherwise attempting to access a SQL Server improperly."
            $SQLCIS_Secure = "audit level,failure"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[2].split(",")[1] -ne "failure")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = $SQLCIS_Check[2].Split('\')[1] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title 
                        #$SQLCIS_Vuln = "Local or builtin accounts don't have access to SQL"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'SQL Server Audit' is set to capture both 'failed' and 'successful logins"
            <#--------------------------------------#>

            $sqlVuln = "SELECT
            S.name AS 'Audit Name'  
            , CASE S.is_state_enabled  
            WHEN 1 THEN 'Y' 
            WHEN 0 THEN 'N' END AS 'Audit Enabled'  
             , S.type_desc AS 'Write Location'  
             , SA.name AS 'Audit Specification Name'  
             , CASE SA.is_state_enabled  WHEN 1 THEN 'Y'  
            WHEN 0 THEN 'N' END AS 'Audit Specification Enabled'  
             , SAD.audit_action_name  
             , SAD.audited_result 
            FROM sys.server_audit_specification_details AS SAD  
             JOIN sys.server_audit_specifications AS SA  
            ON SAD.server_specification_id = SA.server_specification_id  
             JOIN sys.server_audits AS S  ON SA.audit_guid = S.audit_guid 
            WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD') or (SAD.audit_action_id IN ('DAGS', 'DAGF') and (select count(*) from sys.databases where 
            containment=1) > 0);"
 
            $SQLCIS_Comment = "By utilizing Audit instead of the traditional setting under the Security tab to capture successful logins, we reduce the noise in the ERRORLOG. This keeps it smaller and easier to read for DBAs who are attempting to troubleshoot issues with the SQL Server. Also, the Audit object can write to the security event log, though this requires operating system configuration. This gives an additional option for where to store login events, especially in conjunction with an SIEM. The result set should contain 5 rows, one for each of the following audit_action_names: 
            • AUDIT_CHANGE_GROUP • FAILED_LOGIN_GROUP • SUCCESSFUL_LOGIN_GROUP • SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP • FAILED_DATABASE_AUTHENTICATION_GROUP"

            $SQLCIS_Secure = "The result set should contain 5 rows, one for each of the following audit_action_names:"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check -match "AUDIT_CHANGE_GROUP,SUCCESS AND FAILURE" -and $SQLCIS_Check -match "FAILED_LOGIN_GROUP,SUCCESS AND FAILURE" -and $SQLCIS_Check -match "SUCCESSFUL_LOGIN_GROUP,SUCCESS AND FAILURE" )
                    {
                        $SQLCIS_Title = $SQLCIS_Title
                        #$SQLCIS_Vuln = $SQLCIS_Check[2].Split('\')[1] + " has been found"
                        $SQLCIS_Config = "Execute command to see details"
                        $SQLCIS_InUse = "Execute command to see details"
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = "Local or builtin accounts don't have access to SQL"
                        $SQLCIS_Config = ""
                        $SQLCIS_InUse = ""
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies - per Database "
            <#--------------------------------------#>

                Foreach($DBName_item in $SQLDB_Names)
                    {
                       $sqlVuln = "set NOCOUNT ON; use $DBName_item;SELECT name,permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1 AND name <> 'Microsoft.SqlServer.Types';"

                        $SQLCIS_Comment = "Setting CLR Assembly Permission Sets to SAFE_ACCESS will hinder assemblies from accessing external system resources such as files, the network, environment variables, or the registry. Assemblies with EXTERNAL_ACCESS or UNSAFE permission sets can be used to access sensitive areas of the operating system, steal and/or transmit data and alter the state and other protection measures of the underlying Windows Operating System. Assemblies which are Microsoft-created (is_user_defined = 0) are excluded from this check as they are required for overall system functionality. "
                        $SQLCIS_Secure = "1"

                            try{$SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln)
                                if ($SQLCIS_Check[2] -ne $null -or $SQLCIS_Check[2].split(",")[1] -ne "1")
                                    {
                                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])"  
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "False"  
                                    }
                                else
                                    {
                                        $SQLCIS_Title = $SQLCIS_Title
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "True"  
                                     }}catch{} 
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases"
            <#--------------------------------------#>

                Foreach($DBName_item in $SQLDB_Names)
                    {
                       $sqlVuln = "set NOCOUNT ON; use $DBName_item;SELECT db_name() AS Database_Name, name AS Key_Name FROM sys.symmetric_keys WHERE algorithm_desc NOT IN ('AES_128','AES_192','AES_256') AND db_id() > 4"

                        $SQLCIS_Comment = "Per the Microsoft Best Practices, only the SQL Server AES algorithm options, AES_128, AES_192, and AES_256, should be used for a symmetric key encryption algorithm. The following algorithms (as referred to by SQL Server) are considered weak or deprecated and should no longer be used in SQL Server: DES, DESX, RC2, RC4, RC4_12"
                        $SQLCIS_Secure = "AES_256"

                            try{$SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln)
                                if ($SQLCIS_Check[3] -ne $null -or $SQLCIS_Check[2].split(",")[1] -ne "1")
                                    {
                                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])"  
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "False"  
                                    }
                                else
                                    {
                                        $SQLCIS_Title = $SQLCIS_Title
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "True"  
                                     }
                                
                                }
                            catch
                                {
                                    $exceptionMessage = $_.Exception.message
                                    SecureReportError($SecCheck,$exceptionMessage)        
                                }
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system database"
            <#--------------------------------------#>

                    Foreach($DBName_item in $SQLDB_Names)
                    {
                       $sqlVuln = "set NOCOUNT ON; use $DBName_item;SELECT db_name() AS Database_Name, name AS Key_Name FROM sys.asymmetric_keys WHERE key_length < 2048 AND db_id() > 4"

                        $SQLCIS_Comment = "Microsoft Best Practices recommend to use at least a 2048-bit encryption algorithm for asymmetric keys. The RSA_2048 encryption algorithm for asymmetric keys in SQL Server is the highest bitlevel provided and therefore the most secure available choice (other choices are RSA_512 and RSA_1024)."
                        $SQLCIS_Secure = ""

                            try{$SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                                if ($SQLCIS_Check[3] -ne $null -or $SQLCIS_Check[2].split(",")[1] -ne "1")
                                    {
                                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])"  
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "False"  
                                    }
                                else
                                    {
                                        $SQLCIS_Title = $SQLCIS_Title
                                        #$SQLCIS_Vuln = "Find user-created assemblies with a value of 1"
                                        $SQLCIS_Config = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_InUse = "$($DBName_item) is $($SQLCIS_Check[2].split(",")[1])" 
                                        $SQLCIS_Secure = $SQLCIS_Secure
                                        $SQLCIS_Comment = $SQLCIS_Comment
                                        $trueFalse = "True"  
                                     }}catch{}
 
                        $newObjSQLCIS = New-Object -TypeName PSObject
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
                        #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                            Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
                        $fragCISSQL += $newObjSQLCIS
                    }

            <#-------------------------------------#>
            splatSQLChecks
            $SQLCIS_Title = "Ensure Database Backups are Encrypted"
            <#--------------------------------------#>

            $sqlVuln = "SELECT 
            key_algorithm, encryptor_type,     
            database_name,     
            server_name 
            FROM msdb.dbo.backupset;"
 
            $SQLCIS_Comment = "Databases may contain sensitive. Backups of this data allow the data to easily leave the Enterprise and secure environments. Encrypting the backup makes accessing the data much more difficult. A database backup accidentally exposed to the Internet or transmitted outside a secure environment can be easily restored to a SQL Server anywhere and its contents discovered."
            $SQLCIS_Secure = "audit level,failure"

            $SQLCIS_Check = (& sqlcmd -s "," -W -Q $sqlVuln) 
                if ($SQLCIS_Check[1].split(",")[1] -match "--------------")
                    {
                        $SQLCIS_Title = "Warning $SQLCIS_Title Warning"
                        #$SQLCIS_Vuln = $SQLCIS_Check[2].Split('\')[1] + " has been found"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "False"        
                    }
                else
                    {
                        $SQLCIS_Title = $SQLCIS_Title 
                        #$SQLCIS_Vuln = "Local or builtin accounts don't have access to SQL"
                        $SQLCIS_Config = $SQLCIS_Check[2]
                        $SQLCIS_InUse = $SQLCIS_Check[2]
                        $trueFalse = "True"
                    }
 
            $newObjSQLCIS = New-Object -TypeName PSObject
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISTitle -Value $SQLCIS_Title
            #    Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name SQLCISCheck -Value $SQLCIS_Vuln
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Configured -Value $SQLCIS_Config
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Inuse -Value $SQLCIS_InUse
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name CISRecommended -Value $SQLCIS_Secure
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name Comment -Value $SQLCIS_Comment
                Add-Member -InputObject $newObjSQLCIS -Type NoteProperty -Name TrueIsCompliant -Value $trueFalse
            $fragCISSQL += $newObjSQLCIS

        #End of SQL Statement
        }

    <#
       IIS SERVER
    #>
    Import-Module WebAdministration
    $gtIIS = Get-IISSite
    
    $IISExists = ForEach-Object {$gtIIS.state -match "Started" | select-Object -first 1 }
    if ($IISExists -eq $True)
        {






        #End of IIS Statement
        }


    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                      Embedded Image Branding as Baase64 - Tenaka
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
        <#
            Convert image file to base64 for embedded picture in report
            Image is the title image on www.tenaka.net, if you wish to download image and confirm base64 and that it contains nothing malicious 

            [convert]::ToBase64String((get-content -path C:\Image\Image.png -Encoding Byte)) >> C:\image\base.txt

            [convert]::FromBase64String((get-content -path C:\Image\base.txt -Encoding Byte)) >> C:\image\Image.png   
        #>



    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                            Compliance Status
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

        if ($fragBitLocker -like "*warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Bitlockerisnotenabled">Bitlocker</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Very High Risk"
               $fragSummary += $newObjSummary
             }

       if ($fragUnQuoted -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#unquoted">Unquoted Paths Vulnerability</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Very High Risk"
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
    
        if ($BiosUEFI -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#BiosUEFI">Out of date Firmware for BIOS or UEFI</a>'
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

        if ($fragkernelModeVal -like "*warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#KernelMode">Kernel-mode Hardware-enforced Stack Protection is not enabled</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
             }

        if ($fragPreAuth -like "*warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#PreAuth">There are AD accounts that dont Pre-Authenticated</a>'
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


       if ($fragTrusted4Delegate -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Domain">User Unconstrained Delegation</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            }

       if ($fragTrusted4Delegate -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Domain">User Constrained Delegation</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            }

       if ($fragConstrained -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Domain">Computer Constrained Delegation</a>'
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
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#RegPW">Passwords in the Registry</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            } 

       if ($fragPSPasswords -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#PSHistory">Passwords in Powershell History</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            }


        if ($fragwFile -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#sysFileWrite">File in Program Files or Windows Directories are Writeable</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            } 

       if ($fragReg -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#RegWrite">Registry Keys that are Writeable</a>'
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

       if ($fragSecOptions -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#secOptions">Security Options that Prevent MitM Attack are Enabled</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "High Risk"
               $fragSummary += $newObjSummary
            } 

       if ($SchedTaskPerms -ne $null)
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#schedDir">Scheduled Tasks with Scripts and Permissions are Weak</a>'
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

       if ($fragLegNIC -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#LegNetProt">Legacy Network Protocols are Enabled</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium to High Risk"
               $fragSummary += $newObjSummary
            } 

        if ($fragAutoRunsVal -like "*warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#AutoRuns">AutoRuns Requires Review</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
             }

        if ($fragPCElevate -like "*warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#SoftElevation">Installation of Software will Auto Elevate</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
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
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }


          if ($SchedTaskListings -ne $null)
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#schedTask">Scheduled Tasks Contain Base64 or Commands that Require Reviewing</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            } 
       
       if ($fragwFold -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#nonSysDirWrite">Directories that are Writeable and Non System</a>'
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

       if ($fragASR -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#asr">Attack Surface Reduction GPOs have not been Set</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
                $fragSummary += $newObjSummary
            }

       if ($fragRunSpoolerSvc -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#asr">Print Spooler is enabled on a Server or DC</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }

        if ($fragAutoLogon -like "*warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#AutoLogon">The Registry contains Autologon credentials</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }

       if ($fragWindowsOSVal -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                          Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#WinSSLF">Windows Hardening Policies Recommended by Microsoft are Missing</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }

       if ($fragEdgeVal -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#EdgeSSLF">Edge Hardening Policies Recommended by Microsoft are Missing</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }


       if ($fragOfficeVal -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#OfficeSSLF">Office Hardening Policies Recommended by Microsoft are Missing</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
            }
       

        if ($fragCISSQL -like "*Warning*")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#SQLCIS">SQL Server is CIS Benchmarks</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Medium Risk"
               $fragSummary += $newObjSummary
             }

       if ($fragUnConstrained -like "*Warning*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#Domain">Computer Unconstrained Delegation</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Informational"
               $fragSummary += $newObjSummary
            }

        if ($fragSQLVer -like "*SQL Server *")
             {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#SQLVersion">SQL Server is Installed</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Informational"
               $fragSummary += $newObjSummary
             }

       if ($fragShare -like "*C$*")
            {
                $newObjSummary = New-Object psObject
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Vulnerability -Value '<a href="#shares">There are System Shares available</a>'
                     Add-Member -InputObject $newObjSummary -Type NoteProperty -Name Risk -Value "Informational"
               $fragSummary += $newObjSummary
            }



    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                         Helps and Explanations
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

        $Intro = "<br><br>Thanks for using the vulnerability report written by <a href=`"https://www.tenaka.net`" class=`"class1`">Tenaka.net</a>, please show your support and visit my site, it's non-profit and Ad-free. <br>
        <br>Any issues with the report's accuracy please do let me know and I'll get it fixed asap. The results in this report are a guide and not a guarantee that the tested system is not without further defects or vulnerability.<br>
        <br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail.<br><br>The html output can be imported into Excel for further analysis and uses the True and False values as a drop-down filter.<br>Open Excel, Data, Import from Web. Enter the file path in the following format file:///C:/SecureReport/NameOfReport.htm, then select multiple items and click on Load and select 'Load To', click on Table.<br><br>Further support for this report can be found @ <a href=`"https://www.tenaka.net/windowsclient-vulnscanner`" class=`"class1`">Vulnerability Scanner</a>"
        #$Intro2 = "The results in this report are a guide and not a guarantee that the tested system is not without further defect or vulnerability.<br>The tests focus on known and common issues with Windows that can be exploited by an attacker. Each section contains a small snippet to provide some context, follow the links for further detail.<br><br>The html output can be imported into Excel for further analysis and uses the True and False values as a drop-down filter.<br><br>Open Excel, Data, Import from Web. Enter the file path in the following format file:///C:/SecureReport/NameOfReport.htm, then select multiple items and click on Load and select 'Load To', click on Table.<br>"
        $Finish = "This script has been provided by Tenaka.net, if it's beneficial, please provide feedback and any additional feature requests gratefully received. "
        $descripBitlocker = "TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then Accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM. <br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/bitlocker`" class=`"class1`">Bitlocker</a>"
        $descripVirt = "Virtualization-based security (VBS), isolates core system resources to create secure regions of memory. Enabling VBS allows for Hypervisor-Enforced Code Integrity (HVCI), Device Guard and Credential Guard. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs<br> <br><a href=`"https://www.tenaka.net/deviceguard-vs-rce`" class=`"class1`">WDAC vs RCE</a> and <a href=`"https://www.tenaka.net/pass-the-hash`" class=`"class1`">Pass the Hash</a> <br><br>Secure Boot is a security standard to ensure only trusted OEM software is allowed at boot. At startup the UEFi and boot software's digital signatures are validated preventing rootkits. <br> <br>More on Secure Boot can be found here @ https://media.defense.gov/2020/Sep/15/2002497594/-1/-1/0/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF/CTR-UEFI-SECURE-BOOT-CUSTOMIZATION-20200915.PDF<br>"
        $descripVirt2 = "Virtualization-based security (VBS), isolates core system resources to create secure regions of memory. Enabling VBS allows for Hypervisor-Enforced Code Integrity (HVCI), Device Guard and Credential Guard. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs<br> <br><a href=`"https://www.tenaka.net/deviceguard-vs-rce`" class=`"class1`">WDAC vs RCE</a> and <a href=`"https://www.tenaka.net/pass-the-hash`" class=`"class1`">Pass the Hash</a> <br>"
        $descripSecOptions = "<br>GPO settings can be found @ Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options<br><br>Prevent credential relay with Impacket and Man in the Middle by Digitally Signing for SMB and LDAP connections enforcement. <br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/smb-relay-attack`" class=`"class1`">SMB-Relay-Attack</a><br> <br>System cryptography: Force strong key protection for user keys stored on the computer should only be set on clients and not Servers<br>"
        $descripLSA = "Enabling RunAsPPL for LSA Protection allows only digitally signed binaries to load as a protected process preventing credential theft and Access by code injection and memory Access by processes that aren't signed. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection<br>"
        $descripDLL = "Loading DLL's default behaviour is to call the dll from the current working directory of the application, then the directories listed in the environmental variable. Setting 'DLL Safe Search' mitigates the risk by moving CWD to later in the search order. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order<br>"
        $descripHyper = "Hypervisor Enforced Code Integrity prevents the loading of unsigned kernel-mode drivers and system binaries from being loaded into system memory. <br> <br>Further information can be found @ https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity<br>"
        $descripElev = "Auto Elevate User is a setting that elevates users allowing them to install software without being an administrator. "
        $descripFilePw = "Files that contain password or credentials"
        $descripAutoLogon = "MECM\SCCM\MDT could leave Autologon credentials including a clear text password in the Registry."
        $descripUnquoted = "The Unquoted paths vulnerability is when a Windows Service's 'Path to Executable' contains spaces and not wrapped in double-quotes providing a route to System. <br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a><br>"
        $descripProcPw = "Processes that contain credentials to authenticate and Access applications. Launching Task Manager, Details and add 'Command line' to the view."
        $descripLegacyNet = "LLMNR and other legacy network protocols can be used to steal password hashes. <br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/responder`" class=`"class1`">Responder</a><br>"
        $descripRegPer ="Weak Registry permissions allowing users to change the path to launch malicious software.<br><br>Further information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a>"
        $descripSysFold = "Default System Folders that allow a User the Write permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br> Further information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a><br>"
        $descripCreateSysFold = "Default System Folders that allows a User the CreateFile permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.<br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a><br>"
        $descripNonFold = "A vulnerability exists when enterprise software has been installed on the root of C:\. The default permissions allow a user to replace approved software binaries with malicious binaries. <br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a><br>"
        $descripFile = "System files (Exe's and Dll's) that allow users to write can be swapped out for malicious software binaries. <br> <br>Further  information can be found @ <a href=`"https://www.tenaka.net/unquotedpaths`" class=`"class1`">UnQuoted Paths</a>"
        $descripFirewalls = "Firewalls should always block inbound and exceptions should be to a named IP and Port.<br> <br>Further  information can be found @ <a href=`"https://www.tenaka.net/whyhbfirewallsneeded`" class=`"class1`">Why Hostbased Firewalls are Essential</a><br>" 
        $descripTaskSchPerms = "Checks for Scheduled Tasks excluding any that reference System32 as a directory. These potential user-created tasks are checked for scripts and their directory permissions are validated. No user should be allowed to Access the script and make amendments, this is a privilege escalation route." 
        $descripTaskSchEncode = "Checks for encoded scripts, PowerShell or exe's that make calls off box or run within Task Scheduler" 
        $descriptDriverQuery = "All Drivers should be signed with a digital signature to verify the integrity of the packages. 64bit kernel Mode drivers must be signed without exception"
        $descriptAuthCodeSig = "Checks that digitally signed files have a valid and trusted hash. If any Hash Mis-Matches then the file could have been altered"
        $descriptDLLHijack = "DLL Hijacking is when a malicious dll replaces a legitimate dll due to a path vulnerability. A program or service makes a call on that dll gaining the privileges of that program or service. Additionally missing dll's presents a risk where a malicious dll is dropped into a path where no current dll exists but the program or service is making a call to that non-existent dll. This audit is reliant on programs being launched so that DLL's are loaded. Each process's loaded dll's are checked for permissions issues and whether they are signed. The DLL hijacking audit does not currently check for missing dll's being called. Process Monitor filtered for 'NAME NOT FOUND' and path ends with 'DLL' will."
        $descripCredGu = "Credential Guard securely isolating the LSA process preventing the recovery of domain hashes from memory. Credential Guard only works for Domain joined clients and servers.<br> <br>Further information can be found @ <a href=`"https://www.tenaka.net/pass-the-hash`" class=`"class1`">Pass the Hash</a><br>"
        $descripLAPS = "Local Administrator Password Solution (LAPS) is a small program with some GPO settings that randomly sets the local administrator password for clients and servers across the estate. Domain Admins have default permission to view the local administrator password via DSA.MSC. Access to the LAPS passwords may be delegated unintentionally, this could lead to a serious security breach, leaking all local admin accounts passwords for all computer objects to those that shouldn't have Access. <br> <br>Installation guide can be found @ <a href=`"https://www.tenaka.net/post/local-admin-passwords`" class=`"class1`">LAPS Installation</a>. <br> <br>Security related issue details can be found @ <a href=`"https://www.tenaka.net/post/laps-leaks-local-admin-passwords`" class=`"class1`">LAPS Leaking Admin Passwords</a><br>"
        $descripURA = "User Rights Assignments (URA) control what tasks a user can perform on the local client, server or Domain Controller. For example the 'Log on as a service' (SeServiceLogonRight) provides the rights for a service account to Logon as a Service, not Interactively. <br> <br> Access to URA can be abused and attack the system. <br> <br>Both SeImpersonatePrivilege (Impersonate a client after authentication) and SeAssignPrimaryTokenPrivilege (Replace a process level token) are commonly used by service accounts and vulnerable to escalation of privilege via Juicy Potato exploits.<br> <br>SeBackupPrivilege (Back up files and directories), read Access to all files including SAM Database, Registry and NTDS.dit (AD Database). <br> <br>SeRestorePrivilege (Restore files and directories), Write Access to all files. <br> <br>SeDebugPrivilege (Debug programs), allows the ability to dump and inject into process memory inc kernel. Passwords are stored in memory in the clear and can be dumped and easily extracted. <br> <br>SeTakeOwnershipPrivilege (Take ownership of files or other objects), take ownership of file regardless of Access.<br> <br>SeNetworkLogonRight (Access this computer from the network) allows pass-the-hash when Local Admins share the same password, remove all the default groups and apply named groups, separating client from servers.<br><br>SeCreateGlobalPrivilege (Create global objects), do not assign any user or group other than Local System as this will allow system takeover<br><br>Further details can be found @ <br>https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment<br>https://www.microsoft.com/en-us/download/details.aspx?id=55319<br><br>**UserRightAssignment-Name - Mouse over to show Microsofts recommended setting"
        $descripRegPasswords = "Searches HKLM and HKCU for the Words 'password' and 'passwd', then displays the password value in the report.<br><br>The search will work with VNC encrypted passwords stored in the registry, from Kali run the following command<br> <br>echo -n PasswordHere | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv<br>"
        $descripASR = "Attack Surface Reduction (ASR) requires Windows Defender Real-Time Antivirus and works in conjunction with Exploit Guard to prevent malware abusing legitimate MS Office functionality<br> <br>Further information can be found @ https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide<br>"
        $descripWDigest = "WDigest was introduced with Windows XP\2003 and has been enabled by default until and including Windows 8 and Server 2012. Enabling allows clear text passwords to be recoverable from LSASS with Mimikatz"
        $descripDomainGroups = "Group membership of the user executing this script. Local admins are required, the account should not have Domain Admins as this can result in privilege escalation."
        $descripDomainPrivs = "Reference User Rights Assignment (URA) section below for further details"
        $descripLocalAccounts = "Local accounts should be disabled when the client or server is part of a Domain. LAPS should be deployed to ensure all local account passwords are unique"
        $descripWindowsOS = "Warning: Absence of a GPO setting will raise an issue as the default setting is not assumed<br>These are recommended GPO settings to secure Windows by Microsoft, do NOT implement without the correct research and testing. Some settings could adversely affect your system.<br> <br>Due to the sheer number of settings, the script contains details and the equivalent GPO settings, search for RECOMMENDED SECURITY SETTINGS section<br><br>MS Security Compliance Toolkit can be found @ <br>https://admx.help/?Category=security-compliance-toolkit<br>https://www.microsoft.com/en-us/download/details.aspx?id=55319<br><br>**WindowsRegValue - Mouse over to show Reg Key to GPO path translation" 
        $descripOffice2016 = "These are recommended GPO settings to secure Office 2016-365 by Microsoft, do NOT implement without the correct research and testing. Some settings could adversely affect your system.<br> Its recommended that Attack Surface Reduction (ASR) is enabled but requires Windows Defender Real-Time Antivirus and works in conjunction with Exploit Guard to prevent malware abusing legitimate MS Office functionality"
        $descripPreAuth = "READ ME - Requires the installation of the AD RSAT tools for this to work.<br><br>Pre-authentication is when the user sends the KDC an Authentication Service Request (AS_REQ) with an encrypted Timestamp. The KDC replies with an Authentication Service Reply (AS_REP) with the TGT and a logon session. The issue arises when the user's account doesn't require pre-authentication, it's a check box on the user's account settings. An attacker is then able to request a DC, and the DC dutifully replies with user encrypted TGT using the user's own NTLM password hash. An offline brute force attack is then possible in the hope of extracting the clear text password, known as AS-REP Roasting <br> <br>Further information @ <a href=`"https://www.tenaka.net/kerberos-armouring`" class=`"class1`">Kerberos Armouring</a><br>"
        $descripAV = ""
        $descripDomainPrivsGps = "Review and minimise members of privileged groups and delegate as much as possible. Don't nest groups into Domain Admins, add direct user accounts only. Deploy User Rights Assignments to explicitly prevent Domain Admins from logging on to Member Servers and Clients more information can be found here @ <a href=`"https://www.tenaka.net/post/deny-domain-admins-logon-to-workstations`" class=`"class1`">URA to Deny Domain Admins Logging to Workstations</a><br><br>Dont add privileged groups to Guests or Domain Guests and yes I've seen Domain Guests added to Domain Admins"
        $descripCerts = ""
        $decripCipher = ""
        $descripKernelMode = "Enabled with Windows 11 22H2 - For code running in kernel mode, the CPU confirms requested return addresses with a second copy of the address stored in the shadow stack to prevent attackers from substituting an address that runs malicious code. Not all drivers are compatible with this security feature. More information can be found here @<br><br>https://techcommunity.microsoft.com/t5/windows-os-platform-blog/understanding-hardware-enforced-stack-protection/ba-p/1247815"
        $descripInstalledApps = "Will assume any installed program older than 6 months is out of date"
        $descripBios = "Will assume any UEFI\BIOS is out of date if its older than 6 months"
        $descripWinUpdates = "Will assume any Windows Updates are out of date if older than 6 months"
        $descripPowershellHistory = "This is unreliable as an audit, the word Password is filtered from the PowerShell search history log. It's best to launch Powershell and type 'history'. However other creds may be logged @ C:\Users\SomeUser\APDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        $descripAutoRuns = "Autoruns are Windows programs set to auto-execute during startup launching when the operating system boots. These include legitimate apps, system utilities, and potentially malicious software. Autoruns can be exploited by planting malicious code in startup locations or manipulating system settings. This grants them persistence and control over compromised systems. Malware in startup locations can steal data, spread, or provide backdoor access. Exploited programs often leverage system vulnerabilities or manipulate user trust through disguised software.<br><br> The `"Run`" or `"RunOnce`" keys in the Windows Registry, like `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`", enabling their malware to launch at boot. Similarly, they might abuse the `"Startup`" folder where shortcuts execute on login. Notable examples include the use of these mechanisms by malware like `"Sasser`" (2004) and `"WannaCry`" (2017) worms. Regularly monitoring and securing these auto-start points is vital to prevent such exploits. Further information can be founds @ https://attack.mitre.org/techniques/T1547/001/ "
        $descripWDAC = "Requires CITool.exe, comes as default with Windows 11 22H2<br><br>WDAC (Windows Defender Application Control), Device Guard was its release name, is a security feature in Windows operating systems designed to enhance system security. In kernel mode, WDAC operates by enforcing code integrity policies, which restrict the execution of unauthorized or unsigned code, preventing malicious software from running. It uses kernel-mode drivers to monitor and control the loading of executables and scripts, ensuring only approved applications run, bolstering system security<br><br>Application Control Policy and Application Control User should be set to Enforce when enabled.<br><br>There should be a named policy that is also set to (CIPolicyEnforced = True) and not Audit (CIPolicyEnforced = False)<br><br>For this to report on WDAC while Enforced, either sign this script or temporarily set 'Set-RuleOption -FilePath C:\WDAC\Policy.xml -Option 11'"
        $descripSQLCIS = 
            "Ensure the SQL Server’s MSSQL Service Account is Not an Administrator.<br><br> 
            Ensure the SQL Server’s SQLAgent Service Account is Not an Administrator.<br><br>
            Ensure the SQL Server’s Full-Text Service Account is Not an Administrator.<br><br> 
            Ensure Database and Application User Input is Sanitized - Sanitizing user input drastically minimizes risk of SQL injection.<br><br>  
            Ensure 'SQL Server Browser Service' is configured correctly - In the case of a default instance installation, the SQL Server Browser service is disabled by default. Unless there is a named instance on the same server, there is typically no reason for the SQL Server Browser service to be running.<br><br>
            "     
        $descripToDo = ""
        $descripSpooler = "The Print Spooler Service should be disabled on Domain Controllers to prevent Unconstrained Delegation and various AD and Kerberos Abuses. <br><br>To reduce the attack vector, consider disabling the spooler service on any Server where its not required."

        $descripUnconstrained = "Unconstrained delegation refers to a mechanism that allows a service to impersonate a user without any restrictions.<br><br>Delegation grants a service the ability to use the Users credentials to access other resources on their behalf. 
        This is typically done to enable seamless and secure access to various services without requiring the user to reauthenticate for each service.<br><br>With unconstrained delegation, there are no restrictions on the services or resources that the delegated authority can access. The service can impersonate the user to access any resource without limitations.
        <br><br>Unconstrained delegation introduces security risks because it grants extensive access to the service. If an attacker gains control over a service that has unconstrained delegation privileges, they could potentially access any resource in the network using the compromised service's credentials.
        <br><br>To reduce the attack vector don't select 'Trust this user for delegation to ANY service (Kerberos only)', instead choose the option 'Trust this user to delegation to SPECIFIC services only'.  "

        $descripconstrained = "Constrained Delegation is when a user delegates authority to a service to access specific resources on their behalf. The delegation is limited to a defined set of services or resources."

        $descripAdminUnconstrained = "Default settings allow for the delegation of accounts. This implies that an application has the capability to operate on behalf of a user through Kerberos delegation, assume the identity of a user across the entire forest with unconstrained delegation for any service<br><br>When delegation is set up, and in the event of an attacker gaining access to the delegated system or account, there is a risk that they may attempt to mimic an administrator account. This could potentially enable lateral movement or compromise the integrity of the domain."
"

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          Colour Mapping
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    $ColorWarning = "#ff9933"        #Orange

    $ColorActiveTab = "#06273a"      #Dark Blue
    $colorContentTab = "#06273a"     #Dark Blue
    $colorPassiveTab = "#28425F"     #Grey Blue medium
    $colorHoverTab = "#ff9933"       #Orange
    $colorHoverTabText = "#06273a"   #Dark Blue
    $colorActiveTabText = "#FFF9EC"  #off white

    $colorBackground = "#28425F"     #Grey Blue medium

    $colorTH = "#06273a"             #Dark Blue
    $colorTD = "#FFF9EC"             #off white

    $colorTable1 = "#06273a"         #Dark Blue
    $colorTable2 = "#28425F"         #Grey Blue medium

    $colorText = "#FFF9EC"           #off white
    $colorTextHover = "#ff9933"      #Orange
    $colorH4 = "#9f9696"             #Grey

    $colorBorders = "#FFF9EC"        #off white


    $font = "Raleway"

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                            Style Sheet
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    $style = @"
        <style>

    body { 
	    height: 100%;
	    background-color: $colorBackground; 
	    color: $colorText; 
	    font-size: 16px; 
	    font-family: $font;
    } 
    h1 { font-size: 2px;  padding: 2px;}
    h2 { font-size: 26px; }
    h3 { font-size: 18px; font-weight: normal;}
    h4 { color: $colorH4; font-weight: normal; }
    p { margin: 0 0 15px; line-height: 24px; color: $colorText; }
    a { color: $colorText; text-decoration: none; border-bottom: }
    a:hover { color: $colorTextHover; }

 /*Width and height of all borber containing tabs*/
    .container { 
	    max-width: 100%; 
        max-height: 100%;
	    min-width: 100%; 
        min-height: 100%;
	    margin: 0 auto; 
	    padding: 1px;
    }

        table
        {   
            border-width: 1px;
            padding: 7px;
            border-style: solid;
            border-color:$colorBorders;
            border-collapse:collapse;
            width:auto
        }
        th
        {
            border-width: 1px;
            padding: 7px;
            font-family:$font;
            border-style: solid;
            border-color:$colorBorders;
            background-color:$colorTH
            width:auto
        }
        td
        {
            border-width: 1px;
            padding:7px;
            font-family:$font;
            border-style: solid; 
            border-color:$colorBorders;
            border-style: $colorTD 
            width:auto
        }
        tr:nth-child(odd) 
        {
            background-color:$colorTable1;
        }
        tr:nth-child(even) 
        {
            background-color:$colorTable2;
        }

    .tabs {
	    position: relative;
	    display: flex;
	    min-height: 20000px;
	    border-radius: 8px 8px 0 0;
        min-width: 100%;
    }

    .headerTab {
	    flex: 1;
    }

    .headerTab label {
	    display: block;
	    box-sizing: border-box;
		    height: 60px;
	
	    padding: 10px;
	    text-align: center;
	    background: $colorPassiveTab;
	    cursor: pointer;
	    transition: background 0.5s ease;
	
    }

    .headerTab label:hover {
	    background: $colorHoverTab;
        color: $colorHoverTabText;
    }

    .contentTab {
	    position: absolute;
	
	    left: 0; bottom: 0; right: 0;
    	    top: 60px; 
	
	    padding: 20px;
	    border-radius: 0 0 8px 8px;
	    background: $colorContentTab;
	
	    transition: 
		    opacity 0.8s ease,
		    transform 0.8s ease		;
		    opacity: 0;
		    transform: scale(0.1);
		    transform-origin: top left;
	
    }

    .contentTab img {
	    float: left;
	    margin-right: 20px;
	    border-radius: 8px;
    }

    /*Active Tab*/
    .headerTab [type=radio] { display: none; }
    [type=radio]:checked ~ label {
	    background: $ColorActiveTab;
        color: $colorActiveTabText;
	    z-index: 2;
    }

    [type=radio]:checked ~ label ~ .contentTab {
	    z-index: 1;
	
		    opacity: 1;
		    transform: scale(1);
    }

    @media screen and (min-width: 100px) {

    }

    @media screen and (min-width: 100px) {
        /*Tab Height*/
	    .headerTab label { 
		    height: 70px;
	    }
	    .contentTab { top: 70px; width: 100%; }

	    }
    }

    </style>

"@


    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          Web Fragments
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    #Top and Tail
    $fragDescrip1 =  $Descrip1 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Intro</span></h3>" | Out-String
    #$FragDescrip2 =  $Descrip2 | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Intro2</span></h3>" | Out-String
    $fragDescripFin =  $DescripFin | ConvertTo-Html -as table -Fragment -PreContent "<h3><span style=font-family:$font;>$Finish</span></h3>" | Out-String
    $frag_descripVirt2 = ConvertTo-Html -as table -Fragment -PostContent "<h4>$descripVirt2</h4>" | Out-String
    
    #Summary
    $frag_Summary = $fragSummary | ConvertTo-Html -As Table -fragment -PreContent "<h2>Compliance</h2>"  | Out-String
            
    #Host details    
    $frag_Host = $fragHost | ConvertTo-Html -As List -Property Name,Domain,Model -fragment -PreContent "<h2>Host Details</h2>"  | Out-String
    $frag_OS = $OS | ConvertTo-Html -As List -property Caption,Version,OSArchitecture,InstallDate -fragment -PreContent "<h2>Windows Details</h2>" | Out-String
    $frag_Patchversion = $fragPatchversion | ConvertTo-Html -As Table  -fragment -PreContent "<h2>Windows Patch</h2>" | Out-String
         $frag_PatchversionN = $frag_Patchversion.replace("<th>*</th>","<th>Windows Patch Level</th>")
    
    $frag_AccountDetails = $AccountDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2>Local Accounts</h2>" -PostContent "<h4>$descripLocalAccounts</h4>" | Out-String 
    $frag_DCList  = $fragDCList | ConvertTo-Html -As Table -fragment -PreContent "<h2>Domain Controllers</h2>" | Out-String 
        $frag_DCListN = $frag_DCList.replace("<th>*</th>","<th>List of Domain Controllers</th>")

    $frag_FSMO = $fragFSMO | ConvertTo-Html -As Table -fragment -PreContent "<h2>FSMO Roles</h2>" | Out-String 
    $frag_DomainGrps = $fragDomainGrps | ConvertTo-Html -As Table -fragment -PreContent "<h2>Privilege Groups</h2>" -PostContent "<h4>$descripDomainPrivsGps</h4>" | Out-String 
    $frag_PreAuth = $fragPreAuth | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Pre-Authenticate</h2>" -PostContent "<h4>$descripPreAuth</h4>" | Out-String
    $frag_NeverExpires = $fragNeverExpires | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Password Never Expires</h2>"  | Out-String
    $frag_ListUserSPNs = $fragListUserSPNs | ConvertTo-Html -as Table -Fragment -PreContent "<h2>List SPNs</h2>"  | Out-String
    $frag_ListComputerSPNs = $fragListComputerSPNs | ConvertTo-Html -as Table -Fragment -PreContent "<h2>List Device SPNs</h2>"  | Out-String
    $frag_UnConstrained = $fragUnConstrained | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Unconstrained Delegation</h2>" -PostContent "<h4>$descripUnconstrained</h4>"  | Out-String 
    $frag_Constrained  = $fragConstrained  | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Constrained Delegation</h2>" -PostContent "<h4>$descripconstrained</h4>"  | Out-String     
    $frag_Trusted4Delegate = $fragTrusted4Delegate | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Unconstrained User Delegation</h2>"  -PostContent "<h4>$descripAdminUnconstrained</h4>"  | Out-String
    $frag_Allowed2Delegate = $fragAllowed2Delegate | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Constrained User Delegation</h2>"  | Out-String
    $frag_GroupDetails =  $GroupDetails  | ConvertTo-Html -As Table -fragment -PreContent "<h2>Built-In Groups</h2>" | Out-String
    $frag_PassPol = $PassPol | Select-Object -SkipLast 3 | ConvertTo-Html -As Table -fragment -PreContent "<h2>Password Policy</h2>" | Out-String
    $frag_InstaApps  =  $InstallApps | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2>Installed Applications</h2>" -PostContent "<h4>$descripInstalledApps</h4>" | Out-String
    $frag_HotFix = $HotFix | ConvertTo-Html -As Table -property HotFixID,InstalledOn,Caption -fragment -PreContent "<h2>Windows Updates</></h2>" -PostContent "<h4>$descripWinUpdates</h4>"| Out-String   
    $frag_InstaApps16  =  $InstallApps16 | Sort-Object publisher,displayname -Unique  | ConvertTo-Html -As Table  -fragment -PreContent "<h2>KB's Listed in Reg</h2>" | Out-String
    $frag_Bios = $BiosUEFI | ConvertTo-Html -As List -fragment -PreContent "<h2>Bios Details</h2>" -PostContent "<h4>$descripBios</h4>"| Out-String
    $frag_Cpu = $cpu | ConvertTo-Html -As List -property Name,MaxClockSpeed,NumberOfCores,ThreadCount -fragment -PreContent "<h2>Processor Details</h2>" | Out-String
    $frag_whoamiGroups =  $whoamiGroups | ConvertTo-Html -As Table -fragment -PreContent "<h2>User Groups</h2>" -PostContent "<h4>$descripDomainGroups</h4>" | Out-String
    $frag_whoamiPriv =  $whoamiPriv | ConvertTo-Html -As Table -fragment -PreContent "<h2>Your Local URA</h2>" -PostContent "<h4>$descripDomainPrivs</h4>" | Out-String
    $frag_Network4 = $fragNetwork4 | ConvertTo-Html -As List -fragment -PreContent "<h2>IPv4 Address</h2>"  | Out-String
    $frag_Network6 = $fragNetwork6 | ConvertTo-Html -As List -fragment -PreContent "<h2>IPv6 Address</h2>"  | Out-String
    $frag_WinFeature = $FragWinFeature | ConvertTo-Html -As table -fragment -PreContent "<h2>Windows Features</h2>"  | Out-String    
    $frag_Appx = $FragAppx | ConvertTo-Html -As table -fragment -PreContent "<h2>Optional Features</h2>"  | Out-String
    $frag_SrvWinFeature = $FragSrvWinFeature | ConvertTo-Html -As table -fragment -PreContent "<h2>Server Features</h2>"  | Out-String
    $frag_MDTBuild = $fragMDTBuild | ConvertTo-Html -As table -fragment -PreContent "<h2>MDT Details</h2>"  | Out-String
        $frag_MDTBuildN = $frag_MDTBuild.replace("<th>*</th>","<th>MDT Deployment Task</th>")

    #Security Review
    $frag_AVStatus = $FragAVStatus | ConvertTo-Html -As Table  -fragment -PreContent "<h2>Antivirus</h2>" -PostContent "<h4>$descripAV</h4>" | Out-String
        $Frag_AVStatusN = $Frag_AVStatus.replace("<th>*</th>","<th>AV Status and Definition</th>")
    
    $frag_BitLocker = $fragBitLocker | ConvertTo-Html -As List -fragment -PreContent "<h2>Bitlocker</h2>" -PostContent "<h4>$descripBitlocker</h4>" | Out-String
        $frag_BitLockerN = $frag_BitLocker.Replace("<td>*:</td>","<td>Bitlocker Configuration</td>")
    
    $frag_Msinfo = $MsinfoClixml | ConvertTo-Html -As Table -fragment -PreContent "<h2>VBS and Secure Boot</h2>" -PostContent "<h4>$descripVirt</h4>"  | Out-String
    $frag_kernelModeVal = $fragkernelModeVal | ConvertTo-Html -As Table -fragment -PreContent "<h2>Kernel-mode</h2>" -PostContent "<h4>$descripKernelMode</h4>"  | Out-String
    $frag_LSAPPL = $fragLSAPPL | ConvertTo-Html -as Table -Fragment -PreContent "<h2>LSA</h2>" -PostContent "<h4>$descripLSA</h4>" | Out-String
    $frag_DLLSafe = $fragDLLSafe | ConvertTo-Html -as Table -Fragment -PreContent "<h2>DLL Safe Search</h2>"  -PostContent "<h4>$descripDLL</h4>"| Out-String
    $frag_DLLHijack = $fragDLLHijack | ConvertTo-Html -as Table -Fragment -PreContent "<h2>DLL Hijacking</h2>" | Out-String
    $frag_DllNotSigned = $fragDllNotSigned | ConvertTo-Html -as Table -Fragment -PreContent "<h2>DLL's not Signed</h2>"  -PostContent "<h4>$descriptDLLHijack</h4>"| Out-String
        $frag_DllNotSignedN = $frag_DllNotSigned.Replace("<tr><th>*</th></tr>","<tr><th>DLL's not Signed</th></tr>")

    $frag_Code = $fragCode | ConvertTo-Html -as Table -Fragment -PreContent "<h2>HECI</h2>" -PostContent "<h4>$descripHyper</h4>" | Out-String
    $frag_PCElevate = $fragPCElevate | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Automatically Elevates</h2>"  -PostContent "<h4>$descripElev</h4>"| Out-String
    $frag_FilePass = $fragFilePass | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Files with Passwords</h2>" -PostContent "<h4>$descripFilePw</h4>" | Out-String
    $frag_AutoLogon = $fragAutoLogon   | ConvertTo-Html -as Table -Fragment -PreContent "<h2>AutoLogon Credentials</h2>"  -PostContent "<h4>$descripAutoLogon</h4>"| Out-String
    $frag_UnQu = $fragUnQuoted | ConvertTo-Html -as Table -Fragment -PreContent "<h2>UnQuoted Paths</h2>" -PostContent "<h4>$DescripUnquoted</h4>" | Out-String
    $frag_LegNIC = $fragLegNIC | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Legacy Network</h2>" -PostContent "<h4>$DescripLegacyNet</h4>" | Out-String
    $frag_SysRegPerms = $fragReg | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Registry Permissions</h2>" -PostContent "<h4>$descripRegPer</h4>" | Out-String
        $frag_SysRegPermsN = $frag_SysRegPerms.Replace("<tr><th>*</th></tr>","<tr><th>Registry Permissions</th></tr>")
    
    $frag_PSPass = $fragPSPass | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Processes with Passwords</h2>" -PostContent "<h4>$Finish</h4>" | Out-String
    $frag_SecOptions = $fragSecOptions | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Security Options</h2>" -PostContent "<h4>$descripSecOptions</h4>" | Out-String
   
    $frag_wFolders = $fragwFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2>User Writeable Non-Sys Dir</h2>" -PostContent "<h4>$descripNonFold</h4>"| Out-String
        $frag_wFoldersN = $frag_wFolders.Replace("<tr><th>*</th></tr>","<tr><th>User Writeable Non-Sys Dir</th></tr>")
    
    $frag_SysFolders = $fragsysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2>User Writeable Sys Dir</h2>"  -PostContent "<h4>$descripSysFold</h4>"| Out-String
        $frag_SysFoldersN = $frag_SysFolders.Replace("<tr><th>*</th></tr>","<tr><th>User Writeable Sys Dir</th></tr>")
    
    $frag_CreateSysFold = $fragCreateSysFold | ConvertTo-Html -as Table -Fragment -PreContent "<h2>User Create Files Sys Dir</h2>"  -PostContent "<h4>$descripCreateSysFold</h4>"| Out-String
        $frag_CreateSysFoldN = $frag_CreateSysFold.Replace("<tr><th>*</th></tr>","<tr><th>User Create Files in Sys Dir</th></tr>")
    
    $frag_wFile = $fragwFile | ConvertTo-Html -as Table -Fragment -PreContent "<h2>User Writeable Sys files</h2>" -PostContent "<h4>$descripFile</h4>" | Out-String
        $frag_wFileN = $frag_wFile.Replace("<tr><th>*</th></tr>","<tr><th>User Writeable System Files</th></tr>")
    
    $frag_FWProf = $fragFWProfile | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Firewall Profile</h2>"  -PostContent "<h4>$DescripFirewalls</h4>"| Out-String
    $frag_FW = $fragFW | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Firewall Rules</h2>" | Out-String
    $frag_TaskPerms =  $SchedTaskPerms | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Scheduled Tasks</h2>"  -PostContent "<h4>$descripTaskSchPerms</h4>" | Out-String
    $frag_RunServices =  $fragRunServices | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Running Services</h2>"  | Out-String
    $frag_RunSpoolerSvc = $fragRunSpoolerSvc | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Running Spooler Service</h2>" -PostContent "<h4>$descripSpooler</h4></details>"  | Out-String
    $frag_AutoRuns = $fragAutoRunsVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2>AutoRuns</h2>" -PostContent "<h4>$descripAutoRuns</h4></details>" | Out-String         
    $frag_TaskListings = $SchedTaskListings | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Encoded Scheduled Tasks</h2>"  -PostContent "<h4>$descripTaskSchEncode</h4>" | Out-String
    
    $frag_DriverQuery = $DriverQuery | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Drivers Not Signed</h2>" -PostContent "<h4>$descriptDriverQuery</h4>" | Out-String
         $frag_DriverQueryN = $frag_DriverQuery.Replace("<tr><th>*</th></tr>","<tr><th>Encoded Scheduled Tasks</th></tr>")

    $frag_Share = $fragShare | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Share Permissions</h2>"  | Out-String 
    $frag_AuthCodeSig = $fragAuthCodeSig | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Authenticode HashMisMatch</h2>" -PostContent "<h4>$descriptAuthCodeSig</h4>"  | Out-String  
    $frag_CredGuCFG = $fragCredGuCFG | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Credential Guard</h2>" -PostContent "<h4>$descripCredGu</h4>" | Out-String
    $frag_LapsPwEna = $fragLapsPwEna | ConvertTo-Html -as Table -Fragment -PreContent "<h2>LAPS</h2>" -PostContent "<h4>$descripLAPS</h4>" | Out-String
    $frag_URA = $fragURA | ConvertTo-Html -as Table -Fragment -PreContent "<h2>URA</h2>" -PostContent "<h4>$descripURA</h4>" | Out-String
    $frag_RegPasswords = $fragRegPasswords | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Passwords Embedded in Reg</h2>" -PostContent "<h4>$descripRegPasswords</h4>" | Out-String
    $frag_ASR = $fragASR | ConvertTo-Html -as Table -Fragment -PreContent "<h2>ASR</h2>" -PostContent "<h4>$descripASR</h4>" | Out-String
    $frag_WDigestULC = $fragWDigestULC | ConvertTo-Html -as Table -Fragment -PreContent "<h2>WDigest</h2>" -PostContent "<h4>$descripWDigest</h4>" | Out-String
    $frag_Certificates = $fragCertificates | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Certificates</h2>" -PostContent "<h4>$descripCerts</h4>" | Out-String
    $frag_CipherSuit = $fragCipherSuit | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Cipher Suites</h2>" -PostContent "<h4>$decripCipher</h4>" | Out-String
    $frag_PSPasswords = $fragPSPasswords | ConvertTo-Html -as Table -Fragment -PreContent "<h2>PowerShell History</h2>" -PostContent "<h4>$descripPowershellHistory</h4>" | Out-String
    $frag_ApplockerSvc = $fragApplockerSvc | ConvertTo-Html -As table -fragment -PreContent "<h2>Applocker Services</h2>"  | Out-String      
    $frag_ApplockerPath = $fragApplockerPath | ConvertTo-Html -As table -fragment -PreContent "<h2>Applocker Path Rules</h2>"  | Out-String
    $frag_ApplockerPublisher = $fragApplockerPublisher | ConvertTo-Html -As table -fragment -PreContent "<h2>Applocker Publisher Rules</h2>" | Out-String
    $frag_ApplockerHash = $fragApplockerHash | ConvertTo-Html -As table -fragment -PreContent "<h2>Applocker Hash Rules</h2>"  | Out-String
    $frag_ApplockerEnforcement = $fragApplockerEnforcement | ConvertTo-Html -As table -fragment -PreContent "<h2>Applocker Enforcement Rules</h2>"  | Out-String  
    $frag_wdacClixml = $fragwdacClixml | ConvertTo-Html -As Table -fragment -PreContent "<h2>WDAC Enforcement</h2>" -PostContent "<h4>$descripToDo</h4></details>"  | Out-String
    $frag_WDACCIPolicy = $fragWDACCIPolicy | ConvertTo-Html -As Table -fragment -PreContent "<h2>WDAC Policy</h2>" -PostContent "<h4>$descripWDAC</h4></details>"  | Out-String
            
    #MS Recommended Secuirty settings (SSLF)
    $frag_WindowsOSVal = $fragWindowsOSVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2>Windows GPO's</h2>" -PostContent "<h4>$descripWindowsOS</h4>" | Out-String
    $frag_EdgeVal = $fragEdgeVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2>MS Edge GPO's</h2>" | Out-String
    $frag_OfficeVal = $fragOfficeVal | ConvertTo-Html -as Table -Fragment -PreContent "<h2>MS Office GPO's</h2>" -PostContent "<h4>$descripOffice2016</h4>" | Out-String
    
    #MS Server Security Checks - SQL
    $frag_SQLVer = $fragSQLVer | ConvertTo-Html -as Table -Fragment -PreContent "<h2>SQL Version</summary></h2>" -PostContent "<h4>$descripToDo</h4></details>"| Out-String
    $frag_SQLDB = $fragSQLDB | ConvertTo-Html -As Table -fragment -PreContent "<h2>SQL Database</summary></h2>" -PostContent "<h4>$descripToDo</h4></details>" | Out-String
    $frag_SQLSvc = $fragSQLSvc | ConvertTo-Html -As Table -fragment -PreContent "<h2>SQL Service Account</summary></h2>" -PostContent "<h4>$descripToDo</h4></details>"| Out-String
    $frag_CISSQL = $fragCISSQL | ConvertTo-Html -As Table -fragment -PreContent "<h2>SQL Server CIS Benchmarks</summary></h2>" -PostContent "<h4>$descripSQLCIS</h4></details>" | Out-String
 
    #MS Server Security Checks go here - IIS
     
    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                     Define OUtput of Report Location
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>
    $secureReport = "C:\SecureReport"
    $OutConfigDir = "SystemReport"  
    $tpSec10 = Test-Path "C:\SecureReport\output\$OutConfigDir\" -ErrorAction SilentlyContinue
    
    if ($tpSec10 -eq $false)
        {
            New-Item -Path "C:\SecureReport\output\$OutConfigDir\" -ItemType Directory -Force
        }

    $working = "C:\SecureReport\output\$OutConfigDir\"
    #$Import2Excel = "C:\SecureReport\output\$OutConfigDir\" + "Import2Excel.html"
    $Report = "C:\SecureReport\output\$OutConfigDir\" + "$OutConfigDir.html"

    <#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
                          Create TABBED Web Page
    <><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    $style | out-file $Report
    $body = @"
        <body>
        <div class="container">
	
	    <h1 align=center style='text-align:center'>$basePNG</h1>

	    <div class="tabs">
		    <div class="headerTab">
			    <input type="radio" id="Summary" name="headerTabs" checked>
			    <label for="Summary">Compliance Status</label>
			    <div class="contentTab">
				    <p>$frag_Summary $Intro </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="OSDetails" name="headerTabs">
			    <label for="OSDetails">Host Details</label>
			    <div class="contentTab">
				    <p>$frag_Host $frag_OS $frag_Bios $frag_Cpu $frag_Network4 $frag_Network6 $frag_Share $frag_MDTBuildN
                     </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="Network" name="headerTabs">
			    <label for="Network">Legacy Networks, Firewalls</label>
			    <div class="contentTab">
				    <p>$frag_LegNIC $frag_FWProf $frag_FW
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="DomainInfo" name="headerTabs">
			    <label for="DomainInfo">Users & Groups</label>
			    <div class="contentTab">
				    <p>$frag_AccountDetails $frag_PassPol $frag_whoamiGroups $frag_DomainGrps $frag_GroupDetails  
                    </p>
			    </div>
		    </div>

		    <div class="headerTab">
			    <input type="radio" id="DomainSPN" name="headerTabs">
			    <label for="DomainSPN">Domain, Kerberos, Delegation</label>
			    <div class="contentTab">
				    <p>$frag_DCListN $frag_FSMO $frag_PreAuth $frag_NeverExpires $frag_ListUserSPNs $frag_ListComputerSPNs $frag_UnConstrained $frag_Constrained $frag_Trusted4Delegate $frag_Allowed2Delegate 
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="URA" name="headerTabs">
			    <label for="URA">URA & Security Options</label>
			    <div class="contentTab">
				    <p>$frag_SecOptions  $frag_URA $frag_whoamiPriv 
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="vbs" name="headerTabs">
			    <label for="vbs">VBS and Bitlocker</label>
			    <div class="contentTab">
				    <p>$frag_BitLockerN $frag_Msinfo $frag_Code $frag_kernelModeVal
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="AppExe" name="headerTabs">
			    <label for="AppExe">AV & Application Execution</label>
			    <div class="contentTab">
				    <p>$Frag_AVStatusN $frag_wdacClixml $frag_WDACCIPolicy $frag_ApplockerSvc $frag_ApplockerEnforcement $frag_ApplockerPath $frag_ApplockerPublisher $frag_ApplockerHash  
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="Software" name="headerTabs">
			    <label for="Software">Software and Features</label>
			    <div class="contentTab">
				    <p>$frag_PatchversionN $frag_HotFix $frag_InstaApps $frag_WinFeature $frag_Appx $frag_InstaApps16 $frag_SrvWinFeature
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="Certs" name="headerTabs">
			    <label for="Certs">Certificates & Ciphers</label>
			    <div class="contentTab">
				    <p>$frag_Certificates $frag_CipherSuit
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="Services" name="headerTabs">
			    <label for="Services">Services, Schedules, UnQuoted</label>
			    <div class="contentTab">
				    <p>$frag_UnQu $frag_TaskListings $frag_TaskPerms $frag_RunSpoolerSvc $frag_AutoRuns $frag_RunServices 
                    </p>
			    </div>
		    </div>

		    <div class="headerTab">
			    <input type="radio" id="FileReg" name="headerTabs">
			    <label for="FileReg">File & Registry</label>
			    <div class="contentTab">
				    <p> $frag_SysRegPermsN $frag_SysFoldersN $frag_CreateSysFoldN $frag_wFileN $frag_wFoldersN
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="DLL" name="headerTabs">
			    <label for="DLL">DLL, Signed Code</label>
			    <div class="contentTab">
				    <p>$frag_DLLSafe $frag_DLLHijack $frag_DllNotSignedN $frag_DriverQueryN $frag_AuthCodeSig
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="Password" name="headerTabs">
			    <label for="Password">Embedded Passwords</label>
			    <div class="contentTab">
				    <p>$frag_AutoLogon $frag_PSPass $frag_RegPasswords $frag_PSPasswords $frag_FilePass
                    </p>
			    </div>
		    </div>



		    <div class="headerTab">
			    <input type="radio" id="GroupPolicy" name="headerTabs">
			    <label for="GroupPolicy">Group Policies</label>
			    <div class="contentTab">
				    <p>$frag_LSAPPL $frag_PCElevate $frag_LapsPwEna $frag_CredGuCFG $frag_WDigestULC $frag_ASR $frag_WindowsOSVal $frag_OfficeVal $frag_EdgeVal
                    </p>
			    </div>
		    </div>


		    <div class="headerTab">
			    <input type="radio" id="SQL" name="headerTabs">
			    <label for="SQL">SQL Server</label>
			    <div class="contentTab">
				    <p>$frag_SQLVer $frag_SQLDB $frag_SQLSvc $frag_CISSQL
                    </p>
			    </div>
		    </div>
    
        </body>
"@ | out-file $Report -Append


<#<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
        Make the Output from PowerShell Look Pretty
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>#>

    $HostDomain = ((Get-CimInstance -ClassName win32_computersystem -ErrorAction SilentlyContinue).Domain) + "\" 
    $repDate = (Get-Date).Date.ToString("yy-MM-dd").Replace(":","_")

    Get-Content $Report | 
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

    <#<><><><><><><><><><><><><><><><><><><><><>
                   Backlog
    <><><><><><><><><><><><><><><><><><><><><><>

    Report on Windows defender and memory protections
    Proxy password reg key

    Forest and Domain health Checks??
    Additional account, delegation queries
    DNS CIS
    Certificate Services CIS
    IIS CIS

    cscript and vbscript reg setting - report on

    Fix Compliance Status to link to the page or section - this is currently broken


    Stuff still hanging over from previous version
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

    Auditing Wec\wef - remote collection point
    Interesting events
    wevtutil "Microsoft-Windows-Wcmsvc/Operational"
    File hash database

    remove powershell commands where performance is an issue, consider replacing with cmd alts

    Audit Settings - ms rec
    Chrome GPOs
    Add further MS Edge GPO checks
    Allign look and feel for all Reg and gpo queries inc mouse over effect

    View all loaded DLLs
    tasklist /m
    
    Find specific DLLs
    tasklist /m | find /i <dll name>

    Running Processes (with Service Names)
    List all running processes, plus PID and service name.
    tasklist /SVC

    sysmon installation??

    get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' #-Name Enabled -Value 0 

    get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' #-name CrashDumpEnabled
        0 = None
        1 = Complete Memory Dump
        2 = Kernel Memory Dump
        3 = Small Memory Dump
        7 = Automatic Memory Dump (Default)


#>
#######################################################################
#


#>


<#
<><><><><><><><><><><><><><><><><><><><><>
    Versioning, Updates and Changes 
<><><><><><><><><><><><><><><><><><><><><>

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
230807.2 - Thought it a good idea to audit services..... The number of active services is exponentially multiplying, the audit is available but not outputted in report unless required by adding the $frag_RunServices to the output sections - too much chaff
230808.1 - Based64 the Tenaka.net imaage and embedded into report 
        
        Convert image file to base64 for embedded picture in report
        Image is the title image on www.tenaka.net, if you wish to download image and confirm base64 and that it contains nothing malicious 

        [convert]::ToBase64String((get-content -path C:\Image\Image.png -Encoding Byte)) >> C:\image\base.txt

        [convert]::FromBase64String((get-content -path C:\Image\base.txt -Encoding Byte)) >> C:\image\Image.png   
230811.1 - Search Powershell History for passwords and usernames
230814.1 - Added Applocker Audit - Hash results show first hash only for each entry
230815.1 - Updated Get-NetfirewallRule from -all to  -PolicyStore activestore 
230816.1 - Added Details and Summary menu
230816.2 - reordered headings and grouping       
230816.3 - reordered compliance status, updated some compliances
230817.1 - Fixed inconsistencies with searching for passwords in the Registry - now also reports correctly the password in the report
230824.1 - Updated Fragments to weed out null fragments so they arent included in the finished report
230824.2 - created additional unfiltered report output as a backup and comparison to the filtered final report
230824.2 - Added final bit for Applocker auditing and showing enforcment mode
230824.3 - Fixed typo in Reg search for passwords
230901.1 - Added WDAC Policy and Enforcement checks
230905.1 - Updated filtering in Password Search in Registry - displays found password in the report also
230905.2 - Updates Installed Windows Features as MS have moved the goal posts and deprecated the dism command to list out packages
230905.3 - Broke Server and Client Features into differenct Fargs
230906.1 - Typo in the Autologon audit, removed the additional space that prevented it working. 
230906.1 - Update IPv4\6 Audits to cope with multiple active NIC's eg Hyper-V Server
230913.1 - Improved ASR reporting and fixed miss reporting when not set to 1 but not 0
230914.1 - Added Windows Patch version
230915.1 - Fixed excessive * char in report
230925.1 - Fixed sizing issues with html css settings 
231013.1 - Removed </span>, left over from original headers.
231029.1 - NEW LOOK AND FEEL - Tabs
231029.2 - SQL Reporting
231029.3 - Truncate all headings to fit into the 31 max char when importing into Excel
231031.1 - Removed href and compliance in page links as this breaks the Excel importing
231102.1 - Fixed Headers in some sections, without a header Excel is unable to identify and import
231106.1 - Identified issue with common unquoted paths query, its case sensitive and filtered out EXE and SYS
231106.2 - Audit Print Spooler on Servers and warning regarding it being enabled on DC's
231109.1 - SPN's, Delegation both Constrained and Uncontrained
231114.1 - Enhancing searching for passwords in PowerShell history
231115.1 - Updated Groups and Group Members 
231115.2 - Updated searching the registry for passwords
231116.1 - Updated Autologon search for passwords - Null isnt Null but empty
231122.1 - Added empty catch{} to suppress access warnings or added silently continue
240110.1 - Added function for directory creation
240110.2 - Added error capture and the display of message
240110.3 - Added output of each check in text format - the fragvars are export
240112.1 - Updated URA for accounts that arent listed by SID as these as these werent reported correctly.
240112.2 - Updated SQL filter to exclude lack of permissions or access issues
#>