Vulnerability Scanner for Windows 10 and 11

The purpose of the script is to check for vulnerabilities and common misconfigurations with Windows and installed applications. These issues can be abused by hackers or disgruntled workers providing privilege escalation routes from user to system and ultimately Domain Admin.

The vulnerability script has been tested on the latest versions of Windows 10 and 11 with PowerShell version 5.1 and outputs a html page.

Do not make changes to your IT systems based on the output of this report without a backup or testing, some of the suggestions are likely to prevent Linux or legacy services from connecting to the domain.

![vulnreport](https://user-images.githubusercontent.com/86342641/146689909-29d17a7c-918a-4a82-8963-e3b1785467ac.png)



Report is saved to C:\Vulnreport\FinishedReport.htm

​

Before everyone gets critical regarding the script formatting, some is due to how ConvertTo-HTML expects the data, most is to help those that aren’t familiar with scripting. There is a conscience decision not to use aliases or abbreviations and where possible to create variables. 

​

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

​

#TPM and Bitlocker

"TPM and Bitlocker protect against offline attack from usb and mounting the local Windows system then accessing the local data. 'TPM and Pin' enhances Bitlocker by preventing LPC Bus (Low Pin Count) bypasses of Bitlocker with TPM.

 

Further information can be found @

https://www.tenaka.net/bitlocker

 

#Secure Boot

Secure Boot is a security standard to ensure only trusted OEM software is allowed at boot. At startup the UEFi and boot software's digital signatures are validated preventing rootkits

 

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

When applications do not fully qualify the DLL path and instead allow searching the default behaviour if for the ‘Current Working Directory’ called 2nd in the list of directories. This allows an easy route to calling malicious DLL’s. Setting ‘DLL Safe Search’ mitigates the risk by moving CWD to later in the search order.

​

Further information can be found @

https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

 

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

​

For the following words:

password, credential

​

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

The Unquoted paths vulnerability is when a Windows Service's 'Path to Executable' contains spaces and not wrapped in double quotes providing a route to System.

 

Further information can be found @

https://www.tenaka.net/unquotedpaths

​

#Legacy Network Protocols

LLMNR and other legacy network protocols can be used to steal password hashes.

 

Further information can be found @

https://www.tenaka.net/responder

 

$descripRegPer ="Weak Registry permissions allowing users to change the path to launch malicious software @ https://www.tenaka.net/unquotedpaths"

 

#Permissions Weakness's in Default System Directories - Write

System default Folders that allow a User the Write permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.

​

Searches:

C:\PerfLogs
C:\Program Files
C:\Program Files (x86)
C:\Windows

​

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

​

#Permissions Weakness's in Default System Directories - Create Files

System default Folders that allow a User the CreateFile permissions. These can be abused by creating content in some of the allowable default locations. Prevent by applying Execution controls eg Applocker.

 

Expected folders that a user can CreateFiles to:

C:\Windows\PLA\ReportsC:\Windows\PLA\Reports\en-GB

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

​

Further information can be found @

https://www.tenaka.net/unquotedpaths

https://www.tenaka.net/applockergpo

​

#Permissions Weakness's in Non-Default Directories

A vulnerability exists when enterprise software has been installed on the root of C:\. The default permissions allow a user to replace approved software binaries with malicious binaries.

​

Further information can be found @

https://www.tenaka.net/unquotedpaths

​

#Files that are Writeable

System files that allowing users to write can be swapped out for malicious software binaries.

 

Further information can be found @

https://www.tenaka.net/unquotedpaths

 

#Firewalls

Firewalls should always block inbound and exceptions should be to a named IP and Port.

 

Further information can be found @

https://www.tenaka.net/whyhbfirewallsneeded
