---
layout: default
---

# Attack path 5

The attack path 5 It's composed by :

	- section 8

The traget division of the company is Security, gcbsec.local untrust domain of the bank
The full network diagram of the target servers are defined in the following section

## Complete network diagram SEC GCB 

![ Attack_path 5 ](/assets/images/attack_path_5.png)

## Assets

The assets of the GCB that should be compromise during the attack path 5 belong to gcbsec.local domain:

```
	- it-track01.it.gcb.local
	- sec-syslog01.gcbsec.local
	- sec-dc.gcbsec.local
```

## Intrusion walkthrough


### 1. it-trak01.it.gcb.local

Access :

```
- Reuse web access credentials extracted from vault of employee15$
- Detect the IT memory issue on the web application and extract the lsass dump
- Impersontae user and hunt for sec-syslog01 server
```

[it-track01.it.gcb.local (Security) ](./it-track01_security.html)


### 2. sec-syslog01.gcbsec.local

Access:

```
- Impersonate amdin user of secsyslog machine
- using Psexec for access with nt authority system privileges
- Dump lsass process
```
[sec-syslog01.gcbsec.local](./sec-syslog01.html)


### 3. sec-dc.gcbsec.local

Access:

```
- Enumerate domain
- detect secsyslogagent as Enterprise admin of gcbsec.local domain
- Impersonate secsyslogagent
- Access to sec-dc target domain as enterprise admin
- dump domain hashes 
```
[sec-dc.gcbsec.local](./sec-dc.html)




[back](./)
