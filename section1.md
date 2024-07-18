---
layout: default
---

# Attack path 1

The attack part 1 It's composed by two different sections

	- section 1
	- section 2

The full network diagram of the target servers are defined in the following section

## Complete network diagram

![ Attack_path 1](/assets/images/attack_path_1.png)

## Assets

The assets of the GCB that should be compromise during the attack path 1 belong to three different domains, it.gcb.local, msp.local and internal.msp.local:

```
	- employee15.it.gcb.local
	- it-appsrv01.it.gcb.local
	- it-sqlsrv02.it.gcb.local
	- msp-sqlreport.msp.local
	- msp-srv01.msp.local
	- internal-srv06.internal.msp.local
```

## Intrusion walkthrough

The starting point It's the domain computer of the itemplyee15, with hostname employee15.it.gcb.local. The initial privileges on the server are medium level and the AV Microsoft defender are enabled, so It's required an initial privilege escalation:

### 1. employee15.it.gcb.local

Privilege escalation:
```
- Enumerate local privileges
- Create new vulnerable service
- Install malicious binary
```
[employee15.it.gcb.local](./employee15.html)


### 2. it-appsrv01.it.gcb.local

Access:

```
- Enumerate groups
- Enumerate Domain Acls 
- Add group membership
- Abusse LAPS on Target Machine
```
Privilege Escalation:
```
- Reverse shell virtual machine Ubuntu
- Extract ketab ticket
- Dump credentials
```
[it-appsrv01.it.gcb.local](./it-appsrv01.html)


### 3. it-sqlsrv02.it.gcb.local

Access:
```
- Access with Local Administrator privileges
- Impersonate user
- Enumerate trust domain
```
[it-sqlsrv02.it.gcb.local](./it-sqlsrv02.html)

### 4. msp-sqlreport.msp.local

Lateral Movement:
```
- Use extracted credentilas for lateral movement
- Dump Lsass process
- Enumerate msp-srv06
- Port forwarding
```
[msp-sqlreport.msp.local](./msp-sqlreport.html)

### 5. msp-srv01.msp.local

Access:
```
- Access with Local Administrator privileges using PSWA with port-forwarding
- Dump Lsass process
```
[msp-srv01.msp.local](./msp-srv01.html)

### 6. internal-srv06.internal.msp.local

Access:
```
- Enumerate Domain ACLs
- Abusse of self-Membership rigths
- Access with Local Administrator privileges
- Dump Lsass process
```
	
[internal-srv06.internal.msp.local](./internal-srv06.html)

[back](./)


