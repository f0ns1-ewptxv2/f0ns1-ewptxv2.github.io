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

### employee15.it.gcb.local

```
```
[employee15.it.gcb.local](./employee15.html)


### it-appsrv01.it.gcb.local

```
```
[it-appsrv01.it.gcb.local](./it-appsrv01.html)


### it-sqlsrv02.it.gcb.local

```
```
[it-sqlsrv02.it.gcb.local](./it-sqlsrv02.html)

### msp-sqlreport.msp.local

```
```
[msp-sqlreport.msp.local](./msp-sqlreport.html)

### msp-srv01.msp.local

```
```
[msp-srv01.msp.local](./msp-srv01.html)

### internal-srv06.internal.msp.local

```
```	
[internal-srv06.internal.msp.local](./internal-srv06.html)

[back](./)

