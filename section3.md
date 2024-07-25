---
layout: default
---

# Attack path 3

The attack path 3 It's composed by three different sections

	- section 3
	- section 6

The full network diagram of the target servers are defined in the following section

## Complete network diagram Finance GCB 

![ Attack_path 3](/assets/images/attack_path_3.png)

## Assets

The assets of the GCB that should be compromise during the attack path 2 belong to two different domains, it.gcb.local, gcbfinance.local:

```
	- it-track01.it.gcb.local
	- finance-vanessa.gcbfinance.local
	- finance-dc01.gcbfinance.local
```

## Intrusion walkthrough


### 1. it-track-01.it.gcb.local

Access :

```
- Access to it-track01 with Admin user
- Hunt for inbound web connection
- Sniff HTTP network traffic
- Extract vanessa credentials of finance domain
```

[it-track01.it.gcb.local (finance) ](./it-track01_finance.html)


### 2. finance-vanessa.gcbfinance.local

Access:

```
- Enumerate Windows JEA features endpoints
- Abuse JEA privileges
- Modify local administrators group
- Access with administrator privileges
- Dump Lsass process
```
[finance-vanessa.gcbfinance.local](./finance-vanessa.html)


### 3. finance-dc01.gcbfinance.local

Access:

```
- Enumerate domain gcbfinance.local
- Perform unconstrained delagtion attack
- Perform DCsync attack with extracted TGT
- Access to finance-dc01 with Domain Admin privileges
- Extract domain hashes

```
[finance-dc01..gcbfinance.local](./internal-batch.html)




[back](./)
