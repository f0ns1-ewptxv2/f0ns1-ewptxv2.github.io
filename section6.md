---
layout: default
---

# Attack path 6

The attack path 6 It's composed by :

	- section 9

The traget division of the company is acc data, untrust gcbacc.local domain of the bank
The full network diagram of the target servers are defined in the following section

## Complete network diagram SEC GCB 

![ Attack_path 5 ](/assets/images/attack_path_6.png)

## Assets

The assets of the GCB that should be compromise during the attack path 6 belong to gcbacc.local domain:

```
	- sec-dc.gcbsec.local
	- acc-dc07.gcbacc.local
	- acc-data.gcbacc.local
```

## Intrusion walkthrough


### 1. sec-dc.gcbsec.local

Access :

```
- Trusted domains enumeration unrechables from it.gcb.local
- Hunt for cleartext credentials
```

[ sec-dc.gcbsec.local (hunt) ](./sec-dc_hunt.html)


### 2. acc-dc07.gcbacc.local

Access:

```
- Hunt for lateral movement
- Shadow principals enumeration
- Abuse of shadow principals relationship between domains
- Lateral movement Access to acc-dc07.gcb.local
- Disable AV dump domain hashes
```
[acc-dc07.gcbacc.local](./acc-dc07.html)


### 3. acc-data.gcbacc.local

Access:

```
- Impersonate Domain Admin of accgcb.local
- Lateral movement access to acc-data.gcbacc.local
- Disable AV and dump Lsass process
- Hunt for cleartext credentials
```
[acc-data.gcbsec.local](./acc-data.html)




[back](./)
