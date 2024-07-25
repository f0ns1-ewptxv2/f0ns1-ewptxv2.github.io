---
layout: default
---

# Attack path 6

The attack path 6 It's composed by :

	- section 9

The traget of the comany is acc data division of the bank
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
- Reuse web access credentials extracted from vault of employee15$
```

[ sec-dc.gcbsec.local (hunt) ](./sec-dc_hunt.html)


### 2. acc-dc07.gcbacc.local

Access:

```

```
[scc-dc07.gcbacc.local](./acc-dc07.html)


### 3. acc-data.gcbacc.local

Access:

```
 
```
[acc-data.gcbsec.local](./sec-dc.html)




[back](./)
