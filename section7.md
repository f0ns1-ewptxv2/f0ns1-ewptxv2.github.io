---
layout: default
---

# Attack path 7

The attack path 7 It's composed by :

	- section 10

The traget division of the company is IT and GCB Global central Bank
The full network diagram of the target servers are defined in the following section

## Complete network diagram SEC GCB 

![ Attack_path 5 ](/assets/images/attack_path_7.png)

## Assets

The assets of the GCB that should be compromise during the attack path 7 belong to it.gcb.local and gcb.local domains:

```
	- it-dc.gcb.local
	- gcb-dc.gcb.local
```

## Intrusion walkthrough


### 1. it-dc.it.gcb.local

Access :

```
- Hunt for domain credentials passwords
- validate the users that could belong the cleartext credentials
- Authenticate in IT domain such org admin
- Enumerate DOmain ACls
- Abuse of douan ACLs and perform DCSync attack
- Impersonante Domain Admin
- Access to it-dc.it.gcb.local
- Dump domain hashes
```

[ it-dc.it.gcb.local ](./it-dc.html)


### 2. dc-gcb.gcb.local

Access:

```
- Abuse of child-parnet trust domain
- Access to gcb-dc.local such Enterprise admin
- Dump domain hashes
```
[ gcb-dc.gcb.local ](./gcb-dc.html)




[back](./)
