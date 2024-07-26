---
layout: default
---

# Attack path 4

The attack path 4 It's composed by :

	- section 7

The traget division of the GCB company is the Human Resources, gcbhr.local domain of the bank
The full network diagram of the target servers are defined in the following section

## Complete network diagram HR GCB 

![ Attack_path 4](/assets/images/attack_path_4.png)

## Assets

The assets of the GCB that should be compromise during the attack path 2 belong to gcbhr.local domain:

```
	- hr-mail.gcbhr.local
	- hr-erika.gcbhr.local
	- hr-dc02.gcbhr.local
```

## Intrusion walkthrough


### 1. hr-mail.gcbhr.local

Access :

```
- Enumerate hosts for Network range
- Found SMTP server
- Connect to POP3 service and extract mailbox for vanessa finance user

```

[hr-mail.gcbhr.local](./hr-mail.html)


### 2. hr-erika.gcbhr.local

Access:

```
- Perform a custom phising attack
- Build a Crafted LNK binary with malicious payload
- Impersonte user Romi of IT domain like a sender
- Obtain a reverse shell
- Bypass UAC from command line
- Privilege escalation
- Dump Lsass process
```
[hr-erika.gcbhr.local](./hr-erika.html)


### 3. hr-dc02.gcbhr.local

Access:

```
- Impersonate user erika-admin
- Enumerate domain and found Windows Exchange permissions
- Abuse Dacl privileges in order to perform a DCsync attack
- Access to Domain Controller with Domain Admin privileges
- Dump Lsass process
```
[hr-dc02.gcbhr.local](./hr-dc02.html)




[back](./)
