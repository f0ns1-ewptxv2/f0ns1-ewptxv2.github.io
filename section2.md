---
layout: default
---

# Attack path 1

The attack path 2 It's composed by three different sections

	- section 3
	- section 4
	- section 5

The full network diagram of the target servers are defined in the following section

## Complete network diagram

![ Attack_path 2](/assets/images/attack_path_2.png)

## Assets

The assets of the GCB that should be compromise during the attack path 2 belong to three different domains, it.gcb.local, msp.local and internal.msp.local:

```
	- it-track01.it.gcb.local
	- it-preprod.it.gcb.local
	- internal-batch.internal.msp.local
	- internal-dc01.internal.msp.local
	- msp-dc01.msp.local
```

## Intrusion walkthrough

The starting point It's the domain computer of the itemplyee15, with hostname employee15.it.gcb.local. You should enum the it.gcb.local domain using bloodhound in order to proced qith it-track01 access:

### 1. it-track-01.it.gcb.local

Access :
```
- Enumerate domain privilges 
- Abusse of RCBD
- Set new SPN to the target machine
- Abuse of constrained delagation in order to access like Domain Admin on the target machine it-track01 
- Disable AV
- Dump Lsass process 
```

[it-track01.it.gcb.local](./it-track01.html)


### 2. it-preprod.it.gcb.local

Access:

```

```
[it-preprod.it.gcb.local](./it-preprod.html)


### 3. internal-batch.internal.msp.local

Access:
```

```
[internal-batch.it.gcb.local](./internal-batch.html)

### 4. internal-dc01.internal.msp.local

Lateral Movement:
```

```
[internal-dc01.internal.msp.local](./internal-dc01.html)

### 5. msp-dc01.msp.local

Access:
```

```
[msp-dc01.msp.local](./msp-dc01.html)



[back](./)


