---
layout: default
---

# Attack path 8

The attack path 8 It's composed by :

	- section 11

The traget of the company is GCB Global central Bank WSUS and airgap disconected environment
The full network diagram of the target servers are defined in the following section

## Complete network diagram SEC GCB 

![ Attack_path 5 ](/assets/images/attack_path_8.png)

## Assets

The assets of the GCB that should be compromise during the attack path 8 belong to gcb.local and gcbvault.local domains:

```
	- gcb-wsus.gcb.local
	- vault-srv.gcbvault.local
	- vault-dc.gcbvault.local
	- vault-db.gcbvault.local
```

## Intrusion walkthrough


### 1. gcb-wsus.gcb.local

Access :

```
- Access with Enterprise Admin privileges
- Enumerate wsus connected computers
```

[ gcb-wsus.gcb.local ](./gcb-wsus.html)


### 2. vault-srv.gcbvault.local

Access:

```
- Remote access with wsus malicious update
- Disable AV and Dump Lsass
- Enumerate Hyper-V VM
```
[ vault-srv.gcbvault.local ](./vault-srv.html)


### 2. vault-dc.gcbvault.local

Access:

```
- Manage VM and stop DC service with administrator privileges
- Mount the VHDI in local Filesystem
- Extract Hives
- Use DSInternal tools in order to extract domain user accounts and hashes
- Unmount FileSystem and Strat DC VM 
```
[ vault-dc.gcbvault.local ](./vault-dc.html)

### 2. vault-srv.gcbvault.local

Access:

```
- Access with vaultdbadmin user
- Extract the final Transfer Flag 
- Obtaining GCB Powned certificate
```
[ vault-db.gcbvault.local ](./vault-db.html)



[back](./)
