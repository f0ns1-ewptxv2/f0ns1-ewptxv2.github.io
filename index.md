---
layout: default
---


Global Central bank certification:

```
https://www.alteredsecurity.com/gcb
```

In this blog the choosen language it's English.

```
The global environment contains fully patched Windows Server 2019 machines
```

Thanks to the GCB support because I learned a lot during the exploitation process related to Active Directory pentesting, abuses, bypases, etc.

## Section Index

This index describe the walktrouh that I follow in order to perform the full compromise of Global Central Bank laboratory:

  1. [Attack_path_1](./section1.html)
  2. [Attack_path_2](./section2.html)
  3. [Attack_path_3](./section3.html)
  4. [Attack_path_4](./section4.html)
  5. [Attack_path_5](./section5.html)
  6. [Attack_path_6](./section6.html)
  7. [Attack_path_7](./section7.html)
  7. [Attack_path_8](./section8.html)




## Complete Infraestructure certification diagram

![GCB Domains](/assets/images/gcb_network_domains.png)

## Compromissed servers by domain

On the following list I describe the compromissed servers for each domain:

### gcb.local

```
gcb-dc.gcb.local
```

### it.gcb.local

```
it-employee15.it.gcb.local
it-appsrv01.it.gcb.local
it-sqlsrv02.it.gcb.local
it-track01.it.gcb.local
it-preprod01.it.gcb.local
it-dc.it.dc.local
```

### msp.local

```
msp-sqlreport.msp.local
msp-srv01.msp.local
msp-dc01.msp.local
```

### internal.msp.local

```
internal-srv01.internal.msp.local
internal-batch.internal.msp.local
internal-dc01.internal.msp.local
```

### gcbfinance.local

```
finance-vanessa.gcbfinance.local
finance-dc01.gcbfinance.local
```

### gcbsec.local

```
sec-syslog01.gcbsec.local
sec-dc.gcbsec.local
```

### gcbhr.local

```
hr-mail.gcbhr.local
hr-erika.gcbhr.local
hr-dc02.gcbhr.local
```

### gcbacc.local

```
acc-dc07.gcbacc.local
acc-data.gcbacc.local
```

### gcbvault.local

```
vault-srv.gcbvault.local
vault-dc.gcbvault.local
vault-db.gcbvault.local
```
## FAQS

## Whoami
Ildefonso González Sánchez
https://www.linkedin.com/in/ildefonso-gonz%C3%A1lez-s%C3%A1nchez-0b693555/




