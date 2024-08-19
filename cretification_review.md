---
layout: default
---

# Cretification Review

The [Certified Red Team Master] `CRTM` is an offensive certification fully hands-on, that cover all techniques required to perform an effective penetration test on Microsoft Environments.
From my side, the properly learning path to obtain this certification is :

	1. `CRTP` [Certified Red team Professional]
	2. `CRTE` [Certified Red Team Expert]
	3. `CRTM` [Certified Red Team Master]
	
The CRTM certification is based in two different steps, the Lab [Global Central Bank] `GCB` certification Lab and certification Exam [Certified Red Team master] `CRTM`.
The both has It's own badge:
	
	1. [Badge GCB](https://eu.badgr.com/public/assertions/onjqIRydQh-MChKX9Y9ejA?identity__email=fonso.gonzalezsan@gmail.com)
	2. [Badge CRTM](https://www.credential.net/7095643a-23bc-4f70-b914-3e6f3582886a#gs.dugr1w)

The most important Part of the certification It's the `CGB` Lab, It is an extensive and amazing platform, that allow you to attack a complete Company (It's simulate a Bank environment) such an internal employee with a low level of privilege across the domain. Could be an exercise for example based on assume the breach, or an insider.
You'll find 9 different domains with different types of Trusted relationship and with or without misconfigurations distributed on 30 different servers, and in all of them you must execute commands.

From my point of view, one of the most important differences with `CRTP` and `CRTE` is that you haven't walkthrough, which It's means that you are alone and the scenario is more realistic than the other certifications.
But during my learning hours across the platform, I could contact with GCB support, that provide you an excellent support Tips or Hints on order to become to compromissed the complete Global Central Bank. That, I mean, It's the best way to learn, work by yourself and ask your questions or doubts from your personal hacker mind.
The Certification cover the following techniques:
	
	- Domain enumeration
	- Services and ports enumeration
	- Local Privilege Escalation in Windows Servers
	- Privilege Escalation in Windows Domains
	- Lateral Movements
	- Pivoting And Port-forwarding
	- Disable Windows Double-hop errors
	- Abuse of Microsoft Windows features: WSDL
	- Abuse of Microsoft Windows features: LAPS
	- Abuse of Microsoft Windows features: JEA
	- Abuse of Microsoft Windows features: Trusted domains
	- Abuse of Microsoft Windows features: AV Evasion
	- Abuse of Microsoft Windows features: Domain Misconfigurtaions
	- Abuse of Microsoft Windows features: Domains Trusted relationship
	- Abuse of Microsoft Windows features: Domains Trusted SID History injection
	- Abuse of Microsoft Windows features: Domains Trusted Parent-Child Relationship
	- Abuse of Microsoft Windows features: Domain ACLs
	- Abuse of Microsoft Windows features: Domain Constrained Delegation
	- Abuse of Microsoft Windows features: Domain Uncosntrained Delegation based Resource
	- Phissing attack simulations
	- Network traffic sniffer
	- Abuse of network services with improper authentication
	- Hunt and Re-use credentials
	- Abuse of privileges on Virtual Machines Hyper-V
	- busse of Microsoft Windows features: WSUS updates

Some techniques that I learned during `CRTE` certification are not included on `CRTM` such Abuse of Domain certificates or GSAM windows features, but all the other techniques could be learned deeper.
All the changes that you'll perform across the certification LAB domains are revert in 24 h.

Finally, If you'll finish the certification Lab by yourself understanding the misconfigurations and how to exploit it, probably you couldn't pass the exam.
Why? Because the exam It's not only offensive. I'm explained it on the next section.

## Exam Review

The certification exam: 
	- 4 days (no proctored)
	- 48 h with certification lab access
	- 48 h for make a report

The exam environment:
	- 2 domains
	- 6 servers
	
The exam has two different parts the first part It's similar to `CRTE` exam with domain misconfigurations based on the techniques that you learned on `GCB` Lab and the second part is based on detect and perform a solution, for mitigating the breach, misconfiguration or entry point.     

### Offensive Part

It depends of your initial level, but if you obtained the GCB certification previously could be funny and you'll enjoy during the required hours. 
In my first and unique exam attempt. I taked breaks, sleep, cook, eat, etc and I used more than 30 hours during the weekend. 

### Defensive Part

The defensive part It's an extra part that you should complete after compromises the full environment. And was awesome too.
Before finish the 48 h of lab access, you should change the domain configurations that allow you also understand the attacks from a different point of view, change Domain ACls, domains GPOs, windows features etc.
During the last 3 hours I performed an interview that I successfully passed for my actual Job position :). Great! 

## Conclusions

Finally, you should create an Exam Report with Executive and Technical exam attack paths, that should include the full details of Offensive and Defensive parts.
After wait 7 days, you'll receive an email with your exam feedback !

The key in order to pass the exam and obtain the certification, `the GCB support want to help you!`

[back](./)
