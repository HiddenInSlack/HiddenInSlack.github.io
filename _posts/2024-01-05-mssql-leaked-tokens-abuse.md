---
layout: post
title: "Abusing leaked token handles in MSSQL"
date: 2024-01-05 10:00:00
Author: Iago Abad Barreiro
toc: true
---

## Context

Microsoft SQL server provides two main authentication methods:

* SQL authentication mode
* Windows authentication mode

There is also the possibility to use a mixture of both.

### SQL authentication mode

In this mode, Microsoft SQL server maintains its own usernames and passwords independently of Windows.

### Windows authentication mode

In this mode, Microsoft SQL server uses Windows credentials. This could be local or, in case the server is joined to a domain, it can also be Active Directory credentials.

When users log in with this type of credentials, a token handle for this user will be present in ```sqlserv.exe``` process. Furthermore, the token handle will remain open for an indefinite amount of time.

If we have compromised the Microsoft SQL server and have the capacity to execute code, we can impersonate tokens present in ```sqlserv.exe``` looking for local privilege escalation or Active Directory lateral movement opportunities.

In the following [repository](https://github.com/blackarrowsec/Handly/tree/main/MSSQL) you can see a weaponization, along with details about the technique.

Shoutout to [Kurosh](https://x.com/_Kudaes_) for his [post](https://www.tarlogic.com/blog/token-handles-abuse/) on leaked token handles abuse, as well as for the help provided in the creation of this weaponization.
