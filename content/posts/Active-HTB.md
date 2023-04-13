---
title: "Active HTB"
date: 2023-04-12T21:03:19-07:00
draft: false
---

# Recon

~~~sh
sudo nmap -p- -sU -sS -min-rate=10000 -T5 10.10.10.100

PORT      STATE SERVICE  
53/tcp    open  domain  
88/tcp    open  kerberos-sec  
135/tcp   open  msrpc  
139/tcp   open  netbios-ssn  
389/tcp   open  ldap  
445/tcp   open  microsoft-ds  
464/tcp   open  kpasswd5  
593/tcp   open  http-rpc-epmap  
636/tcp   open  ldapssl  
3268/tcp  open  globalcatLDAP  
5722/tcp  open  msdfsr  
9389/tcp  open  adws  
47001/tcp open  winrm  
49152/tcp open  unknown  
49153/tcp open  unknown  
49154/tcp open  unknown  
49155/tcp open  unknown  
49157/tcp open  unknown  
49158/tcp open  unknown  
49165/tcp open  unknown  
49172/tcp open  unknown  
49173/tcp open  unknown  
53/udp    open  domain  
123/udp   open  ntp
~~~

It looks like an active directory server! For better enumeration of the domain
~~~sh
sudo nmap -sC -A -O 10.10.10.100

PORT      STATE SERVICE       VERSION  
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)  
| dns-nsid:  
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)  
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-13 02:33:56Z)  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First  
-Site-Name)  
445/tcp   open  microsoft-ds?  
464/tcp   open  kpasswd5?  
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  tcpwrapped  
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First  
-Site-Name)  
3269/tcp  open  tcpwrapped  
49152/tcp open  msrpc         Microsoft Windows RPC  
49153/tcp open  msrpc         Microsoft Windows RPC  
49154/tcp open  msrpc         Microsoft Windows RPC  
49155/tcp open  msrpc         Microsoft Windows RPC  
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0  
49158/tcp open  msrpc         Microsoft Windows RPC  
49165/tcp open  msrpc         Microsoft Windows RPC  
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).  
TCP/IP fingerprint:  
OS:SCAN(V=7.93%E=4%D=4/12%OT=53%CT=1%CU=33035%PV=Y%DS=2%DC=T%G=Y%TM=64376A5  
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=104%TI=I%CI=I%II=I%SS=S%TS=  
OS:7)OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M5  
OS:3CNW8ST11%O6=M53CST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200  
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M53CNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S  
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%  
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=  
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%  
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(  
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=  
OS:N%T=80%CD=Z)  
  
Network Distance: 2 hops  
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:window  
s  
  
Host script results:  
|_clock-skew: 13s  
| smb2-time:  
|   date: 2023-04-13T02:35:01  
|_  start_date: 2023-04-13T02:09:16  
| smb2-security-mode:  
|   210:  
|_    Message signing enabled and required
~~~

# Active Directory

Checking the SMB server there is a file called `groups.xml` and it contains a `cpassword`  which is gpp encryption and using a tool called `gpp-decrypt` it is possible to decrypt the password! Or if you are on blackarch use `https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py`


Then checking what permissions the gained creds have..
~~~sh
smbmap -u "SVC_TGS" -p "[REDACTED]" -H active.htb  
  
________  ___      ___  _______   ___      ___       __         _______  
/"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\  
(:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)  
\___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/  
__/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /  
/" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \  
(_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)  
-----------------------------------------------------------------------------  
SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com  
https://github.com/ShawnDEvans/smbmap  
  
  
[+] IP: active.htb:445  Name: unknown                   Status: Authenticated  
Disk                                                    Permissions     Comment  
----                                                    -----------     -------  
ADMIN$                                                  NO ACCESS       Remote Admin  
C$                                                      NO ACCESS       Default share  
IPC$                                                    NO ACCESS       Remote IPC  
NETLOGON                                                READ ONLY       Logon server share  
Replication                                             READ ONLY  
SYSVOL                                                  READ ONLY       Logon server share  
Users                                                   READ ONLY
~~~


# Kerberoasting 

It is when an authenticated user requests for a SPN ticket that has hashes or sensitive data. Use one of Impacket's scripts to obtain an SPN then crack the hash! Then login to get the root flag!
