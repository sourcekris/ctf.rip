---
id: 684
title: 'BSides Canberra CTF 2016 - LiveCD - Forensics Challenge'
date: 2016-04-17T09:22:57+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=684
permalink: /bsides-canberra-ctf-2016-livecd-forensics-challenge/
themepixels_post_link_target:
  - 'yes'
themepixels_enable_post_header:
  - default
themepixels_enable_post_meta_single:
  - default
themepixels_enable_post_featured_content:
  - default
themepixels_enable_post_categories:
  - default
themepixels_enable_post_tags:
  - default
themepixels_enable_post_share:
  - default
themepixels_enable_post_author_info_box:
  - default
themepixels_enable_related_posts:
  - default
themepixels_enable_post_next_prev_links:
  - default
themepixels_enable_topbar:
  - default
themepixels_enable_sticky_header:
  - default
themepixels_header_layout:
  - default
themepixels_site_layout:
  - default
themepixels_sidebar_position:
  - default
post_views_count:
  - "1373"
image: /images/2016/04/bsides.png
categories:
  - Uncategorized
---
The inaugural BSides Canberra Australia was held this Friday and Saturday and of course since we were going to be there we entered their CTF. I was expecting a small competition with reasonably basic challenges but what I got was a huge pool of great challenges to choose from. We did well and fought hard but a couple of mistakes cost us a lot of time so 3rd place was the best we could achieve. Prizes were amazing though (SANS NetWars entry!), even for 3rd place so I'm very happy!

This challenge was all about Linux memory analysis and from talking to some people the sticking point was finding a working Volatility profile. It's not my first Linux memory analysis rodeo though so that wasn't a problem. Here's the clue:

> LiveCD (150pts)
> 
> With the introduction of new metadata laws, the government has become aware that Andrew has been up to naughty things that he really shouldn't do. Red flags included Google searches such as "How to do well in CEH", "CISSP for beginners" and "Which CREST certificate is the best?". Since he is clearly a danger to himself and others, the AFP recently raided his house and took possession of all his computers.
> 
> Much to their dismay, the AFP found the web history they required to charge Andrew with crimes against infosec was encrypted. Thinking he was smart, Andrew used LiveCD with a one time pad program to derive the encryption key, so when this day came no one could possibly have evidence of his embarrassing web history. Unfortunately for him, he simply suspended the VM instead of shutting it down properly, leaving a nice RAM snapshot on the disk. The link below is this snapshot.
> 
> ctf.bsides:10000/chals/forensics/dump.vmem
> 
> GOAL
  
> Examine the snapshot and see if you can recover the encryption key so Andrew can be appropriately punished.

First thing we do is grab the file and examine the strings, we're looking for:

  1. Operating system
  2. Exact version numbers of Kernel

A quick strings with no flags tells us pretty quickly its a Linux OS, since most CTFs these days use Ubuntu Linux for challenge systems we look for strings that will indicate the Kernel version being used and the OS it comes from:


```
root@kali:~/ctfs/bsides/forensics/dump# strings dump.vmem | grep Linux | grep Ubuntu | head -1
Linux version 4.2.0-16-generic (buildd@lcy01-07) (gcc version 5.2.1 20151003 (Ubuntu 5.2.1-21ubuntu2) ) #19-Ubuntu SMP Thu Oct 8 15:35:06 UTC 2015 (Ubuntu 4.2.0-16.19-generic 4.2.3)

root@kali:~/ctfs/bsides/forensics/dump# strings dump.vmem | grep 'Ubuntu 15'
Linux 4.2.0-16-generic Ubuntu 15.10
```


We can see the kernel version turns out to be `4.2.0-16-generic`. We now need to find a Volatility profile for this. A quick browse on the profile repo here <https://github.com/volatilityfoundation/profiles/tree/master/Linux/Ubuntu/x64> yields two Ubuntu Kernel profiles. Firstly I grab the Ubuntu1510.zip profile and check out the contents:


```
root@kali:~/ctfs/bsides/forensics/dump# unzip -t Ubuntu1510.zip
Archive: Ubuntu1510.zip
testing: Ubuntu1510/ OK
testing: Ubuntu1510/.DS_Store OK
testing: __MACOSX/ OK
testing: __MACOSX/Ubuntu1510/ OK
testing: __MACOSX/Ubuntu1510/._.DS_Store OK
testing: Ubuntu1510/boot/ OK
testing: Ubuntu1510/boot/System.map-4.2.0-22-generic OK
testing: Ubuntu1510/module.dwarf OK
No errors detected in compressed data of Ubuntu1510.zip.
```


We see it's for Kernel version `4.2.0-22-generic`. So we cannot use this one. Damn. I check out the second 15.10 profile called `Ubuntu1510server.zip`.


```
root@kali:~/ctfs/bsides/forensics/dump# wget -q https://github.com/volatilityfoundation/profiles/raw/master/Linux/Ubuntu/x64/Ubuntu1510server.zip
root@kali:~/ctfs/bsides/forensics/dump# unzip -t Ubuntu1510server.zip
Archive: Ubuntu1510server.zip
testing: Ubuntu1510server/ OK
testing: Ubuntu1510server/.DS_Store OK
testing: __MACOSX/ OK
testing: __MACOSX/Ubuntu1510server/ OK
testing: __MACOSX/Ubuntu1510server/._.DS_Store OK
testing: Ubuntu1510server/boot/ OK
testing: Ubuntu1510server/boot/System.map-4.2.0-16-generic OK
testing: Ubuntu1510server/module.dwarf OK
```


Brilliant, this is for our kernel version, so we place the `Ubuntu1510server.zip` into /usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/ and verify Volatility can see it:


```
root@kali:~/ctfs/bsides/forensics/dump# volatility --info | grep Linux
Volatility Foundation Volatility Framework 2.5
linux_banner - Prints the Linux banner information
linux_yarascan - A shell in the Linux memory image
LinuxUbuntu1510serverx64 - A Profile for Linux Ubuntu1510server x64
LinuxUbuntu1510x64 - A Profile for Linux Ubuntu1510 x64
```


Neat, so we now start checking out the contents of the memory dump. I start with a list of the running processes. I see something which catches my eye based on the clue:


```
root@kali:~/ctfs/bsides/forensics/dump# volatility -f dump.vmem --profile=LinuxUbuntu1510serverx64 linux_psaux
Volatility Foundation Volatility Framework 2.5
Pid Uid Gid Arguments
1 0 0 /sbin/init splash
2 0 0 [kthreadd]
3 0 0 [ksoftirqd/0]
4 0 0 [kworker/0:0]
...
2167 1000 1000
2168 1000 1000
2199 1000 1000 ./otp
```


Process ID 2199 is interesting looking one "OTP" being an acronym for "One Time Pad". I check the user's bash history next to see if they ran anything else interesting recently:


```
root@kali:~/ctfs/bsides/forensics/dump# volatility -f dump.vmem --profile=LinuxUbuntu1510serverx64 linux_bash
Volatility Foundation Volatility Framework 2.5
Pid Name Command Time Command
-------- -------------------- ------------------------------ -------
2168 bash 2016-03-16 23:59:58 UTC+0000 ./otp
2168 bash 2016-03-16 23:59:58 UTC+0000 export remember=b25lIHRpbWUgcGFkcyBhcmUgYSBiaXRjaCBmb3Iga2V5IGRpc3RyaWJ1dGlvbiwgcmVtZW1iZXIgdG8gc2F2ZSBENFdhaU9pZDlpUlZsYUhmV1dWT3l3SXJlOXVVYTFHanQ0anZjeGlVaVl0TSBzb21ld2hlcmUuCg==
2168 bash 2016-03-16 23:59:58 UTC+0000 > .bash_history
2168 bash 2016-03-17 00:01:26 UTC+0000 clear
2168 bash 2016-03-17 00:01:29 UTC+0000 ./otp
```


Interesting environment variable you have there, it decodes to:

`one time pads are a bitch for key distribution, remember to save D4WaiOid9iRVlaHfWWVOywIre9uUa1Gjt4jvcxiUiYtM somewhere.` 
  

Great so looks like we have a key to a one time pad. At this point, based on the goal which was to recover the encryption key, I thought I was done. But this was not the flag, we had to dig deeper. I decided to dump the otp process next.
  
```
root@kali:~/ctfs/bsides/forensics/dump# volatility -f dump.vmem --profile=LinuxUbuntu1510serverx64 -p 2199 linux_procdump -D procdump
Volatility Foundation Volatility Framework 2.5
Offset Name Pid Address Output File
------------------ -------------------- --------------- ------------------ -----------
0xffff880000f16040 otp 2199 0x0000000000400000 procdump/otp.2199.0x400000
root@kali:~/ctfs/bsides/forensics/dump# ls -lah procdump/otp.2199.0x400000
-rw-r--r-- 1 root root 0 Apr 17 18:20 procdump/otp.2199.0x400000
```

Dang, Volatility cannot easily dump the process. I read some online posts about this but nothing conclusive that can help me trivially recover the binary. So I decide to check the proc maps and dump those instead:

  
```
root@kali:~/ctfs/bsides/forensics/dump# volatility -f dump.vmem --profile=LinuxUbuntu1510serverx64 -p 2199 linux_proc_maps | tail -17 | awk '{print "volatility -f dump.vmem --profile=LinuxUbuntu1510serverx64 -p 2199 linux_dump_map -D dump -s "$4}' | sh
Volatility Foundation Volatility Framework 2.5
Volatility Foundation Volatility Framework 2.5
Task VM Start VM End Length Path
---------- ------------------ ------------------ ------------------ ----
2199 0x0000000000400000 0x0000000000401000 0x1000 dump/task.2199.0x400000.vma
Volatility Foundation Volatility Framework 2.5
Task VM Start VM End Length Path
---------- ------------------ ------------------ ------------------ ----
2199 0x0000000000600000 0x0000000000601000 0x1000 dump/task.2199.0x600000.vma
Volatility Foundation Volatility Framework 2.5
Task VM Start VM End Length Path
---------- ------------------ ------------------ ------------------ ----
2199 0x000000000077e000 0x000000000079f000 0x21000 dump/task.2199.0x77e000.vma
...

```

  
  <p>
    I import these into IDA Pro, on this point I had help from the admins that IDA Pro can import a bunch of files like this and "just work" that was neat. To get this working on Windows I imported the `task.2199.0x600000.vma` file and was able to reverse engineer the encryption system.
  </p>
  
  <p>
    Essentially the main function does the following:
  </p>
  
  <ol>
    <li>
      Defines 44 static integers
    </li>
    <li>
      Asks the user for a key
    </li>
    <li>
      Iterates the integers XORing each integer with the bytes
    </li>
  </ol>
  
  <p>
    Here's the function that does the encryption/decryption:
  </p>
  
  
```
_BYTE *__fastcall encrypt_decrypt(__int64 a1, signed int a2, __int64 a3)
{
  __int64 v4; // [sp+8h] [bp-28h]@1
  _BYTE *v5; // [sp+20h] [bp-10h]@1
  signed int i; // [sp+2Ch] [bp-4h]@2

  v4 = a3;
  v5 = malloc(a2);
  if ( v5 )
  {
    for ( i = 0; i < a2; ++i )
      v5[i] = *(i + a1) ^ *(i % 45 + v4);
  }
  return v5;
}
```

  
  <p>
    I quickly use python to take a copy/paste of the ciphertext bytes from the IDA decompilation and XOR it with the key we learned earlier:
  </p>
  
  
```
#!/usr/bin/python

ciphertext = [int(x.split()[2].strip(';')) for x in open('d').readlines()]

key = "D4WaiOid9iRVlaHfWWVOywIre9uUa1Gjt4jvcxiUiYtM"

plaintext = ""
for c in range(len(ciphertext)):
   plaintext += chr(ciphertext[c] ^ ord(key[c]))

print plaintext

```

  
  <p>
    We then make a text file with the bytes and run the script to recover the flag:
  </p>
  
  
```

root@kali:~/ctfs/bsides/forensics/dump# cat > d
  v8 = 6;
  v9 = 103;
  v10 = 30;
  v11 = 37;
  v12 = 44;
  v13 = 28;
  v14 = 54;
  v15 = 39;
  v16 = 109;
...

root@kali:~/ctfs/bsides/forensics/dump# python decrypt.py 
BSIDES_CTF{9d493c4db5a9620fc70f50e6bb5bc049}
```
