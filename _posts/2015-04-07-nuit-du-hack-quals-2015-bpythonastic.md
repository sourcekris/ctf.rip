---
id: 239
title: 'Nuit du Hack Quals 2015 - Bpythonastic - Forensic Challenge'
date: 2015-04-07T03:01:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=239
permalink: /nuit-du-hack-quals-2015-bpythonastic/
post_views_count:
  - "803"
image: /images/2015/04/bpy-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---

CTFing at Easter time was super challenging. Endless family commitments, using my iPhone to browse challenges while at the dinner table and thinking through how to attack them when I can finally get to a PC. Fortunately NDH seemed to go for long enough for me to at least try a few of the challenges, which I did!

I've decided to document Bpythonastic for the reason that it was worth 300 points and not everyone got it, surprising because it was a trivial challenge.


<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/bpy-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/bpy-1.png" height="91" width="400" /></a>
</div>

The challenge, like many at NDH2k15 was just a link to a file. Which when you download it is a 81Mb file that extracts a 1.4GB raw file:


```
root@mankrik:~/ndh/bpy# ls -lah  
total 1.5G  
drwxr-xr-x 2 root root 4.0K Apr 5 12:37 .  
drwxr-xr-x 15 root root 4.0K Apr 5 10:38 ..  
-rw-r--r-- 1 root root 81M Apr 3 03:10 Bpythonastic.tar.gz  
-rw-r--r-- 1 root root 1.4G Mar 20 03:32 chall.raw  
```

file reports it as a ELF file. It might be a memory dump I suppose.

```
root@mankrik:~/ndh/bpy# file chall.raw   
chall.raw: ELF 64-bit LSB core file x86-64, version 1 (SYSV)  
```
Let's just use strings and look for a flag.


```
root@mankrik:~/ndh/bpy# strings chall.raw | grep -c flag  
2893  
```

Ok 2893 instances of the word flag, thats a few but we're looking for something related to Python I guess from the name of the challenge so I'll widen the context of the grep to show a little before and after and review them quickly.

Before long I spot this python code in the strings.


```
 >>> from chall import *  
 >>> flag=Challenge()  
 >>> flag=base64.b64encode(pickle.dumps(flag))  
 >>> print flag  
 KGljaGFsbApDaGFsbGVuZ2UKcDAKKGRwMQpTJ2ZsYWcnCnAyClMnYTYzOWEyMWE0YTc0NzAzZmEwNDJk  
 NjE3NjgxYWE0NGJiNGQxYzA4YmM1ZmJmN2VmZDZiNDU1ODJiMGYwZDQwMycKcDMKc1MnaWQnCnA0Ckkw  
 CnNTJ2F1dGhvcicKcDUKUydZZ2dkcmFzaWwnCnA2CnNiLg==  
```

When I decode the base64 string I see this:

```
(ichall  
Challenge  
p0  
(dp1  
S'flag'  
p2  
S'a639a21a4a74703fa042d617681aa44bb4d1c08bc5fbf7efd6b45582b0f0d403'  
p3  
sS'id'  
p4  
I0  
sS'author'  
p5  
S'Yggdrasil'  
p6  
sb.  
```

Ok so that looks right, the flag is hashed though and we need the raw value. So we need to find what is generating this hash.

We look a little further in the strings output and find this:


```
     self.author="Yggdrasil"  
     self.flag=hashlib.sha256("Yougotit").hexdigest()  
 import chall  
 flag=Challenge()  
```

Which I conclude is probably the code that generates the above code, so the flag is probably "Yougotit". I submitted it and it was correct.

So 300 points for using strings and grep. Nice.