---
id: 222
title: 'Hack.Lu - Creative Cheating 150pt Crypto Challenge'
date: 2015-10-22T09:47:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=222
permalink: /hacklu-creative-cheating-150pt-crypto/
post_views_count:
  - "507"
image: /images/2015/10/cc-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
A mid week CTF when I have final exams! Argh! Still I play because I'm an idiot. Fun CTF, hard to read the font they chose but still fun. This was a classical RSA challenge with almost no difficult points but I'll write up anyway.

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/10/cc-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/10/cc-2.png" /></a>
</div>

Ok so the linked file is a PCAPNG file and we're given two RSA public keys.

Immediately I'm thinking those modulii are too small and so I just go and plug them into factordb.com. I'm rewarded and have our p & q values for both Alice and Bob:

  * Alice: http://factordb.com/index.php?query=1696206139052948924304948333474767
  * Bob: http://factordb.com/index.php?query=3104649130901425335933838103517383

Next I examine the PCAP. It's trivial to extract the data which is just base64 encoded ciphertext strings. I just use wireshark for this because tcpflow is giving me grief over the PCAP:

```
root@mankrik:~/hacklu/creative# cat strings.64 
U0VRID0gMTM7IERBVEEgPSAweDNiMDRiMjZhMGFkYWRhMmY2NzMyNmJiMGM1ZDZMOyBTSUcgPSAweDJlNWFiMjRmOWRjMjFkZjQwNmE4N2RlMGIzYjRMOw==
U0VRID0gMDsgREFUQSA9IDB4NzQ5MmY0ZWM5MDAxMjAyZGNiNTY5ZGY0NjhiNEw7IFNJRyA9IDB4YzkxMDc2NjZiMWNjMDQwYTRmYzJlODllM2U3TDs=
U0VRID0gNTsgREFUQSA9IDB4OTRkOTdlMDRmNTJjMmQ2ZjQyZjlhYWNiZjBiNUw7IFNJRyA9IDB4MWUzYjZkNGVhZjExNTgyZTg1ZWFkNGJmOTBhOUw7
U0VRID0gNDsgREFUQSA9IDB4MmMyOTE1MGYxZTMxMWVmMDliYzlmMDY3MzVhY0w7IFNJRyA9IDB4MTY2NWZiMmRhNzYxYzRkZTg5ZjI3YWM4MGNiTDs=
...
```

Theres 148 messages total, when we decode them, each consists of three components:</p> 
  
  <ul>
    <li>
      Sequence number
    </li>
    <li>
      Data
    </li>
    <li>
      Signature
    </li>
  </ul>

An example is below:

```
SEQ = 13; DATA = 0x3b04b26a0adada2f67326bb0c5d6L; SIG = 0x2e5ab24f9dc21df406a87de0b3b4L;
SEQ = 0; DATA = 0x7492f4ec9001202dcb569df468b4L; SIG = 0xc9107666b1cc040a4fc2e89e3e7L;
SEQ = 5; DATA = 0x94d97e04f52c2d6f42f9aacbf0b5L; SIG = 0x1e3b6d4eaf11582e85ead4bf90a9L;
SEQ = 4; DATA = 0x2c29150f1e311ef09bc9f06735acL; SIG = 0x1665fb2da761c4de89f27ac80cbL;
...
```

Ok so immediately you know the sequence numbers are out of order so reassembly in order is probably required later. If you parse the data you'll also notice sequence numbers repeat. For example:

```
root@mankrik:~/hacklu/creative# ./c1.py | grep 
"SEQ = 0"
SEQ = 0; DATA = 0x7492f4ec9001202dcb569df468b4L; SIG = 0xc9107666b1cc040a4fc2e89e3e7L;
SEQ = 0; DATA = 0x633282273f9cf7e5a44fcbe1787bL; SIG = 0x2b15275412244442d9ee60fc91aeL;
SEQ = 0; DATA = 0x59e9bb001b0d9167dbc39dd544c9L; SIG = 0x66e706951133b2d1bfde29dc82aL;
```

So my theory becomes:

<ol>
  <li>
    Data is out of sequence, reassemble in order
  </li>
  <li>
    Use the digital signatures to validate which of the multiple data blocks is the correct one for that sequence number
  </li>
</ol>

This is simple to code, we just need the math. A signature is calculated as:

<ul>
    <li>
      <i style="font-family: Times, 'Times New Roman', serif; font-size: x-large;">s = m<sup>d</sup> mod n</i>
    </li>
</ul>

To validate a signature, you calculate:

<ul>
  <li>
    <i style="font-family: Times, 'Times New Roman', serif; font-size: x-large;">v = s<sup>e</sup> mod n</i>
  </li>
</ul>

The resulting v should match your decrypted m. If they do, then you have a validated message. Here we have the Python:

```
#!/usr/bin/python

from pwn import *
import binascii
import sys

e = 0x10001

#alice - http://factordb.com/index.php?query=1696206139052948924304948333474767
a_n = 0x53a121a11e36d7a84dde3f5d73cf
a_p = 44106885765559411
a_q = 38456719616722997

#bob - http://factordb.com/index.php?query=3104649130901425335933838103517383
b_n = 0x99122e61dc7bede74711185598c7
b_p = 62515288803124247
b_q = 49662237675630289

def egcd(a, b):
    x,y, u,v = ,1, 1,
    while a != :
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return x

codez = open('strings.64').read().splitlines()

messages = []
for code in codez:
 msg = b64d(code).split(';')[:3]
 out = []
 for m in msg:
  out.append(m.split('=')[1].strip().replace('0x','').replace('L',''))
 
 messages.append(out)  

flag = []
for msg in messages:
 seq = int(msg[],10)
 c   = int(msg[1],16)
 sig = int(msg[2],16)

 d = egcd(e, (b_p - 1) * (b_q - 1))
 m = pow(c, d, b_n)
 v = pow(sig,e,a_n) # calculate the actual signature
 
 if m == v:
  flag.append([seq,chr(m)])

flag.sort(key=lambda y: int(y[]))
print "[+] flag: ",
for c in flag:
 sys.stdout.write(c[1])

print
```     

And the flag:

```
root@mankrik:~/hacklu/creative# ./c.py 
[+] flag: flag{n0th1ng_t0_533_h3r3_m0v3_0n}
```