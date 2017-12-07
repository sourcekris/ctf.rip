---
id: 236
title: 'PlaidCTF - curious - Crypto 70 Point Challenge'
date: 2015-04-22T00:43:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=236
permalink: /plaidctf-curious-crypto-70-poin/
post_views_count:
  - "652"
image: /images/2015/04/Capture-5.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/Capture-5.png" imageanchor="1" style="clear: left; float: left; margin-bottom: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/Capture-5.png" height="200" width="135" /></a>
</div>

A 70 point crytpo challenge with the the following clue:

>**Curious**_
>Crypto (70 pts)
>The curious case of the random e.
>We've captured the flag encrypted several times... do you think you can recover it?

A very quick challenge for me. We are only presented with a clue that the flag had been captured encrypted several times. The included file is a list of 101 different "N : e : c" values such as these:

```
 {N : e : c}  
 {0xfd2066554e7f2005082570ddf50e535f956679bf5611a11eb1734268ffe32eb0f2fc0f105dd117d9d739767f300918a67dd97f52a3985483aca8aa54998a5c475842a16f2a022a3f5c389a70faeaf0500fa2d906537802ee2088a83f068aba828cc24cc83acc74f04b59a0764de7b64c82f469db4fecd71876eb6021090c7981L : 0xa23ac312c144ce829c251457b81d60171161655744b2755af9b2bd6b70923456a02116b54136e848eb19756c89c4c46f229926a48d5ac030415ef40f3ea185446fa15b5b5f11f2ec2f0f971394e285054182d77490dc2e7352d7e9f72ce25793a154939721b6a2fa176087125ee4f0c3fb6ec7a9fdb15510c97bd3783e998719L : 0x593c561db9a04917e6992328d1ecadf22aefe0741e5d9abbbc12d5b6f9485a1f3f1bb7c010b19907fe7bdecb7dbc2d6f5e9b350270002e23bd7ae2b298e06ada5f4caa1f5233f33969075c5c2798a98dd2fd57646ad906797b9e1ce77194791d3d0b097de31f135ba2dc7323deb5c1adabcf625d97a7bd84cdf96417f05269f4L}  
```

Given that we have the values n, e and c we assume we're talking RSA here as these are commonly used to represent the values of the modulus (N), the exponent (e) and the ciphertext (c). In RSA the modulus and the exponent together form the public key.

So given that it is RSA we start thinking about all the different types of cryptanalysis we can do when we have many keys and one plaintext. I thought about a common factor attack but quickly discounted it when I looked at the size of the exponents.

Just like the recent <a href="http://ctf.rip/?p=238" target="_blank">BCTF warmup challenge</a>, we have here a case of overly large exponents. It would be interesting to check these exponents for a vulnerability to Wiener's attack.

I re-used my warmup exploit but modified it to read the curious file and iterate over the exponents to see if we could crack any of them for the value of "d".

After 59 failures we reach success as the 60th exponent in the list was vulnerable to Wiener's attack. We then quickly solved for "M" to receive the flag:



```
 root@mankrik:~/plaid/curious# ./curiouspwner.py   
 [+] Loaded 101 ciphertexts and public keys.  
 [+] Attacking n[0] and e[0]  
 [+] Wiener attack in progress...  
 [+] Attacking n[1] and e[1]  
 [+] Wiener attack in progress...  
 [+] Attacking n[2] and e[2]  
 [+] Wiener attack in progress...  
 [+] Attacking n[3] and e[3]  
 [+] Wiener attack in progress...  
 ...  
 [+] Attacking n[59] and e[59]  
 [+] Wiener attack in progress...  
 [+] Attacking n[60] and e[60]  
 [+] Wiener attack in progress...  
 [+] Found d = 23974584842546960047080386914966001070087596246662608796022581200084145416583  
 [+] Flag:  
 flag_S0Y0UKN0WW13N3R$4TT4CK!  
```

And here's the exploit we used to get there, again based on the code from https://github.com/pablocelayes/rsa-wiener-attack:

```
 #!/usr/bin/python  
 import ContinuedFractions, Arithmetic  
 import sys  
 import base64  
 import gmpy  
 import sympy  
 import math  
 import fractions  
 import struct  
 sys.setrecursionlimit(100000)  
 f = open('cap','rb')  
 rsastuff = f.read()  
 f.close()  
 rsatrunk = rsastuff.splitlines()  
 modulii = []  
 exponents = []  
 ciphers = []  
 for junk in rsatrunk:  
      gear = junk.split(":")  
      gear[0] = gear[0].replace("{","")  
      gear[2] = gear[2].lstrip()  
      gear[2] = gear[2].replace("}","")  
      if "N" in gear[0]:     # handle the header  
           continue  
      modint = long(gear[0],16)  
      expint = long(gear[1],16)  
      ciphint = long(gear[2],16)  
     modulii.append(modint)  
      exponents.append(expint)  
      ciphers.append(ciphint)  
 print "[+] Loaded " + str(len(ciphers)) + " ciphertexts and public keys."  
 def hack_RSA(e,n):  
   print "[+] Wiener attack in progress..."  
   frac = ContinuedFractions.rational_to_contfrac(e, n)  
   convergents = ContinuedFractions.convergents_from_contfrac(frac)  
   for (k,d) in convergents:  
     #check if d is actually the key  
     if k!=0 and (e*d-1)%k == 0:  
       phi = (e*d-1)//k  
       s = n - phi + 1  
       # check if the equation x^2 - s*x + n = 0  
       # has integer roots  
       discr = s*s - 4*n  
       if(discr>=0):  
         t = Arithmetic.is_perfect_square(discr)  
         if t!=-1 and (s+t)%2==0:  
           return d  
 for a in range(len(modulii)):  
      print "[+] Attacking n["+str(a)+"] and e["+str(a)+"]"  
      hacked_d = hack_RSA(exponents[a], modulii[a])  
      testd = str(hacked_d)  
      if "None" in testd:  
           continue  
      else:  
           print "[+] Found d = " + str(hacked_d)  
           m = pow(ciphers[a], hacked_d, modulii[a])  
           print "[+] Flag:"  
           print("%0512x" %m).decode("hex")  
           quit()  
```