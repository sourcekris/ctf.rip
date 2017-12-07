---
id: 860
title: 'Sharif CTF 2016 - LSB Oracle - Crypto Challenge'
date: 2016-12-19T11:10:34+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=860
permalink: /sharif-ctf-2016-lsb-oracle-crypto-challenge/
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
  - "1063"
image: /images/2016/12/lsboracle.png
categories:
  - Write-Ups
tags:
  - crypto
  - LSB
  - rsa
  - side-channel
---
Cool challenge that I've wanted a reason to solve for a while because I always miss these in CTFs of the past (Tokyo Westerners CTF had a <a href="http://mslc.ctf.su/wp/tokyo-westernsmma-ctf-2016-pinhole-attack-crypto-500/" target="_blank">good, harder one previously</a>).

The clue we're given is a LSB Oracle. It contains a `description.py` python script and a `lsb_oracle.vmp.exe` PE32 Windows executable. 

At first glance you're thinking, a local Windows binary oracle? Just RE the binary and extract the private key and you're done, forget the oracle. Yeah not much of a challenge there but you'll find in this case the binary is packed by some nasty binary packer and ain't nobody got time to unpack that.

So let's just start this writeup with what we're looking at. If we check the `description.py` we get an overview of the encryption algorithm in play here.  
```
#! /usr/bin/env python3
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
n = -1  # get it from the provided EXE file
e = -1  # get it from the provided EXE file
flag = b'' # redacted
key = RSA.construct((n, e))
cipher = PKCS1_v1_5.new(key)
ctxt = bytes_to_long(cipher.encrypt(flag))
print(ctxt)
# output is:
# 2201077887205099886799419505257984908140690335465327695978150425602737431754769971309809434546937184700758848191008699273369652758836177602723960420562062515168299835193154932988833308912059796574355781073624762083196012981428684386588839182461902362533633141657081892129830969230482783192049720588548332813
```
 

It's RSA w/PKCS v1.5 padding and we have the encrypted flag but not the values of `<em>n</em>` or `<em>e</em>` yet. Those are supposedly provided by the binary? Fine lets check that. 
```
root@kali:~/sharif16/lsboracle# wine ./lsb_oracle.vmp.exe 2>/dev/null
Usage:
  lsb_oracle.exe /? : Prints usage.
  lsb_oracle.exe /story : My story.
  lsb_oracle.exe /pubkey : Public key.
  lsb_oracle.exe /decrypt : Decryption mode.
root@kali:~/sharif16/lsboracle# wine ./lsb_oracle.vmp.exe /pubkey 2>/dev/null
n = 120357855677795403326899325832599223460081551820351966764960386843755808156627131345464795713923271678835256422889567749230248389850643801263972231981347496433824450373318688699355320061986161918732508402417281836789242987168090513784426195519707785324458125521673657185406738054328228404365636320530340758959
e = 65537
```
 

So great, now we have `<em>n</em>`, `<em>e</em>`, `<em>c</em>`. How does the Oracle work? Let's try feeding it a known ciphertext. 
```
root@kali:~/sharif16/lsboracle# wine ./lsb_oracle.vmp.exe /decrypt 2>/dev/null
Enter a valid ciphertext, and I'll return the LSB of its decryption. Enter -1 when you're done.
120357855677795403326899325832599223460081551820351966764960386843755808156627131345464795713923271678835256422889567749230248389850643801263972231981347496433824450373318688699355320061986161918732508402417281836789242987168090513784426195519707785324458125521673657185406738054328228404365636320530340758959
1
```
 

So it returns `1` or `` which is the Least Significant Bit (LSB) of the plaintext. Ok great. But how does that assist us? Time to explain what an LSB Oracle attack is.

In cryptography, an **oracle** is defined as some "black box" mechanism that will leak some information about a cryptographic operation on your input. The output of the oracle is always the same for a specific input. So the oracle can be used to learn about the plaintext piece by piece, up to and including complete plaintext recovery.

In our case here we have a **LSB** oracle. In that, for every input ciphertext, the oracle will decrypt it using it's private key and then inform us about the single least significant bit of that decrypted plaintext. The least significant bit in this case will tell us if the resulting number is **Odd** or **Even**. This is also known as a "parity side channel attack" and I learned all about from <a href="http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html" target="_blank">this paper by Riccardo Focardi that you can read here</a>. Remember that in RSA math our plaintext and ciphertext are just long integers. We convert them to strings to be useful to us but below when I talk about plaintext or ciphertext math, I just mean math on those long integers.

In this challenge our LSB oracle binary will give us a `1` if our flag plaintext is odd and a `` if our flag plaintext is even. We can confirm this by encrypting the number 2, which is even, with our public key. The math is really simply `2<sup><em>e</em></sup> mod <em>n</em>`. We can do it quickly in python: 
```
root@kali:~/sharif16/lsboracle# python
Python 2.7.11+ (default, Mar 23 2016, 11:35:56) 
[GCC 5.3.1 20160316] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> (2**65537) % 120357855677795403326899325832599223460081551820351966764960386843755808156627131345464795713923271678835256422889567749230248389850643801263972231981347496433824450373318688699355320061986161918732508402417281836789242987168090513784426195519707785324458125521673657185406738054328228404365636320530340758959
72910010640285174094997587185551356924537414375206704298772224726782723295187717459370566588834774314920378452694223658375323231285440968762166580911897754818170564503438514053703279919650869219319294754896284356961452566617368956549938715854416816362722874755251572502108452034663155930058802495607041897789L
```
 

If we now ask the oracle to decrypt this for us we get: 
```
Enter a valid ciphertext, and I'll return the LSB of its decryption. Enter -1 when you're done.
72910010640285174094997587185551356924537414375206704298772224726782723295187717459370566588834774314920378452694223658375323231285440968762166580911897754818170564503438514053703279919650869219319294754896284356961452566617368956549938715854416816362722874755251572502108452034663155930058802495607041897789
0
```
 

So yes, the number 2 is even! Thanks Oracle you're the best.

Ok so we also know that earlier, when we plugged our flag ciphertext into the oracle we get the number `1`, so the flag plaintext is odd. Now what if we multiply our plaintext message by `2 mod <em>n</em>`? The math again is simple and only two results are possible:

  1. If our original plaintext (`m`) is less than `<em>n</em> / 2` (`<em>m</em> < <em>n</em>/2`) then we have `2<em>m</em> mod <em>n</em> = 2<em>m</em>` which is _always an even number_.
  2. If however, `<em>m</em> > n / 2` then we'll get `2<em>m</em> mod <em>n</em> = 2<em>m</em> - <em>n</em>`, which MUST be odd because our `<em>n</em>` is always an odd number being the product of two large primes.

So now to the cool part, because of the "_multiplicative property of RSA_", that is, if we conduct multiplications of two ciphertexts modulo `<em>n</em>`, the result is the SAME as if we encrypted the multiplication of those two corresponding plaintexts. Take this quick example to wrap your head around this property.

Let's take a sample 256 bit key pair and encrypt two integers, we'll use small integers to illustrate the point.  
```
>>> import libnum
>>> p = libnum.generate_prime(128) # Generate a 128bit p and q
>>> q = libnum.generate_prime(128)
>>> n = p*q
>>> n # this is our modulus
64278170916625948483834062133931519159382410978263975061749044447937374034339L
>>> e = 65537
>>> c2 = (2**e) % n # c2 is ciphertext of "2"
>>> c5 = (5**e) % n # c5 is ciphertext of "5"
>>> c2
60335932119204006272459010286119055561957646972585895686986408275611079718448L
>>> c5
37618001713247798728450664371399049814475441705054426324335095938705215314143L
```
 

So we have our two ciphertexts, let's multiply our `c<sub>2</sub> * c<sub>5</sub> mod <em>n</em>`: 
```
>>> (c2*c5) % n
25167384272145301126889142978999354588966381263519681447821071653459223573824L
```
 

Ok let's decrypt the resulting ciphertext and see how our multiplication affected it: 
```
>>> phi = (p-1) * (q-1)        
>>> d = libnum.invmod(e,phi)  # quickly calculate the RSA private exponent
>>> c_multiplied = (c2*c5) % n
>>> pow(c_multiplied, d, n)
10L

```
 

Wow, so we actually ended up with 2 x 5, the product of the plaintexts, just by multiplying the ciphertexts (modulo `<em>n</em>`)! RSA is cool.

How does that help us with the oracle attack?

Well now what we can do is multiply the ciphertext of the integer `2` by our flag ciphertext (modulo `<em>n</em>`) and then ask our oracle if the resulting plaintext after decryption is odd or even? If it's even then we know our plaintext is less than `<em>n</em> / 2`. If it's odd we know our plaintext is between `<em>n</em> / 2` and `<em>n</em> - 1`. Wow that has halved the amount of possible plaintexts!!!

If continue this way and encrypt the integer `4`, then multiple the result by our flag ciphertext (modulo `<em>n</em>`) we get four possible outcomes for our plaintext:

  1. `0 - <em>n</em>/4`, the oracle returns 0
  2. `<em>n</em>/4 - <em>n</em>/2`, the oracle returns 1
  3. `<em>n</em>/2 - 3<em>n</em>/4`, the oracle returns 0
  4. `3<em>n</em>/4 - <em>n</em>-1`, the oracle returns 1

Since we already eliminated half the plaintexts when we multiplied our ciphertext by the ciphertext of `2` earlier, we only need to examine half of these possibilities in the mulitiplication of our ciphertext by `4`.

So you can see what we actually have here is a binary search for the plaintext, one which will take N attempts (i.e. N questions to the oracle) to recover the plaintext where N is equal to the bit length of the ciphertext.

This is because at each step, we're multiplying the ciphertext by the ciphertext of `2` (modulo `<em>n</em>`) and splitting the possible plaintexts in half, until finally we converge on the plaintext itself.

Finally here is our solution, written in Python with some help from the paper linked above. We implement this attack in Linux and use Wine to execute the oracle binary. 
```
#!/usr/bin/python
import libnum, decimal
from pwn import *
# from ./lsb_oracle.vmp.exe /pubkey
n = 120357855677795403326899325832599223460081551820351966764960386843755808156627131345464795713923271678835256422889567749230248389850643801263972231981347496433824450373318688699355320061986161918732508402417281836789242987168090513784426195519707785324458125521673657185406738054328228404365636320530340758959
e = 65537
# from description.py
c = 2201077887205099886799419505257984908140690335465327695978150425602737431754769971309809434546937184700758848191008699273369652758836177602723960420562062515168299835193154932988833308912059796574355781073624762083196012981428684386588839182461902362533633141657081892129830969230482783192049720588548332813
# Encrypt the plaintext integer 2
c_of_2 = pow(2,e,n)
# Run the oracle in wine. Works fine. Who needs windows.
p = process(['wine','lsb_oracle.vmp.exe','/decrypt'])
print "[*] Starting wine and LSB Oracle..."
p.recvlines(4)
# Ask the oracle for the LSB of a decryption of c
def oracle(c):
    p.sendline(str(c))
    return int(p.recvlines(2)[0])
# code from http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html 
# by Riccardo Focardi
def partial(c,n):
    k = n.bit_length()
    decimal.getcontext().prec = k    # allows for 'precise enough' floats
    lower = decimal.Decimal(0)
    upper = decimal.Decimal(n)
    for i in range(k):
        possible_plaintext = (lower + upper)/2
        if not oracle(c):
            upper = possible_plaintext            # plaintext is in the lower half
        else:
            lower = possible_plaintext            # plaintext is in the upper half
        c=(c*c_of_2) % n     # multiply y by the encryption of 2 again
    # By now, our plaintext is revealed!
    return int(upper)
print "[*] Conducting Oracle attack..."
print repr(libnum.n2s(partial((c*c_of_2)%n,n)))
```
 

Which we run and find the PKCS 1.5 randomly padded plaintext flag! 
```
root@kali:~/sharif16/lsboracle# ./solve.py 
[+] Starting program '/usr/bin/wine': Done
[*] Starting wine and LSB Oracle...
[*] Conducting Oracle attack...
'\x02\xa9\x12\xa7uA\x94\x8e\x8c2\xd5(\xda\x1eq?\xf7\xd0TL\xe8\xde1$\xbf\xe4w\xe1\x18\x12\x1f\xef\x03\x8b{\x7f\xb2\x9c\xa6Bs\xd2\xfe&\xe8+k7\xd8\xe7\xa5\x0b\xaf\xa8R\x12\x93\x0e,\xdfp\xff\x9a\xe7\x9b\xbduN4\x85I\xde3\x07\xb2n\xa4\xdb"\xd5\xfaf\x84\x00SharifCTF{65d7551577a6a613c99c2b4023039b0a}'
```

Fun one.