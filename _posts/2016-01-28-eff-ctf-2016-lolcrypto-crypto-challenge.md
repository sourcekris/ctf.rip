---
id: 515
title: 'EFF-CTF 2016 - LOLCrypto - Crypto Challenge'
date: 2016-01-28T03:43:36+00:00
author: Steven
layout: post
guid: https://ctf.rip/?p=515
permalink: /eff-ctf-2016-lolcrypto-crypto-challenge/
post_views_count:
  - "1295"
image: /images/2016/01/xnet.png
categories:
  - Write-Ups
tags:
  - crypto
  - eff
---
I have a guest writeup this week for the EFF-CTF we did. Welcome Steven who I worked with to solve the EFF-CTF this week which was part of <a href="https://www.usenix.org/conference/enigma2016" target="_blank">Enigma 2016 security conference</a>.  Take it away Steven:

Level0x3 for the EFF-CTF required cracking homebrew crypto. The level was as follows:

<img class="alignnone size-full wp-image-516" src="/images/2016/01/1.png" alt="1" width="1084" height="386" srcset="/images/2016/01/1.png 1084w, /images/2016/01/1-300x107.png 300w, /images/2016/01/1-768x273.png 768w, /images/2016/01/1-1024x365.png 1024w, /images/2016/01/1-660x235.png 660w" sizes="(max-width: 1084px) 100vw, 1084px" />

At first we tried "aaaa" as our input as a test.

<img class="alignnone size-full wp-image-519" src="/images/2016/01/aaaa1.png" alt="aaaa1" width="714" height="101" srcset="/images/2016/01/aaaa1.png 714w, /images/2016/01/aaaa1-300x42.png 300w, /images/2016/01/aaaa1-660x93.png 660w" sizes="(max-width: 714px) 100vw, 714px" />

Interesting, lets make sure it's deterministic by checking the same input again.

<img class="alignnone size-full wp-image-520" src="/images/2016/01/aaaa2.png" alt="aaaa2" width="719" height="101" srcset="/images/2016/01/aaaa2.png 719w, /images/2016/01/aaaa2-300x42.png 300w, /images/2016/01/aaaa2-660x93.png 660w" sizes="(max-width: 719px) 100vw, 719px" />

hmm, everything changed.

We then tested a single character to see what the length of the output would be.

<img class="alignnone size-full wp-image-518" src="/images/2016/01/3.png" alt="3" width="218" height="104" />

It's looking as if one character becomes 4 numbers when encrypted. Lets test that theory:

<img class="alignnone size-full wp-image-521" src="/images/2016/01/aa.png" alt="aa" width="303" height="94" srcset="/images/2016/01/aa.png 303w, /images/2016/01/aa-300x93.png 300w" sizes="(max-width: 303px) 100vw, 303px" />

"aa" becomes 8 numbers, so we are on the right path.

I had the idea to add the numbers up and see if them came to the same summation. Which they did! If that failed, I was going to check if some mathematical operation of the 4 numbers (or part of) would be the same. Failing that, perhaps one or more of the numbers were decoys and discarded when decrypted.

  * 67+12+2+77 = 158
  * 30+56+48+24 = 158
  * 65+7+56+30 = 158
  * 52+20+54+32 = 158

Yep! So, our theory is groups of 4 numbers add to the same sum. Lets make sure our ciphertext that we need to crack has groups of 4.

I used https://regex101.com with /[0-9]+/g

<img class="alignnone size-full wp-image-525" src="/images/2016/01/Capture.png" alt="Capture" width="593" height="408" srcset="/images/2016/01/Capture.png 593w, /images/2016/01/Capture-300x206.png 300w" sizes="(max-width: 593px) 100vw, 593px" />

Perfect.

We can now use a chosen plain text attack, so we encrypt "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._ :1234567890&#8242;!"

We can then can map the output to each character in that list.

Kris created a script in Python that could do that for us:
  
```


#!/usr/bin/python

c = map(int, open('ciphertext.txt', 'r').read().split())
alphacipher = map(int, open('alphabetciphered.txt', 'r').read().split())

alphabet = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._ :1234567890'!")

# Generate a translation table
translation = []
for i in range(,len(alphacipher),4):
  j = alphacipher[i] + alphacipher[i+1] + alphacipher[i+2] + alphacipher[i+3]
  translation.append(j)

# decipher ciphertext
plaintext = []
for i in range(,len(c),4):
  j = c[i] + c[i+1] + c[i+2] + c[i+3]
  plaintext.append(alphabet[translation.index(j)])

print "[+] Plaintext: " + "".join(plaintext)


```

Which when we run, gives us the flag:

```
root@kalimate:~/eff# python dec2.py 
[+] Plaintext: This week's decryption passphrase is: Don't BULLRUN me bro!

```