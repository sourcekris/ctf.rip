---
id: 235
title: 'PlaidCTF - strength - Crypto 110 Point Challenge'
date: 2015-04-24T12:46:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=235
permalink: /plaidctf-strength-crypto-110-poin/
post_views_count:
  - "332"
image: /images/2015/04/Capture-4.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/-BKzYT2lto14/VTbz1DLs05I/AAAAAAAAAHU/TTMxR3JQPY4/s1600/Capture.PNG" imageanchor="1" style="clear: left; float: left; margin-bottom: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/Capture-4.png" height="200" width="135" /></a>
</div>

It's my lucky day, two RSA challenges back to back and this one is worth some nice points.

>**Strength**
>Crypto (110 pts)
>Strength in Difference
>We've captured the flag encrypted several times... do you think you can recover it
  

Along with this clue we had a file containing again a list of long numbers with a header listing them as "N : e : c" format. So again yeah, RSA public keys along with corresponding ciphertext. The clue essentially tells us that all of the ciphertexts should be the same.

```
 {N : e : c}  
 {<u>0xa5f7f8aaa82921f70aad9ece4eb77b62112f51ac2be75910b3137a28d22d7ef3be3d734dabb9d853221f1a17b1afb956a50236a7e858569cdfec3edf350e1f88ad13c1efdd1e98b151ce2a207e5d8b6ab31c2b66e6114b1d5384c5fa0aad92cc079965d4127339847477877d0a057335e2a761562d2d56f1bebb21374b729743L</u> : 0x1614984a0df : 0x7ded5789929000e4d7799f910fdbe615824d04b055336de784e88ba2d119f0c708c3b21e9d551c15967eb00074b7f788d3068702b2209e4a3417c0ca09a0a2da4378aa0b16d20f2611c4658e090e7080c67dda287e7a91d8986f4f352625dceb135a84a4a7554e6b5bd95050876e0dca96dc21860df84e53962d7068cebd248dL}  
 {<u>0xa5f7f8aaa82921f70aad9ece4eb77b62112f51ac2be75910b3137a28d22d7ef3be3d734dabb9d853221f1a17b1afb956a50236a7e858569cdfec3edf350e1f88ad13c1efdd1e98b151ce2a207e5d8b6ab31c2b66e6114b1d5384c5fa0aad92cc079965d4127339847477877d0a057335e2a761562d2d56f1bebb21374b729743L</u> : 0x15ef25e10f54a3 : 0x7c5b756b500801e3ad68bd4f2d4e1a3ff94d049774bc9c37a05d4c18d212c5b223545444e7015a7600ecff9a75488ed7e609c3e931d4b2683b5954a5dc3fc2de9ae3392de4d86d77ee4920fffb13ad59a1e08fd25262a700eb26b3f930cbdc80513df3b7af62ce22ab41d2546b3ac82e7344fedf8a25abfb2cbc717bea46c47eL  
```

This time we note a couple of things. Firstly the exponents are a much more reasonable size so we won't use Wiener's attack. Secondly all of the modulii are the same. Third, the exponents are all different.

So here, we want to use a common modulus attack. This attack works when the same message is sent multiple times with the same modulus (n) and different public exponents (e). If we can find two exponents which have no common factors (i.e. with a gcd == 1) then we can use simple math to recover the plaintext. The attack works like this.

  1. Firstly, iterate through our list of exponents and examine each exponent pair (call them e, and f) for common factors
  2. If no common factors are found, if <span style="font-family: Times, Times New Roman, serif;"><i>gcd(e, f)</i></span> == 1, then calculate _<span style="font-family: Times, Times New Roman, serif;">r</span>_ and _<span style="font-family: Times, Times New Roman, serif;">s</span>_ in the equation:
  * <i style="font-family: Times, 'Times New Roman', serif;"><span style="font-size: large;">e*r + f*s = 1</span></i>

  3. <span style="font-family: inherit;">Calculate the plain text using the equation</span>
  * <span style="font-family: Times, Times New Roman, serif; font-size: large; font-style: italic;">(M<sup>e</sup> mod n)</span><sup style="font-family: Times, 'Times New Roman', serif; font-size: x-large; font-style: italic;">r</sup><span style="font-family: Helvetica Neue, Arial, Helvetica, sans-serif;">x</span> <span style="font-family: Times, Times New Roman, serif; font-size: large; font-style: italic;">(M<sup>f</sup> mod n)</span><sup style="font-family: Times, 'Times New Roman', serif; font-size: x-large; font-style: italic;">s</sup> <span style="font-family: Times, Times New Roman, serif; font-size: large; font-style: italic;">= M</span><sup style="font-family: Times, 'Times New Roman', serif; font-size: x-large; font-style: italic;">er+fs</sup> <span style="font-family: Times, Times New Roman, serif; font-size: large; font-style: italic;">mod n = M mod n</span>

To implement this we found someone else had already done this previously for VolgaCTF 2013. You can read <a href="http://h34dump.com/2013/05/volgactf-quals-2013-crypto-200/" target="_blank">their writeup here</a>.

```
 #!/usr/bin/python  
 import sys  
 sys.setrecursionlimit(5000)   
 # math code from http://h34dump.com/2013/05/volgactf-quals-2013-crypto-200/   
 def gcd(a, b):  
  if a == 0:  
   x, y = 0, 1;  
   return (b, x, y);  
  tup = gcd(b % a, a)  
  d = tup[0]  
  x1 = tup[1]  
  y1 = tup[2]  
  x = y1 - (b / a) * x1  
  y = x1  
  return (d, x, y)  
 #solve the Diophantine equation a*x0 + b*y0 = c  
 def find_any_solution(a, b, c):  
  tup = gcd(abs(a), abs(b))  
  g = tup[0]  
  x0 = tup[1]  
  y0 = tup[2]  
  if c % g != 0:  
   return (False, x0, y0)  
  x0 *= c / g  
  y0 *= c / g  
  if a < 0:  
   x0 *= -1  
  if b < 0:  
   y0 *= -1  
  return (True, x0, y0)  
 # read all the rsa stuff into a buffer   
 f = open('captured_827a1815859149337d928a8a2c88f89f','rb')  
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
     if "N" in gear[0]:   # handle the header  
         continue  
     modulii.append(long(gear[0],16))  
     exponents.append(long(gear[1],16))  
     ciphers.append(long(gear[2],16))  
 print "[+] Performing common modulus attack..."  
 for a in exponents:  
   for b in exponents:  
     if a <> b:  
           c1 = ciphers[exponents.index(a)]  
           c2 = ciphers[exponents.index(b)]  
           n = modulii[exponents.index(a)]  
           (x, a1, a2) = find_any_solution(a, b, 1)  
           if a1 < 0:  
             (x, c1, y) = find_any_solution(c1, n, 1)#get inverse element  
             a1 = -a1  
           if a2 < 0:  
             (x, c2, y) = find_any_solution(c2, n, 1)  
             a2 = -a2  
           m = (pow(c1, a1, n) * pow(c2, a2, n)) % n  
           flag = ("%0512x" %m).decode("hex")  
           if "flag" in flag:   
                print "[+] Flag: " + flag   
                quit()  
```

When we run the code we get the flag

```
 root@mankrik:~/plaid/strength# ./strpwn.py  
 [+] Performing common modulus attack...  
 [+] Flag: flag_Strength_Lies_In_Differences  
```