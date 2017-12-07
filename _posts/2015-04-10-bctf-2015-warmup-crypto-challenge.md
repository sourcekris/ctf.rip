---
id: 238
title: 'BCTF 2015 - warmup - Crypto Challenge'
date: 2015-04-10T04:53:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=238
permalink: /bctf-2015-warmup-crypto-challenge/
post_views_count:
  - "2763"
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
I felt like going back and writing up this warmup challenge from BCTF since I enjoyed it so much. I have just recently finished studying RSA at university so it was still fresh in my mind when starting this challenge.

This was the first challenge published when BCTF launched and it was only worth 50 points. So how hard could it be? Strangely not too many people got this in comparison to the other easy challenges!

What we had were two things. A long string of hex which we assume is ciphertext:

```
 c=0x1e04304936215de8e21965cfca9c245b1a8f38339875d36779c0f123c475bc24d5eef50e7d9ff5830e80c62e8083ec55f27456c80b0ab26546b9aeb8af30e82b650690a2ed7ea407dcd094ab9c9d3d25a93b2140dcebae1814610302896e67f3ae37d108cd029fae6362ea7ac1168974c1a747ec9173799e1107e7a56d783660418ebdf6898d7037cea25867093216c2c702ef3eef71f694a6063f5f0f1179c8a2afe9898ae8dec5bb393cdffa3a52a297cd96d1ea602309ecf47cd009829b44ed3100cf6194510c53c25ca7435f60ce5f4f614cdd2c63756093b848a70aade002d6bc8f316c9e5503f32d39a56193d1d92b697b48f5aa43417631846824b5e86  
```

And a RSA public key:

```
 root@mankrik:~/bctf/warmup# cat warmup-c6aa398e4f3e72bc2ea2742ae528ed79.pub  
 -----BEGIN PUBLIC KEY-----  
 MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAQEDZxmNa1YU6VgTrdjyKkcX  
 vHK+HqvZM9G4aUT9t1uO0jC+YtfRtp0iIJXBKMhvggEuyxFhkf2dAYptAvhNsnvF  
 GiEwfchvS/dxxpHBQ+Wr5Um1vS1usaIf1icOfhtI/gYR+7LhsLNSTm9N6LTko0Xa  
 RKE96CW3JgjbbHxKQLeCZubIe7/e9rSDgdScRQeli81Ht21ktFkIsVi9frxNrLCx  
 z9bCwZV09A6y79Dp4Q3HAFytObyvUrnqw4czaNaQMcXnJGhKRPBo79HT3Altm11k  
 EeWL3uQ+RrmaDQSUudsoGVr5Aa/xMNSm4gPa0I2lf6fkAmKlutsqMj7aKLRGlqsw  
 XQKCAQEA85Wdl44C658G3vPzNdj4r9dgmVHdrGC3FLbCKvD6kS8hCzQga9JKlgHH  
 jfSgJ18Qf9OrVS2VBX65NOcb3c1wRcJLGFh7jI/PWt1MXYPwx3yU3JxQy+Q44rZ7  
 r9MWM7aq8XgdkMOtbwPQN7MyGAGyNUbUg+Z+JgZ/eyI0fdvAwtWSzoFMv138zBQU  
 N/FOCzmQ+IBh5fC65fAeP6cNsOlgXnz9V16cge/uxSnDP9kDeiD9is1ROsljd2gx  
 PmP5g4rjURzdCporUW8hSMjUdaNgoGNZRJc57s0lGrtCsBRXPkOfL6RXNVeyVpn/  
 wR5jHOjul1qG5+JyvPX3apNFA0j+Pw==  
 -----END PUBLIC KEY-----  
```

So what to do? The first thing I did was examine the public key because at first glance, it's about twice as long as it should be. Luckily openssl has a mode for exactly that:

```
 root@mankrik:~/bctf/warmup# openssl rsa -pubin -inform PEM -text -noout -in warmup-c6aa398e4f3e72bc2ea2742ae528ed79.pub   
 Public-Key: (2050 bit)  
 Modulus:  
   03:67:19:8d:6b:56:14:e9:58:13:ad:d8:f2:2a:47:  
   17:bc:72:be:1e:ab:d9:33:d1:b8:69:44:fd:b7:5b:  
   8e:d2:30:be:62:d7:d1:b6:9d:22:20:95:c1:28:c8:  
   6f:82:01:2e:cb:11:61:91:fd:9d:01:8a:6d:02:f8:  
   4d:b2:7b:c5:1a:21:30:7d:c8:6f:4b:f7:71:c6:91:  
   c1:43:e5:ab:e5:49:b5:bd:2d:6e:b1:a2:1f:d6:27:  
   0e:7e:1b:48:fe:06:11:fb:b2:e1:b0:b3:52:4e:6f:  
   4d:e8:b4:e4:a3:45:da:44:a1:3d:e8:25:b7:26:08:  
   db:6c:7c:4a:40:b7:82:66:e6:c8:7b:bf:de:f6:b4:  
   83:81:d4:9c:45:07:a5:8b:cd:47:b7:6d:64:b4:59:  
   08:b1:58:bd:7e:bc:4d:ac:b0:b1:cf:d6:c2:c1:95:  
   74:f4:0e:b2:ef:d0:e9:e1:0d:c7:00:5c:ad:39:bc:  
   af:52:b9:ea:c3:87:33:68:d6:90:31:c5:e7:24:68:  
   4a:44:f0:68:ef:d1:d3:dc:09:6d:9b:5d:64:11:e5:  
   8b:de:e4:3e:46:b9:9a:0d:04:94:b9:db:28:19:5a:  
   f9:01:af:f1:30:d4:a6:e2:03:da:d0:8d:a5:7f:a7:  
   e4:02:62:a5:ba:db:2a:32:3e:da:28:b4:46:96:ab:  
   30:5d  
 Exponent:  
   00:f3:95:9d:97:8e:02:eb:9f:06:de:f3:f3:35:d8:  
   f8:af:d7:60:99:51:dd:ac:60:b7:14:b6:c2:2a:f0:  
   fa:91:2f:21:0b:34:20:6b:d2:4a:96:01:c7:8d:f4:  
   a0:27:5f:10:7f:d3:ab:55:2d:95:05:7e:b9:34:e7:  
   1b:dd:cd:70:45:c2:4b:18:58:7b:8c:8f:cf:5a:dd:  
   4c:5d:83:f0:c7:7c:94:dc:9c:50:cb:e4:38:e2:b6:  
   7b:af:d3:16:33:b6:aa:f1:78:1d:90:c3:ad:6f:03:  
   d0:37:b3:32:18:01:b2:35:46:d4:83:e6:7e:26:06:  
   7f:7b:22:34:7d:db:c0:c2:d5:92:ce:81:4c:bf:5d:  
   fc:cc:14:14:37:f1:4e:0b:39:90:f8:80:61:e5:f0:  
   ba:e5:f0:1e:3f:a7:0d:b0:e9:60:5e:7c:fd:57:5e:  
   9c:81:ef:ee:c5:29:c3:3f:d9:03:7a:20:fd:8a:cd:  
   51:3a:c9:63:77:68:31:3e:63:f9:83:8a:e3:51:1c:  
   dd:0a:9a:2b:51:6f:21:48:c8:d4:75:a3:60:a0:63:  
   59:44:97:39:ee:cd:25:1a:bb:42:b0:14:57:3e:43:  
   9f:2f:a4:57:35:57:b2:56:99:ff:c1:1e:63:1c:e8:  
   ee:97:5a:86:e7:e2:72:bc:f5:f7:6a:93:45:03:48:  
   fe:3f  
```

Ok so an RSA public key is generally made up of two components of the RSA encryption process, the modulus (n) and the exponent (e). The modulus is a product of two secret prime numbers called p and q and is a super long integer represented correctly above. The exponent is a number that is used to exponentiate the plaintext in order to arrive at the ciphertext.

In RSA it is generally safe to use exponents that are moderately large, like around 65537 which is considered a "safe" size. Too small and too large exponents weaken the security of the cryptosystem and can be taken advantage of.

In this case the exponent is WAY too large and this can be taken advantage of using what is called a <a href="http://en.wikipedia.org/wiki/Wiener's_attack" target="_blank">Wiener's attack</a>, named after the cryptologist who wrote about it.

Using this attack we can take the values of e and n and solve for the private exponent, d.

These are the two equations that make this meaningful.

Textbook RSA Encryption can be simply stated:

<span style="font-family: Times, Times New Roman, serif; font-size: large;"><i>C = M<sup>e</sup> </i>mod<i> n</i></span>

Decryption can be simplified to this:

<span style="font-family: Times, Times New Roman, serif; font-size: large;"><i>M = C<sup>d</sup> </i>mod<i> n</i></span>

So since we have c (ciphertext), n (modulus) and a way to calculate d, we could simply calculate our plaintext, m if we're lucky.

Fortunately there's a Python implementation for this attack on the internet already. You'll want to <a href="https://github.com/pablocelayes/rsa-wiener-attack" target="_blank">Git clone into this repository</a>, and then in there I've modified their sample program to do our bidding:

```
 #!/usr/bin/python  
 import ContinuedFractions, Arithmetic  
 import time  
 import sys  
 import base64  
 import binascii  
 import gmpy  
 import sympy  
 import math  
 import fractions  
 import struct  
 sys.setrecursionlimit(100000)  
 # modulus from the RSA public key  
 n=0x367198D6B5614E95813ADD8F22A4717BC72BE1EABD933D1B86944FDB75B8ED230BE62D7D1B69D222095C128C86F82012ECB116191FD9D018A6D02F84DB27BC51A21307DC86F4BF771C691C143E5ABE549B5BD2D6EB1A21FD6270E7E1B48FE0611FBB2E1B0B3524E6F4DE8B4E4A345DA44A13DE825B72608DB6C7C4A40B78266E6C87BBFDEF6B48381D49C4507A58BCD47B76D64B45908B158BD7EBC4DACB0B1CFD6C2C19574F40EB2EFD0E9E10DC7005CAD39BCAF52B9EAC3873368D69031C5E724684A44F068EFD1D3DC096D9B5D6411E58BDEE43E46B99A0D0494B9DB28195AF901AFF130D4A6E203DAD08DA57FA7E40262A5BADB2A323EDA28B44696AB305D  
 # exponent from the RSA public key  
 e=0xF3959D978E02EB9F06DEF3F335D8F8AFD7609951DDAC60B714B6C22AF0FA912F210B34206BD24A9601C78DF4A0275F107FD3AB552D95057EB934E71BDDCD7045C24B18587B8C8FCF5ADD4C5D83F0C77C94DC9C50CBE438E2B67BAFD31633B6AAF1781D90C3AD6F03D037B3321801B23546D483E67E26067F7B22347DDBC0C2D592CE814CBF5DFCCC141437F14E0B3990F88061E5F0BAE5F01E3FA70DB0E9605E7CFD575E9C81EFEEC529C33FD9037A20FD8ACD513AC9637768313E63F9838AE3511CDD0A9A2B516F2148C8D475A360A06359449739EECD251ABB42B014573E439F2FA4573557B25699FFC11E631CE8EE975A86E7E272BCF5F76A93450348FE3F  
 def hack_RSA(e,n):  
   print "Performing Wiener's attack. Don't Laugh..."  
   time.sleep(1)  
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
 hacked_d = hack_RSA(e, n)  
 print "d=" + str(hacked_d)  
```

Which gives us d when run:

```
 root@mankrik:~/bctf/warmup/rsa-wiener-attack# ./weener.py  
 Performing Wiener's attack. Don't Laugh...  
 d=4221909016509078129201801236879446760697885220928506696150646938237440992746683409881141451831939190609743447676525325543963362353923989076199470515758399  
```

So now it' should just be a matter of calculating the plaintext and printing out the result. Which we modify our weener.py exploit to do.

```
 #!/usr/bin/python  
 import ContinuedFractions, Arithmetic  
 import time  
 import sys  
 import base64  
 import binascii  
 import gmpy  
 import sympy  
 import math  
 import fractions  
 import struct  
 sys.setrecursionlimit(100000)  
 # modulus from the RSA public key  
 n=0x367198D6B5614E95813ADD8F22A4717BC72BE1EABD933D1B86944FDB75B8ED230BE62D7D1B69D222095C128C86F82012ECB116191FD9D018A6D02F84DB27BC51A21307DC86F4BF771C691C143E5ABE549B5BD2D6EB1A21FD6270E7E1B48FE0611FBB2E1B0B3524E6F4DE8B4E4A345DA44A13DE825B72608DB6C7C4A40B78266E6C87BBFDEF6B48381D49C4507A58BCD47B76D64B45908B158BD7EBC4DACB0B1CFD6C2C19574F40EB2EFD0E9E10DC7005CAD39BCAF52B9EAC3873368D69031C5E724684A44F068EFD1D3DC096D9B5D6411E58BDEE43E46B99A0D0494B9DB28195AF901AFF130D4A6E203DAD08DA57FA7E40262A5BADB2A323EDA28B44696AB305D  
 # exponent from the RSA public key  
 e=0xF3959D978E02EB9F06DEF3F335D8F8AFD7609951DDAC60B714B6C22AF0FA912F210B34206BD24A9601C78DF4A0275F107FD3AB552D95057EB934E71BDDCD7045C24B18587B8C8FCF5ADD4C5D83F0C77C94DC9C50CBE438E2B67BAFD31633B6AAF1781D90C3AD6F03D037B3321801B23546D483E67E26067F7B22347DDBC0C2D592CE814CBF5DFCCC141437F14E0B3990F88061E5F0BAE5F01E3FA70DB0E9605E7CFD575E9C81EFEEC529C33FD9037A20FD8ACD513AC9637768313E63F9838AE3511CDD0A9A2B516F2148C8D475A360A06359449739EECD251ABB42B014573E439F2FA4573557B25699FFC11E631CE8EE975A86E7E272BCF5F76A93450348FE3F  
 c=0x1e04304936215de8e21965cfca9c245b1a8f38339875d36779c0f123c475bc24d5eef50e7d9ff5830e80c62e8083ec55f27456c80b0ab26546b9aeb8af30e82b650690a2ed7ea407dcd094ab9c9d3d25a93b2140dcebae1814610302896e67f3ae37d108cd029fae6362ea7ac1168974c1a747ec9173799e1107e7a56d783660418ebdf6898d7037cea25867093216c2c702ef3eef71f694a6063f5f0f1179c8a2afe9898ae8dec5bb393cdffa3a52a297cd96d1ea602309ecf47cd009829b44ed3100cf6194510c53c25ca7435f60ce5f4f614cdd2c63756093b848a70aade002d6bc8f316c9e5503f32d39a56193d1d92b697b48f5aa43417631846824b5e86  
 def hack_RSA(e,n):  
   print "Performing Wiener's attack. Don't Laugh..."  
   time.sleep(1)  
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
 hacked_d = hack_RSA(e, n)  
 print "d=" + str(hacked_d)  
 m = pow(c, hacked_d, n)  
 print "So the flag is:"  
 print("%0512x" %m).decode("hex")  
```

Which gives us the following result, including the flag.

```
 root@mankrik:~/bctf/warmup/rsa-wiener-attack# ./weener.py  
 Performing Wiener's attack. Don't Laugh...  
 d=4221909016509078129201801236879446760697885220928506696150646938237440992746683409881141451831939190609743447676525325543963362353923989076199470515758399  
 So the flag is:  
 BCTF{9etRea4y!}  
```

What a trip through the pitfalls of RSA!

Writeup: Dacat