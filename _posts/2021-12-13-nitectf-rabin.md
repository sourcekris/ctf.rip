---
title: 'niteCTF - Rabin to the Rescue'
date: 2021-12-13T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/nitectf/title.PNG
categories:
  - Write-Ups
  - Crypto
---
Another fun CTF that gave me plenty of challenges to learn from. I solved a good amount of the Crypto challenges in this one as well as the crypto related pwn challenge. This one got some good use out of [my own RSA tooling](https://github.com/sourcekris/goRsaTool) so I decided to write it up.

#### <a name="rabin"></a>Rabin to the Rescue - Crypto - 443 points

This challenge reads:

```
It may look like a piece of cake, but you need to dive deep into it.

nc rabin.challenge.cryptonite.team 1337
```

The challenge comes with one `rabin_to_the_rescue.py` which is the python source of the service running online. The code looks like this:

```python
from Crypto.Util.number import *
from sympy import *
import random

def mixer(num):
    while(num>1):
        if(int(num) & 1):
            num=3*num+1
        else:
            num=num/2
    return num

def gen_sexy_primes():
    p=getPrime(256)
    q=p+6

    while((p%4!=3) or (q%4!=3)):
        p=getPrime(256)
        q=nextprime(p+1)
    return p, q

p, q=gen_sexy_primes()
n=p*q
    

def encrypt(m, e, n):
    return pow(m, e, n)
    
e=int(mixer(q-p))*2

print("________________________________________________________________________________________________")
print("\n\n")
print("-----------------------------------")
print("-----------------------------------")
print("-----------------------------------")
print("               /\\")
print("            __/__\\__")
print("            \\/    \\/")
print("            /\\____/\\")
print("            ``\\  /``  ")
print("               \\/")
print("-----------------------------------")
print("-----------------------------------")
print("-----------------------------------")
print("\n\n")
print("Welcome to the Encryption challenge!!!!")
print("\n")
print("Menu:")
print("=> [E]ncrypt your message")
print("=> [G]et Flag")
print("=> E[x]it")
print("________________________________________________________________________________________________")

while(true):
    choice=input(">>")
    if choice.upper()=='E':
        print("Enter message in hex:")
        try:
            m=bytes_to_long(bytes.fromhex(input()))
        except:
            print("Wrong format")
            exit(0)
        ciphertext=encrypt(m,e,n)
        print("Your Ciphertext is: ")
        print(hex(ciphertext)[2:])
    elif choice.upper()=='G':
        print("Your encrypted flag is:")
        with open('flag.txt','rb') as f:
            flag=bytes_to_long(f.read())
        t=random.randint(2, 2*5)
        for i in range(t):
            ciphertext=encrypt(flag,e,n)
        print(hex(ciphertext)[2:])
    elif choice.upper()=='X':
        print("Exiting...")
        break
    else:
        print("Please enter 'E','G' or 'X'")
```

So its a service that will generate an "RSA" like set of encryption parameters, and then offer to do two things:

- Encrypt an arbitrary plaintext with the RSA parameters.
- Show you an encrypted flag.

There's a few bugs in the implementation that help us and a few bugs that hinder us. Let's explain

#### The Bugs

##### Prime Selection

This is how the large primes are chosen:

```python
def gen_sexy_primes():
    p=getPrime(256)
    q=p+6

    while((p%4!=3) or (q%4!=3)):
        p=getPrime(256)
        q=nextprime(p+1)
    return p, q
```



The first bug is that the prime selection method is really weak for RSA. It wants "sexy primes". Sexy primes are when two primes differ by just 6. Any modulus generated with such primes is trivially factorable with something like [Fermat Factorisation](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) method.

##### Exponent Selection

The exponent is selected by this method:

```python
def mixer(num):
    while(num>1):
        if(int(num) & 1):
            num=3*num+1
        else:
            num=num/2
    return num

e=int(mixer(q-p))*2
```

Since `p - q` is always `6`, this function always returns `2`. It will never not be 2. This is a bug because RSA does not work properly with a modulus of 2 so we need to work around that later.

##### Encryption Rounds

I don't know what is intended in this section of the code, maybe they intended for the flag to be encrypted multiple times?

```python
        t=random.randint(2, 2*5)
        for i in range(t):
            ciphertext=encrypt(flag,e,n)
```

Anyway it doesn't do anything except encrypt the flag once, but repeatedly. Not real useful for security but necessary for us to make our lives easier.

#### The Solutions

Even though `2` is an invalid modulus, I still plan on solving this via RSA methods. So in order to solve this problem we need the modulus used in the encryption.

Since the server will encrypt any plaintext, we can use that as an oracle to learn the modulus using [this method discussed here](https://crypto.stackexchange.com/questions/65965/determine-rsa-modulus-from-encryption-oracle).

Since the exponent is only 2 though, encrypting small values like suggest 2, 3, 4 and 9 is insufficient. We need some value that is guaranteed to wrap modulo `n`.

So in order to do that I chose these numbers instead:

- `e2 = 2^1000`
- `e4 = (2^1000)^2`
- `e3 = 3^1000`
- `e9 = (3^1000)^2`

With these numbers chosen I connected to the server and asked it to encrypt my values as well as send me the ciphertext:

```shell
-----------------------------------
-----------------------------------
-----------------------------------
               /\
            __/__\__
            \/    \/
            /\____/\
            ``\  /``  
               \/
-----------------------------------
-----------------------------------
-----------------------------------



Welcome to the Encryption challenge!!!!


Menu:
=> [E]ncrypt your message
=> [G]et Flag
=> E[x]it
________________________________________________________________________________________________
>>e
Enter message in hex:
010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Your Ciphertext is: 
657881fe3b2185abc8f6f97c2ba956a93711d718ac25d8c5d43f716d686bf092eeb05deb3cd65a4b733a7631781144a52306b939570d1ccfc7a1577394bd70c
>>e
Enter message in hex:
0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Your Ciphertext is: 
30cd23bbc0e674d5ac7b5119051d79c1694eba71ffb99dd2849b504b8b52595bae6b5dc5ffcaef70f19286c56103fc0e7dd812aa732b5175dca224cedec42309
>>e
Enter message in hex:
01f2dd011353698b8240c1d3a8966cb97bd189e62de18b737a5f2a204c3465c3f4cfb517240c4b0bf6bc8c1c1c23522fdd8144dd38eeac64b714394e4a0fd910694426da120a7d348358fcc35338b723a04b9ba8cfe20edfac8e6626b458d62cbba3c979a16b2c373b454c22de8f3ab1d74bdb0ab340616c35824d1b60a23c10087a8fb1c54063addde0244ab3df0171eea92c34990f5bcb3b488c83b30a15a606e9c17a8e7ab6ce065bd2a048f32939dc42ec08348318c4940c56f7867dbe5616937bd3b85b21
Your Ciphertext is: 
2cbf95638a52b35b94710e03357c218de97b19b0f09aa7beec814f11ff106c4ab12c712f27d1517ad9230649485e9b22d0d06b13f5d0b0905e8a69cded52bebd
>>e
Enter message in hex:
03cc2096fa0be5cf1df2c53ff4ad9cf8686b86384482b127f7c5596293c1db79cb32fc37d5067090f7536e6c3c726b4b801408df0f528e03612930e3a826307d55fcf3efa91a2ab89e19b6debea122869849d90b8eb85a78eba05cf951d4d1b24c41147a90b39248f6ae0bbe6fa8c5a12a9cacccba014b28dc387693c8567a4d1bb8d3546b8ca25e7a01143ebb7698dd2982c2544aca88149d8b731fa7479532f7139c2b849601f600d77e6fa21f075d277a6bc6596456dd8b76b9659f8ff156500736cc06b21d9cd9d7fc04707221e60cdeb7ae6050ca1aad6c893e367d551d2141bd9e852426329d0e02da77c7c1a05aeae93c30c2e4f6203ed65eee102b77f5df0891ed6009bd79ccc8a6a2b21fedddc837ab936ba8398d65766a8a2f03c2c81eb7aa86e542b781194e19528baa6349df8fee0b46d5d03d180ceddd082e2dff70878fe15f12c4040da0fb534cf1397901cacbf81936df2730ca5e2baaaf3dc552f85c499cb7c76dd5024cf9febc23cbc82ec47855b43086b8bfc5c0b93cbcaa43b130f0b094e2b185e07a41
Your Ciphertext is: 
1f89e35dce436f681f7a4ce7ba7c12c2e5c53dc68f83f95e1e021dcf71c3addf2dd41d60b85929d890c6843e9a764756214ad4f42aec0eeff0aaf5dc20ae3292
>>g
Your encrypted flag is:
eac4a0bf0af96bb6485f1ee08a18be22049e408118b9d805ed37f9b32790f415ad13d4a8487b2f33b75037eaea9bc1f39d940d7c898689856bdf6950dce9fa1
>>
```

With these numbers collected I want to calculate the following:

- `gcd(e2^2 - e4, e3^2 - e9)`

For this I have tooling already built; [goRsaTool](https://github.com/sourcekris/goRsaTool):

```shell
$ cat > findmod.txt
e2 = 0x657881fe3b2185abc8f6f97c2ba956a93711d718ac25d8c5d43f716d686bf092eeb05deb3cd65a4b733a7631781144a52306b939570d1ccfc7a1577394bd70c
e4 = 0x30cd23bbc0e674d5ac7b5119051d79c1694eba71ffb99dd2849b504b8b52595bae6b5dc5ffcaef70f19286c56103fc0e7dd812aa732b5175dca224cedec42309
e3 = 0x2cbf95638a52b35b94710e03357c218de97b19b0f09aa7beec814f11ff106c4ab12c712f27d1517ad9230649485e9b22d0d06b13f5d0b0905e8a69cded52bebd
e9 = 0x1f89e35dce436f681f7a4ce7ba7c12c2e5c53dc68f83f95e1e021dcf71c3addf2dd41d60b85929d890c6843e9a764756214ad4f42aec0eeff0aaf5dc20ae3292

$ goRsaTool -key findmod.txt -attack oraclemodulus
Recovered modulus:
n = 3823764509294606690677150613108312680560894488443794278642334173900438477843053351537343539446110446266124970385048950250278942540622478152965517651430033
```

Now we have `n` its a trivial matter to find the primes, I create a fake key with a fake exponent and factor the primes quickly. It was during writing this challenge that I [improved my tool](https://github.com/sourcekris/goRsaTool/commit/41883804be7f2edb658466ba04508f9b5f3792a8) to print out the key's prime numbers during `verbose` mode operation.

```shell
$ cat > fakekey.txt
n = 3823764509294606690677150613108312680560894488443794278642334173900438477843053351537343539446110446266124970385048950250278942540622478152965517651430033
e = 65537

$ goRsaTool -key fakekey.txt -attack fermat -verbose
rsatool: rsatool.go:94: starting up...
2021/12/13 22:28:42 fermat factorization attempt beginning with timeout 5m0s
Prime 0: 61836595227216437443312015875694562668835858514683229972362574341252303164867
Prime 1: 61836595227216437443312015875694562668835858514683229972362574341252303164699
...
```

Now we have at least one prime we can find the plaintext even if the real exponent  is 2 by using my tool's `defectivee` mode. We just need a partial known plaintext. Since we know the flag format is `nite{`we can use that:

```shell
$ python -c "from Crypto.Util.number import bytes_to_long; print(bytes_to_long(b'nite{'))"

474215638395

$ cat > realkey.txt
n = 3823764509294606690677150613108312680560894488443794278642334173900438477843053351537343539446110446266124970385048950250278942540622478152965517651430033
e = 2
c = c = 0xeac4a0bf0af96bb6485f1ee08a18be22049e408118b9d805ed37f9b32790f415ad13d4a8487b2f33b75037eaea9bc1f39d940d7c898689856bdf6950dce9fa1
p = 61836595227216437443312015875694562668835858514683229972362574341252303164867
kpt = 474215638395

$ goRsaTool -key realkey.txt -attack defectivee
-----BEGIN RSA PRIVATE KEY-----
MIIBNgIBAAJASQIr7XFz2T5BWc0I3l1ealqLlIeMqnU/gL6irsRV3EAnDa/SqqiO
LVDTeEtMVk7kpBi9ByGGZ518hNZsL/dKkQIBAgJACSBFfa4ueyfIKzmhG8urzUtR
cpDxlU6n8BfUVdiKu4fitCSH8orIlTIxhW60AX3AJj634ZK7OhtdKa7diyxj9wIh
AIi2RcmLKSTB36OmatYlMHG5EX79RdZLYUmbr7/rShXDAiEAiLZFyYspJMHfo6Zq
1iUwcbkRfv1F1kthSZuvv+tKFRsCICItkXJiykkwd+jpmrWJTBxuRF+/UXWS2FJm
6+/60oVxAiAiLZFyYspJMHfo6Zq1iUwcbkRfv1F1kthSZuvv+tKFRwIgIv3kJd8M
DfrD6FzhcLc7ozPwqyt+EMECCzicOL2/Jxg=
-----END RSA PRIVATE KEY-----

Recovered plaintext: 
nite{r3p34t3d_r461n_3ncrypt10n_l1tr4lly_k1ll5_3d6f4adc5e}
```

Which yeah was the flag!
