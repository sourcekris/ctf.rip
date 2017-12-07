---
id: 244
title: 'BCTF 2015 - weak_enc Crypto challenge'
date: 2015-03-23T09:43:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=244
permalink: /bctf-2015-weakenc-crypto-challenge/
post_views_count:
- "345"
image: /images/2015/03/weak1-1.png
categories:
- Uncategorized
- Write-Ups
tags:
- "2015"
---
After a challenging enough "Warm Up" challenge at BCTF2015 which involved cracking a poorly thought out RSA encryption, the next challenge we decided to tackle was the weak_enc challenge worth only 200 points. I don't normally do crypto but the warmup challenge really got me in the mood so, here we go!

The challenge was fairly self explanatory thankfully, a link for a download, a cipher text to crack and an IP / port where a server can be reached:

<div class="separator" style="clear: both; text-align: center;">
<a href="/images/2015/03/weak1-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/weak1-1.png" /></a>
</div>

<div class="separator" style="clear: both; text-align: center;">
</div>

<div class="separator" style="clear: both; text-align: center;">
</div>

So firstly I downloaded the file and decompressed it. It had a .py extension so we knew it would be a Python script. Examining the code in the Python we find it is an encryption server code which listens on port 8888/tcp.

We also see it uses a salt as part of the encryption function and that the salt is not included in the files we downloaded. It imports "SALT" from a python module "grandmaToldMeNotToTalkToBigBadWolf".

```
import hashlib  
import string  
from grandmaToldMeNotToTalkToBigBadWolf import SALT  
DEBUG= False  
MSGLENGTH = 40000  
```

Cool. Let's create a arbitrary salt file for now so we can see the service in action:

```
root@mankrik:~/bctf/weak# echo SALT='abcd' > grandmaToldMeNotToTalkToBigBadWolf.py  
root@mankrik:~/bctf/weak# python weak_enc-40eb1171f07d8ebb06bbf36849d829a1.py   
```

Let's connect to it and see what happens:

```
root@mankrik:~# nc localhost 8888  
Please provide your proof of work, a sha1 sum ending in 16 bit's set to 0, it must be of length 21 bytes, starting with QN+yjqWfMwADrUsv  
test  
Check failed  
```

Ok before we can even access the encryption server, we have a riddle to solve? We must be able to solve this riddle to proceed to the next level because I have a feeling that, even though we have the full code of the encryption algorithm, without the salt, we will never decrypt the challenge.

The only way we're getting the salt is through the live BCTF server. So we need to pass this test.

As it turns out, this is a fairly standard riddle used in CTF competitions often. We solve it using a brute force approach using Python itertools module to build every possible combination of characters and test for combinations that meet the requirements. I have reused <a href="https://rdot.org/forum/showthread.php?t=2626" target="_blank">code from this link</a> with some modifications for our particular circumstances below:

```
proof = puzzlefromserver  
charset = ''.join( [ chr( x ) for x in xrange( 0, 128 ) ] )  
found = False  
for comb in itertools.combinations( charset, 5 ):  
 test = proof + ''.join( comb )  
 ha=hashlib.sha1()  
 ha.update( test )  
 if ( ord( ha.digest()[ -1 ] ) == 0x00 and  
     ord( ha.digest()[ -2 ] ) == 0x00):  
   found = True  
   break  
if not found:  
 print 'Could not find string =('  
 quit()  
```

The output of the snippet above is a string in the variable "test" that meets the criteria demanded of us by the server.

So it's time to start whipping up a client to begin probing our way through the encryption part of this crypto challenge.

For this I'm using Binjitsu, which I am still learning and finding great features in every day. The first thing I want to do is just connect, and then pass the riddle and get to the Encryption service. Let's use this code to do that:

```
#!/usr/bin/python  
from pwn import *  
import hashlib, itertools  
# This is the plaintext we are going to encrypt  
plaintext = 'a' * 1  
conn = remote('localhost',8888)  
#conn = remote('146.148.79.13',8888)  
task = conn.recvline()  
line = task.split()  
proof = line[25]  
print "Got challenge ("+proof+"). Brute forcing a response..."  
charset = ''.join( [ chr( x ) for x in xrange( 0, 128 ) ] )  
found = False  
for comb in itertools.combinations( charset, 5 ):  
 test = proof + ''.join( comb )  
 ha=hashlib.sha1()  
 ha.update( test )  
 if ( ord( ha.digest()[ -1 ] ) == 0x00 and  
     ord( ha.digest()[ -2 ] ) == 0x00):  
   found = True  
   break  
if not found:  
 print 'Could not find string =('  
 quit()  
print "Responding to challenge..."  
conn.send(test)  
conn.sendafter(':', plaintext + "n")  
encrypted = conn.recvline()  
line = encrypted.split()  
print "Plaintext "+plaintext+" encrypted is "+line[3]  
conn.close()  
```

And when we run it...

```
root@mankrik:~/bctf/weak# python pwnweak.py.p1  
[+] Opening connection to localhost on port 8888: Done  
Got challenge (3REpDAwCe+Mmxb85). Brute forcing a response...  
Responding to challenge...  
Plaintext a encrypted is Q0isU8Y=  
[*] Closed connection to localhost port 8888  
```

Ok cool we're in! And now I have a script I can encrypt anything with. That's step 1.

Next we need to figure out a way to approach the deduction of the salt. Let's browse the server code some more.

```
def LZW(s, lzwDict): # LZW written by NEWBIE  
 for c in s: updateDict(c, lzwDict)  
  print lzwDict # have to make sure it works  
 result = []  
```

Notice here we have a LZW function which is a lossless compression algorithm. Whether this algorithm implements true LZW or not is not important. What is important is that it's a compression algorithm (presumably) and that's cool because compression gives us interesting results when encrypting.

The idea I'm using here, is that, when you add a salt to a plaintext and compress them before encryption, if the plaintext and the salt have common factors then the ciphertext will be of a unexpected, and shorter, length. Let's take this oversimplified example:

* Case #1
* Salt: beef
* Plaintext: aaaaaa
* Ciphertext: AzTzDa

* Case #2
* Salt: beef
* Plaintext: eeeeee
* Ciphertext: TrZw

Notice how in this example, the plaintext containing letters that coincide with those found inside the salt resulted in a shorter ciphertext? From this we can deduce that the letter "e" is within the salt.

We try this in our "lab" environment by modifying our Python code with a for loop, from the server code we know that the salt can only contain lowercase letters a-z because it checks that, so that's cool.

Let's iterate through the characters a-z against our lab where we've configured the salt "abcd" and see what happens! Here's a <a href="http://ctf.rip/?page_id=117" target="_blank">link to the full code of this version</a>.

```
# iterate through lowercase letters  
for letter in range(97,122+1):  
   plaintext = chr(letter) * 10  
   conn = remote('localhost',8888)  
```

Then let's run our code against our lab server, I'm only interested in seeing the encrypted results so I'll grep for "encrypted":

```
root@mankrik:~/bctf/weak# python pwnweak.py.p2 | grep encrypted  
Plaintext aaaaaaaaaa encrypted is Q0isU8aHWYY=  
Plaintext bbbbbbbbbb encrypted is Q0isU8eHWYY=  
Plaintext cccccccccc encrypted is Q0isU8SHWYY=  
Plaintext dddddddddd encrypted is Q0isU8GHWY8=  
Plaintext eeeeeeeeee encrypted is Q0isU8KGWoc=  
Plaintext ffffffffff encrypted is Q0isU8KGWoc=  
Plaintext gggggggggg encrypted is Q0isU8KGWoc=  
Plaintext hhhhhhhhhh encrypted is Q0isU8KGWoc=  
Plaintext iiiiiiiiii encrypted is Q0isU8KGWoc=  
Plaintext jjjjjjjjjj encrypted is Q0isU8KGWoc=  
```

Wow check that out. For letters a - d the encrypted output differs but for all other encryptions the ciphertext is the same. So we deduce the salt has the letters a,b,c, and d. Cool.

Let's do this against the production server! They can't mind just 26 connections surely!

```
Plaintext gggggggggg encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext hhhhhhhhhh encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext iiiiiiiiii encrypted is NxQ1NDMYcDcw53gfGi8u 
Plaintext jjjjjjjjjj encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext kkkkkkkkkk encrypted is NxQ1NDMYcDcw53gcGi8u 
Plaintext llllllllll encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext mmmmmmmmmm encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext nnnnnnnnnn encrypted is NxQ1NDMYcDcw53geGi8u 
Plaintext oooooooooo encrypted is NxQ1NDMYcDcw53gdGi8u 
Plaintext pppppppppp encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext qqqqqqqqqq encrypted is NxQ1NDIZcTY/5HkaBS4t 
Plaintext rrrrrrrrrr encrypted is NxQ1NDIZcTY/5HkaBS4t  
```

Excellent, we're making progress. We know a couple of things from this.

 1. We know the salt is much longer than our "lab" salt because the ciphertext is much longer for the same input.
 2. We also know that the sale must contain the letters "i", "k", "o", and "n". All other ciphertexts remain the same.

Where to go from here? It is next possible to deduce the position of each byte in the salt by examining the individual bits in the ciphertext output. That is complicated though so is there anything we can do to quickly brute force this?

I got the idea from a colleague to assume that the salt fit the basic rules of an English language word and build a list of anagrams using the "ikon" letters, then apply them as salts in the server code until I reached a decryption of a known plaintext that matched a known ciphertext from the production server.

So we know:

 1. The string "gggggggggg" encrypts to "NxQ1NDIZcTY/5HkaBS4t".
 2. The salt is > 4 bytes
 3. The salt contains characters i,k,o and n

We assume:

The salt is an english word or at least a string that is made up of words following the rules of the english language (i.e. no "ooo" sequences)

So I made these modifications to the server code, which basically takes a plaintext from the client, then brute forces every combination of the 15 combinations of 4 letter uses of the letters i,k,o and n I came up with and sends them to the client.

Why did I chose 4 bytes and 5 sets of 4 bytes? At first I tried other values but by the time I found the salt this was the code I had. This is capable of searching for salts in any multiple of 4 bytes by modifying the itertools repeat value as well as the format string:

```
...  
def encrypt(m,salt):  
 lzwDict = dict()  
 toEnc = LZW(salt + m, lzwDict)  
 key = hashlib.md5(salt*2).digest()  
...  
   print "looking for salts"  
   koala = ('ikon', 'ionk', 'inok','onik','oink','nino','nini', 'niko', 'koni', 'koin', 'kino', 'niok', 'noik','noki','niko',);  
   for findsalt in itertools.product(koala, repeat = 5):  
       salttry = '{}{}{}{}{}'.format(*findsalt)  
       print "Salt: " + salttry  
       encd = encrypt(msg, salttry)  
       print "Encrypted: " + encd  
       req.sendall(salttry + ":" + encd + "n")  
...  
```

On the client side I went back to my basic, single throw non-looping client that just sends the string "gggggggggg" and then polls the server for every encrypted output. The server will be sending us a LOT so I just put it in a while loop forever because it was quick and easy. Here's a <a href="http://ctf.rip/?page_id=118" target="_blank">link to this version of the client</a>.

```
# This is the plaintext we are going to encrypt  
plaintext = 'g' * 10  
conn.sendafter(':', plaintext + "n")  
while True:  
   encrypted = conn.recvline()  
   print "Response: " + encrypted  
```

Then we wanna run it until we get a string containing the known good ciphertext we previously retrieved from the production server "NxQ1NDIZcTY/5HkaBS4t". Within 3 minutes we got the following output:

```
root@mankrik:~/bctf/weak# time python pwnweak.py.p3 | grep NxQ1  
Response: inokonikniokonikoink:iJykNxQ1QNqCzMLoilrI580hIg==  
Response: niniinokniniionkikon:Q3LUXv0lUVNxQ1dZV1WUYF9W  
Response: nikonikoninikonikoni:NxQ1NDIZcTY/5HkaBS4t  
```

Congrats, we now know the salt used to encrypt on the production server is "nikonikoninikonikoni". This is step 2 done! This challenge is not solved yet though. We have a message to decrypt next.

So taking what we know now, how can we apply this to decryption? I first thought to analyse the encryption and compression functions but before I got too far I noticed just how closely the encrypted versions of the long strings of n, i, k, and o matched the decryption challenge.

For example, from earlier we know:

1. Challenge ciphertext: NxQ1NDMYcDcw53gVHzI7
2. 10 n's ciphertext: NxQ1NDMYcDcw53geGi8u
3. 10 letters not in the list i,k,o,n: NxQ1NDIZcTY/5HkaBS4t

Notice that the ciphertext for letters in the list i,k,o,n are correct until the last 5 bytes of the challenge ciphertext. Can we apply our salt brute force technique to the challenge to result in a quick win?

Firstly, let's set our server code back to "stock" and configure our SALT correctly now that we know it.

Next we'll modify the client code to again, use a loop to continuously ask our localhost server to encrypt values. This time our plaintext will iterate through blocks of 4 characters we used previously to find the salt.

You can view the client code <a href="http://ctf.rip/?page_id=119" target="_blank">we used at this link</a>.

  We started with a ciphertext of 4 bytes, then increased it in blocks of 4 bytes until we had this code which looked for 12 byte plaintexts:

```
import hashlib, itertools  
# list of combinations of plaintext possibly  
pool = ('ikon', 'ionk', 'inok','onik','oink','nino','nini', 'niko', 'koni', 'koin', 'kino', 'niok', 'noik','noki','niko',);  
# iterate through the combinations  
for findsalt in itertools.product(pool, repeat = 3):  
   plaintext = '{}{}{}'.format(*findsalt)  
   conn = remote('localhost',8888)  
```

When run, we received a result in just over 2 minutes. We confirmed the string NxQ1NDMYcDcw53gVHzI7 is the result of encrypting the plaintext "nikoninikoni".

```
root@mankrik:~/bctf/weak# date; python pwnweak.py.p4 | grep NxQ1NDMYcDcw53gVHzI7  
Monday 23 March 20:28:18 AEDT 2015  
Plaintext nikoninikoni encrypted is NxQ1NDMYcDcw53gVHzI7  
^C
root@mankrik:~/bctf/weak# date  
Monday 23 March 20:30:35 AEDT 2015  
```

Woot. That's the third and final step to this challenge. We submit the flag and get the 200 points.

A good challenge with many new steps for me, use of deduction and brute force together was very fun. Thanks to BCTF team.

Writeup: Dacat