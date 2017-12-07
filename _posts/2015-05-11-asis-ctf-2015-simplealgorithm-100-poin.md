---
id: 231
title: 'ASIS CTF 2015 - simple_algorithm - 100 point Crypto Challenge'
date: 2015-05-11T09:39:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=231
permalink: /asis-ctf-2015-simplealgorithm-100-poin/
post_views_count:
  - "531"
image: /images/2015/05/2-7.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-_QSPxelMLZI/VVBsTf6u9DI/AAAAAAAAAKg/MvFVU9NRIqA/s1600/2.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="207" src="/images/2015/05/2-7.png" width="400" /></a>
</div>

I worked on this one first because it was one of the earliest challenges available and for the point value must be a quick solve. We are given very little information in the challenge but at least the provided file has everything we need.

```
root@mankrik:~/asis/algo# tar -Jxvf simple_algorithm_5a0058082857cf27d6e51c095ac59bd5
simple_algorithm/
simple_algorithm/enc.txt
simple_algorithm/._simple_algorithm.py
simple_algorithm/simple_algorithm.py
```

If we examine the ciphertext we see a long integer:

```
root@mankrik:~/asis/algo/simple_algorithm# cat enc.txt 
2712733801194381163880124319146586498182192151917719248224681364019142438188097307292437016388011943193619457377217328473027324319178428
```

And if we check the python code we see the details of the cipher algorithm:

```
#!/usr/bin/python

flag = '[censored]'
hflag = flag.encode('hex')
iflag = int(hflag[2:], 16)

def FAN(n, m):
    i = 
    z = []
    s = 
    while n > :
     if n % 2 != :
      z.append(2 - (n % 4))
     else:
      z.append()
     n = (n - z[i])/2
     i = i + 1
    z = z[::-1]
    l = len(z)
    for i in range(, l):
        s += z[i] * m ** (l - 1 - i)
    return s

i = 
r = ''
while i < len(str(iflag)):
    d = str(iflag)[i:i+2]
    nf = FAN(int(d), 3)
    r += str(nf)
    i += 2

print r
```

What it does is take 2 bytes of the plaintext at a time, converts that to an integer, does some math on that integer and then concatenates the result of that math to the list of existing integers to form the ciphertext.

Initially I tried to simply reverse the algorithm but that turned out not to be feasible. The output of the math results in integers that are either 2 or 3 digits long and there's no way to know from the ciphertext which you're dealing with and so you'd have a large amount of trial and error.

I next tried enciphering some sample strings and noticed that enciphering a simple "ASIS{00000000000000000000000000000000}" string gets me 14 integers closer to solving the ciphertext:
  
```
root@mankrik:~/asis/algo/simple_algorithm# ./simple_algorithm.py 
2712733801194321673080924280272919148112712871921790216656907207572172432448111947191682811944216233193618028182875719416452697218
root@mankrik:~/asis/algo/simple_algorithm# cat enc.txt 
2712733801194381163880124319146586498182192151917719248224681364019142438188097307292437016388011943193619457377217328473027324319178428

```

So given this idea, and the knowledge that all ASIS flags contain only hexadecimal digits 0-9 and a-f I decided to brute force attack this part of the challenge.

What I decided initially to try is to iterate each character through 0-9, a-f byte by byte. However since the algorithm takes 2 bytes of plaintext and produces 2-3 digit integers it was extremely unreliable.

The basic algorithm I came up with is:

  * Beginning at the 1st character in the MD5sum, encrypt the text ASIS{x0000000000000000000000000000000} call it C<sub>i</sub>
  * Compare C<sub>i</sub> with the ciphertext C by counting the number of correct integers in the result
  * If C<sub>i</sub> improves the count of integers we have correct in our last pass by 2+ then put this C<sub>i</sub> in a list and label it with how many correct integers it had. Call this result a "good result"
  * Once we've checked every character 0-9, a-f in that position in the plaintext then compare all of the "good results" for this position to find the best result. Assume that is correct and move to the next position.

Next I switched to n-grams and iterated through digrams and trigrams and got increasingly accurate results but finally decided to settle on quadgrams which gave 100% reliable cracking in an acceptable amount of time.

```
root@mankrik:~/asis/algo/crack# ./simplepwn2.py 
[+] Cracking ciphertext...
[+] Flag so far: ASIS{a9ab0000000000000000000000000000}
[+] Flag so far: ASIS{a9ab115c000000000000000000000000}
[+] Flag so far: ASIS{a9ab115c488a00000000000000000000}
[+] Flag so far: ASIS{a9ab115c488a31180000000000000000}
[+] Flag so far: ASIS{a9ab115c488a311896da000000000000}
[+] Flag so far: ASIS{a9ab115c488a311896dac4e800000000}
[+] Flag so far: ASIS{a9ab115c488a311896dac4e8bc200000}
[+] Flag so far: ASIS{a9ab115c488a311896dac4e8bc20a6d7}
[+] Flag: ASIS{a9ab115c488a311896dac4e8bc20a6d7}
```

And finally, here's the code which takes the basic code provided in the challenge and uses it to crack the cipher:

```
#!/usr/bin/python

import string
import itertools

# try n-grams of how many characters at a time?
atatime=4

# Example:  ASIS{b026324c6904b2a9cb4b88d6d61c81d1}
initflag = 'ASIS{00000000000000000000000000000000}'

encint = "2712733801194381163880124319146586498182192151917719248224681364019142438188097307292437016388011943193619457377217328473027324319178428"

def FAN(n, m):
    i = 
    z = []
    s = 
    while n > :
     if n % 2 != :
      z.append(2 - (n % 4))
     else:
      z.append()
     n = (n - z[i])/2
     i = i + 1
    z = z[::-1]
    l = len(z)
    for i in range(, l):
        s += z[i] * m ** (l - 1 - i)
    return s

def enc(plaintext):
 hflag = plaintext.encode('hex')
 iflag = int(hflag[2:], 16)
 i = 
 r = ''
 while i < len(str(iflag)):
     d = str(iflag)[i:i+2]
     nf = FAN(int(d), 3)
     r += str(nf)
     i += 2

 return r 

def compareit(attemptstr):
       enclist = list(encint)
       attempt = list(attemptstr)
       correct = 
       for c in range(len(enclist)):
           if attempt[c] == enclist[c]:
         correct += 1 
           else:
                break

       return correct


# start exchanging pairs at the n'th column
startchar = 5
# baseline from that column of correct integers in output
baseline  = 14
alphabet = '0123456789abcdef'
pair = startchar
currentflag = initflag

print "[+] Cracking ciphertext..."

while pair < len(initflag)-1:

 flaglist = list(currentflag)
 goodresults = []
 # for every pair of hexdigits
 for maybe in itertools.product(alphabet, repeat=atatime): 
  flaglist[pair] = maybe[]
  flaglist[pair+1] = maybe[1]
  flaglist[pair+2] = maybe[2]
  flaglist[pair+3] = maybe[3]

  tryflag = "".join(flaglist)
  attempt = enc(tryflag)
  result = compareit(attempt)
  if result > baseline+2:
   maybelist = list(maybe)
   maybelist.append(result)
   goodresults.append(maybelist)
   
 bestresult = 
 bestfit = ""

 # Parse the good results looking for the best result
 for r in goodresults:
  if r[atatime] > bestresult:
   bestresult  = r[atatime]
   flaglist[pair]  = r[]
   flaglist[pair+1] = r[1]
   flaglist[pair+2] = r[2]
   flaglist[pair+3] = r[3]

 currentflag = "".join(flaglist)
 print "[+] Flag so far: " + currentflag
   
 pair += atatime

print "[+] Flag: " + currentflag
```