---
id: 227
title: 'CSAW 2015 Quals - FTP (RE300) Challenge'
date: 2015-09-21T10:24:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=227
permalink: /csaw-2015-quals-ftp-re300-challenge/
post_views_count:
  - "477"
image: /images/2015/09/rdf-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
It's been a long break between the last CTF I wrote up and now. To be honest there has been a bit of a lull in the number and quality of CTFs since earlier in the year. It seems they are starting up again though and that's great news.

This weekend our team took part in CSAW 2015 Qualifiers round and finished a respectable 124th or so out of 1000 or so teams by scoring 2,210 points. I'm happy with that but more happy with the way the team worked together. Great job guys.

Here is the clue for this writeup:

>We found an ftp service, I'm sure there's some way to log on to it.
>nc 54.175.183.202 12012
><a href="https://github.com/smokeleeteveryday/CTF_WRITEUPS/blob/master/2015/CSAWCTF/reversing/ftp/challenge/ftp" target="_blank">ftp_0319deb1c1c033af28613c57da686aa7</a>

So a remote server listening on port 12012 and a file called "ftp", we perform the usual first steps. Download the file, use "file" command, use "strings" to check for simple flags.

We found it was a Linux ELF binary for 64bit architectures. Given this is a reverse engineering challenge I placed the file directly into IDA Pro to browse the disassembly while starting the process on a local system. It's written quite well (for a CTF program!) so it starts up first try and listens on port 12012 on localhost.

Upon connecting we see a welcome banner, I try the usual FTP commands such as USER and PASS and these work correctly. I don't have a valid username yet so let's check out those functions in IDA Pro to see how authentication works.

In IDA Pro I first open the Strings sub-view and find a nice easy string related to authentication. I found one called "Please send password for user". I double click this string and then follow the Data Xref to a function "sub_40159B".

This function seems to be taking the username and password, then validating them against stored constants. In the IDA Pro decompilation, the authentication mechanism looks like this:

```
if ( !strncmp(*(a1 + 32), "blankwall", 9uLL) && hash_password(*(a1 + 40), 0x40309CLL) == 0xD386D209 )
    {
      *(a1 + 1216) = 1;
      send_message(*a1, "logged inn");
      dword_604408 = 102;
    }
```

So I've already renamed some of those functions in the snippet above, what it's doing is validating that your username is "blankwall" and your password hashed is equivalent to 0xD386D209.

Next I built a quick and dirty "FTP Client" in Python to send username "blankwall" with a password of "ABCDE" to see how the hash function deals with that. I located the hash function at **sub_401540** and set a breakpoint there in GDB w/PEDA.

_**Note**: You have to be careful when debugging this program as it fork's a new process ID for each connection, so I only attach the debugger after sending my username (but before sending my password)._

Here's the code of my testing client:

```
#!/usr/bin/python

from pwn import *

target = "127.0.0.1"
password = "ABCDE"

conn=remote(target, 12012)
print "[+] " + conn.recvline()

print "[+] Sending user: blankwall"
conn.sendline("USER blankwall")
print "[+] " + conn.recvline()

raw_input("[+] Attach Debugger")

print "[+] Sending password: " + password
conn.sendline("PASS " + password)
print "[+] " + conn.recvline()

conn.close()
```

I found that this function performs what I later found to be called "multiplicative hash" on the user input. It also uses a modulus to prevent overflowing the integer. Since a modulus is used, reversing the algorithm to "decrypt" the stored password value of 0xD386D209 is not possible as information is destroyed during the hashing process.

So the only way to recover the password I thought was to recreate the algorithm exactly and then brute force inputs until my hashed output was 0xD386D209! In order to do that I found the decompiled version of the function to be a good starting point:

```
__int64 __fastcall hash_password(__int64 a1)
{
  int i; // [sp+10h] [bp-8h]@1
  int v3; // [sp+14h] [bp-4h]@1

  v3 = 5381;
  for ( i = ; *(i + a1); ++i )
    v3 = 33 * v3 + *(i + a1);
  return v3;
}
```

However for me stepping through the binary in PEDA instruction by instruction gave an even simpler explanation of what the function was doing to the input as we can see the hash function building the output in the RAX/RCX registers. Here is the code I worked on. It prints the hash value after every calculation. This enables me to follow along with GDB to ensure my implementation of the multiplicative hash algorithm is correct.

```
#!/usr/bin/python

def enc(a1):
  start = 0x1505;
  print hex(start)
  op = start << 5
  print hex(op)
  op = op + start
  print hex(op)
  for i in a1:
        op = op + ord(i)
        print hex(op)
        saveop = op
        op = op << 5
        print hex(op)
        op = op + saveop
        print hex(op)

  op = op + 10
  print hex(op)
  return str(hex(op))[-8:]

print enc("ABCDE")
```

Which when run showed me the output step by step:

```
root@mankrik:~/csaw/ftp# ./enc1.py 
0x1505
0x2a0a0
0x2b5a5
0x2b5e6
0x56bcc0
0x5972a6
0x5972e8
0xb2e5d00
0xb87cfe8
0xb87d02b
0x170fa0560
0x17c81d58b
0x17c81d5cf
0x2f903ab9e0
0x310cbc8faf
0x310cbc8ff4
0x6219791fe80
0x652a44e8e74
0x652a44e8e7e
a44e8e7e
```

This final value agreed with GDB so I knew it was correct.

Once I had this function implemented in Python, I used the magic itertools Python module to calculate every combination of alphabetic characters. I tried 4,5 and finally 6 character passwords before finally striking gold and finding that the password "cookie" hashes successfully to 0xD386D209. I used this code for that:

```
#!/usr/bin/python

import itertools

target = "d386d209"

alphabet = list("abcdefghijklmnopqrstuvwxyz")

def enc(a1):
  start = 0x1505;
  op = start << 5 
  op = op + start
  for i in a1:
 op = op + ord(i)
        saveop = op
   op = op << 5
   op = op + saveop

  op = op + 10
  return str(hex(op))[-8:]

print "[+] Brute forcing hash: 0x" + target
for i in itertools.product(alphabet, repeat=6):
 encrypted = enc(i)
 if(encrypted == target):
  print "[+] Found it: " + "".join(i)
  break
```


Now we had the password I was able to login. After login though I was again stuck. We could use the LIST command to view the files stored on the FTP server but the usual FTP command "RETR" to retrieve files seemed to be bugged and kept throwing up "Invalid characters" error message.

Back to IDA Pro. At this point I spent an hour or so reversing the RETR command to find out what I needed to fix to get it to send me a file. To no avail really. Then I regrouped my thoughts and approached the problem from another angle. What if the solution was built into the FTP server itself.

A quick few minutes later and I identified the function "sub\_4025F8" which seemed to only exist to give a flag called "re\_solution.txt" to connected clients! Great! This function is only called from one place too. In fact it's only ever called in response to entering a simple command in the FTP server:



<div class="separator" style="clear: both; text-align: center;">
  <a href="http://4.bp.blogspot.com/-ICLt2qQV8cU/Vf-gi0jYnXI/AAAAAAAAANM/14Int8nk7N4/s1600/rdf.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="465" src="/images/2015/09/rdf-2.png" width="640" /></a>
</div>

So back to the server we went, logged in with our found username, cracked password, and knowledge of the command, and we were rewarded with the flag!

Final exploit for this challenge follows:

```
#!/usr/bin/python

import itertools
from pwn import *

targethost = "54.175.183.202"

target = "d386d209"

alphabet = list("abcdefghijklmnopqrstuvwxyz")

def enc(a1):
  start = 0x1505;
  op = start << 5
  op = op + start
  for i in a1:
        op = op + ord(i)
        saveop = op
        op = op << 5
        op = op + saveop

  op = op + 10
  return str(hex(op))[-8:]

print "[+] Cracking password: 0x"+target

for i in itertools.product(alphabet, repeat=6):
        encrypted = enc(i)
        if(encrypted == target):
                print "[+] Found it: " + "".join(i)
                password = "".join(i)
                break


conn=remote(targethost, 12012)
print "[+] " + conn.recvline()
print "[+] Sending user: blankwall"
conn.sendline("USER blankwall")
print "[+] " + conn.recvline()
print "[+] Sending password: " + password
conn.sendline("PASS " + password)
print "[+] " + conn.recvline()
print "[+] Send RDF"
conn.sendline("RDF")
print "[+] Flag: " + conn.recvline()
conn.close()
```

Easy game!