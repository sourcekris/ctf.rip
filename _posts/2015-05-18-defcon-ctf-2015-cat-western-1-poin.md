---
id: 230
title: 'Defcon CTF 2015 - Cat western - 1 Point Coding Challenge'
date: 2015-05-18T09:06:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=230
permalink: /defcon-ctf-2015-cat-western-1-poin/
post_views_count:
  - "547"
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
Defcon was finally here and I was so totally pumped for it. When it dropped, so did my jaw, it wasn't going to be easy. That's for sure. Defcon had some of the evilest, trickiest challenges I've ever faced in a CTF. And it was super fun because of it.

This challenge itself was a break from all the pwnables which I found really irritating in their multilayered complexity. This was simple, get in, work on data, get the flag. Single step stuff.

The challenge gives only the following clue:

**_Catwestern_**
  
**  
** 
  
_meow catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999_
  
_  
_ 
  
Upon connecting to that host with netcat we see the following:

```
# nc catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999
****Initial Register State****
rax=0x33d34005adc0a57c
rbx=0xe318943106ae1bf9
rcx=0x805e3dd411fbc177
rdx=0x9a951fd093fea167
rsi=0xdecfe15b09b2a5f5
rdi=0x8c1473c5803b0f4c
r8=0xf3888ac64cb3b981
r9=0xda321f211f484523
r10=0xadb76e93d0e8fa1e
r11=0x54acc124703437a
r12=0x6ba39546c9366ffa
r13=0x2250452bedb3e99a
r14=0x525e1ed890af328e
r15=0xdfcbd919b08f5cbe
****Send Solution In The Same Format****
About to send 81 bytes: 
H��I�׵m
I �H��)o�zL)�I��� �^M!�I��M �H��M��I��H��I��
```

Hrmm, whats this even about?

Given that it's talking about registers, my first thought is that maybe the binary data represents a memory dump of registers that we're supposed to unpack and send back. But after some thought, that was not much of a challenge so I looked for other vectors.

Next I thought about the terminology used in the server response. "Initial Register State"? "Send solution in same format"? Hmm. Well what operates on registers? Machine code I suppose. I wrote a quick Python client to grab just the binary data from the host into a file called "data.bin".

I then wrote a quick C program to act as a host for my test:

```
root@mankrik:~/defcon/cat# cat hw.c
#include</span>

void main(void) {
 printf("Hello world!n");
}
```

Next I used GDB to inject my data.bin file into this process:

```
root@mankrik:~/defcon/cat# gcc hw.c -o hw
root@mankrik:~/defcon/cat# gdb ./hw
GNU gdb (GDB) 7.4.1-debian
...
(no debugging symbols found)...done.
gdb-peda$ br main
Breakpoint 1 at 0x400510
gdb-peda$ r
...

Breakpoint 1, 0x0000000000400510 in main ()
gdb-peda$ restore data.bin binary $pc
Restoring binary file data.bin into memory (0x400510 to 0x40055b)
gdb-peda$ x/20i $pc
=> 0x400510 <main+4>: nop
   0x400511 <main+5>: inc    rdx
   0x400514 <main+8>: shrd   r13,r11,0x6
   0x400519 <main+13>: shrd   r9,r11,cl
   0x40051d: mul    rdi
   0x400520 <__libc_csu_fini>: adc    rbx,0x5b4087d2
   0x400527: adc    rbx,r13
   0x40052a: shld   rax,r11,0x1
   0x40052f: push   r8
   0x400531 <__libc_csu_init+1>: shld   rdi,rax,0xd
   0x400536 <__libc_csu_init+6>: add    rbx,r13
   0x400539 <__libc_csu_init+9>: adc    r13,r12
   0x40053c <__libc_csu_init+12>: and    r15,0x7fac5ea2
   0x400543 <__libc_csu_init+19>: xor    rdi,rdx
   0x400546 <__libc_csu_init+22>: xor    r14,r11
   0x400549 <__libc_csu_init+25>: sbb    r9,r14
   0x40054c <__libc_csu_init+28>: xor    rax,0x586fd268
   0x400552 <__libc_csu_init+34>: imul   r15,r15,0x7053ef41
   0x400559 <__libc_csu_init+41>: pop    rax
   0x40055a <__libc_csu_init+42>: ret    
```

As I suspected, the binary blob is x86 instructions that operate on registers and then returns. Cool. Now, how to programatically do this?

Since my host binary is working so well in hosting this parasite, I decided to make GDB do all the heavy lifting in this exploit and simply script it to do what I wanted.

In Python I grab the binary data and initial states from the network, write a GDB script to load the binary data into the main() function of a hello world C program. Execute the code, crash on the "ret" instruction, examine the final state registers and send them to the server.

The output looks like this:

```
[+] Opening connection to catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me on port 9999: Done
[+] Getting register states.
[+] Received binary data of size 75:
[+] Building GDB script ...
[+] Executing code...
[+] Parsing registers...
[+] Uploading final state registers...
[>>] rax=0xc4dd04450d8a82e2
[>>] rbx=0xecec03e91686ddeb
[>>] rcx=0xbc71ad0689c1b33d
[>>] rdx=0xc53b9356b687985d
[>>] rsi=0x4997cd7d0cbedd1d
[>>] rdi=0x1bcddcc53dbff749
[>>] r8=0xc4dd04450d8a82e2
[>>] r9=0xc4af29843ee93987
[>>] r10=0x5eb67a469067a63d
[>>] r11=0x554004b2b7283702
[>>] r12=0x677751cce192919e
[>>] r13=0x711711cc7f408fec
[>>] r14=0xe550fc117a587e8f
[>>] r15=0x2748e3d257567b22
[+] Recieving all data: Done (66B)
[*] Closed connection to catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me port 9999
[+] Result: The flag is: Cats with frickin lazer beamz on top of their heads!
```

And here's the code!

```
#!/usr/bin/python

from pwn import *
import subprocess
import re
import os

HOST='catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me'
PORT=9999

conn = remote(HOST,PORT)

print "[+] Getting register states."
regstates = conn.recvuntil("****Send")

# Store the states in a list
initials = []
for register in regstates.splitlines():
 if '****' in register:
  continue
 else:
  initials.append(register.split("=")[])
  initials.append(register.split("=")[1])
   
conn.recvline()
size = int(conn.recvline().split(" ")[3],10)
data = conn.recvn(size)
print "[+] Received binary data of size " + str(size)
with open('data.bin','wb') as f:
 f.write(data) 

print "[+] Building GDB script ..."
with open('gdbscript.txt','wb') as f:
 f.write("pset option ansicolor offnbr mainnrn")
 a = 
 while a < len(initials):
  f.write("set $" + initials[a] + "=" + initials[a+1]+"n")
  a += 2
 
 f.write("info regnrestore data.bin binary $pcncninfo regnquitn")

print "[+] Executing code..."
with open(os.devnull) as DEVNULL:
 gdbout = subprocess.check_output(['gdb','-x','gdbscript.txt','./hw'], stderr=DEVNULL)
print "[+] Parsing registers..."

foundsegv = 
finals = []
for line in gdbout.splitlines():
 if 'Stopped reason: SIGSEGV' in line: # the ret instruction causes segv
  foundsegv = 1
 
 i = 
 while i < len(initials):
  if initials[i] in line and foundsegv > :
   finalval = re.split('s+',line)[1]
   finals.append(initials[i])
   finals.append(finalval)
  i+=2

print "[+] Uploading final state registers..."
i = 
while i < len(finals):
 payload = finals[i] + "=" + finals[i+1]
 print "[>>] " + payload
 conn.sendline(payload)
 i += 2
 
result = conn.recvall()
print "[+] Result: " + result
conn.close()
```