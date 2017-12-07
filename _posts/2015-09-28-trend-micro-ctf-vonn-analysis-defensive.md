---
id: 226
title: 'Trend Micro CTF - vonn - Analysis-Defensive (100) Challenge'
date: 2015-09-28T04:58:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=226
permalink: /trend-micro-ctf-vonn-analysis-defensive/
post_views_count:
  - "667"
image: /images/2015/09/jzpatch-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
Trend Micro CTF was this weekend. This is the first one of these Trend Micro CTF I've done and I was expecting it to be really well run and fun.

I was pretty surprised to see the real situation though. I felt the difficulty scaling was all over the place and just too many guessing games. Also a lack of communication with no official IRC channel and only a couple of tweets from Trend throughout the day.

Anyway, I still am determined to document at least one solution per CTF so here's the one I decided because I liked the idea.

This is in the Analysis-Defensive category, which is essentialy the same as any other CTF's Reverse Engineering category. We are given a ZIP file containing a single file called "vonn":

```
root@mankrik:~/trend/analysisdef/vonn# file vonn
vonn: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xbbc2897f089dcc360a98a482764ad499e209fb74, not stripped
```

Which is a 64 bit ELF binary that is not stripped. Neat.

When we execute it we just get the string

```
root@mankrik:~/trend/analysisdef/vonn# ./vonn
You are on VMM!
```

(Oh the program deletes itself also, just a tip, make a backup of it first)

Which doesn't say a lot but is a good clue. Trend Micro being a company related to AV has probably dealt with VM aware threats quite a lot. So perhaps this program uses a trick to determine if it's on a VM and behaves a certain way because of it.

Let's look in IDA Pro:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v8; // ST58_8@1
  unsigned __int64 v9; // ST68_8@1
  unsigned __int64 v10; // ST78_8@1
  int result; // eax@4
  unsigned __int64 v12; // [sp+B8h] [bp-18h]@1
  unsigned __int64 v13; // [sp+C0h] [bp-10h]@1
  unsigned __int64 v14; // [sp+C8h] [bp-8h]@1

  __asm { cpuid }
  v8 = __rdtsc();
  v9 = __rdtsc();
  v10 = __rdtsc();
  v12 = (v9 | (_RDX << 32)) - (v8 | (_RDX << 32));
  v13 = (v10 | (_RDX << 32)) - (v9 | (_RDX << 32));
  v14 = (__rdtsc() | (_RDX << 32)) - (v10 | (_RDX << 32));
  if ( v12 == v13 || v13 == v14 || v12 == v14 )
  {
    result = puts("You are not on VMM");
  }
  else
  {
    puts("You are on VMM!");
    result = ldex(*argv);
  }
  return result;
}
```

Yep sure enough, if you are not on a VM then just print a message, but if you ARE on a VM then run the ldex() function passing a pointer to argv, the command line arguments.

The ldex() function seems to be where all the magic happens:

```
__int64 __fastcall ldex(const char *a1)
{
  void *buf; // ST20_8@2
  int v2; // eax@2
  void *v3; // ST28_8@2
  int fd; // [sp+14h] [bp-ECh]@1
  int v6; // [sp+18h] [bp-E8h]@1
  struct stat stat_buf; // [sp+30h] [bp-D0h]@1
  __int64 v8; // [sp+C0h] [bp-40h]@1
  __int64 v9; // [sp+C8h] [bp-38h]@1
  char v10; // [sp+D0h] [bp-30h]@1
  __int64 v11; // [sp+E0h] [bp-20h]@1
  __int64 v12; // [sp+E8h] [bp-18h]@1
  char v13; // [sp+F0h] [bp-10h]@1
  __int64 v14; // [sp+F8h] [bp-8h]@1

  v14 = *MK_FP(__FS__, 40LL);
  v8 = '.../pmt/';
  v9 = ',,...,,,';
  v10 = ;
  v11 = '.../pmt/';
  v12 = ',,...,,,';
  v13 = ;
  fd = open(a1, );
  v6 = open("/tmp/...,,,...,,", 66);
  fstat(fd, &stat_buf);
  if ( stat_buf.st_size <= 20480 )
  {
    unlink("/tmp/...,,,...,,");
    exit(-1);
  }
  buf = malloc(stat_buf.st_size + 20480);
  v2 = read(fd, buf, stat_buf.st_size);
  v3 = malloc(stat_buf.st_size + 20480);
  Decrypt(&v8, (char *)buf + 20480, stat_buf.st_size - 20480, &v11, v3, stat_buf.st_size - 20480);
  if ( (signed int)write(v6, v3, stat_buf.st_size - 20480) <  )
    exit(-1);
  fchmod(v6, 0x1C0u);
  close(v6);
  unlink(a1);
  execv("/tmp/...,,,...,,", 0LL);
  return *MK_FP(__FS__, 40LL) ^ v14;
}
```

All this is doing is opening a new file in the /tmp/ path called "...,,,...,,", decrypting a payload into that file, executing it, then cleaning up by deleting itself.

First thing we need to do is grab the payload. Since there's no file in /tmp/ after we execute this from the command line, I assume that the payload is also deleting itself.

Instead, we run "vonn" inside a debugger and set a breakpoint on the execv() call...

```
root@mankrik:~/trend/analysisdef/vonn# gdb ./vonn
GNU gdb (GDB) 7.4.1-debian

...

gdb-peda$ br execv
Breakpoint 1 at 0x400950
gdb-peda$ r
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
You are on VMM!
Legend: code, data, rodata, value
Breakpoint 1, execv (path=0x401123 "/tmp/...,,,...,,", argv=0x0) at execv.c:26
26 execv.c: No such file or directory.
gdb-peda$ ^Z
[1]+  Stopped                 gdb ./vonn
root@mankrik:~/trend/analysisdef/vonn# ls -la /tmp/...,,,...,, 
-rwx------ 1 root root 13312 Sep 28 12:24 /tmp/...,,,...,,
root@mankrik:~/trend/analysisdef/vonn# file /tmp/...,,,...,, 
/tmp/...,,,...,,: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xc6faaf0c45fa077ef6a28d0fe87925ed46ea43de, not stripped
```

Great. I make a copy of the payload and let's analyse this in IDA Pro:

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v8; // ST58_8@1
  unsigned __int64 v9; // ST68_8@1
  unsigned __int64 v10; // ST78_8@1
  unsigned __int64 v11; // rdx@1
  int result; // eax@4
  unsigned __int64 v13; // [sp+B8h] [bp-18h]@1
  unsigned __int64 v14; // [sp+C0h] [bp-10h]@1

  __asm { cpuid }
  v8 = __rdtsc();
  v9 = __rdtsc();
  v10 = __rdtsc();
  v13 = (v9 | (_RDX << 32)) - (v8 | (_RDX << 32));
  v14 = (v10 | (_RDX << 32)) - (v9 | (_RDX << 32));
  v11 = (__rdtsc() | (_RDX << 32)) - (v10 | (_RDX << 32));
  if ( v13 == v14 || v14 == v11 || v13 == v11 )
  {
    rnktmp(4197584LL, argv, v11, _RCX);
    result = unlink("/tmp/...,,,...,,");
  }
  else
  {
    result = unlink("/tmp/...,,,...,,");
  }
  return result;
}

```

Ok this is looking familiar no? This is the same main function as the dropper ("vonn") except there are no printf() messages and the non-VM function looks to be doing the work this time.

So the solution becomes clear at this point. The challenge is a two part binary. A dropper and an encrypted payload. When run on a VM the dropper will decrypt the payload, however the payload will only perform it's duties on a non-VM system.

To get the flag we only need to run the payload on a bare metal system.

Unfortunately I don't have that ready to hand, so I resort to patching the payload. In the graph view I identify an easy "JZ" instruction I can flip to a "JMP" instruction to take our desired execution path:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-E6ov_8I2rHQ/VginTgarhSI/AAAAAAAAANo/N_pbxWAWo0c/s1600/jzpatch.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="322" src="/images/2015/09/jzpatch-2.png" width="640" /></a>
</div>

This JZ lives at address 0x400a33 in memory so let's use pwntools to patch that to a JMP and execute the patched version:

```
from pwn import *
import os
binary = ELF('/tmp/...,,,...,,')
binary.write(0x400a33, 'xeb')
binary.save('/tmp/...,,,...,,.patched')
os.chmod('/tmp/...,,,...,,.patched',755)
p = process('/tmp/...,,,...,,.patched')
flag = p.recvuntil('}')
print "[+] Flag: " + flag

```

Which we combine with GDB to get us the flag like so:

```
root@mankrik:~/trend/analysisdef/vonn# gdb ./vonn
GNU gdb (GDB) 7.4.1-debian
...
Reading symbols from /root/trend/analysisdef/vonn/vonn...(no debugging symbols found)...done.
gdb-peda$ br execv
Breakpoint 1 at 0x400950
gdb-peda$ r
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
You are on VMM!

Breakpoint 1, execv (path=0x401123 "/tmp/...,,,...,,", argv=0x0) at execv.c:26
26 execv.c: No such file or directory.
gdb-peda$ ^Z
[1]+  Stopped                 gdb ./vonn
root@mankrik:~/trend/analysisdef/vonn# python vonnpatch.py 
[+] Starting program '/tmp/...,,,...,,.patched': Done
[*] Program '/tmp/...,,,...,,.patched' stopped with exit code 255
[+] Flag: TMCTF{ce5d8bb4d5efe86d25098bec300d6954}
```

Not too bad. A good 100 point challenge IMHO.