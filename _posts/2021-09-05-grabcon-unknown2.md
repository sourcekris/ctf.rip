---
title: 'GrabCON 2021: Unknown 2'
date: 2021-09-05T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/grabcon/unknown2title.jpg
categories:
  - Write-Ups
  - Reversing
---
Fun CTF with quite a lot of variety in the challenges. I spent a bit of time on the binary reversing and pwning challenges this time because they seemed quite solvable for my basic skills. This is the 2nd in the "unknown" series.

#### <a name="unknown2"></a>Unknown 2 - Reversing - 150 points

This challenge reads:

```
I don't know.

Author: 0xSN1PE

(27 solves)
```

With the challenge we get this file:

* `med_re_2 (sha1:3e0133b0db63a3bfee7d5d551ebff6957230b51d)`

As I'd do with any challenge a quick examination of the file reveals a packed Linux ELF binary:

```shell
$ file med_re_2 
med_re_2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), statically
linked, no section header
$ strings med_re_2 | grep UPX
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $

```

Fortunately the file unpacks cleanly with `upx -d`

```shell
$ ls -la med_re_2 
-rwxrw-rw- 1 root root 19952 Sep  5 15:49 med_re_2     

$ upx -d med_re_2                                                                                                                         
                       Ultimate Packer for eXecutables                                                       
                          Copyright (C) 1996 - 2020                                                           
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020                                 

        File size         Ratio      Format      Name                                                         
   --------------------   ------   -----------   -----------                                                 
     53088 <-     19952   37.58%   linux/amd64   med_re_2                                                    
     
Unpacked 1 file.                                                                                             
$ ls -la med_re_2                                                                                           
-rwxrw-rw- 1 root root 53088 Sep  5 15:49 med_re_2
$ file med_re_2
med_re_2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically 
linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=8c647d87ce01879a967ee42dc5d9d4111a6b1b19, for GNU/Linux 3.2.0, 
with debug_info, not stripped
```

Running the file gives us very little new information, it doesn't ask for a key or anything:

```shell
$ ./med_re_2

___.          .__                              
\_ |__ _____  |  | _____    ____   ____  ____  
 | __ \\__  \ |  | \__  \  /    \_/ ___\/ __ \ 
 | \_\ \/ __ \|  |__/ __ \|   |  \  \__\  ___/ 
 |___  (____  /____(____  /___|  /\___  >___  >
     \/     \/          \/     \/     \/    \/ 


Comparison is the death of joy.
```

In `ghidra` we learn a lot more, firstly it's a Golang binary which means we need to start in the `main.main` function. Here we see after some searching that the flag related stuff happens in a function called `main.one` which is gated by some comparison:

![main.main function](/images/2021/grabcon/unknown21.PNG)

I don't really know what the comparison is and instead of messing about checking it, I figured I might try and patch it out instead. 

To do this I changed the instruction at `0x00103f96` from a `JNZ` (opcode `75`) to a `JMP` (opcode `74`) with a hex editor. I saved the patched binary and ran it again, the behaviour changes:

![patching binary](/images/2021/grabcon/unknown22.PNG)

```shell
$ ./patch1                                                                       

___.          .__                              
\_ |__ _____  |  | _____    ____   ____  ____  
 | __ \\__  \ |  | \__  \  /    \_/ ___\/ __ \ 
 | \_\ \/ __ \|  |__/ __ \|   |  \  \__\  ___/ 
 |___  (____  /____(____  /___|  /\___  >___  >
     \/     \/          \/     \/     \/    \/ 

Enter the password: 
Go back
```

Now it wants a password. I don't know what the password it expects is but after some looking around in the `main.one` function I come across another comparison:

![another comparison](/images/2021/grabcon/unknown23.PNG)

After some trial and error in `gdb` I confirm that the code is summing the ascii values of the characters of the password. If the sum total of the characters is equal to 0x195 then this check succeeds. Notice below how I first saw this. When I sent the password `A` then the comparison was  `0x195 == 0x41?`

```shell
$ gdb ./patch1                                                                   
...
Reading symbols from ./patch1...
gdb-peda$ br *0x555555557a8b
Breakpoint 1 at 0x555555557a8b
gdb-peda$ r
Starting program: /root/grabcon/unknown2/patch1 

___.          .__                              
\_ |__ _____  |  | _____    ____   ____  ____  
 | __ \\__  \ |  | \__  \  /    \_/ ___\/ __ \ 
 | \_\ \/ __ \|  |__/ __ \|   |  \  \__\  ___/ 
 |___  (____  /____(____  /___|  /\___  >___  >
     \/     \/          \/     \/     \/    \/ 


Enter the password: 
A
...
[-------------------------------------code-------------------------------------]
   0x555555557a7d <main.one+1140>:      mov    rax,QWORD PTR [rax+0x8]
   0x555555557a81 <main.one+1144>:      cmp    QWORD PTR [rbp-0x48],rax
   0x555555557a85 <main.one+1148>:      jl     0x5555555579a6 <main.one+925>
=> 0x555555557a8b <main.one+1154>:      cmp    QWORD PTR [rbp-0x38],0x195
...

Thread 1 "patch1" hit Breakpoint 1, main.one () at med_re_2.go:30
30      med_re_2.go: No such file or directory.

gdb-peda$ x/1wx $rbp-0x38
0x7fffcf7aad58: 0x00000041
gdb-peda$
```

To get an ASCII string with values of 0x195 (405 decimal) I just send char 50 (ascii `2`) x 7 and char 55 (ascii `7`) x 1: 

- `22222227 = 0x195`

I ran the patched program and entered that password, not sure what to expect:

```shell
$ ./patch1                                                                                                                                                                               
___.          .__
\_ |__ _____  |  | _____    ____   ____  ____  
 | __ \\__  \ |  | \__  \  /    \_/ ___\/ __ \ 
 | \_\ \/ __ \|  |__/ __ \|   |  \  \__\  ___/ 
 |___  (____  /____(____  /___|  /\___  >___  >
     \/     \/          \/     \/     \/    \/ 

Enter the password: 
22222227 
Here ya go -> GrabCON{ 626c61636b647261676f6e }
```

However I got the flag straight away. I wasn't expecting it, but it was done. 

Probably my first Golang RE challenge in a CTF and I didn't mind it that much.

