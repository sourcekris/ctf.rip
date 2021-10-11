---
title: 'DigitalOverdose: Time'
date: 2021-10-11T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/digitaloverdose/timetitle.png
categories:
  - Write-Ups
  - Reversing
---
Great CTF with a lot of variety of challenges plus great infrastructure stability. Nice job team. This challenge I solved using a backup idea I had when my original solution wasn't working. Details below.

#### <a name="time"></a>Time - Reverse Engineering - 125 points

This challenge reads:

```
Perseverance Arrives at Mars!
You are now the master of time!

23 solves
```

With this challenge comes a file called `time` which is a Linux ELF binary:

```shell
$ file time
time: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3376dc1a92787bdc410ff6d2b627d1483812e448, 
for GNU/Linux 3.2.0, not stripped
```

A quick check with `strings` shows no low hanging fruit so further investigation is required. I fire up Ghidra and check out the `main()` function in the decompiler:

```c
int main(void)

{
  int flagmatch;
  undefined aes_ctx [192];
  char *ciphertext;
  undefined8 key;
  undefined8 keytime;

  time_t timet;
  int i;
  
  keytime = 0;
  uStack48 = 0;
  uStack40 = 0;
  key = 0;
  uStack64 = 0;
  ciphertext = (char *)0x11283c52c7f437a8;
  uStack96 = 0xda92120d98ec7669;
  uStack88 = 0x7bd2fafa02bc48c8;
  uStack80 = 0x8fb0cf6982db479c;
  timet = time((time_t *)0x0);
  snprintf((char *)&keytime,0x11,"%li",timet);
  key = keytime;
  uStack64 = uStack48;
  AES_init_ctx_iv(aes_ctx,&key,iv);
  AES_CBC_decrypt_buffer(aes_ctx,&ciphertext,0x20);
  flagmatch = strncmp("DO{",(char *)&ciphertext,3);
  if (flagmatch == 0) {
    printf("Flag: ");
    for (i = 0; i < 0x1b; i = i + 1) {
      putchar((int)*(char *)((long)&ciphertext + (long)i));
    }
    putchar(L'\n');
  }
  else {
    puts("Decryption failed!");
  }
  return 0;
}
```

So this is nice and easy, it's doing the following:

- Getting the current time and using the string representation as a key.
- Using a constant initialization vector (IV) and that a key made of the string representation of the time, decrypting a constant ciphertext.
- If the Ciphertext begins with `DO{` then the decryption succeeded and the flag is printed.

Then all we need to decrypt this is the components in the binary and to implement the algorithm in Python or something and count backwards until the payload decrypts?

Well that seems logical but after exhausting a large amount of the possible keyspace with a Python script it wasn't working. 

So out comes my **backup solution**. 

First I wrote a quick shared object to replace the `libc` `time()` function. I need a way for it to take input from the environment though because I didn't want to fiddle with my actual clock or anything. So I wrote this stub:

```c
#include<time.h>
#include<stdlib.h>

time_t time(time_t *__timer) {
    return atoi(getenv("TIMETHING"));
}
```

It just gets a string from `TIMETHING` in the local environment and returns that as an integer to the callee.

Next I wrote a quick C program to test it actually works:

```c
#include<stdio.h>
#include<stdlib.h>  
#include<time.h>  

int main(void) { 
  time_t ttime = time(0);   
  printf("%li",ttime);
}
```

Then I run a quick test to check this is doing what I want:

```shell
$ gcc tt.c -shared -o tt.so
$ gcc test.c -o test
$ ./test
1633947242
$ export TIMETHING=13371337
$ LD_PRELOAD=./tt.so ./test
13371337
```

Great. We can, by `LD_PRELOAD` force `time()` to be whatever we want. All we need to do now is run time backwards (by decrementing `TIMETHING`) until we get the flag.

To speed things up I re-read the clue `Perseverance Arrives at Mars!`. That was pretty useful because Perseverance landed on Mars in February 2021. So that seems like a good place to start. I wrote the following Python to wrap this all up:

```python
import subprocess
import os

os.environ["LD_PRELOAD"] = "./tt.so"

twodays = 86400*2
perseverance = 1613606400  # 2021-02-18

for t in range(perseverance+twodays, 0, -1):
    os.environ["TIMETHING"] = str(t)
    out = subprocess.check_output("./time", env=os.environ)
    if b'Decryption failed' not in out:
        print("flag: %s" % out)

```

After about 5 minutes runtime (subprocess calls are slower than doing the attack directly against AES) we got:

```shell
$ ./solve.py 
flag: b'Flag: DO{V3ry_n1Ce_t1MInG5_!1}\x08\x08\x08\n'
```

I'm still not sure why my Python code did not solve it. I probably got the endianness of one of the components wrong or something but this backup method solved it while I was trying to get that working so that was nice to not need to debug the python anymore.

