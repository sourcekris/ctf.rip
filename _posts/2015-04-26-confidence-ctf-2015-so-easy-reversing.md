---
id: 234
title: 'CONFidence CTF 2015 - So Easy - Reversing 100 Point Challenge'
date: 2015-04-26T08:40:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=234
permalink: /confidence-ctf-2015-so-easy-reversing/
post_views_count:
  - "523"
image: /images/2015/04/soeasy-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/soeasy-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/soeasy-2.png" height="77" width="400" /></a>
</div>


Did not have a lot of time this weekend for Dragon Sector's CONFidence CTF but I did quickly do this reversing challenge. It was the most solved challenge so low hanging fruit and all that. The challenge consisted of a single file download:

```
root@mankrik:~/dragon/easy# file re_100_final    
re_100_final: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x39f589e2bae8d0f011cbf456b7e1bda97f9aa87d, stripped
```

When we strings the binary we see a flag-like string "dRGNs{tHISwASsOsIMPLE}" which isn't the flag but is a key we need so we pocket that for later.

```
root@mankrik:~/dragon/easy# strings re_100_final   
/lib/ld-linux.so.2  
...  
Please enter secret flag:  
%31s  
Nope.  
Excellent Work!  
Result: %s  
;*2$"  
dRGNs{tHISwASsOsIMPLE}  
```

No other command line static analysis tools gave me much to look at early on so I won't bore you with more output from those.

I ran the tool first, it asks for a secret key, so I tried what we had just found earlier:

```
root@mankrik:~/dragon/easy# ./re_100_final   
Please enter secret flag:  
dRGNs{tHISwASsOsIMPLE}  
Nope!  
```

Oh ok. Nope. Let's try ltrace the execution to see what library calls it makes:

```
root@mankrik:~/dragon/easy# echo dRGNs{tHISwASsOsIMPLE} | ltrace ./re_100_final   
 __libc_start_main(0x8048a25, 1, 0xffc3b944, 0x8048b10, 0x8048b80 <unfinished ...>  
 printf("%s", "")                                           =   
 calloc(32, 4)                                             = 0x085ed008  
 __cxa_atexit(0x804873c, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048729, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048716, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048703, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486f0, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486dd, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486cd, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486ba, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804860f, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485fc, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048635, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048681, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485c3, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048648, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804866e, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048694, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486a7, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485e9, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485b0, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804865b, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804859d, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048622, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485d6, , , 0x804b000, 2)                              =   
 puts("Please enter secret flag:"Please enter secret flag:  
 )                                   = 26  
 scanf(0x8048c06, 0x804b080, 0xffc3b94c, 0xffc3b898, 0xf7637515)                    = 1  
 strcmp("dRGNs{tHISwASsOsIMPLE}", "DrgnS{ThisWasSoSimple}")                      = 1  
 printf("Result: %sn", "Nope.n" <unfinished ...>  
 strlen("Result: %sn")                                        = 11  
 <... printf resumed> )                                        = 11  
 putchar(78, 0x8048290, 0x804b024, , 0x60f0b4)                            = 78  
 putchar(111, 0x8048290, 0x804b024, , 0x60f0b4)                            = 111  
 putchar(112, 0x8048290, 0x804b024, , 0x60f0b4)                            = 112  
 putchar(101, 0x8048290, 0x804b024, , 0x60f0b4)                            = 101  
 putchar(33, 0x8048290, 0x804b024, , 0x60f0b4)                            = 33  
 putchar(10, 0x8048290, 0x804b024, , 0x60f0b4Nope!  
 )                            = 10  
 +++ exited (status ) +++ 
 ```

Ok so it seems our string has been flipped in case so the <b>strcmp </b>fails. Let's try the flipped case version as the input:


```
root@mankrik:~/dragon/easy# echo DrgnS{ThisWasSoSimple} | ltrace ./re_100_final   
 __libc_start_main(0x8048a25, 1, 0xff9bce44, 0x8048b10, 0x8048b80 <unfinished ...>  
 printf("%s", "")                                           =   
 calloc(32, 4)                                             = 0x09725008  
 __cxa_atexit(0x804873c, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048729, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048716, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048703, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486f0, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486dd, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486cd, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486ba, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804860f, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485fc, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048635, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048681, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485c3, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048648, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804866e, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048694, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80486a7, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485e9, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485b0, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804865b, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x804859d, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x8048622, , , 0x804b000, 2)                              =   
 __cxa_atexit(0x80485d6, , , 0x804b000, 2)                              =   
 puts("Please enter secret flag:"Please enter secret flag:  
 )                                   = 26  
 scanf(0x8048c06, 0x804b080, 0xff9bce4c, 0xff9bcd98, 0xf765b515)                    = 1  
 strcmp("dRGNs{tHISwASsOsIMPLE}", "dRGNs{tHISwASsOsIMPLE}")                      =   
 printf("Result: %sn", "Excellent Work!n" <unfinished ...>  
 strlen("Result: %sn")                                        = 11  
 <... printf resumed> )                                        = 11  
 putchar(78, 0x8048290, 0x804b024, , 0x6330b4)                            = 78  
 putchar(111, 0x8048290, 0x804b024, , 0x6330b4)                            = 111  
 putchar(112, 0x8048290, 0x804b024, , 0x6330b4)                            = 112  
 putchar(101, 0x8048290, 0x804b024, , 0x6330b4)                            = 101  
 putchar(33, 0x8048290, 0x804b024, , 0x6330b4)                            = 33  
 putchar(10, 0x8048290, 0x804b024, , 0x6330b4Nope!  
 )                            = 10  
 +++ exited (status ) +++ 
 ```

Ok that's confusing! The strcmp succeeds but we still get "Nope!" on the terminal even though there's a printf call with "Excellent Work!".

I don't think we're doing it right. The clue for the next part is about how the program is writing to stdout. Ignore the printf call for a second and look at all the putchar() calls. Those are what's writing the "Nope!" to the terminal.

Let's go back to static analysis, this time with IDA. Here's the psuedocode for the function we've been thinking we're looking at. It's too simple and not helpful.

```
int sub_8048A25()  
 {  
  int i; // [sp+14h] [bp-Ch]@2  
  int v2; // [sp+18h] [bp-8h]@11  
  puts("Please enter secret flag:");  
  if ( scanf("%31s", user_input) == 1 )  
  {  
   for ( i = (int)user_input; *(_BYTE *)i; ++i )  
   {  
    if ( *(_BYTE *)i <= 96 || *(_BYTE *)i > 122 )  
    {  
     if ( *(_BYTE *)i > 64 && *(_BYTE *)i <= 90 )  
      *(_BYTE *)i += 32;  
    }  
    else  
    {  
     *(_BYTE *)i -= 32;  
    }  
   }  
   v2 = (int)"Nope.n";  
   if ( !strcmp(fake_flag, user_input) )  
    v2 = (int)"Excellent Work!n";  
   printf("Result: %sn", v2);  
  }  
  return ;  
 }  
 ```

Let's use the clue we found earlier and check into putchar usage.


<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/putchar-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/putchar-2.png" height="320" width="284" /></a>
</div>

Ok then, putchar is called only by sub_804873C, let's look at the psuedocode for this function:

```
 int sub_804873C()  
 {  
  int result; // eax@7  
  char v1; // [sp+13h] [bp-15h]@1  
  signed int i; // [sp+14h] [bp-14h]@1  
  v1 = 1;  
  for ( i = ; i <= 22; ++i )  
  {  
   if ( *(_DWORD *)(4 * i + dword_804B0A4) != byte_804B0A0[i - 32] )  
   {  
    v1 = ;  
    break;  
   }  
  }  
  if ( v1 )  
  {  
   putchar(69);  // E
   putchar(120); // x 
   putchar(99);  // c
   putchar(101); // e 
   putchar(108); // l 
   putchar(108); // l 
   putchar(101); // e 
   putchar(110); // n
   putchar(116); // t
   putchar(32);  // space
   putchar(87);  // W
   putchar(111); // o 
   putchar(114); // r 
   putchar(107); // k 
   putchar(33);  // !
   result = putchar(10); // n  
  }  
  else  
  {  
   putchar(78);  // N
   putchar(111); // o 
   putchar(112); // p 
   putchar(101); // e 
   putchar(33);  // !
   result = putchar(10);  // n
  }  
  return result;  
 }  

```

So it looks like this function is the real decision maker on if we get "Nope!" or "Excellent Work!". Is that important? Is that how this challenge works? We don't know yet but we could find out with some dynamic analysis really quickly.

Let's make note of the address of the comparison point. After some back and forth in GDB and IDA I found that the key <b>cmp </b>instruction is located here at 0x804877c:

```
.text:0804875F loc_804875F:              ; CODE XREF: sub_804873C+57 j  
 .text:0804875F         mov   eax, ds:dword_804B0A4  
 .text:08048764         mov   edx, [ebp+var_14]  
 .text:08048767         shl   edx, 2  
 .text:0804876A         add   eax, edx  
 .text:0804876C         mov   edx, [eax]  
 .text:0804876E         mov   ecx, [ebp+var_14]  
 .text:08048771         mov   eax, [ebp+var_C]  
 .text:08048774         add   eax, ecx  
 .text:08048776         movzx  eax, byte ptr [eax]  
 .text:08048779         movsx  eax, al  
 .text:0804877C         cmp   edx, eax  
 .text:0804877E         setnz  al  
 .text:08048781         test  al, al  
 .text:08048783         jz   short loc_804878B  
 .text:08048785         mov   [ebp+var_15],   
 .text:08048789         jmp   short loc_8048795  
```

Let's get into GDB (I'm using pedahere ) and watch this instruction in action. We set a breakpoint at the 0x804877c point and run the program.

For now I'm just going to keep using the only key we know so far "DrgnS{ThisWasSoSimple}":


```
root@mankrik:~/dragon/easy# gdb ./re_100_final   
 GNU gdb (GDB) 7.4.1-debian  
 Reading symbols from /root/dragon/easy/re_100_final...(no debugging symbols found)...done.  
 gdb-peda$ b *0x804877c  
 Breakpoint 1 at 0x804877c  
 gdb-peda$ r  
 Please enter secret flag:  
 DrgnS{ThisWasSoSimple}  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x64 ('d')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x0   
 EDX: 0x64 ('d')  
 ESI: 0xf7fb5ce0 --> 0x0   
 EDI: 0x0   
 EBP: 0xffffd378 --> 0xffffd3b8 --> 0xffffd3d8 --> 0xffffd458 --> 0x0   
 ESP: 0xffffd350 --> 0x1   
 EIP: 0x804877c (cmp  edx,eax)  
 EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)  
 [-------------------------------------code-------------------------------------]  
   0x8048774:     add  eax,ecx  
   0x8048776:     movzx eax,BYTE PTR [eax]  
   0x8048779:     movsx eax,al  
 => 0x804877c:     cmp  edx,eax  
   0x804877e:     setne al  
   0x8048781:     test  al,al  
   0x8048783:     je   0x804878b  
   0x8048785:     mov  BYTE PTR [ebp-0x15],0x0  
 [------------------------------------stack-------------------------------------]  
 0000| 0xffffd350 --> 0x1   
 0004| 0xffffd354 --> 0x8048290 --> 0x62696c00 ('')  
 0008| 0xffffd358 --> 0x804b024 --> 0xf7ed4190 (push  esi)  
 0012| 0xffffd35c --> 0x0   
 0016| 0xffffd360 --> 0x1e5c0b4   
 0020| 0xffffd364 --> 0x0   
 0024| 0xffffd368 --> 0x804b0a0 --> 0x0   
 0028| 0xffffd36c --> 0x804b080 ("dRGNS{tHISwASsOsIMPLE}")  
 [------------------------------------------------------------------------------]  
 Legend: code, data, rodata, value  
 Breakpoint 1, 0x0804877c in ?? ()  
```

So at our first breakpoint we can see EAX is being compared to EDX and we're in luck. For the first iteration they're equal so perhaps we'll get further. PEDA is really helpful here as it just represents both EAX, EDX and their ASCII characters without us needing to do anything.

In GDB you could do similar with "display/c $edx" "display/c $eax" but you have to do the ascii conversion manually.

Let's "c"ontinue for a few loops and see where it breaks:

```
gdb-peda$ r  
 Please enter secret flag:  
 Drgns{ThisWasSoSimple}  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x64 ('d')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x0   
 EDX: 0x64 ('d')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x52 ('R')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x1   
 EDX: 0x52 ('R')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x47 ('G')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x2   
 EDX: 0x47 ('G')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x4e ('N')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x3   
 EDX: 0x4e ('N')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x53 ('S')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x4   
 EDX: 0x73 ('s')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 Nope!  
 [Inferior 1 (process 54226) exited normally]  
 Warning: not running or target is remote  
 gdb-peda$ r  
 Please enter secret flag:  
 Drgns{ThisWasSoSimple}  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x64 ('d')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x0   
 EDX: 0x64 ('d')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 Nope!  
 [Inferior 1 (process 54227) exited normally]  
 Warning: not running or target is remote  
 gdb-peda$ r  
 Please enter secret flag:  
 DrgnS{ThisWasSoSimple}  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x64 ('d')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x0   
 EDX: 0x64 ('d')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x52 ('R')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x1   
 EDX: 0x52 ('R')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x47 ('G')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x2   
 EDX: 0x47 ('G')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x4e ('N')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x3   
 EDX: 0x4e ('N')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x73 ('s')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x4   
 EDX: 0x73 ('s')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x7b ('{')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x5   
 EDX: 0x7b ('{')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 [----------------------------------registers-----------------------------------]  
 EAX: 0x74 ('t')  
 EBX: 0xf7fb4ff4 --> 0x15fd7c   
 ECX: 0x6   
 EDX: 0x6e ('n')  
 Breakpoint 1, 0x0804877c in ?? ()  
 gdb-peda$ c  
 Nope! 
```

Phew. We got all the way through "DrgnS{" but failed on the first letter in the flag after that. We had "t" but it was expecting "n"! Well now we've got an idea of how to wrap this up real quick.

We go back and modify our flag to suit, remembering that our input case is always inverted. We begin with: "DrgnS{NhisWasSoSimple}".

Running through the debugger we learn letter by letter what the expected flag should be, making a correction each time. Soon enough we learn the flag to be:

<b><i>DrgnS{NotEvenWarmedUp}</i></b>

We submit the flag and rewarded with 100 points.