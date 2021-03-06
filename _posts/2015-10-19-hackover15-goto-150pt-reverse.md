---
id: 223
title: 'Hackover15 - goto - 150pt Reverse Engineering Challenge'
date: 2015-10-19T11:20:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=223
permalink: /hackover15-goto-150pt-reverse/
post_views_count:
  - "511"
image: /images/2015/10/goto-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
I didn't get time to play Hackover 15 as much as I wanted. It looked like a really fun competition but unfortunately it overlapped with Hitcon 2015. However I woke up super early (6am Saturday - eek!) to get a few hours in on Hackover before Hitcon started.

Here's an RE challenge I did very quickly and I just want to show how sometimes the environment you work in gives you a leg up. In this case PEDA (the GDB add-on) gave me the flag faster than I could reverse the binary.

The clue was:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-NqqG3jxhPCM/ViTMpBinU7I/AAAAAAAAAPY/VabMObOp63s/s1600/goto.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="94" src="/images/2015/10/goto-2.png" width="640" /></a>
</div>

The file, a compressed tarball, contains just one file: "goto.bin" which identifies as "data" with file...

<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">root@mankrik:~/hackover/re150/writeup# tar -zxvf goto-03661d1a42ad20065ef6bfbe5a06287c.tgz 
goto.bin
root@mankrik:~/hackover/re150/writeup# file goto.bin 
goto.bin: data

```

</div>

Small headscratch here. I look at the file in XXD and see there's some shell script header here:

<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">root@mankrik:~/hackover/re150/writeup# xxd goto.bin | head -5
0000000: 543d 743b 6361 7420 2430 207c 2074 6169  T=t;cat $0 | tai
0000010: 6c20 2d63 202b 3735 207c 2067 756e 7a69  l -c +75 | gunzi
0000020: 7020 2d20 3e20 2454 3b63 686d 6f64 202b  p - > $T;chmod +
0000030: 7820 2454 3b2e 2f24 543b 726d 202e 2f24  x $T;./$T;rm ./$
0000040: 543b 6578 6974 2030 3b0a 1f8b 0808 efae  T;exit 0;.......
root@mankrik:~/hackover/re150/writeup# head -1 goto.bin
T=t;cat $0 | tail -c +75 | gunzip - > $T;chmod +x $T;./$T;rm ./$T;exit 0;

```

</div>

Fine... Great... Mild obfuscation I am ok with <img src="https://ctf.rip/images/classic-smilies/icon_smile.gif" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />

I decide just to let it decode itself...

<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">root@mankrik:~/hackover/re150/writeup# sh goto.bin
PASSWORD:^C
root@mankrik:~/hackover/re150/writeup# ls -la t
-rwxr-xr-x 1 root root 4882 Oct 19 22:01 t
root@mankrik:~/hackover/re150/writeup# file t
t: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), for GNU/Linux 2.6.24, dynamically linked (uses shared libs), stripped

```

</div>

We now have the meat of the challenge, the ELF binary. Executing it, as we saw, simply asks for a PASSWORD:. I assume the flag is the password. Either way off to IDA Pro we go....

I decide to dynamically examine comparison points before diving in to perform a full static analysis. Often times simpler RE challenges can be solved rapidly with dynamic analysis, skipping a lot of time on the static analysis. I decide to set breakpoints at obvious loops.

The second such loop I examine is this one, I set a breakpoint at 0x4006aa (the cmp instruction):

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/10/goto1-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/10/goto1-2.png" /></a>
</div>

I fire up GDB w/PEDA and watch the program execution:

<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">root@mankrik:~/hackover/re150# gdb ./t 
GNU gdb (GDB) 7.4.1-debian
gdb-peda$ br *0x4006aa
Breakpoint 1 at 0x4006aa
gdb-peda$ r
warning: no loadable sections found in added symbol-file system-supplied DSO at 0x7ffff7ffa000
PASSWORD:a
[----------------------------------registers-----------------------------------]
RAX: 0x601071 ("aMTCvd@CacAOEe #EgkPTSrd#S_oAOS e#SmvSO gs# eeSODoe#GtrWOEnr$Re1OONnt%Ao5ROIa ^Nr{DaE y&TCI 20sDgo#ET_ 20l 20iu$DFU 20d 20v!% 20_S 20j 20e 20^ 20{E 20k 20  20& 20t_ 20a 20y 20( 20hG 20s 20o 20^ 20iO 20d 20u 20& 20sT 20j 20  20* 20iO 20k 20u 20^ 20s_ 20l 20p 20& 20aW 20a 20, 20* 20dH 20"...)
RBX: 0x7fffffffe228 --> 0x7fffff000061 
RCX: 0xfbad2268 
RDX: 0x602010 --> 0x0 
RSI: 0x7ffff7ff4002 --> 0x0 
RDI: 0x7fffffffe22a --> 0xe26f00007fffff00 
RBP: 0x602010 --> 0x0 
RSP: 0x7fffffffe220 --> 0xc2 
RIP: 0x4006aa (cmp    cl,0x10)
R8 : 0x7ffff7dd8df0 --> 0x0 
R9 : 0x7ffff7fcf700 (0x00007ffff7fcf700)
R10: 0x22 ('"')
R11: 0x246 
R12: 0x40077f (xor    ebp,ebp)
R13: 0x7fffffffe360 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40069e: mov    eax,0x601068
   0x4006a3: add    rax,0x9
   0x4006a7: mov    cl,BYTE PTR [rax-0x9]
=> 0x4006aa: cmp    cl,0x10
   0x4006ad: je     0x4006b6
   0x4006af: mov    BYTE PTR [rdx],cl
   0x4006b1: inc    rdx
   0x4006b4: jmp    0x4006a3
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe220 --> 0xc2 
0008| 0x7fffffffe228 --> 0x7fffff000061 
0016| 0x7fffffffe230 --> 0x7fffffffe26f --> 0x7fffffffe36036 
0024| 0x7fffffffe238 --> 0x1 
0032| 0x7fffffffe240 --> 0x1 
0040| 0x7fffffffe248 --> 0x4008dd (add    rbx,0x1)
0048| 0x7fffffffe250 --> 0x7ffff7a61c48 --> 0xc001200002732 
0056| 0x7fffffffe258 --> 0x400890 (push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004006aa in ?? ()
gdb-peda$ 

```

</div>

Ok nothing so far, let's watch this loop for a while. I hit "c" for continue and watch the screen idly while the loop iterates. It's about at this point I stop because I notice a string being built in memory...

<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">gdb-peda$ 

[----------------------------------registers-----------------------------------]
RAX: 0x6010ef --> 0x10261020106b1045 
RBX: 0x7fffffffe228 --> 0x7fffff000061 
RCX: 0xfbad2253 
RDX: 0x60201e --> 0x0 
RSI: 0x7ffff7ff4002 --> 0x0 
RDI: 0x7fffffffe22a --> 0xe26f00007fffff00 
<span style="background-color: yellow;">RBP: 0x602010 ("hackover15{I_U")</span>
RSP: 0x7fffffffe220 --> 0xc2 
RIP: 0x4006aa (cmp    cl,0x10)
R8 : 0x7ffff7dd8df0 --> 0x0 
R9 : 0x7ffff7fcf700 (0x00007ffff7fcf700)
R10: 0x22 ('"')
R11: 0x246 
R12: 0x40077f (xor    ebp,ebp)
R13: 0x7fffffffe360 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40069e: mov    eax,0x601068
   0x4006a3: add    rax,0x9
   0x4006a7: mov    cl,BYTE PTR [rax-0x9]
=> 0x4006aa: cmp    cl,0x10
   0x4006ad: je     0x4006b6
   0x4006af: mov    BYTE PTR [rdx],cl
   0x4006b1: inc    rdx
   0x4006b4: jmp    0x4006a3
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe220 --> 0xc2 
0008| 0x7fffffffe228 --> 0x7fffff000061 
0016| 0x7fffffffe230 --> 0x7fffffffe26f --> 0x7fffffffe36036 
0024| 0x7fffffffe238 --> 0x1 
0032| 0x7fffffffe240 --> 0x1 
0040| 0x7fffffffe248 --> 0x4008dd (add    rbx,0x1)
0048| 0x7fffffffe250 --> 0x7ffff7a61c48 --> 0xc001200002732 
0056| 0x7fffffffe258 --> 0x400890 (push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00000000004006aa in ?? ()
gdb-peda$ 

```

</div>

I decide to let this run to it's foregone conclusion.... Eventually the string decoding completes and RBP points to the entire flag:
  
<!-- HTML generated using hilite.me -->

<div style="background: #272822; border-width: .1em .1em .1em .8em; border: solid gray; overflow: auto; padding: .2em .6em; width: auto;">
  <pre style="line-height: 125%; margin: 0;">RBP: 0x602010 ("hackover15{I_USE_GOTO_WHEREEVER_I_W4NT}")

```

</div>

I'm happy with that, I take the quick win and move on. I never did analyse the binary I but I don't mind...