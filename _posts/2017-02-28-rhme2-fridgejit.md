---
id: 955
title: 'Riscure RHme2: FridgeJIT - Reverse Engineering Challenge'
date: 2017-02-28T09:13:12+00:00
author: admin
layout: post
guid: https://ctf.rip/?p=955
permalink: /rhme2-fridgejit/
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
  - "640"
image: /images/2017/03/map.png
categories:
  - Write-Ups
tags:
  - avr
  - re
---
First part of a long series of well thought out challenges in the RHme2 CTF. This one was the "introduction" one but it was tricky and certainly worth the 400 points I feel. Here's my approach which I believe is different to how some others solved it. First, the clue:

> A senior technical manager of a fridge manufacturer demanded the ability to update the firmware in their new product line (we need to monitor and control the temperature, right?) of all deployed devices over the air and without user interaction. This way, the manufacturer could improve the user experience by providing firmware updates, even when the fridge is 1 or 2 years old.
> 
> It turned out that the CPU that comes with the fridges does not allow self-upgrading the firmware, so the developers built a VM for the fridge software which at that time was just a few lines of code. Incidentally, half of the development and test team was fired 2 months after releasing the new product line.
> 
> A crafty customer has been able to reverse engineer the software and programmed the fridge with different software. His goal was to build a digital safe, but the guy claims not being able to make the application small enough to fit inside the VM. However, to be sure we ask you to check whether this is correct.
> 
> Are you able to crack the password? We have been able to extract the full firmware image of a slightly different fridge and a memory dump of their fridge. We hope this is enough...
> 
> Note: The flag is in a different format than usually...
> 
>   * Challenge
>   * firmware.bin
>   * memory.dmp

Wow. A lot of stuff here, let's analyse the challenge. What we're dealing with here is an AVR firmware containing an embedded virtual machine (VM). The application running on the VM is some kind of digital safe? Let's look at the files to see if those are of any help...

For the analysis of this we have:

  1. An unencrypted `firmware.bin` file.
  2. The `memory.dmp` of a fridge with this code installed.
  3. The ordinary encrypted challenge binary in Intel Hex format.

Let's do our first pass at information gathering and just load the challenge binary onto the RHme2 board: 
```
root@kali:~/rhme/fridgejit# ../flash.sh fridgejit.hex </p> 

avrdude: AVR device initialized and ready to accept instructions

Reading | ################################################## | 100% 0.00s

avrdude: Device signature = 0x1e950f (probably m328p)
avrdude: NOTE: "flash" memory has been specified, an erase cycle will be performed
To disable this feature, specify the -D option.
avrdude: erasing chip
avrdude: reading input file "fridgejit.hex"
avrdude: input file fridgejit.hex auto detected as Intel Hex
avrdude: writing flash (11648 bytes):

Writing | ################################################## | 100% 13.65s

avrdude: 11648 bytes of flash written

avrdude done. Thank you.

root@kali:~/rhme/fridgejit# ./com.py
[*] Switching to interactive mode
\xff\x00
Password:
```
Ok. Just getting a password prompt here. What's the deal?

Let's look at the firmware.bin a bit. It's not encrypted so are there any interesting strings inside? 
```
Loader>
Loader> Provide bootrom (hex encoded)
Loader> Authentication failed
Loader>
Input error
\[Finished\] \[Finished\] [s]tep
[c]ontinue
[r]eset
[d]ebug
[e]xecute
[l]oad
\---------/
\-----------/
| Z: %01x C: %01x |
| R3: %08lx IP: %08lx |
| R2: %08lx SP: %08lx |
| R1: %08lx R5: %08lx |
| R0: %08lx R4: %08lx |
/---------\
/-----------\
| 

>>
[ FridgeJIT Console ] [1;1H
y%u/g5
Changelog
17-03-2002:
JMB: Updated instruction set. Must fix debugger!!!
```
Oh nice, looks like an entire debug interface inside this thing! Sweet. How do we access it. Well actually, this firmware.bin is a legitimate AVR binary, we can flash it to an Arduino and take a look I think? I connect a spare Arduino UNO to my computer and flash away: 
```
root@kali:~/rhme/fridgejit# avrdude -c arduino -p atmega328p -P /dev/ttyUSB1 -b57600 -u -V -U flash:w:firmware.bin
...
avrdude: 11006 bytes of flash written

avrdude done. Thank you.

root@kali:~/rhme/fridgejit# ./com1.py
[*] Switching to interactive mode
Loader> Authentication failed
Loader> Provide bootrom (hex encoded)
Loader> $
```
It seems this is not working so well though because I only receive 'Input Error' or a reset, never seeing the debug interface from the strings we saw. 

At this point it was time to look at the AVR binary `firmware.bin` in static analysis tools. I spent a long time getting IDA Pro to give good results with ATmega328p binaries. I found this was a fairly poorly maintained function of IDA Pro, for what reason I don't know. However <a href="http://thanat0s.trollprod.org/2014/01/loader-un-binaire-arduino-dans-ida/" target="_blank">this article (all in French) was a godsend</a> because it got me up and running eventually.

I spent quite a while piecing together what I came to call the "VM bytecode" parsing routines in the binary. Eventually I learned that the solution to this challenge was not going to be in the firmware. The firmware did not ask for a Password itself. This left me with the conclusion that the Password prompt is actually being presented from VM bytecode being executed on the RHme2 board. 

Oh dear.

We need to go deeper!

The solution must be somewhere else, our remaining file? memory.dmp? Yes let's figure out how to use this file. Our French IDA Pro helping article from before describes how to load additional binary files into IDA Pro. We're able to load the `memory.dmp` file this way. While doing this would work, maybe there's an easier way. I really want to be able to dynamically analyse this `firmware.bin` file and maybe even inject `memory.dmp`. How do we do that?

There's not too many ways to debug binary only AVR code outside of maybe using hardware debuggers sold by Atmel? I don't know anything about that. I did track down that Atmel produce a debugger as part of Atmel Studio. The problem is, there is no way to interact with binaries within the Atmel Studio **7** debugger via a serial terminal. What? That seems like a big feature to just ignore.

A bit of Googling lead us to this, <a href="http://www.helmix.at/hapsim/" target="_blank">HAPSIM, an AVR peripheral simulator</a> for Atmel Studio. The only catch is, its only for Atmel Studio 4. Fine, time to go back in time to 2011. Thankfully <a href="http://www.atmel.com/tools/studioarchive.aspx" target="_blank">Atmel archive old Studio versions here</a>. I grab build 4.19 (build 730) and install it on Windows 7, it won't install on Windows 10, not a good sign. A bit more futzing about and it works! Wow. Except it's super slow and writing to the terminal.

<img src="/images/2017/03/disasm.png" alt="" width="1510" height="1003" class="alignnone size-full wp-image-957" srcset="/images/2017/03/disasm.png 1510w, /images/2017/03/disasm-300x199.png 300w, /images/2017/03/disasm-768x510.png 768w, /images/2017/03/disasm-1024x680.png 1024w" sizes="(max-width: 1510px) 100vw, 1510px" />

At this point I got a bit stuck, we spent a lot of time dynamically analysing the code. First we learned that by setting IP directly to 0x704 we could bypass the `Loader>` prompt and go directly to the VM debugger in the firmware. This seemed to be a bit faulty though so learning much is slow. 

After some time I realise this debugger has some pretty awesome features to both load and save memory dumps from the running binary. I get the idea to compare the `memory.dmp` from the challenge with the memory dump from the `firmware.bin` in a blank running state. That is, with no VM code loaded. With this idea I might be able to isolate the VM bytecode in the `memory.dmp`? 

With the `firmware.bin` loaded, but suspended, I used the _Debug -> Up/Download Memory_ function and wrote the contents of the Data memory to disk. The output was a Intel Hex file, so I used `avr-objcopy` to convert it to a binary file and then hand compared it with the `memory.dmp` file. It looked pretty familiar! It turns out that our memory dump corresponds to offset 0x100 onward in `memory.dmp` 

<img src="/images/2017/03/comparememory.png" alt="" width="1500" height="463" class="alignnone size-full wp-image-959" srcset="/images/2017/03/comparememory.png 1500w, /images/2017/03/comparememory-300x93.png 300w, /images/2017/03/comparememory-768x237.png 768w, /images/2017/03/comparememory-1024x316.png 1024w" sizes="(max-width: 1500px) 100vw, 1500px" />

Searching a bit more and I feel like we're getting closer. Our `memory.dmp` is clearly loading the word "Password" into memory here (in 4 byte chunks, little endian byte order):

<img src="/images/2017/03/password.png" alt="" width="722" height="289" class="alignnone size-full wp-image-960" srcset="/images/2017/03/password.png 722w, /images/2017/03/password-300x120.png 300w" sizes="(max-width: 722px) 100vw, 722px" />

We can see other strings like Correct and Incorrect being loaded to. This looks like VM bytecode, at a guess, loading from 0x2b8 -> 0x558 in this `memory.dmp` file since these are surrounded by blocks of null bytes. I use `dd` to grab this code out of the binary. 
```
root@kali:~/rhme/fridgejit# dd if=memory.dmp skip=$((0x2b8)) count=$((0x558-0x2b8)) bs=1 of=vmcode.bin
672+0 records in
672+0 records out
672 bytes copied, 0.00100586 s, 668 kB/s
root@kali:~/rhme/fridgejit# xxd -p vmcode.bin
050025000400203a01000500647204006f77010005007373040061500100
04500088125003060410000a045000a8125004500120125067c60540ffff
0440ffee0d2016241800121304500050125069730a110410000a05004500
0400217401000500636504007272010005006f6304006e49010003060450
00a80a4412501400210000001400215104100004045000a81d18002613ff
4aec05002172040072450100030612501f2901200000161418002d022013
06201c20043000010803091314002bcd0a22010001100450008812500450
00010306080106000000160418003b044000000861086113baab1b300723
08250905140037f20a110410000805002074040063650100050072720400
6f4301000306045000a80a4412501ffbe34604000011045000c412500430
00020450003812500450018c1250180061045001b01250180061045001cc
12501800610450020c12501800610450023412501800610450025c125018
0061045002701250180061045002881250180061045000f812507cc20450
0050125054f804500088125006400d20104205103d67041082a50a410510
5dd504103c4f1614131be8e708030640051023250410dbf808410510536d
04103b6d1614138d765a080306400a2204100010045000540e510c250410
0000045000470e510c2504100008045000300e510c25041000180450005f
0e510c2509420a2216241151132e0450e2bd08030640055020590c150a41
0a550450bde909450450001011450450074c094516241363045000881250
08030640045000131145051038150410cfb210150a41051093170410eee5
161413330803064009410520d4190420837a1624139fc99a080306400812
091411100540b2ef04402c9016141366320d080306400a400a410a420a43
052066d70420db8e16241300
```
Nice but how do we confirm this? I sort of let it sit here for a while because I was unable to get the FridgeJIT VM to work. 

I went on to other challenges including the following challenges to this one, and stumbled across an idea. It seems the other challenge binaries do not have the same faults we're seeing on FridgeJIT's VM. I download "The Weird Machine" challenge binary and this is what I see when I flash it to the RHme2 board: 
```
oot@kali:~/rhme/weirdmachine# ../flash.sh the\_weird\_machine.hex 

avrdude: AVR device initialized and ready to accept instructions

Reading | ################################################## | 100% 0.00s

avrdude: Device signature = 0x1e950f (probably m328p)
avrdude: NOTE: "flash" memory has been specified, an erase cycle will be performed
To disable this feature, specify the -D option.
avrdude: erasing chip
avrdude: reading input file "the\_weird\_machine.hex"
avrdude: input file the\_weird\_machine.hex auto detected as Intel Hex
avrdude: writing flash (13312 bytes):

Writing | ################################################## | 100% 15.42s

avrdude: 13312 bytes of flash written

avrdude done. Thank you.

root@kali:~/rhme/weirdmachine# ./com.py
[*] Switching to interactive mode
\xff\x00Loader> Authentication failed
Loader> Provide bootrom (hex encoded)
Loader> 22
Oops!
-----------\ /---------\
| >> 0000: UNKNOWN | | R0: 00000000 R4: 00000000 |
| | | R1: 00000000 R5: 00000000 |
| | | R2: 00000000 SP: 00000100 |
| | | R3: 00000000 IP: 00000000 |
| | | Z: 0 C: 0 |
\-----------/ \---------/

>> $ help
help [l]oad
[e]xecute
[d]ebug
[r]eset
[c]ontinue
```
A debugger! And if I load what we suspect is our "VM bytecode"? 
```
>> l
Loader> $ 050025000400203a01000500647204006..... <all the vm bytecode here>
[ FridgeJIT Console ] 

>> e
Password:
```
Oh nice! It gives us the "Password" prompt, this confirms we actually DO have the VM bytecode! Now to disassemble it. How do we even start this? We have a debugger! Let's not use "e" let's try "d" instead: 
```
>> l
Loader> $ 050025000400203a01000500647204006..... <all the vm bytecode here>
[ FridgeJIT Console ] /-----------\ /---------\
| >> 0000: 05002500 MOVH r0 #2500 | | R0: 00000000 R4: 00000000 |
| 0004: 0400203a MOVL r0 #203a | | R1: 00000000 R5: 00000000 |
| 0008: 0100 PUSH r0 | | R2: 00000000 SP: 00000100 |
| 000a: 05006472 MOVH r0 #6472 | | R3: 00000000 IP: 00000000 |
| 000e: 04006f77 MOVL r0 #6f77 | | Z: 0 C: 0 |
\-----------/ \---------/

>>

```
It's now a disassembler  <img src="https://ctf.rip/images/classic-smilies/icon_smile.gif" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />We can even step through the code instruction by instruction and learn everything about the VM code necessary. By the time we're finished with the disassembler we have this asm code for the virtual machine: 
```
0000 05002500 ; MOVH r0 #2500
0004 0400203a ; MOVL r0 #203a
0008 0100 ; PUSH r0
000a 05006472 ; MOVH r0 #6472
000e 04006f77 ; MOVL r0 #6f77
0012 0100 ; PUSH r0
0014 05007373 ; MOVH r0 #7373
0018 04006150 ; MOVL r0 #6150
001c 0100 ; PUSH r0
001e 04500088 ; MOVL r5 #0088
0022 1250 ; CALL r5
0024 0306 ; MOV r0 SP
0026 0410000a ; MOVL r1 #000a
002a 045000a8 ; MOVL r5 #00a8
002e 1250 ; CALL r5
0030 04500120 ; MOVL r5 #0120
0034 1250 ; CALL r5
0036 67c6 ; unknown
0038 0540ffff ; MOVH r4 #ffff
003c 0440ffee ; MOVL r4 #ffee
0040 0d20 ; NOT r2
0042 1624 ; CMP r2 r4
0044 180012 ; JNZ #12
0047 13 ; RET
0048 04500050 ; MOVL r5 #0050
004c 1250 ; CALL r5
004e 6973 ; unknown
0050 0a11 ; XOR r1 r1
0052 0410000a ; MOVL r1 #000a
0056 05004500 ; MOVH r0 #4500
005a 04002174 ; MOVL r0 #2174
005e 0100 ; PUSH r0
0060 05006365 ; MOVH r0 #6365
0064 04007272 ; MOVL r0 #7272
0068 0100 ; PUSH r0
006a 05006f63 ; MOVH r0 #6f63
006e 04006e49 ; MOVL r0 #6e49
0072 0100 ; PUSH r0
0074 0306 ; MOV r0 SP
0076 045000a8 ; MOVL r5 #00a8
007a 0a44 ; XOR r4 r4
007c 1250 ; CALL r5
007e 140021 ; JMP #21
0081 00 ; NOP
0082 00 ; NOP
0083 00 ; NOP
0084 140021 ; JMP #2151
0087 51 ; unknown
0088 04100004 ; MOVL r1 #0004
008c 045000a8 ; MOVL r5 #00a8
0090 1d ; unknown
0091 180026 ; JNZ #26
0094 13 ; RET
0095 ff4aec ; unknown
0098 05002172 ; MOVH r0 #2172
009c 04007245 ; MOVL r0 #7245
00a0 0100 ; PUSH r0
00a2 0306 ; MOV r0 SP
00a4 1250 ; CALL r5
00a6 1f29 ; unknown
00a8 0120 ; PUSH r2
00aa 00 ; NOP
00ab 00 ; NOP
00ac 1614 ; CMP r1 r4
00ae 18002d ; JNZ #2d
00b1 0220 ; POP r2
00b3 13 ; RET
00b4 0620 ; MOV r2 [r0] 00b6 1c20 ; unknown
00b8 04300001 ; MOVL r3 #0001
00bc 0803 ; ADD r0 r3
00be 0913 ; SUB r1 r3
00c0 14002bcd ; JMP #2b
00c4 0a22 ; XOR r2 r2
00c6 0100 ; PUSH r0
00c8 0110 ; PUSH r1
00ca 04500088 ; MOVL r5 #0088
00ce 1250 ; CALL r5
00d0 04500001 ; MOVL r5 #0001
00d4 0306 ; MOV r0 SP
00d6 0801 ; ADD r0 r1
00d8 0600 ; MOV r0 [r0] 00da 00 ; NOP
00db 00 ; NOP
00dc 1604 ; CMP r0 r4
00de 18003b ; JNZ #3b
00e1 04400000 ; MOVL r4 #0000
00e5 0861 ; ADD SP r1
00e7 0861 ; ADD SP r1
00e9 13 ; RET
00ea baab1b30 ; unknown
00ee 0723 ; MOV [r2] r3
00f0 0825 ; ADD r2 r5
00f2 0905 ; SUB r0 r5
00f4 140037 ; JMP #37
00f7 f2 ; unknown
00f8 0a11 ; XOR r1 r1
00fa 04100008 ; MOVL r1 #0008
00fe 05002074 ; MOVH r0 #2074
0102 04006365 ; MOVL r0 #6365
0106 0100 ; PUSH r0
0108 05007272 ; MOVH r0 #7272
010c 04006f43 ; MOVL r0 #6f43
0110 0100 ; PUSH r0
0112 0306 ; MOV r0 SP
0114 045000a8 ; MOVL r5 #00a8
0118 0a44 ; XOR r4 r4
011a 1250 ; CALL r5
011c 1ffbe346 ; unknown
0120 04000011 ; MOVL r0 #0011
0124 045000c4 ; MOVL r5 #00c4
0128 1250 ; CALL r5
012a 04300002 ; MOVL r3 #0002
012e 04500038 ; MOVL r5 #0038
0132 1250 ; CALL r5
0134 0450018c ; MOVL r5 #018c
0138 1250 ; CALL r5
013a 180061 ; JNZ #61
013d 045001b0 ; MOVL r5 #01b0
0141 1250 ; CALL r5
0143 180061 ; JNZ #61
0146 045001cc ; MOVL r5 #01cc
014a 1250 ; CALL r5
014c 180061 ; JNZ #61
014f 0450020c ; MOVL r5 #020c
0153 1250 ; CALL r5
0155 180061 ; JNZ #61
0158 04500234 ; MOVL r5 #0234
015c 1250 ; CALL r5
015e 180061 ; JNZ #61
0161 0450025c ; MOVL r5 #025c
0165 1250 ; CALL r5
0167 180061 ; JNZ #61
016a 04500270 ; MOVL r5 #0270
016e 1250 ; CALL r5
0170 180061 ; JNZ #61
0173 04500288 ; MOVL r5 #0288
0177 1250 ; CALL r5
0179 180061 ; JNZ #61
017c 045000f8 ; MOVL r5 #00f8
0180 1250 ; CALL r5
0182 7cc2 ; unknown
0184 04500050 ; MOVL r5 #0050
0188 1250 ; CALL r5
018a 54f8 ; unknown
018c 04500088 ; MOVL r5 #0088
0190 1250 ; CALL r5
0192 0640 ; MOV r4 [r0] 0194 0d20 ; NOT r2
0196 1042 ; unknown
0198 05103d67 ; MOVH r1 #3d67
019c 041082a5 ; MOVL r1 #82a5
01a0 0a41 ; XOR r4 r1
01a2 05105dd5 ; MOVH r1 #5dd5
01a6 04103c4f ; MOVL r1 #3c4f
01aa 1614 ; CMP r1 r4
01ac 13 ; RET
01ad 1be8e7 ; unknown
01b0 0803 ; ADD r0 r3
01b2 0640 ; MOV r4 [r0] 01b4 05102325 ; MOVH r1 #2325
01b8 0410dbf8 ; MOVL r1 #dbf8
01bc 0841 ; ADD r4 r1
01be 0510536d ; MOVH r1 #536d
01c2 04103b6d ; MOVL r1 #3b6d
01c6 1614 ; CMP r1 r4
01c8 13 ; RET
01c9 8d765a ; unknown
01cc 0803 ; ADD r0 r3
01ce 0640 ; MOV r4 [r0] 01d0 0a22 ; XOR r2 r2
01d2 04100010 ; MOVL r1 #0010
01d6 04500054 ; MOVL r5 #0054
01da 0e51 ; unknown
01dc 0c25 ; OR r2 r5
01de 04100000 ; MOVL r1 #0000
01e2 04500047 ; MOVL r5 #0047
01e6 0e51 ; unknown
01e8 0c25 ; OR r2 r5
01ea 04100008 ; MOVL r1 #0008
01ee 04500030 ; MOVL r5 #0030
01f2 0e51 ; unknown
01f4 0c25 ; OR r2 r5
01f6 04100018 ; MOVL r1 #0018
01fa 0450005f ; MOVL r5 #005f
01fe 0e51 ; unknown
0200 0c25 ; OR r2 r5
0202 0942 ; SUB r4 r2
0204 0a22 ; XOR r2 r2
0206 16241 ; CMP r2 r4
0208 1151 ; unknown
020a 13 ; RET
020b 2e ; unknown
020c 0450e2bd ; MOVL r5 #e2bd
0210 0803 ; ADD r0 r3
0212 0640 ; MOV r4 [r0] 0214 05502059 ; MOVH r5 #2059
0218 0c15 ; OR r1 r5
021a 0a41 ; XOR r4 r1
021c 0a55 ; XOR r5 r5
021e 0450bde9 ; MOVL r5 #bde9
0222 0945 ; SUB r4 r5
0224 04500010 ; MOVL r5 #0010
0228 1145 ; unknown
022a 0450074c ; MOVL r5 #074c
022e 0945 ; SUB r4 r5
0230 1624 ; CMP r2 r4
0232 13 ; RET
0233 63 ; unknown
0234 04500088 ; MOVL r5 #0088
0238 1250 ; CALL r5
023a 0803 ; ADD r0 r3
023c 0640 ; MOV r4 [r0] 023e 04500013 ; MOVL r5 #0013
0242 1145 ; unknown
0244 05103815 ; MOVH r1 #3815
0248 0410cfb2 ; MOVL r1 #cfb2
024c 1015 ; unknown
024e 0a41 ; XOR r4 r1
0250 05109317 ; MOVH r1 #9317
0254 0410eee5 ; MOVL r1 #eee5
0258 1614 ; CMP r1 r4
025a 13 ; RET
025b 33 ; unknown
025c 0803 ; ADD r0 r3
025e 0640 ; MOV r4 [r0] 0260 0941 ; SUB r4 r1
0262 0520d419 ; MOVH r2 #d419
0266 0420837a ; MOVL r2 #837a
026a 1624 ; CMP r2 r4
026c 13 ; RET
026d 9fc99a ; unknown
0270 0803 ; ADD r0 r3
0272 0640 ; MOV r4 [r0] 0274 0812 ; ADD r1 r2
0276 0914 ; SUB r1 r4
0278 1110 ; unknown
027a 0540b2ef ; MOVH r4 #b2ef
027e 04402c90 ; MOVL r4 #2c90
0282 1614 ; CMP r1 r4
0284 13 ; RET
0285 66320d ; unknown
0288 0803 ; ADD r0 r3
028a 0640 ; MOV r4 [r0] 028c 0a40 ; XOR r4 r0
028e 0a41 ; XOR r4 r1
0290 0a42 ; XOR r4 r2
0292 0a43 ; XOR r4 r3
0294 052066d7 ; MOVH r2 #66d7
0298 0420db8e ; MOVL r2 #db8e
029c 1624 ; CMP r2 r4
029e 13 ; RET

```
This is now becoming a much more achievable solution. By using the portions of code that are clearly loading strings onto the stack, especially the function that loads the "Correct" string @ 0x00f8 we get the idea of the code using this thought process:

  1. `0x00f8` prints the "Correct" message
  2. `0x00f8` is cross referenced from `0x017c`
  3. `0x017c` is preceded by a string of CALL / JNZ instructions. These look to operate on the password input
  4. These referenced functions are: 
      * `0x18c`
      * `0x1b0`
      * `0x1cc`
      * `0x20c`
      * `0x234`
      * `0x25c`
      * `0x270`
      * `0x288`
  5. I label these "check\_1" to "check\_8".
  6. Each of these check_N functions operate on register r4 as input with various bitwise operations.
  7. Along the way we learn the operation of 3 unknown opcodes 
      * `0x10 - ROL`
      * `0x11 - ROR`
      * `0xe - SHL`

Let's examine and reverse each check function, starting with check_1:

**Check 1**
```
018c 04500088 ; MOVL r5 #0088
0190 1250 ; CALL r5 (DST: 0x88)
0192 0640 ; MOV r4 [r0] 0194 0d20 ; NOT r2 (r2=0xffffffee) r2: 0x11
0196 1042 ; ROTL32(r4,r2) (r4, r2=0x11)
0198 05103d67 ; MOVH r1 #3d67
019c 041082a5 ; MOVL r1 #82a5
01a0 0a41 ; XOR r4 r1 (r1=0x3d6782a5)
01a2 05105dd5 ; MOVH r1 #5dd5
01a6 04103c4f ; MOVL r1 #3c4f
01aa 1614 ; CMP r1 r4 (r1=0x5dd53c4f)
01ac 13 ; RET
```
This one's trivial but hinges on two critical facts. We must know `r2` value going into this function. For this we must go back up and look at what I call the `initialize_for_check` function referenced from `0x012a`: 
```
012a 04300002 ; MOVL r3 #0002 ; initialize for check_1
012e 04500038 ; MOVL r5 #0038 ; sets r2=0xffffffee, r4=0xffffffee
0132 1250 ; CALL r5 (DST: 0x38) :init\_for\_checking2
```
This calls `0x0038`

 which does: 
```
0038 0540ffff ; MOVH r4 #ffff
003c 0440ffee ; MOVL r4 #ffee
0040 0d20 ; NOT r2
0042 1624 ; CMP r2 r4
0044 180012 ; JNZ #12
0047 13 ; RET
```
So we set `r4` to `0xffffffee` and compare `r2` to `r4`. If this comparison fails we jump somewhere undesirable. So what is the correct value of `r2`? It is `!0xffffffee = 0x11`. 

The next critical fact we needed was to understand the operation of opcode `0x1042` which is the undocumented `ROL` instruction. Once we have the initial value of `r2`, and the understanding of the `ROL` instruction, we can solve for `r4` in this function.

  * `r4 = ROR(0x5dd53c4f ^ 0x3d6782a5, 0x11)`
  * `r4 = 0x5f753059`
  * `r4 = "Y0u_"`

For each check function I also wrote some VM code to help me validate my answer, or even derive the answer for me, for check_1 I got:

  * `0520ffff0420ffee05405f75044030590d20104205103d67041082a50a4105105dd504103c4f00`

**Check 2**

Check two is much simpler, we just do math on two constants to derive r4: 
```
:check_2
01b0 0803 ; ADD r0 r3
01b2 0640 ; MOV r4 [r0] 01b4 05102325 ; MOVH r1 #2325
01b8 0410dbf8 ; MOVL r1 #dbf8
01bc 0841 ; ADD r4 r1
01be 0510536d ; MOVH r1 #536d
01c2 04103b6d ; MOVL r1 #3b6d
01c6 1614 ; CMP r1 r4
01c8 13 ; RET
```
We can derive the expected input as such:

  * `r4 = (0x536d3b6d - 0x2325dbf8) & 0xffffffff`
  * `r4 = 0x30475f75`
  * `r4 = "0G_u"`

The check code I wrote for this function is:

  * `0540304704405f75051023250410dbf808410510536d04103b6d00`

**Check 3**

Check three spends some time setting up a copy of what the input (r4) should be using OR and SHL instructions. We solved it by stepping through the code in the debugger as it has no prerequisites. You can see the output of each instruction in the comments in the assembly code. 
```
:check_3
01cc 0803 ; ADD r0 r3
01ce 0640 ; MOV r4 [r0] 01d0 0a22 ; XOR r2 r2 (r2=0x00)
01d2 04100010 ; MOVL r1 #0010
01d6 04500054 ; MOVL r5 #0054
01da 0e51 ; SHL32(r5,r1)
01dc 0c25 ; OR r2 r5 (r2=0x00, r5=0x540000) = r2: 0x00540000
01de 04100000 ; MOVL r1 #0000
01e2 04500047 ; MOVL r5 #0047
01e6 0e51 ; SHL32(r5,r1)
01e8 0c25 ; OR r2 r5 (r2=0x00540000, r5=0x00540047) = r2: 0x00540047
01ea 04100008 ; MOVL r1 #0008
01ee 04500030 ; MOVL r5 #0030
01f2 0e51 ; SHL32(r5,r1)
01f4 0c25 ; OR r2 r5 (r2=0x00540047, r5=0x54003000) = r2: 0x54543047
01f6 04100018 ; MOVL r1 #0018
01fa 0450005f ; MOVL r5 #005f
01fe 0e51 ; SHL32(r5,r1)
0200 0c25 ; OR r2 r5 (r2=0x54543047, r5=0x5f000000) = r2: 0x5f543047
0202 0942 ; SUB r4 r2
0204 0a22 ; XOR r2 r2 (r2 = 0x00)
0206 16241 ; CMP r2 r4
0208 1151 ; ROTR32(r5,r1) (r5=0x5f000000, r1=0x18) r5: 0x0000005f
020a 13 ; RET
```
The result is that r4 must be 0x5f543047 or "G0T_" for this check to pass. The check code I wrote for this function is:

  * `0a2204100010045000540e510c2504100000045000470e510c2504100008045000300e510c25041000180450005f0e510c2509420a2200`

**Check 4**

If you haven't noticed by now, each of these check functions is building 4 bytes of the flag, however each check function only produces two new bytes. So far we have only found "Y0u\_G0T\_" in 3 check functions. So each function gives us 2 new bytes and 2 old bytes we already knew. That proves handy because my disassembly of function `check_4` seems to be broken in some way. I reversed it but got the wrong answer. In order to save time I attempted to skip reversing `check_4` because we would learn the 2 new bytes from this check in `check_5` if everything goes smoothly. 

**Check 5**

Another simple check, the assembly code with comments is below: 
```
:check_5
0234 04500088 ; MOVL r5 #0088
0238 1250 ; CALL r5
023a 0803 ; ADD r0 r3
023c 0640 ; MOV r4 [r0] 023e 04500013 ; MOVL r5 #0013
0242 1145 ; ROTR32 r4 r5 rotr32(r4,r5=0x13) r4: 0xee862e4b
0244 05103815 ; MOVH r1 #3815
0248 0410cfb2 ; MOVL r1 #cfb2
024c 1015 ; ROTL32(r1,r5) (r1=0x3815cfb2) r1: 0x7d91c0ae
024e 0a41 ; XOR r4 r1
0250 05109317 ; MOVH r1 #9317
0254 0410eee5 ; MOVL r1 #eee5
0258 1614 ; CMP r1 r4 (r1=0x9317eee5)
025a 13 ; RET
```
In this code block, we're first ROR'ing the input by 0x13 bits then ROL'ing a constant by 0x13 bits. We're then XOR'ing them together, if the output of this operation is 0x9317eee5 then our input was right. We can solve for r4 as follows:

  * `r4 = ROL(0x9317eee5 ^ ROR(0x3815cfb2,0x13),0x13)`
  * `r4 = 0x725f7431`
  * `r4 = "1t_r"`

  * Check Program: `0540725f04407431045000131145051038150410cfb210150a41051093170410eee500`

**Check 6**

So we solved `check_5` ok which means our skipping of `check_4` was probably fine. Check 6 is a tiny check but it introduces the notion of dependencies upon previous checks. So no more skipping checks from here on out! Here's the assembly code: 
```
:check_6
025c 0803 ; ADD r0 r3
025e 0640 ; MOV r4 [r0] 0260 0941 ; SUB r4 r1
0262 0520d419 ; MOVH r2 #d419
0266 0420837a ; MOVL r2 #837a
026a 1624 ; CMP r2 r4 (r2=0xd419837a)
026c 13 ; RET
```
So all we need to do is add a constant value to `r1` to get our required input value. Where is `r1` set though? Actually it was left over from `check_5`. You can see `r1` gets set at `0x0250:0x0254` to `0x9317eee5`. So we need that. We can solve for `r4` as follows:

  * `r1 = 0x9317eee5` 
  * `r2 = 0xd419837a`
  * `r4 = (r1 + r2) & 0xffffffff`
  * `r4 = 0x6731725f `
  * `r4 = "_r1g"`

  * Check Program: `054067310440725f051093170410eee509410520d4190420837a00`

**Check 7**

Lot's of dependencies in this function too. We need `r2` from `check_6` and `r1` from `check_5` and `r0` for this one. Where do we learn `r0` from? Well we have enough information to solve for both `r0` and `r4` here. Let's take a look: 
```
:check_7
; var r2 = 0xd419837a (set @ 0x262:0x266)
; var r1 = 0x9317eee5 (set @ 0x250:0x254)
; var r0 = 0x0c (deduced)

0270 0803 ; ADD r0 r3
0272 0640 ; MOV r4 [r0] 0274 0812 ; ADD r1 r2 (r1=0x9317eee5, r2=0xd419837a)
0276 0914 ; SUB r1 r4 (r1=0x6731725f-r4=0x74686731) r1:result = f2c90b2e
0278 1110 ; ROTR32(r1,r0) (r1=0xf2c90b2e, r0=0x0c)
027a 0540b2ef ; MOVH r4 #b2ef
027e 04402c90 ; MOVL r4 #2c90
0282 1614 ; CMP r1 r4 (r4=0xb2ef2c90)
0284 13 ; RET
```
To solve for `r4` we need to follow these steps:

Find r1 following the arithmetic in the code:

  * `r1 = 0x9317eee5`
  * `r2 = 0xd419837a`
  * `r1 = r1 + r2`
  * `r1 = 0x6731725f`

Solve for `r0`, I did this using Python to iterate each possible value of `r4` and `r0` with a 32 bit ROL implementation. This was simple, especially since we knew that the first two bytes would be identical to the second two bytes of the previous 4 byte block (i.e. 0x6731):

  * `0xb2ef2c90 = ROR(0x6731725f-r4, r0)`
  * `r0 = 0xc`
  * `r4 = 0x74686731`
  * `r4 = "1ght"`

  * Check Program: `0520d4190420837a051093170410eee5050000000400000c05407468044067310812091411100540b2ef04402c9000`

**Check 8**

Eighth and final check! In this check we have four total dependencies from either previous checks, deductions, or initialization functions.  
```
:check_8
0288 0803 ; ADD r0 r3 (r0=0xc, r3=0x2) r0:0xe
028a 0640 ; MOV r4 [r0] 028c 0a40 ; XOR r4 r0 (r0=0xe)
028e 0a41 ; XOR r4 r1 (r1=0xb2ef2c90)
0290 0a42 ; XOR r4 r2 (r2=0xd419837a)
0292 0a43 ; XOR r4 r3 (r3=0x2)
0294 052066d7 ; MOVH r2 #66d7
0298 0420db8e ; MOVL r2 #db8e
029c 1624 ; CMP r2 r4 (r2=0x66d7db8e)
029e 13 ; RET
```
We need:

  * `r0 = 0x0c` (deduced in check_7)
  * `r1 = 0xb2ef2c90` (set @ 0x276)
  * `r2 = 0xd419837a` (set @ 0x262:0x266)
  * `r3 = 0x2` (set @ 0x012a)

Once we have those the easiest way to find the solution here is to just update `r0` to the right value then run this code backwards:

  * `r0 = r0 + r3`
  * `r0 = 0xc + 0x2`
  * `r0 = 0xe`
  * `r4 = 0x66d7db8e ^ r3 ^ r2 ^ r1 ^ r0`
  * `r4 = 0x66d7db8e ^ 0x2 ^ 0xd419837a ^ 0xb2ef2c90 ^ 0x0e`
  * `r4 = 0x0021746a`
  * `r4 = 'ht!\x00'`

  * VM Check Code: `054066d70440db8e050000000400000e0510b2ef04102c900520d4190420837a05300000043000020a400a410a420a4300`

**Putting it all Together**

Concatenating the input values for the checks we reversed we get the string `Y0u_G0t_1t_r1ght!`. I tried submitting this as the flag and it worked!

Long solution but very satisfying to get.