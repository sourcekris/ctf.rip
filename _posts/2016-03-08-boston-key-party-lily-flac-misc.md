---
id: 625
title: 'Boston Key Party 2016 - lily.flac - Misc'
date: 2016-03-08T11:04:38+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=625
permalink: /boston-key-party-lily-flac-misc/
post_views_count:
  - "2268"
image: /images/2016/03/lily-660x406.png
categories:
  - Write-Ups
tags:
  - Audio
  - FLAC
  - Stego
  - WAV
---
Sorry but this challenge was not solved by me during the competition but afterwards I came to know the solution by way of IRC and wanted to document it in case I forget. It was only worth 2 points but was solved by very few teams during the competition. Normally I don't let this bug me but I missed these obvious things so I'll share them with others so we don't make such mistakes next time <img src="http://ctf.rip/wp-content/plugins/classic-smilies/img/icon_smile.gif" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />

lily.flac was a FLAC file, a type of lossless compression for audio files. When we download the file we can decompress it with the flac program pre-installed on Kali:

```
root@kali:~/bkp/misc/lily# file lily.flac 
lily.flac: FLAC audio bitstream data, 8 bit, stereo, 8 kHz, 4230852 samples
root@kali:~/bkp/misc/lily# flac -d lily.flac 

flac 1.3.1, Copyright (C) 2000-2009  Josh Coalson, 2011-2014  Xiph.Org Foundation
flac comes with ABSOLUTELY NO WARRANTY.  This is free software, and you are
welcome to redistribute it under certain conditions.  Type `flac' for details.

lily.flac: done         
root@kali:~/bkp/misc/lily# file lily.wav 
lily.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, stereo 8000 Hz
```

Ok great. Next I examine the file in sound visualization tools looking for common steganography approaches. I learnt of a great free tool called Sonic Visualizer for this process but i got the most useful information using the Spectrogram function of Audacity. See the screenshot below:

<img class="wp-image-626 aligncenter" src="/images/2016/03/lily.png" alt="lily" width="927" height="570" srcset="/images/2016/03/lily.png 1531w, /images/2016/03/lily-300x185.png 300w, /images/2016/03/lily-768x473.png 768w, /images/2016/03/lily-1024x630.png 1024w, /images/2016/03/lily-660x406.png 660w" sizes="(max-width: 927px) 100vw, 927px" />

Here we see that the wave consists of a <a href="https://en.wikipedia.org/wiki/Sawtooth_wave" target="_blank">sawtooth wave</a> and is probably computer generated "filler" the interesting point is the scrambled waveform before the sawtooth. This indicates data is probably here. There is a similar formation at the end of the file. This indicates there could be another type of file with it's own header/footer encoded within.

If we make an assumption and believe that within this WAV file is an encoded binary of some other kind we can begin to come up with the solution using "frequency analysis" by eye. First we open the WAV file in a hex editor and skip past the RIFF Wave file header. The WAV file data starts after the "data" marker. Here we can see many bytes of 0x80. In any typical binary file the most common byte is 0x00. If we maintain our assumption that our WAV file is really an encoded binary then we can say then it may be simply XOR'd and since any value XOR'd with 0x00 is itself, the key may very well be 0x80.

<img class="wp-image-627 aligncenter" src="/images/2016/03/lily2.png" alt="lily2" width="684" height="427" srcset="/images/2016/03/lily2.png 739w, /images/2016/03/lily2-300x187.png 300w, /images/2016/03/lily2-660x412.png 660w" sizes="(max-width: 684px) 100vw, 684px" />

We can use Xortool to conduct a quick attempt at this:

```
root@kali:~/bkp/misc/lily# xortool-xor -h 80 -f lily.wav  > lily.bin
root@kali:~/bkp/misc/lily# strings lily.bin | head -10
/lib64/ld-linux-x86-64.so.2
eqz_B	
libc.so.6
putchar
__libc_start_main
__gmon_start__
GLIBC_2.2.5
```

Wow, these look like strings you'd see in an ELF binary! We found it. Next we just need to delete the extra WAV header bytes and see if we can run the file:

```
root@kali:~/bkp/misc/lily# hexeditor -b lily.bin
root@kali:~/bkp/misc/lily# chmod +x lily.bin
root@kali:~/bkp/misc/lily# ./lily.bin 
BKPCTF{hype for a Merzbow/FSF collab album??}
```

Can't believe it! Wish I figured that out earlier.