---
id: 585
title: 'Pragyan 2016 - Harry Potter - Steganography'
date: 2016-02-28T09:36:13+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=585
permalink: /pragyan-2016-harry-potter-steganography/
post_views_count:
  - "1049"
image: /images/2016/02/logo-660x304.png
categories:
  - Write-Ups
---
<img class="alignnone size-full wp-image-587 aligncenter" src="/images/2016/02/HP.png" alt="HP" width="385" height="131" srcset="/images/2016/02/HP.png 385w, /images/2016/02/HP-300x102.png 300w" sizes="(max-width: 385px) 100vw, 385px" />

Pragyan CTF might not have been on the CTFTime timetable this year but it ran during the week so we took part. We in fact finished 2nd outright with 1251 points. Equal in points to first place but arriving there later and only one challenge remained unsolved.

A minor 35 points for this harmless looking stego challenge so how hard can it be? In fact it was one of the last challenges I solved, probably due to the use of a cipher I had never heard of. It had only a 5% solve rate too so I guess a lot of folks struggled.

Actually before I go into the solution, that was an overarching theme of Pragyan for me, ciphers.... soooo mannnyyyy ciphers. I believe almost every challenge wound up with some ciphertext you had to solve. So it was fun like that.

This begins with an <a href="https://raw.githubusercontent.com/sourcekris/ctf-solutions/master/steganography/pragyan-harry-potter/HP.png" target="_blank">innocent image file</a> which when downloaded quickly gives away a secret:

```
root@kali:~/pragyan/stego# file HP.png 
HP.png: PNG image data, 385 x 131, 8-bit colormap, non-interlaced
root@kali:~/pragyan/stego# pngcheck HP.png 
HP.png  additional data after IEND chunk
ERROR: HP.png
```

Using strings we see this...
```
root@kali:~/pragyan/stego# strings HP.png 
IHDR
...
IEND
wherE ShOUld onE ReaLly lOoK fOr tHis flag
```

Hmm, at first I extracted the uppercase characters resulting in a "ciphertext" of ESOUERLOKOH. We hammered this string into so many cipher solvers for literally days with no luck. 

We then decided to look more into ciphers which involve the way the entire string was encoded, this lead us to the "<a href="http://rumkin.com/tools/cipher/baconian.php" target="_blank">Bacon</a>" cipher. Using this cipher if we take each lowercase letter to represent an "A" and each uppercase character a "B" we get the string:

```
wherEShOUldonEReaLlylOoKfOrtHisflag
AAAABBABBAAAABBAABAAABABABAABAAAAAA
```

Which, using an online solver we get the plaintext "bydelta" which did turn out to be the flag.