---
id: 574
title: 'InternetWache 2016 - Crypto-Pirat - Cryptography Challenge'
date: 2016-02-22T03:22:13+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=574
permalink: /internetwache-2016-crypto-pirat-cryptography-challenge/
post_views_count:
  - "1809"
image: /images/2016/02/wache-660x207.png
categories:
  - Write-Ups
---
<img class="alignnone size-full wp-image-576" src="/images/2016/02/crypto-pirat.png" alt="crypto-pirat" width="626" height="168" srcset="/images/2016/02/crypto-pirat.png 626w, /images/2016/02/crypto-pirat-300x81.png 300w" sizes="(max-width: 626px) 100vw, 626px" />

Creative challenge that involved several layers of encoding to reveal a flag. The challenge being the obscurity of the first layer.

We're given a ZIP <a href="https://github.com/internetwache/Internetwache-CTF-2016/tree/master/tasks/crypto50/task" target="_blank">containing one file</a> and a clue with some hints that the cipher may be of East German origin. Some googling quickly gives us the name of the cipher "Tapir" which fits as it's an anagram of "Pirat" from the clue. However it's not immediately clear how the Tapir cipher relates to the file we have which, appears to be UTF-8 gibberish initially.

<img class="alignnone size-full wp-image-577" src="/images/2016/02/crypto-pirat2.png" alt="crypto-pirat2" width="915" height="194" srcset="/images/2016/02/crypto-pirat2.png 915w, /images/2016/02/crypto-pirat2-300x64.png 300w, /images/2016/02/crypto-pirat2-768x163.png 768w, /images/2016/02/crypto-pirat2-660x140.png 660w" sizes="(max-width: 915px) 100vw, 915px" />

A hint is dropped about how "there were 9 planets between 1935-2006" and I'm wondering how planets are related to UTF-8 gibberish and Tapir ciphers. I decide to take the UTF-8 symbols at face value and look into if there's any correlation there.

I find that indeed, the planets do have symbols. There's a few Wikipedia pages with some documentation on these very symbols, <a href="https://en.wikipedia.org/wiki/Astronomical_symbols" target="_blank">here for example</a>.

So if we assign integers to these symbols in the range of 1 - 9 based on their index from the Sun we learn two things:

  * Only four planets are represented using four different symbols 
      1. Neptune (Trident)
      2. Venus (Female)
      3. Pluto (weird P thing)
      4. Earth (XOR symbol)

I wrote a converter in Python to quickly produce a translation of the planetary symbols into integers:
  
```
#!/usr/bin/python
# -*- coding: utf-8 -*-

import codecs

ciphertext = codecs.open('README.txt','r','utf-8').read()

planets = { u'♀' : 2, u'⊕' : 3, u'♆' : 8, u'♇' : 9, ' ' : '' }
nextcipher = "".join([str(planets.get(c)) for c in ciphertext])

print nextcipher
```

Which gives us the following long list of integers:

<img class="size-full wp-image-579 aligncenter" src="/images/2016/02/crypto-pirat3.png" alt="crypto-pirat3" width="723" height="138" srcset="/images/2016/02/crypto-pirat3.png 723w, /images/2016/02/crypto-pirat3-300x57.png 300w, /images/2016/02/crypto-pirat3-660x126.png 660w" sizes="(max-width: 723px) 100vw, 723px" />

At which point the relationship to "Tapir" cipher begins to make sense. If we dredge up a Tapir cipher decoder we can see these integers can possibly make sense in that context.

<img class="size-full wp-image-583 aligncenter" src="/images/2016/02/tapir.jpg" alt="tapir" width="396" height="284" srcset="/images/2016/02/tapir.jpg 396w, /images/2016/02/tapir-300x215.jpg 300w" sizes="(max-width: 396px) 100vw, 396px" />

If we split these into groups of two integers and decode with Tapir cipher we get the following output:

```
.- --.. ..-. .... .-- - - ..-. -- ...- ... 
... -.-. -..- ..--- ..- --. .- -.-- .... 
-.-. -..- ..--- -.. --- --.. ... .-- ....- 
--.. ...-- ... .-.. ..... .-- --. . ..--- 
-.-. --... -. --.. ... -..- . --- .-. .--- 
.--. ..- -...- -...- -...- -...- -...- -...-
```

Which is immediately recognizable as Morse Code. So we decode further and find the following:

```
KZFHWTTFMVSSCX2UGAYHCX2DOZSW4Z3SL5WGE2C7NZSXEORJPU======
```

Ok now we're looking at some Base32? Decoding it it appears we're on the right track:

  * VJ{Neee!\_T00q\_Cvengr\_lbh\_ner:)}

Which, when we ROT13 we get:

  * IW{Arrr!\_G00d\_Pirate\_you\_are:)}

Full problem and solution on my GitHub here: <a href="https://github.com/sourcekris/ctf-solutions/tree/master/crypto/internetwache-crypt-pirat" target="_blank">https://github.com/sourcekris/ctf-solutions/tree/master/crypto/internetwache-crypt-pirat</a>