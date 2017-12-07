---
id: 592
title: 'Pragyan 2016 - Crack This - Forensics Challenge'
date: 2016-02-28T09:53:58+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=592
permalink: /pragyan-2016-crack-this-forensics-challenge/
post_views_count:
  - "788"
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
image: /images/2016/02/cracktitle-660x170.png
categories:
  - Write-Ups
---
<img class="alignnone size-full wp-image-593" src="/images/2016/02/cracktitle.png" alt="cracktitle" width="984" height="253" srcset="/images/2016/02/cracktitle.png 984w, /images/2016/02/cracktitle-300x77.png 300w, /images/2016/02/cracktitle-768x197.png 768w, /images/2016/02/cracktitle-660x170.png 660w" sizes="(max-width: 984px) 100vw, 984px" />

Another puzzle we solved late into the piece. We had a TGZ file containig two things a PCAP file and a Clue.txt.

The PCAP file contained a single packet with the following data inside:

```
root@kali:~/pragyan/forensics/crack-this# tcpdump -r problem.pcap -A
reading from file problem.pcap, link-type EN10MB (Ethernet)
05:59:54.303760 IP localhost.32769 > localhost.9600: UDP, length 20
E..0..@.@.<...........%.....rukgzuzfiuypreymqcja
```

The Clue.txt had just the following seemingly redundant information:

```
root@kali:~/pragyan/forensics/crack-this# cat Clue.txt 
IP - 127.0.0.1
Port - 32769
```

We analysed the cipher with Crypto Crack tool and it gave us these suggested ciphers to try:

```
IC: 32,  Max IC: 125,  Max Kappa: 188
Digraphic IC: 0,  Even Digraphic IC: 0
3-char repeats: 0,  Odd spaced repeats: 50
Avg digraph: 375,  Avg digraph discrep.: 110
Most likely cipher type has the lowest score.

Running Key............14
6x6 Bifid..............22
Period 7 Vigenere......24
Beaufort...............25
Patristocrat...........25
Porta..................25
```

Porta stood out since the "Clue.txt" specifically says "Port" but nonetheless i tried all of them. Eventually trying a dictionary attack using each and stumbling upon a partial decryption using the key "local":

  * <span style="text-decoration: underline;">mayth</span>cftvcgidrgrjqws

Given the other Star Wars related flags so far my eyes were quick to spot this. I checked the key and put 2 + 2 together. The clue with the 127.0.0.1 address, 127.0.0.1 -> "localhost".

I tried a decryption using Porta, with key = localhost and got the flag:

  * maytheforcebewithyou

<img class="size-full wp-image-594 aligncenter" src="/images/2016/02/crackthis.png" alt="crackthis" width="694" height="703" srcset="/images/2016/02/crackthis.png 694w, /images/2016/02/crackthis-296x300.png 296w, /images/2016/02/crackthis-660x669.png 660w" sizes="(max-width: 694px) 100vw, 694px" />

