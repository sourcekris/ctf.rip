---
id: 835
title: 'H4ckIT CTF 2016: Interceptor - Crypto Challenge'
date: 2016-10-03T06:09:26+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=835
permalink: /h4ckit-ctf-2016-interceptor-crypto-challenge/
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
  - "926"
image: /images/2016/10/h4ck1t.png
categories:
  - Write-Ups
tags:
  - crypto
  - rsa
---
Quick writeup for this one so I remember it for later. Although this CTF ran all week, we sorta need that, since it took about a day for the challenge GUI to load every time you clicked something. Ugh. Anyways, this was an interesting challenge because it appeared very simple but I wasn't immediately solving it using quick tricks. Anyway lets look at the clue:

> Looks like in this time Alice and Bob have decided to pay a minimal attention to malicious Eve, who has been "sniffing"(as always) all the traffic during their private chat. Is their private life\`s secret in danger for now?.. h4ck1t{key}

There's a link with [a file](https://github.com/sourcekris/ctf-solutions/blob/master/crypto/h4ck1t16-interceptor/EvelSniff_c637ac54760f179a5aa3e164847405fa.log) containing three sets of public keys and ciphertexts.

Usual attempts at factoring the moduli are not successful, and common factor attacks amongst the moduli are also unsuccessful. I am then reminded of Cryptopals challenge about the RSA broadcast attack with an public exponent of 3 (e=3). In our case the profile of the challenge fits this exactly: <https://cryptopals.com/sets/5/challenges/40>

The overview is, when you have a plaintext, encrypted three times with different public keys, we can use the chinese remainder theorem to solve for the plaintext cubed.

Using python, and libnum, we quickly code up a solution: 
```
#!/usr/bin/python
# RSA broadcast attack for Interceptor challenge @ H4ckIT 2016
# @ctfkris - Capture the Swag
import libnum
rsashit = [int(x.strip().split('=')[1]) for x in open('EvelSniff_c637ac54760f179a5aa3e164847405fa.log').readlines() if '=' in x]
n_0 = rsashit[1]
n_1 = rsashit[4]
n_2 = rsashit[7]
ct_0 = rsashit[2]
ct_1 = rsashit[5]
ct_2 = rsashit[8]
# product of all moduli
N_012 = n_0 * n_1 * n_2
# n1 * n2
m_s_0 = n_1 * n_2
# n0 * n2
m_s_1 = n_0 * n_2
# n0 * n1
m_s_2 = n_0 * n_1
crt = libnum.solve_crt([ct_0,ct_1,ct_2], [n_0,n_1,n_2])
c_0 = crt % n_0
c_1 = crt % n_1
c_2 = crt % n_2
result = ((c_0 * m_s_0 * libnum.invmod(m_s_0, n_0)) + (c_1 * m_s_1 * libnum.invmod(m_s_1, n_1)) + (c_2 * m_s_2 * libnum.invmod(m_s_2, n_2))) % N_012 
pt = libnum.nroot(result, 3)
print libnum.n2s(pt)
```
 

Which gives us the flag! Nice! 
```
root@kali:~/ctf-solutions/crypto/h4ck1t16-interceptor# ./portugal.py 
key=bff149a0b87f5b0e00d9dd364e9ddaa0
```
