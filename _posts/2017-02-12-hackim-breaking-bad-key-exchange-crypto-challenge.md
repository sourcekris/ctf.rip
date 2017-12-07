---
id: 895
title: 'HackIM - Breaking Bad Key Exchange - Crypto Challenge'
date: 2017-02-12T06:14:45+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=895
permalink: /hackim-breaking-bad-key-exchange-crypto-challenge/
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
  - "818"
image: /images/2017/02/hackim.png
categories:
  - Write-Ups
tags:
  - crypto
  - diffie-hellman
  - hackim
---
HackIM time again. This year seemed slightly better organized than last year. Some nice challenges. I don't think this challenge was worth 350 points but I'll document my solution anyway in sort of a "what not to do" when making a crypto challenge. Here's the clue including the image they gave as a description:

> Breaking Bad Key Exchange 
> 
> Hint 1 : in the range (1 to g*q), there are couple of pairs yielding common secrete as 399.
  
> Hint 2 : 'a' and 'b' both are less than 1000 
> 
> Flag Format: flag{a,b}<img src="/images/2017/02/cryptopuzzle2.png" alt="" width="1102" height="515" class="alignnone size-full wp-image-896" srcset="/images/2017/02/cryptopuzzle2.png 1102w, /images/2017/02/cryptopuzzle2-300x140.png 300w, /images/2017/02/cryptopuzzle2-768x359.png 768w, /images/2017/02/cryptopuzzle2-1024x479.png 1024w, /images/2017/02/cryptopuzzle2-748x350.png 748w" sizes="(max-width: 1102px) 100vw, 1102px" />

Ok so we already know everything from the get go, we have the generator (`g`) the modulus (`q`) the results of the Diffie-Hellman-Merkle key exchange math for Alice and Bob (generally called `A` and `B`) and we even know the resulting secret number (`g<sup>ab</sup> mod q`). The challenge asks us only to find little `a` and little `b`.

We're given a set of constraints. Our search field is `g*q` and our `a`, `b` are less than 1,000. 

Why don't they just tell us the answer?

A simple search finds the probably a,b pairs, we can do this very rapidly in Python. Coding in the constraints makes the operation very fast. 
```
#!/usr/bin/python
import itertools
# generator and modulus from challenge
g = 10
q = 541
a_s = []
b_s = []
for x in range(g*q):
    if g**x % q == 298:
        a_s.append(x)
    if g**x % q == 330:
        b_s.append(x)
p_flags = [] # possible flags
for i in itertools.product(a_s,b_s):
    if i[0] > 1000 or i[1] > 1000: # a and b cannot be over 1000 according to hint
        continue
    exp = i[0]*i[1]
    if g**exp % q == 399: 
        flg = "flag{"+str(i[0])+","+str(i[1])+"}"
        if flg not in p_flags:
            p_flags.append(flg)
print "[*] Possible flags:"
print '\n'.join(p_flags)

```
 

When we run it we get a list of possible values for a, b in the flag format: 
```
root@kali:~/hackim/crypto/dh# python bf.py 
[*] Possible flags:
flag{170,268}
flag{170,808}
flag{710,268}
flag{710,808}

```
 

The flag ends up being `flag{170,808}` 

I think the challenge author here struggled because of the number of valid results which find `399` as the mutually agreed secret key in this DH exchange. It felt like this challenge was forced in because a Diffie-Hellman challenge sounded like a neat idea. I think teaching DH in this way is ok but maybe for 50 points.