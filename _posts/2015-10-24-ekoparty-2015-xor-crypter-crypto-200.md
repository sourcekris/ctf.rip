---
id: 220
title: 'EKOPARTY 2015 - XOR Crypter - Crypto 200'
date: 2015-10-24T02:27:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=220
permalink: /ekoparty-2015-xor-crypter-crypto-200/
post_views_count:
  - "573"
image: /images/2015/10/x-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---

Very quick challenge this one, solved in one line shell script. Here's the clue:


<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/10/x-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/10/x-2.png" /></a>
</div>

The ZIP file contains a Python script called "shiftcrypt.py". The meat is this part:

```
result = []
blocks = struct.unpack("I" * (len(data) / 4), data)

print repr(blocks)

for block in blocks:
    result += [block ^ block >> 16]
```

The first thing I thought here is, this is not right? We can just do the same operation and get back the original data yes?

Let's try, we take the string they gave us to decrypt:

  * CjBPewYGc2gdD3RpMRNfdDcQX3UGGmhpBxZhYhFlfQA=

And we make it encrypt it again:

```
root@mankrik:~/ekoparty/crypto200# echo CjBPewYGc2gdD3RpMRNfdDcQX3UGGmhpBxZhYhFlfQA= | base64 -d > c; ./shiftcrypt.py "`cat c`" | tail -1 | base64 -d
EKO{unshifting_the_unshiftable}
```
There we go, our flag: EKO{unshifting_the_unshiftable}