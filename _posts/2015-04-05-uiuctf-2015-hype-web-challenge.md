---
id: 240
title: 'UIUCTF 2015 - hype - Web Challenge'
date: 2015-04-05T02:29:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=240
permalink: /uiuctf-2015-hype-web-challenge/
post_views_count:
  - "392"
image: /images/2015/04/hype-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
Didn't have time to do UIUCTF this year since it ran concurrently with NDH but I did this challenge to help a team member out who was doing it and it only took 15 minutes. It was a fun challenge called hype, worth 100 points.

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/hype-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/hype-1.png" height="56" width="400" /></a>
</div>

With the challenge was a link to a website:<a href="http://a050032a39d870de1be70314b90d0917.tk"/> and a link to a Youtube video<a href="https://www.youtube.com/watch?v=B3vkL1nxQDI"/>

I didn't pay attention to the Youtube link but the website gave the following output:

```
 root@mankrik:~/uiu/hype# curl http://a050032a39d870de1be70314b90d0917.tk/  
 <html>  
 <head>  
 <title>Yolo</title>  
 </head>  
 <body>  
 <pre>  
 /*************************************************  
  * Your goal is to find the flag on this domain. *  
  *************************************************/  
 "176.9.206.182:7624":  
 {  
   "password": "uhnptlpq1j8yy2nrp7nmhfn7s1vgp4r"  
   "publicKey": "wzd7680uungk7u2jm9h0l49xsr38532dcdfvgd5qtcgt84suw8w0.k"  
 }  
 "188.226.224.130:18510":  
 {  
   "password": "thonaeriecioloshoopaetefaiphuga"  
   "publicKey": "cuwf4rmtbkz1c94x3nmvj359cn8ww6146k17qvj2dx9spnxhtyq0.k"  
 }  
 "84.114.155.197:10592":  
 {  
   "password": "fesijdojsdyrdyrdyrdyrdyrdyrdyr"  
   "publicKey": "kkm9h5my5tld01trzs3pt5szzsl462csnxj930kyxdn35gwj6150.k"  
 }  
 
```
  
 </body>  
 </html>  
```

Ok so we know the goal, but what to do. I tried connecting to the given hosts on the given port numbers but that seemed like the wrong direction so I Googled some of the information and began to learn just what "Hyperboria" is.

From Hyperboria.net:

>Hyperboria is a global decentralized network of "nodes" running cjdns software. The goal of Hyperboria is to provide an alternative to the internet with the principles of security, scalability and decentralization at the core. Anyone can participate in the network by locating a peer that is already connected.

Which leads us to the question of, what is CJDNS?

From https://github.com/cjdelisle/cjdns

>Cjdns implements an encrypted IPv6 network using public-key cryptography for address allocation and a distributed hash table for routing. This provides near-zero-configuration networking, and prevents many of the security and scalability issues that plague existing networks.

Ok. So it looks like what we have is a list of Hyperboria peers we need to use to access the website via it's Hyperboria IPv6 address.

I installed CJDNS, added the given nodes as peers and started the CJDNS routing daemon. The next step was just to connect to the<http://a050032a39d870de1be70314b90d0917.tk/>site's IPv6 address which we learned via DNS:

```
root@mankrik:~/uiu/hype# nslookup -type=AAAA a050032a39d870de1be70314b90d0917.tk  
Server:          192.168.152.2  
Address:     192.168.152.2#53  
Non-authoritative answer:  
a050032a39d870de1be70314b90d0917.tk     has AAAA address fcbe:4b13:cb2d:6d85:b2e6:f8ec:d290:39b8  
```

And fired up firefox with the URL: http://[fcbe:4b13:cb2d:6d85:b2e6:f8ec:d290:39b8]/

Which gave us the flag:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/hype2-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/hype2-1.png" height="183" width="400" /></a>
</div>