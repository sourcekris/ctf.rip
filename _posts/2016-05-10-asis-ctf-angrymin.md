---
id: 741
title: 'ASIS CTF 2016 - Angrymin - Misc Challenge'
date: 2016-05-10T13:21:51+00:00
author: 0pc0d3
layout: post
guid: https://ctf.rip/?p=741
permalink: /asis-ctf-angrymin/
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
  - "1451"
image: /images/2016/05/an1.png
categories:
  - Write-Ups
tags:
  - asis
  - juniper backdoor
  - misc
---
<img src="/images/2016/05/angrymin.png" alt="angrymin" width="604" height="880" class="alignnone size-full wp-image-742" srcset="/images/2016/05/angrymin.png 604w, /images/2016/05/angrymin-206x300.png 206w" sizes="(max-width: 604px) 100vw, 604px" />

Guest post by team member 0pc0d3 today, thanks Opc0d3 damn that name is hard to type.

Firstly, we check the firewall. However, the URL does not resolve to an address.

<img src="/images/2016/05/an1.png" alt="an1" width="618" height="342" class="alignnone size-full wp-image-743" srcset="/images/2016/05/an1.png 618w, /images/2016/05/an1-300x166.png 300w" sizes="(max-width: 618px) 100vw, 618px" />

So let's have a look at the documents and manuals that the angry admin backed up.

<img src="/images/2016/05/an2.png" alt="an2" width="609" height="251" class="alignnone size-full wp-image-744" srcset="/images/2016/05/an2.png 609w, /images/2016/05/an2-300x124.png 300w" sizes="(max-width: 609px) 100vw, 609px" />

Unpacking it, we can see that the document allows us to identify the firewall is a Juniper firewall and the version could be around 6.3.0, which is vulnerable to <a href="https://community.rapid7.com/community/infosec/blog/2015/12/20/cve-2015-7755-juniper-screenos-authentication-backdoor" target="_blank">CVE-2015-7755</a>. This vulnerability pertains to a backdoor password in ScreenOS. However, we will need to find the firewall.

Running the "host" command, we can see that the firewall is using IPv6.


```
juniper.asis-ctf.ir has IPv6 address 2406:d501::613c:a652
```


We quickly spin up a DO Droplet with an IPv6 interface allows us to reach out to our firewall.


```
root@angry:~# nmap -A -T4 -6 2406:d501:0:0:0:0:613c:a652

Starting Nmap 6.40 ( http://nmap.org ) at 2016-05-07 07:22 EDT
Warning: 2406:d501::613c:a652 giving up on port because retransmission cap hit (6).
Nmap scan report for 2406:d501::613c:a652
Host is up (0.22s latency).
Not shown: 992 closed ports
PORT    STATE    SERVICE    VERSION
22/tcp  open     ssh        OpenSSH 6.0p1 Debian 4+deb7u1 (protocol 2.0)
| ssh-hostkey: 1024 26:c5:a6:f3:68:fc:12:86:65:2b:8e:2b:cc:a0:62:2b (DSA)
|_2048 77:03:0f:db:66:9e:22:f7:d1:91:36:66:d6:0d:5e:9a (RSA)
```


Now all we need to do is SSH into the firewall, use the backdoor password `<<< %s(un='%s') = %u` and we're at the home stretch. However, the user names "root" nor "system" did not work. After trying several expected user names, we go back hunting for a valid username. The last piece of our puzzle.

We then realized that tar keeps a record of the username of the archive's creator, and via the "-t" parameter, we found the user name we needed.

<img src="/images/2016/05/an3.png" alt="an3" width="727" height="296" class="alignnone size-full wp-image-745" srcset="/images/2016/05/an3.png 727w, /images/2016/05/an3-300x122.png 300w" sizes="(max-width: 727px) 100vw, 727px" />

Our elusive username is `craigswright`.

<img src="/images/2016/05/an4.png" alt="an4" width="740" height="171" class="alignnone size-full wp-image-746" srcset="/images/2016/05/an4.png 740w, /images/2016/05/an4-300x69.png 300w" sizes="(max-width: 740px) 100vw, 740px" />

Flag: ASIS{wh0\_1n\_h15\_r16h7\_m1nd\_w0uld\_b3l13v3\_cr416\_wr16h7\_15\_54705h1_n4k4m070}