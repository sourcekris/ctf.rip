---
id: 853
title: 'SECCON 2016 Quals - Memory Analysis - Forensics Challenge'
date: 2016-12-11T08:22:09+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=853
permalink: /seccon-2016-quals-memory-analysis-forensics-challenge/
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
  - "907"
image: /images/2016/12/seccon.png
categories:
  - Write-Ups
tags:
  - forensics
  - memory analysis
---
Very unimaginativly entitled challenge with a lot of hints should have been pretty straightforward. And yeah it was pretty much so a very quick writeup this time. The clue was:

> Memory Analysis
  
> 100 points
> 
> Find the website that the fake svchost is accessing.
  
> You can get the flag if you access the website!!
> 
> memoryanalysis.zip
  
> The challenge files are huge, please download it first.
  
> Hint1: http://www.volatilityfoundation.org/
  
> Hint2: Check the hosts file

Gotta respect that clue, straight to the point. We downoad the image and ask Volatility to identify it using `imageinfo`. 
```
root@kali:~/seccon/memory# volatility -f forensic_100.raw imageinfo
Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/root/seccon/memory/forensic_100.raw)
                      PAE type : PAE
                           DTB : 0x34c000L
                          KDBG : 0x80545ce0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-12-06 05:28:47 UTC+0000
     Image local date and time : 2016-12-06 14:28:47 +0900

```
 

Windows XP, haven't seen one of these in a while. We try the suggested profile using `pslist` and it works. We start about identifying this nasty fake svchost process, which can it be? 
```
root@kali:~/seccon/memory# volatility -f forensic_100.raw pslist | grep svchost
Volatility Foundation Volatility Framework 2.5
0x81e18da0 svchost.exe             848    672     20      216      0      0 2016-12-06 05:27:08 UTC+0000                                 
0x82151ca8 svchost.exe             936    672     10      272      0      0 2016-12-06 05:27:08 UTC+0000                                 
0x82312450 svchost.exe            1036    672     87     1514      0      0 2016-12-06 05:27:08 UTC+0000                                 
0x81f92778 svchost.exe            1088    672      7       83      0      0 2016-12-06 05:27:08 UTC+0000                                 
0x81e41928 svchost.exe            1320    672     12      183      0      0 2016-12-06 05:27:10 UTC+0000                                 
0x81e4f560 svchost.exe            1704    672      5      107      0      0 2016-12-06 05:27:10 UTC+0000                                 
0x81f65da0 svchost.exe            1776    672      2       23      0      0 2016-12-06 05:27:10 UTC+0000                                 
```
 

I assumed it would be a later PID so I work backwards and `procdump` each binary to quickly check which looks legit and which looks fake. The strings output of PID 1704 compared for PID 1776 quickly tells me that its likely that 1776 is the fake svchost process. 
```
root@kali:~/seccon/memory# volatility -f forensic_100.raw -p 1704 -D dump procdump
Volatility Foundation Volatility Framework 2.5
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x81e4f560 0x01000000 svchost.exe          OK: executable.1704.exe
root@kali:~/seccon/memory# volatility -f forensic_100.raw -p 1776 -D dump procdump
Volatility Foundation Volatility Framework 2.5
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x81f65da0 0x00400000 svchost.exe          OK: executable.1776.exe
root@kali:~/seccon/memory/dump# strings executable.1776.exe | grep pdb
D:\Temp\code_sample\jdmbackgroundprocess\Release\JDMBackgroundProcessTest.pdb
root@kali:~/seccon/memory/dump# strings executable.1704.exe | grep pdb
svchost.pdb
```
 

Other strings in the 1776 procdump binary indicate this process spawns a web connection by calling Internet Explorer with the command: C:\Program Files\Internet Explorer\iexplore.exe http://crattack.tistory.com/entry/Data-Science-import-pandas-as-pd

If we go to that site now though there is just a Japanese blog about Data Science among other topics. No sign of a flag.

At this point I considered the importance of all of the clue pieces. What does the "Check the hosts file" mean?
   
I used the volatility `dumpfiles` module to dump cached files from the memory dump but the Windows OS "hosts" file was not cached at the time of the dump so this was not helpful.

I also tried the `sockets` command but again, there were no actual active connections during the time of the memory dump. 
```
root@kali:~/seccon/memory# volatility -f forensic_100.raw --profile=WinXPSP3x86 sockets
Volatility Foundation Volatility Framework 2.5
Offset(V)       PID   Port  Proto Protocol        Address         Create Time
---------- -------- ------ ------ --------------- --------------- -----------
0x81e2aa70        4      0     47 GRE             0.0.0.0         2016-12-06 05:27:20 UTC+0000
0x8216fe98     1320   1900     17 UDP             192.168.88.131  2016-12-06 05:27:16 UTC+0000
0x81e37e98     1080   1034      6 TCP             0.0.0.0         2016-12-06 05:27:21 UTC+0000
0x81f15e98        4    139      6 TCP             192.168.88.131  2016-12-06 05:27:12 UTC+0000
0x82173650      684    500     17 UDP             0.0.0.0         2016-12-06 05:27:13 UTC+0000
0x81f46b80     1080   1033     17 UDP             127.0.0.1       2016-12-06 05:27:21 UTC+0000
0x822b0258     2028   1028      6 TCP             127.0.0.1       2016-12-06 05:27:16 UTC+0000
0x81a3de98        4    445      6 TCP             0.0.0.0         2016-12-06 05:26:58 UTC+0000
0x8215f2a0      936    135      6 TCP             0.0.0.0         2016-12-06 05:27:08 UTC+0000
0x81e49e98        4    137     17 UDP             192.168.88.131  2016-12-06 05:27:12 UTC+0000
0x81f13e98     1036    123     17 UDP             127.0.0.1       2016-12-06 05:27:13 UTC+0000
0x822b4430      684      0    255 Reserved        0.0.0.0         2016-12-06 05:27:13 UTC+0000
0x81e127e0        4    138     17 UDP             192.168.88.131  2016-12-06 05:27:12 UTC+0000
0x81f6e7e0        4   1032      6 TCP             0.0.0.0         2016-12-06 05:27:20 UTC+0000
0x81e88b30     1036    123     17 UDP             192.168.88.131  2016-12-06 05:27:13 UTC+0000
0x81e1ce98     1320   1900     17 UDP             127.0.0.1       2016-12-06 05:27:16 UTC+0000
0x81f9b550      684   4500     17 UDP             0.0.0.0         2016-12-06 05:27:13 UTC+0000
0x81a3d008        4    445     17 UDP             0.0.0.0         2016-12-06 05:26:58 UTC+0000
```
 

About now I decided perhaps the clue wasn't about checking the target system's hosts file, what about my own hosts file? Perhaps when the memory dump was taken the IP address of this http://crattack.tistory.com/ was different. I recalled earlier I had seen a tcpview.exe process running in the `pslist`. I dumped that process' memory: 
```
root@kali:~/seccon/memory# volatility -f forensic_100.raw --profile=WinXPSP3x86 pslist | grep tcp
Volatility Foundation Volatility Framework 2.5
0x819b4380 tcpview.exe            3308   1556      2       84      0      0 2016-12-06 05:28:42 UTC+0000                                 
root@kali:~/seccon/memory# volatility -f forensic_100.raw --profile=WinXPSP3x86 -p 3308 -D dump memdump
Volatility Foundation Volatility Framework 2.5
************************************************************************
Writing tcpview.exe [  3308] to 3308.dmp

```
 

After some quick searching through the strings output we see this interesting combination: 
```
crattack.tistory.com:http
153.127.200.178:80
```
 

However the site today resolves as follows: 
```
root@kali:~/seccon/memory/dump# host crattack.tistory.com
crattack.tistory.com has address 175.126.170.110
```
 

A bit of hosts file twiddling later... 
```
root@kali:~/seccon/memory/dump# echo 153.127.200.178 crattack.tistory.com >> /etc/hosts
root@kali:~/seccon/memory/dump# curl http://crattack.tistory.com/entry/Data-Science-import-pandas-as-pd
SECCON{_h3110_w3_h4ve_fun_w4rg4m3_}
```

Done!