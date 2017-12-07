---
id: 228
title: 'HUST Festival - Network 300 Challenge'
date: 2015-05-24T07:08:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=228
permalink: /hust-festival-network-300-challenge/
post_views_count:
  - "398"
image: /images/2015/05/1-6.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
HUST festival was this weekend and we participated although many parts of the festival were Korean language, they made a great effort to put English clues in for all the challenges.

This challenge was one of the earliest available so we tackled it first. It was pretty much just a PCAP file with instructions to connect to an IP address on port 22.

We downloaded the file, unzipped it and found the PCAP to be pretty large in size:
  
```
root@mankrik:~/hust/net300# unzip net_7be01f8e.zip 
Archive:  net_7be01f8e.zip
  inflating: league_of_access.pcap   
root@mankrik:~/hust/net300# file league_of_access.pcap 
league_of_access.pcap: pcap-ng capture file - version 1.0
root@mankrik:~/hust/net300# ls -lah league_of_access.pcap 
-rw-r--r-- 1 root root 9.1M May 22 15:09 league_of_access.pcap
```

Whenever I have a bigger PCAP I use a Windows program called <a href="http://www.netresec.com/?page=NetworkMiner" target="_blank">Network Miner</a> to get a graphical overview of different attributes of the traffic in the PCAP. Network Miner needs a PCAP file (i.e. not a PCAP-NG file) so I used Wireshark to "Save As" a PCAP file before importing it into Network miner.

In Network Miner, I used the Session window to sort the connections found in the PCAP by different attributes. I sorted by "Server Port" column to notice that the user conducted a port scan against the target server

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://3.bp.blogspot.com/-qN48r_1n0nc/VWFvNHsWz5I/AAAAAAAAALU/79tAdBpLwWc/s1600/1.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="424" src="/images/2015/05/1-6.png" width="640" /></a>
</div>

I then checked the SSH connections and noted the timestamps of the connections. I noted that the final SSH connection attempts happened some minutes after the port scan completed.

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-wAIK5NOW4cc/VWFvpJFW7KI/AAAAAAAAALc/IhZnItK1jHU/s1600/2.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="164" src="/images/2015/05/2-6.png" width="640" /></a>
</div>

I then examined some of the other tabs in Network miner. In the Parameters window I noticed quite a few Referrer entries from a Russian blog post about "port knocking":

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/-oRmd2hDOMuE/VWFwZ1MFXrI/AAAAAAAAALs/qEZkt1Y9HYA/s1600/3.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="122" src="/images/2015/05/3-4.png" width="640" /></a>
</div>

I also found some more "port knocking" hints in the DNS tab:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://3.bp.blogspot.com/-G8Q3q5GtBSk/VWFw7XUL2XI/AAAAAAAAAL0/RddZwdwgsqY/s1600/4.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="48" src="/images/2015/05/4-4.png" width="640" /></a>
</div>

Lastly, there was a couple of other things I noted in the images tab, a few items mentioning "hidden files":

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-hjRif00FtTc/VWFxyQ1dr1I/AAAAAAAAAME/yw8Mq0jTyWw/s1600/5.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="103" src="/images/2015/05/5-4.png" width="320" /></a>
</div>

Ok so now I feel it's time to switch over to Wireshark because I have a good idea of the method of attack here:

  1. Port knocking, to open an SSH port
  2. Hidden files on the host

<div>
</div>

In Wireshark I setup a filter to just examine traffic to/from this host in question:

  * "ip.src == 223.194.105.178 or ip.dst == 223.194.105.178"

Next, I scrolled down to the Frame #'s shown during the Network Miner investigation to see if the user was able to successfully get that SSH fired up.

First I double checked that the user was still getting failed SSH connections, and at Frame # 10905 & 10932 I see a failed connection attempt.

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://3.bp.blogspot.com/-8MXO5zHpiLs/VWF0qsVZjbI/AAAAAAAAAMU/DYL4Jvsthmg/s1600/6.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="82" src="/images/2015/05/6-4.png" width="640" /></a>
</div>

Then later, at frame 10967 & 10968 a successful connection is found:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/--sEr1QHB220/VWF09gXjYKI/AAAAAAAAAMc/aB0pB6O9pkY/s1600/7.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="20" src="/images/2015/05/7-2.png" width="640" /></a>
</div>

So what changed between 10905 and 10967? Well we're thinking port knocking so let's see if we can see a weird bunch of connection attempts before this and see the following:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://4.bp.blogspot.com/-IRtyCDAmjoo/VWF2YqasrSI/AAAAAAAAAMs/3H3TMtPbSGk/s1600/8.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="128" src="/images/2015/05/8-2.png" width="640" /></a>
</div>

At this point im not 100% sure which of these are port knocking and which is just coincidental traffic. So I decided to try all of it. I came with the following command line:

```
root@mankrik:~/hust/net300# nmap -sS -p T:80,4523,2351,2351,4523,443 223.194.105.178; ping -c 1 -t 1 223.194.105.178; icmpush -tstamp -seq 0 -id 13970 -to 1 223.194.105.178; ssh you@223.194.105.178
```

Which actually worked first go. So either I got right or I got lucky.

Anyway, once on the server getting the flag was pretty simple. Using the clue of "hidden" files I expected there to be a file beginning with "." and sure enough there was:

```
-bash-4.1$ find
.
./.bashrc
./.bash_logout
./.bash_profile
./.bashc
./.bash_history
-bash-4.1$ id
uid=500 gid=500(you) groups=500(you)
-bash-4.1$ cat .bashc


++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++
++++++++-----------------+++++++++
+++++++|                 |++++++++
+++++++| Hari60_iz_B3s+! |++++++++
+++++++|                 |++++++++
++++++++-----------------+++++++++
++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++
-bash-4.1$ exit
```