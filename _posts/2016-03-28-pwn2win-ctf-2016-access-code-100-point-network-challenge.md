---
id: 664
title: 'Pwn2Win CTF 2016 - Access Code - 100 Point Network Challenge'
date: 2016-03-28T10:10:31+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=664
permalink: /pwn2win-ctf-2016-access-code-100-point-network-challenge/
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
  - "1380"
image: /images/2016/03/wireshark.jpg
categories:
  - Write-Ups
tags:
  - network
  - pwn2in
---
Cool Brazillian based CTF which I haven't played before. One of the remarkable things about this CTF was the sheer number and breadth of challenges we could go for. They had everything from Electronics to Crypto to Reversing to Physics and Programming challenges! For this one we finished in 10th place so I am very happy with our team work!

This challenge was solved by very few teams so it's worth a writeup. We're given a hostname and IP address and some back story and while I can't access the dashboard right now to give the exact clue, the gist of it was; use your networking skills to find the flag.

**Update**: They released the descriptions:

> SkySoldier86 analyzed the leaked e-mails from the Hacking Team, and has found out that the Club has hired them back in 2014 to develop a new authentication system to their secret servers, Method based in client/server. We managed to access the 'prototype' of the server, that apparently it's finished, but not the client. Your mission is to unveil how it works, for it will be very useful in the future.
> 
> `nc access.pwn2win.party 8111`
So "use your network skills" said to me, get a pcap. So I first tried connecting to the host from my own system. Unfortunately I didn't get very far. I switched to using a EC2 instance and modified the security group to \*gasp\* allow all IP... The wireshark output above is what I first saw. Here's the highlights:

  * Frames 6 - 12 : Return traffic from our outbound connection made from my EC2 to the `access.pwn2win.party` server
  * Frame 14: SYN packet from the server back to us on port 1110/tcp (we're not listening here so my server just sends a `RST` in response)
  * Frames 18-34: `SYN` packets on multiple low destination ports towards our server.
  * Frames 38+: Related to our original outbound connection

Ok so that's interesting. A hint was released on IRC about "understand the control packet". At this point the challenge started to become clear. I setup two things:

  * Netcat on port 1110/tcp
  * IPTables redirects for all ports 100-500 to another netcat listener on another port

I then connected back to the CTF server and got the next key piece of information. On port 1110/tcp I received the message `xor 221`. Cool!  The other ports gave no additional information when their connections were allowed so I then disabled the IPTables redirect. The plan of action was:

  * Grab the "control packet" from port 1110/tcp
  * Listen for incoming connections on port 100-500, store the tcp.dstport value of each
  * Apply the control packet operation to each integer tcp.dstport value
  * Send the concatenated list of them back to the server

I used two things to accomplish this. Tshark and Python. The following Tshark command was executed:


```
tshark -i eth0 -Tfields -e tcp.dstport src host 104.236.81.9 and portrange 100-500 2> /dev/null > ports.txt
```


Simultaneously I ran this Python script.


```
#!/usr/bin/python

import time
import sys
from pwn import *

host = 'access.pwn2win.party'
port = 8111
control_port = 1110

response = ""
prefix = "Code"

# outbound channel
conn = remote(host,port)

# control channel
l = listen(port=control_port, bindaddr='0.0.0.0')
c = l.wait_for_connection()
control_packet = c.recvline()
c.close()

print "[+] Received control packet: " + control_packet.strip()
op = control_packet.split()[0].replace("xor", "^").replace("mod","%")
cv = int(control_packet.split()[1].strip())

banner = conn.recvuntil('Code?')
print "[*] Code should be ready, killing tshark."
subprocess.call(['killall','-TERM','tshark'])
time.sleep(1)
ports = open('ports.txt','r').readlines()
if len(ports) > 1:
    print "[*] Got ports", repr(ports)
    for p in ports:
        p = int(p.strip())
        r = eval(str(p)+op+str(cv))
        print "[.] ", p,op,cv,"=",r
        response += str(r) 
        
response = prefix + response
print "[>] Sending: " + str(response)
conn.sendline(response)
result = conn.recvline()

if 'Wrong Key' in result:
    print "[-] Failed: " + result
    conn.close()
    quit()

conn.interactive()

```


You might spot the important part in the above Python though? The `prefix="Code"`. That was the real challenge, guessing this was needed. I believe this challenge probably would have had a lot more solvers had that been explained in the clue.

Nonetheless we solved it and moved on 100 points richer!