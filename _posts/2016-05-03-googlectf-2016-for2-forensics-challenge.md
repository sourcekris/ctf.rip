---
id: 710
title: 'GoogleCTF 2016 -for2 - Forensics Challenge'
date: 2016-05-03T12:34:31+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=710
permalink: /googlectf-2016-for2-forensics-challenge/
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
  - "1714"
image: /images/2016/05/for2.png
categories:
  - Write-Ups
tags:
  - forensics
  - pcap
  - usb
---
Really quick writeup while I remember. The clue consists of a pcap only. <a href="https://github.com/sourcekris/ctf-solutions/raw/master/forensics/google16-for2/capture.pcapng" target="_blank">The pcap</a> contains USB packet captures. 

<img src="/images/2016/05/for2.png" alt="for2" width="892" height="567" class="alignnone size-full wp-image-711" srcset="/images/2016/05/for2.png 892w, /images/2016/05/for2-300x191.png 300w, /images/2016/05/for2-768x488.png 768w" sizes="(max-width: 892px) 100vw, 892px" />

We identify the type of USB device by using the vendor ID and the product ID which are announced in one of the types of USB packets.


```
root@kali:~/google/for/for2# tshark -r usb.pcap -T fields -e usb.bus_id -e usb.device_address -e usb.idVendor -e usb.idProduct "usb.idVendor > 0" 2>/dev/null
1   3   1133    0x0000c05a
```


We lookup this number online to find it is a Logitech M90/M100 mouse. Ok so mouse movement packets. We also note the second field here which is the USB device_address field.

We know these kinds of packets contain basically x,y and mouse button data in a field called "usb.capdata". Using tshark we can extract it:


```
root@kali:~/google/for/for2# tshark -r capture.pcapng -T fields -e usb.capdata usb.capdata and usb.device_address==3 2> /dev/null | head -5
00:01:fe:00
00:01:ff:00
00:02:00:00
00:03:00:00
00:01:00:00
```


The coordinates (bytes 2 and 3) are signed integer relative offsets from some initial X,Y position. So values > 127 are negative. The first byte indicates whether the left mouse button is down or not.

We write quick python code to extract the coordinates and draw us a picture of every pixel where the mouse button is down.


```
#!/usr/bin/python

from PIL import Image, ImageDraw
from subprocess import check_output

print "[*] Extracting data from pcap"
with open('/dev/null') as DN:
    md = [x.strip() for x in check_output(['tshark','-r','capture.pcapng','-Tfields','-e','usb.capdata','usb.capdata','and','usb.device_address==3'],stderr=DN).splitlines()]

x = 1000    # origin coords
y = 300

img = Image.new("RGB",(1200,800),"white")
dr = ImageDraw.Draw(img)

print "[*] Drawing you a picture!"
for line in md:
    coords = [j if j<128 else (j-256) for j in [int(k,16) for k in line.split(':')]]
    x += coords[1]
    y += coords[2]
    if coords[0] != 0:
        dr.rectangle(((x - 2, y - 2), (x + 2, y + 2)), fill="black")

img.show()
```


Which shows us the flag and a cool kitty cat!

<img src="/images/2016/05/for2flag.png" alt="for2flag" width="1208" height="629" class="alignnone size-full wp-image-712" srcset="/images/2016/05/for2flag.png 1208w, /images/2016/05/for2flag-300x156.png 300w, /images/2016/05/for2flag-768x400.png 768w, /images/2016/05/for2flag-1024x533.png 1024w" sizes="(max-width: 1208px) 100vw, 1208px" />

A fun problem and a quick solve!