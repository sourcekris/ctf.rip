---
id: 787
title: 'SecurityFest 2016 CTF - QRack - Misc Challenge'
date: 2016-06-06T02:35:06+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=787
permalink: /securityfest-2016-ctf-qrack-misc-challenge/
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
  - "1108"
image: /images/2016/06/banner.png
categories:
  - Write-Ups
tags:
  - filesystem
  - undelete
---
Only got to spend 2 hours on this CTF sadly as it was mid-week for me. Sadly because the site was so well designed and the challenges seemed reasonably set. Anyway this was one of the few I solved and I was drawn to it because - QR codes - who doesn't love those?

Heres the clue:

> **QRack - Misc (100)**
> 
> We recovered this from a crashed spaceship. All we know is that aliens love QR, but we humans hate it ...
> <a href="http://dl.securityfest.ctf.rocks/qr.tar.gz" target="_blank">qr.tar.gz</a>

When we download the tarball it extracts to just one file: 
```
 root@kali:~/securityfest# tar xvf qr.tar.gz
img
```
Which seems to be a filesystem:
```
 root@kali:~/securityfest# file img
img: Linux rev 1.0 ext4 filesystem data, UUID=50bdf51b-9895-4a7b-8fbc-2a308ea9ffea (extents) (huge files)[/sh] 

We mount it and see what we have:
[sh]root@kali:~/securityfest# mkdir mnt
root@kali:~/securityfest# mount img mnt
root@kali:~/securityfest# ls mnt
_ { a C e f g H I lost+found N O R S T U Y
, } A D E F h i l n o Q s t u W
root@kali:~/securityfest# file mnt/a
mnt/a: ASCII text
```
A load of ASCII text files containing... 
```
root@kali:~/securityfest# cat mnt/a
H4sIALzISlcAA91VsRHDMAjss4KajO...0PkxnQgBDzwUttf7/4sS9u3/mh3
jfFRtm6dxvk4G/rX0+rOTZrLYDWKS6...xPwj+Z0cU28qitqylgXbMwsOsYy
O6xEm4huETS4NprF7yXCIPGJMBtanG...Gi5tfwGcczytBb1v9IZiU2LmCu/
T24HK6/UqTKY+ddpyW/GuehZUlPP1e...FhGrtC1p1sdyuxgHL7TAr2QM
AAA=
```
Base64 encoded data. Which are Gzip'd files containing ASCII QR codes.

<img src="/images/2016/06/qrack2.png" alt="qrack2" width="735" height="560" class="alignnone size-full wp-image-790" srcset="/images/2016/06/qrack2.png 735w, /images/2016/06/qrack2-300x229.png 300w" sizes="(max-width: 735px) 100vw, 735px" />

So it looks like our task might be to deduce the flag from the QR codes. I scanned each of the codes and each QR code just gives us the letter than corresponds to it's filename. So the order of the letters is the missing piece. One thing that occurred to me at this point is; Why was this challenge delivered in a filesystem? Why not just a tarball? 

One of the things is that you can hide things in filesystems. Let's check the most obvious place to hide stuff in filesystems; Deleted files: 
```
 root@kali:~/securityfest# extundelete -restore-all img
NOTICE: Extended attributes are not restored.
Loading filesystem metadata ... 2 groups loaded.
Loading journal descriptors ... 35 descriptors loaded.
Searching for recoverable inodes in directory / ...
1 recoverable inodes found.
Looking through the directory structure for deleted files ...
0 recoverable inodes still lost.

root@kali:~/securityfest# file RECOVERED_FILES/all
RECOVERED_FILES/all: ASCII text

root@kali:~/securityfest# head -4 RECOVERED_FILES/all
H4sIAB7JSlcAA91UQQ7DMAi77...GISlO5kRCwCaYd+6s/09aOrT/a
XXOcztZt0Lgfd8P/RFp/8ZLWM...EE4r1/uhgTR3UFJuW0YGJmi3NM
q8OaN4noFWGDsdEq616uOUgap...9/4eE+fRtQTF5r
lonxK2Q6YSDr3pPzJbqRb3+fb...c72+a8jAwAAA==
```
Sure enough there's 1 deleted file. I looks to be the missing piece of the puzzle as it is the flag encoded in base64 encoded, gzipped, QR codes. At this point i figure two ways to decode this. Decode all the chunks stored in the 'all' file, scan or automate the scanning of the QR codes to produce the flag. This seems possible. 

The easier way to do it is just extract the base64 encodings, hash them, then compare the file hashes to the existing files on the filesystem.

Unfortunately each encoded file has a slightly different base64 encoded version in the 'all' file versus the standalone file version. Possibly due to the way gzip stored the data in each compressed file. No matter, there's other constant data that exists between the 'all' file and the individual character files.

So we solve this with a giant loop nest where I split the 'all' file into a list of it's sub-parts. Each sub-part is stored of a list of 3-4 lines. I then iterate the main list looking for matches in the sub-part's lines. I compare each line with the list of lines from the individual files. When i find a match I assign that sub-part the letter where I found the match.

A simpler way, in hindsight, may have been to hash just part of the base64 encoded chunks. Say, the second line. However it's done now.

Here is the Python solution. 
```
#!/usr/bin/python
import glob
import sys
files = glob.glob("*")
files.remove('solve.py')
files.remove('all')
alldata = [x.strip() for x in open('all').readlines()]
b64chunks = []
l = 0
while l < len(alldata):
    fourblock = []
    fourblock.extend(alldata[l:l+4])
    try:
        if alldata[l+3].endswith('=') or alldata[l+3].endswith('AAA'):
            b64chunks.append(fourblock)
            l += 4
        else:
            fourblock.append(alldata[l+4])
            b64chunks.append(fourblock)
            l += 5
    except IndexError:
        break
filechunks = {}
for f in files:
    filechunks[f] = [x.strip() for x in open(f).readlines()]
for subchunk in b64chunks:
    gotit = False
    for piece in subchunk:  # the base64 chunk is piece
        if len(piece) > 10:
            for f in filechunks: # f is the filename
                for fsub in filechunks[f]:
                    if fsub == piece:
                        sys.stdout.write(f)
                        gotit = True
                        break
                if gotit:
                    break
print 
```

Which gives us the flag... 
```
root@kali:~/securityfest/misc/qrack/files# ./solve.py
Hello,,,SoYouWantTheFlag\_,,,{}aACDeEfFghHiIlnNoOQRsStTuUWYTheflagsisCODE{I\_HATE\_YOU\_AND_QR}
```
