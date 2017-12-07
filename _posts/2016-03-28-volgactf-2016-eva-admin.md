---
id: 672
title: 'VolgaCTF 2016 - Eva - 300 Point Admin Challenge'
date: 2016-03-28T10:54:50+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=672
permalink: /volgactf-2016-eva-admin/
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
  - "1438"
image: /images/2016/03/volga.jpg
categories:
  - Write-Ups
tags:
  - admin
  - raid
  - volga
---
VolgaCTF stepped up the difficulty this year over last year. Good stuff! Too bad they decided not to use IRC because they probably could've done a better job communicating. There were a lot of server issues and the programming (PPC) challenges were built to require way too many rounds. Tic-tac-toe was 2,000 rounds to begin with but it was quickly obvious the servers couldn't handle the intered. Anyway! I digress from this writeup too much.

<img class="size-full wp-image-674 aligncenter" src="/images/2016/03/eva.png" alt="eva" width="598" height="263" srcset="/images/2016/03/eva.png 598w, /images/2016/03/eva-300x132.png 300w" sizes="(max-width: 598px) 100vw, 598px" />

Eva was a "admin" category challenge. We're given an archive containing files labeled part0 - part9 and a JPG file called key.jpg. The JPG is just a Volga CTF logo and there's no steganographic features it seems.




```
root@kali:~/volga/admin/eva# tar Jtvf eva.tar.xz
drwxr-xr-x serg/serg         0 2016-03-26 15:42 volgactf/
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part5
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part7
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part2
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part1
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part6
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part3
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part8
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part0
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part9
-rw-r--r-- serg/serg 104857600 2016-03-26 15:38 volgactf/part4

```


Upon extracting the archive and using the file command, each one of them checks out as an individual file system in itself.


```
root@kali:~/volga/admin/eva/volgactf# file part0
part0: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x0,32,33), end-CHS (0xc,190,50), startsector 2048, 202752 sectors, extended partition table (last)
root@kali:~/volga/admin/eva/volgactf# file part8
part8: DOS/MBR boot sector; partition 1 : ID=0x83, start-CHS (0x0,32,33), end-CHS (0xc,190,50), startsector 2048, 202752 sectors, extended partition table (last)

```


I wonder if these are part of a RAID array of some kind? There's an easy way to find out, just use `mdadm`:


```
root@kali:~/volga/admin/eva/volgactf# mdadm --misc --examine ./part0
./part0:
          Magic : a92b4efc
        Version : 1.2
    Feature Map : 0x0
     Array UUID : 76511602:3cb6e647:c8dea76f:2238c348
           Name : hdhog:0
  Creation Time : Sat Mar 26 08:33:43 2016
     Raid Level : raid5
   Raid Devices : 10

 Avail Dev Size : 202752 (99.00 MiB 103.81 MB)
     Array Size : 912384 (891.00 MiB 934.28 MB)
    Data Offset : 2048 sectors
   Super Offset : 8 sectors
   Unused Space : before=1960 sectors, after=0 sectors
          State : clean
    Device UUID : 54e5dac0:3dce3647:8d9e7a76:500f7a9a

    Update Time : Sun Mar 27 19:21:19 2016
  Bad Block Log : 512 entries available at offset 72 sectors
       Checksum : e1fff176 - correct
         Events : 22

         Layout : left-symmetric
     Chunk Size : 512K

   Device Role : Active device 9
   Array State : AAAAAAAAAA ('A' == active, '.' == missing, 'R' == replacing)

```


Sweet, this says a lot. It's part of a RAID5 with 9 devices and at the time it was last operating the array was in a clean state. We have a chance to recover this! First I create some loopback devices:


```
root@kali:~/volga/admin/eva/volgactf# cat makeloopbacks.sh 
#!/bin/bash

NUM=0

while [ $NUM -le 9 ] 
do
    echo "Looping back part"$NUM" to /dev/loop"$NUM
    losetup /dev/loop"$NUM" /root/volga/admin/eva/volgactf/part"$NUM"
    let NUM=$NUM+1
done

```


Next I ask mdadm to assemble the array device for me:


```
root@kali:~/volga/admin/eva/volgactf# ./makeloopbacks.sh 
Looping back part0 to /dev/loop0
Looping back part1 to /dev/loop1
Looping back part2 to /dev/loop2
Looping back part3 to /dev/loop3
Looping back part4 to /dev/loop4
Looping back part5 to /dev/loop5
Looping back part6 to /dev/loop6
Looping back part7 to /dev/loop7
Looping back part8 to /dev/loop8
Looping back part9 to /dev/loop9

root@kali:~/volga/admin/eva/volgactf# mdadm --assemble /dev/md1 /dev/loop0 /dev/loop1 /dev/loop2 /dev/loop3 /dev/loop4 /dev/loop5 /dev/loop6 /dev/loop7 /dev/loop8 /dev/loop9
mdadm: /dev/md1 has been started with 10 drives.

```


And lo and behold, Ubuntu helpfully spots the new device and mounts it up for me. I am now at the next phase of the challenge. I have the filesystem assembled but where's the flag? Let's look at what's in the RAID array. The first clue is in the drives list:

<img class="alignnone size-full wp-image-675" src="/images/2016/03/drives.png" alt="drives" width="957" height="479" srcset="/images/2016/03/drives.png 957w, /images/2016/03/drives-300x150.png 300w, /images/2016/03/drives-768x384.png 768w" sizes="(max-width: 957px) 100vw, 957px" />

Encrypted filesystem huh?

Well we were given a "key" right? The clue contains key.jpg. Let's try the text from the image "VolgaCTF" ... Nope...

<img class="size-full wp-image-676 aligncenter" src="/images/2016/03/error.png" alt="error" width="490" height="225" srcset="/images/2016/03/error.png 490w, /images/2016/03/error-300x138.png 300w" sizes="(max-width: 490px) 100vw, 490px" />

Wait a minute, I'm pretty sure you can use "keyfiles" with LUKS right? A few minutes googling gets me the details and the right command to try:


```
root@kali:~/volga/admin/eva/volgactf# cryptsetup luksOpen "/dev/dm-0" "luks-f014690f-667c-459d-b9fe-12dac88d7a4f"  --key-file key.jpg

```


And there's no output but suddenly the disk icon changes to an unlocked padlock... That's good!

<img class="size-full wp-image-677 aligncenter" src="/images/2016/03/unlock.png" alt="unlock" width="302" height="93" srcset="/images/2016/03/unlock.png 302w, /images/2016/03/unlock-300x92.png 300w" sizes="(max-width: 302px) 100vw, 302px" />

I browse to some ungodly folder where Kali has mounted my newly unencrypted files and issue the old trusty flag-hunter command and get the flag:


```
root@kali:/media/root/8e75fd62-e427-4a32-b0fb-a81c152683d2# find . -type f -exec strings {} \;| grep VolgaCTF
4.5.0-gentoo-VolgaCTF{NlTTkaMXwypzOiMDWiUGYw==} (root@hdhog) #6 SMP Sat Mar 26 02:30:56 SAMT 2016

```


Thanks! Fun one and now I can wield a RAID5 array in Linux so I learned something.