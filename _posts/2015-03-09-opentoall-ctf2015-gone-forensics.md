---
id: 247
title: 'OpenToAll CTF2015 - Gone (Forensics)'
date: 2015-03-09T15:58:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=247
permalink: /opentoall-ctf2015-gone-forensics/
blogger_bid:
  - "7326167176284420232"
blogger_blog:
  - ctf.rip
blogger_id:
  - "4033276666526541849"
blogger_author:
  - "18405699329239146182"
blogger_comments:
  - "0"
blogger_permalink:
  - /2015/03/opentoall-ctf2015-gone-forensics.html
blogger_thumbnail:
  - http://4.bp.blogspot.com/-J6PYMnw4l2M/VP3CwI7ANVI/AAAAAAAAAB8/63zZIFZ_QRo/s1600/gone4.PNG
post_views_count:
  - "530"
image: /images/2015/03/gone4-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---

This challenge in the forensics genre had only the following as the clue:

>It seems that my files are gone!
><a href="https://github.com/ctfs/write-ups-2015/blob/master/opentoall-ctf-2015/forensics/gone/gone.img.tar.bz2" style="background: transparent; box-sizing: border-box; line-height: 25.6000003814697px; text-decoration: none;">http://public.givemesecurity.info/gone.img.tar.bz2</a>

Upon downloading and decompressing the gone.img.tar.bz2 file you find a Linux EXT4 filesystem which you can mount.

```
root@mankrik:~/opentoall/gone/tmp# file 1fdb86c25131bb3aa247bada29b29115.img   
 1fdb86c25131bb3aa247bada29b29115.img: Linux rev 1.0 ext4 filesystem data, UUID=1385df22-b2ce-4b4f-858e-79ae1932ca1a (extents) (huge files)  
```
However upon mounting the filesystem you find it to be empty. 

Since the name of the challenge is "Gone" you assume the challenge is to recover the files for the flag. To do so the first thing we try is to unmount and use the Linux fsck.ext4 program to scan and correct filesystem issues. This seems to fix quite a number of issues:

```
root@mankrik:~/opentoall/gone/tmp# fsck.ext4 1fdb86c25131bb3aa247bada29b29115.img   
e2fsck 1.42.5 (29-Jul-2012)  
ext2fs_open2: The ext2 superblock is corrupt  
fsck.ext4: Superblock invalid, trying backup blocks...  
1fdb86c25131bb3aa247bada29b29115.img was not cleanly unmounted, check forced.  
Pass 1: Checking inodes, blocks, and sizes  
Pass 2: Checking directory structure  
Pass 3: Checking directory connectivity  
Pass 4: Checking reference counts  
Pass 5: Checking group summary information  
Free blocks count wrong for group #0 (6789, counted=488).  
Fix<y>? yes  
Free blocks count wrong for group #1 (2006, counted=228).  
Fix<y>? yes  
Free blocks count wrong (8795, counted=716).  
Fix<y>? yes  
Free inodes count wrong for group #0 (1269, counted=1262).  
Fix<y>? yes  
Free inodes count wrong (2549, counted=2542).  
Fix<y>? yes  
1fdb86c25131bb3aa247bada29b29115.img: ***** FILE SYSTEM WAS MODIFIED *****  
1fdb86c25131bb3aa247bada29b29115.img: 18/2560 files (11.1% non-contiguous), 9524/10240 blocks  
```
Upon next mount we find that yes, we see the files now:

```
root@mankrik:~/opentoall/gone/tmp# mount 1fdb86c25131bb3aa247bada29b29115.img /mnt  
root@mankrik:~/opentoall/gone/tmp# ls -la /mnt  
total 8096  
drwxr-xr-x 3 root root  1024 Mar 5 13:46 .  
drwxr-xr-x 26 root root  4096 Mar 7 06:02 ..  
-rw-r--r-- 1 root root   18 Mar 5 13:36 AE5  
-rw-r--r-- 1 root root 3575808 Mar 5 13:36 file  
-rw-r--r-- 1 root root  97626 Mar 5 13:37 fil.enc  
drwx------ 2 root root  12288 Mar 5 12:47 lost+found  
-rw-r--r-- 1 root root 1214464 Mar 5 13:43 ran2  
-rw-r--r-- 1 root root  23552 Mar 5 13:45 ran3  
-rw-r--r-- 1 root root 1191936 Mar 5 13:46 ran4  
-rw-r--r-- 1 root root 2167808 Mar 5 13:37 rand  
```

Upon examining every file we are not much closer to getting a flag here, so more research is required. The filenames "AE5" and "fil.enc" stand out very starkly (immediately we think AE5 = AES, file.enc = encrypted file?) so we keep that in the back of our mind.

First we run the "file" command against every file to try and identify if any are useful to us. Not much comes back:

```
AE5:    ASCII text  
file:    data  
fil.enc:  data  
lost+found: directory  
ran2:    data  
ran3:    data  
ran4:    data  
rand:    data  
```
So lets follow up on that "AE5" and "fil.enc" lead we saw originally. Lets examine AE5 since it's just ASCII text:<

```
root@mankrik:/mnt# cat AE5  
 4[71A3j9[22?/+u0  
```

Ok so that isn't immediately obviously anything but it *MIGHT* be a key? So let's put it in our pocket for later. Next the file.enc file, whats that about? "file" command just says data, which is not usually a great thing, lets take a look at the header ourselves real quick:
  
```
root@mankrik:/mnt# xxd fil.enc | head -5  
 0000000: 5361 6c74 6564 5f5f 9439 e6c5 4330 e12e Salted__.9..C0..  
 0000010: b05c 5638 fff0 2496 9dac c546 aa1a 1dee .V8..$....F....  
 0000020: 4e89 7d16 d17c ccf9 162a 6a50 b923 e9bd N.}..|...*jP.#..  
 0000030: 6046 3415 ecb7 e1a4 f261 f325 194c f390 `F4......a.%.L..  
 0000040: 2202 fcdd 7142 4a40 3b9b 9f16 2792 29bc "...qBJ@;...'.).  
```
Ok, so the first bytes are the word "Salted__", you may know this from experience or you may just Google this but this means the file was encrypted using the OpenSSL command and it was encrypted with a salt.

So we have a file encrypted with openssl and a text file that might have a key, and it's called AES. So let's just try decrypting the file?

```
root@mankrik:/mnt# openssl enc -d -in fil.enc -out fil.dec -aes256 -k `cat AE5`  
bad decrypt  
140154050635432:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
root@mankrik:/mnt# file fil.dec  
fil.dec: data  
```

Ok so not much luck; an error from OpenSSL about the file, bad decrypt error, and the result is just more "data". What are we doing wrong here?

At this point this challenge is more about cryptography than forensics. You have to understand that AES is a block cipher with a block size of 128 bits (16 bytes) and that block ciphers can operate in one of several modes of operation (e.g. ECB, CBC, CTR etc). Each of these modes of operation will result in different encrypted files. Finally, AES can accept keys with length 128, 192 and 256 bits! So before we rule out AES, since it's the only clue we have, we need to try harder!

So let's write a quick script covering every possible mode and key length for AES that openssl supports. To save you time, here's a list:

```
-aes-128-cbc -aes-128-cbc-hmac-sha1 -aes-128-cfb -aes-128-cfb1 -aes-128-cfb8 -aes-128-ctr -aes-128-ecb -aes-128-gcm -aes-128-ofb -aes-128-xts -aes-192-cbc -aes-192-cfb -aes-192-cfb1 -aes-192-cfb8 -aes-192-ctr -aes-192-ecb -aes-192-gcm -aes-192-ofb -aes-256-cbc -aes-256-cbc-hmac-sha1 -aes-256-cfb -aes-256-cfb1 -aes-256-cfb8 -aes-256-ctr -aes-256-ecb -aes-256-gcm -aes-256-ofb -aes-256-xts -aes128 -aes192   
```

And here's the script we came up with to quickly try all of the possibilities:

```
#!/bin/bash  
 KEY=`cat AE5`  
 AESMODES="-aes-128-cbc -aes-128-cbc-hmac-sha1 -aes-128-cfb -aes-128-cfb1 -aes-128-cfb8 -aes-128-ctr -aes-128-ecb -aes-128-gcm -aes-128-ofb -aes-128-xts -aes-192-cbc -aes-192-cfb -aes-192-cfb1 -aes-192-cfb8 -aes-192-ctr -aes-192-ecb -aes-192-gcm -aes-192-ofb -aes-256-cbc -aes-256-cbc-hmac-sha1 -aes-256-cfb -aes-256-cfb1 -aes-256-cfb8 -aes-256-ctr -aes-256-ecb -aes-256-gcm -aes-256-ofb -aes-256-xts -aes128 -aes192"  
 for mode in $AESMODES  
 do  
      openssl enc -d -in fil.enc -out /tmp/fil"$mode".dec -k $KEY $mode  
 done  
```

And when we run it, we get a lot of errors...

```
root@mankrik:/mnt# sh aes.sh   
bad decrypt  
139805199214248:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
Segmentation fault  
bad decrypt  
139964237162152:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
bad decrypt  
bad decrypt  
140564537820840:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
bad decrypt  
139941861820072:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
bad decrypt  
bad decrypt  
139964176520872:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
Segmentation fault  
bad decrypt  
140288415119016:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
bad decrypt  
bad decrypt  
139797559735976:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
bad decrypt  
140161216915112:error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length:evp_enc.c:532:  
```
But let's see what happened anyway, the script put all of the "decrypted" (mostly botched) files into /tmp/ so lets check them out:

```
root@mankrik:/mnt# file /tmp/*.dec  
/tmp/fil-aes-128-cbc.dec:      data  
/tmp/fil-aes-128-cbc-hmac-sha1.dec: empty  
/tmp/fil-aes-128-cfb1.dec:     data  
/tmp/fil-aes-128-cfb8.dec:     data  
/tmp/fil-aes-128-cfb.dec:      PNG image data, 855701748 x 4133316295, 218-bit  
/tmp/fil-aes-128-ctr.dec:      PNG image data, 1300 x 1076, 8-bit/color RGBA, non-interlaced  
/tmp/fil-aes128.dec:        data  
/tmp/fil-aes-128-ecb.dec:      data  
/tmp/fil-aes-128-gcm.dec:      SysEx File - AudioVertrieb  
/tmp/fil-aes-128-ofb.dec:      PNG image data, 356303344 x 1815138770, 170-bit  
/tmp/fil-aes-128-xts.dec:      data  
/tmp/fil-aes-192-cbc.dec:      data  
/tmp/fil-aes-192-cfb1.dec:     data  
/tmp/fil-aes-192-cfb8.dec:     data  
/tmp/fil-aes-192-cfb.dec:      data  
/tmp/fil-aes-192-ctr.dec:      data  
/tmp/fil-aes192.dec:        data  
/tmp/fil-aes-192-ecb.dec:      data  
/tmp/fil-aes-192-gcm.dec:      data  
/tmp/fil-aes-192-ofb.dec:      data  
/tmp/fil-aes-256-cbc.dec:      data  
/tmp/fil-aes-256-cbc-hmac-sha1.dec: empty  
/tmp/fil-aes-256-cfb1.dec:     data  
/tmp/fil-aes-256-cfb8.dec:     data  
/tmp/fil-aes-256-cfb.dec:      data  
/tmp/fil-aes-256-ctr.dec:      data  
/tmp/fil-aes-256-ecb.dec:      data  
/tmp/fil-aes-256-gcm.dec:      data  
/tmp/fil-aes-256-ofb.dec:      data  
/tmp/fil-aes-256-xts.dec:      data  
```

Ok well that's interesting. A PNG file with what looks to be correct header information seems to have been the result of decryption with AES with 128bit key length and CTR mode of operation.
 
We view the PNG and we have our flag:

<a href="/images/2015/03/gone4-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/gone4-1.png" height="263" width="320" /></a>