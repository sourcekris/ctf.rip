---
id: 826
title: 'CTF(x) iTrash: Forensics Challenge'
date: 2016-08-30T05:37:05+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=826
permalink: /ctfx-itrash-forensics-challenge/
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
  - "524"
image: /images/2016/10/ctfx.png
categories:
  - Write-Ups
---
For this one we're given a link to a Megaupload hosted file. It's a 93mb file so it's gotta be good! The clue was:

> I got locked out of my iTrash <img src="https://ctf.rip/images/classic-smilies/icon_sad.gif" alt=":(" class="wp-smiley" style="height: 1em; max-height: 1em;" />
> 
> `1 2 3`
> `4 5 6`
> `7 8 9`
> 
> Flag format: ctf(n-n-...-n)

Interesting. What is it? We inspect the contents: 
```
root@kali:~/ctfx/itrash# unzip -t iTrash
Archive:  iTrash.zip
    testing: iTrash/                  OK
    testing: iTrash/userdata-qemu.img   OK
    testing: iTrash/hardware-qemu.ini   OK
    testing: iTrash/cache.img         OK
    testing: iTrash/config.ini        OK
    testing: iTrash/userdata.img      OK
    testing: iTrash/emulator-user.ini   OK
No errors detected in compressed data of iTrash.zip.

```
 

I'm not immediately familiar with the filenames but .img files might be filesystems. I inspect a bit more and yeah, they're filesystems: 
```
root@kali:~/ctfx/itrash/iTrash# file userdata-qemu.img 
userdata-qemu.img: Linux rev 1.0 ext4 filesystem data, UUID=57f8f4bc-abf4-655f-bf67-946fc0f9f25b (needs journal recovery) (extents) (large files)
```
 

Digging a bit deeper, I inspect the `config.ini` file and it begins to make sense. This is an AVD - an Android Virtual Device. This is what you typically see when using say the Android SDK and you want to test an APK in an emulated Android environment. This one is an x86 Android machine and we could easily boot it if we wanted. I did that using the following method:

  1. On my Santoku Linux VM (or anywhere Android SDK is installed) I copied the entire iTrash folder to `~/.android/avd/`
  2. I renamed the folder `iTrash.avd`
  3. I created a file `~/.android/avd/iTrash.ini` with the following contents:
  
    
```
avd.ini.encoding=UTF-8
path=/home/santoku/.android/avd/iTrash.avd
path.rel=avd/iTrash.avd
target=android-21
    
```

  4. I updated the `~/.android/avd/iTrash.avd/*.ini` files to ensure they had the correct paths. e.g. hardware-qemu.ini needs update paths to the .img files
  5. Load AVD Manager from the Android SDK, the iTrash AVD is now listed there.

It turns out this isn't necessary though it helped me click what the challenge is. When the AVD boots we're greeted with the lock screen. It's not a PIN or passcode lock screen - it's one of those "gesture" based lock screens:

<img src="/images/2016/10/lockscreen.png" alt="lockscreen" width="1250" height="963" class="alignnone size-full wp-image-828" srcset="/images/2016/10/lockscreen.png 1250w, /images/2016/10/lockscreen-300x231.png 300w, /images/2016/10/lockscreen-768x592.png 768w, /images/2016/10/lockscreen-1024x789.png 1024w" sizes="(max-width: 1250px) 100vw, 1250px" />

Since the flag format is ctf(n-n-n...) and we have a numeric pattern, my guess is they want the lock screen gesture described as a series of those numbers. How do we get that?

It turns out that in the Android world, gesture patterns are stored on the device itself in a file called `gesture.key`. The pattern is hashed using SHA1 and stored there. In our iTrash AVD this file resides inside the `userdata-qemu.img` file. So let's grab it... 
```
root@kali:~/ctfx/itrash/iTrash# mkdir mnt
root@kali:~/ctfx/itrash/iTrash# mount userdata-qemu.img mnt
root@kali:~/ctfx/itrash/iTrash# find . -name gesture.key
./mnt/system/gesture.key
root@kali:~/ctfx/itrash/iTrash# cat mnt/system/gesture.key | hex
c4bca3d13ba42982f6ee402262e2059c082bfce3

```
 

This is the SHA1 hash of our gesture. Now to crack it? Well it's easier than that. You see for the most part every combination of gesture has already been hashed and there are good online sources of Rainbow Tables for this job. Here is a great example: <https://github.com/KieronCraggs/GestureCrack>

I cloned that repo and used `gesturecrack.py` to good effect: 
```
root@kali:~/ctfx/itrash/GestureCrack# python gesturecrack.py -f ../iTrash/mnt/system/gesture.key
   
        The Lock Pattern code is [6, 4, 7, 3, 8, 5, 0, 1, 2]
        For reference here is the grid (starting at 0 in the top left corner):
        |0|1|2|
        |3|4|5|
        |6|7|8| 
```
 

So is our flag simply ctf(6-4-7-3-8-5-0-1-2)?

Not so fast, our gesture has "0" in it but our keyboard pattern given in the clue is without "0" entirely. It seems we need to shift our numbers one place to the right. So I do that and get the correct flag: ctf(7-5-8-4-9-6-1-2-3)

Cool now we know how to hack Android gestures I guess!
