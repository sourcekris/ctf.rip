---
id: 845
title: 'hack.lu CTF 2016 - Cornelius1 - Crypto Challenge'
date: 2016-10-24T08:11:52+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=845
permalink: /hack-lu-ctf-2016-cornelius1-crypto-challenge/
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
  - "2003"
image: /images/2016/10/hacklu.png
categories:
  - Write-Ups
tags:
  - AES
  - CRIME
  - crypto
  - python
---
Wasn't able to login to this CTF until about 3 hours before it was over. So we got what we could solved in that time. This challenge was fun and I'll go through my solution very fast. Firstly here's the clue:

> Please find Cthulhu's magic [here](https://cthulhu.fluxfingers.net:1505/).
> Attachment: <a href="https://github.com/sourcekris/ctf-solutions/blob/master/crypto/hacklu16-cornelius1/server.rb" target="_blank">server.rb</a>

When you visit the link you don't get much except for a "Hallo fnord" message and a cookie: 
```
 root@kali:~/hacklu/cornelius1# curl -vk https://cthulhu.fluxfingers.net:1505/
*   Trying 149.13.33.84...
* Connected to cthulhu.fluxfingers.net (149.13.33.84) port 1505 (#0)
* found 173 certificates in /etc/ssl/certs/ca-certificates.crt
* found 696 certificates in /etc/ssl/certs
* ALPN, offering h2
* ALPN, offering http/1.1
* SSL connection using TLS1.2 / ECDHE_RSA_AES_256_GCM_SHA384
*    server certificate verification SKIPPED
*    server certificate status verification SKIPPED
*    common name: cthulhu.fluxfingers.net (matched)
*    server certificate expiration date OK
*    server certificate activation date OK
*    certificate public key: RSA
*    certificate version: #3
*    subject: CN=cthulhu.fluxfingers.net
*    start date: Fri, 14 Oct 2016 18:27:00 GMT
*    expire date: Thu, 12 Jan 2017 18:27:00 GMT
*    issuer: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3
*    compression: NULL
* ALPN, server did not agree to a protocol
> GET / HTTP/1.1
> Host: cthulhu.fluxfingers.net:1505
> User-Agent: curl/7.50.1
> Accept: */*
> 
< HTTP/1.1 200 OK 
< Server: nginx/1.4.6 (Ubuntu)
< Date: Mon, 24 Oct 2016 07:46:11 GMT
< Content-Length: 11
< Connection: keep-alive
< Set-Cookie: auth=N26jjGI5D17rlq0Y8wEjr0BhACaYTwVWKpidTf+JGweC5PA=
< 
* Connection #0 to host cthulhu.fluxfingers.net left intact
Hallo fnord
```
 Looking at the `server.rb` code, it's a simple Ruby web server. The one thing it seems to do is take the HTTP GET parameter user, json encode the username with the flag and then send it back to the web client as an AES encrypted cookie. 

 ```
def get_auth(user)
  data = [user, "flag:"+File.read("flag.key").strip]
  json = JSON.dump(data)
  zip = Zlib.deflate(json)
  return Base64.strict_encode64(encrypt(zip))
end
class Srv < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(req,resp)
    user = req.query["user"] || "fnord"
    resp.body = "Hallo #{user}"
    resp.status = 200
    puts get_auth(user).inspect
    cookie = WEBrick::Cookie.new("auth", get_auth(user))
    resp.cookies << cookie
    return resp
  end
end
 ```

Oh hang on, we missed a step in our earlier explaination. Right before the server encrypts the newly minted cookie, it compresses it with zlib. Why is that a problem? Well the issue is that we can control some of the contents of the cookie. When we can control some of the pre-compression payload, we can attempt to leak information about the plaintext by trying different combinations of inputs and measuring the length of the output. Any input that results in a shorter output than some baseline, could be deduced to be a result of the compression algorithm doing it's thing and compressing away duplicate data. Thus we leak the plaintext. Let's test our theory with a couple of curl commands. Since we know the flag begins with `flag`: we can 
```
root@kali:~/hacklu/cornelius1# curl -v https://cthulhu.fluxfingers.net:1505/?user=ABCDEFGHIJKL 2>&1 | grep auth=
< Set-Cookie: auth=e2RvtidZH9OO7VzGftXRF0/QAMOcpySe6KMMAprdiL+OfaW7UwvxTFgF
```
 This gives us a 56 byte auth cookie. 
```
root@kali:~/hacklu/cornelius1# curl -v https://cthulhu.fluxfingers.net:1505/?user=flag:ABCDEFG 2>&1 | grep auth=
< Set-Cookie: auth=4RC9KuUVjxpsaZewvUhA7Anw0Z1NYv/LKFZnze1jk+lGHcAvyg==
```
 This gives us a 52 byte auth cookie. Interesting! Can we simply deduce further data this way? I code a quick Python requests loop to see: 
```
import requests,string
s = requests.Session()
for c in string.ascii_letters:
    r = s.get("https://cthulhu.fluxfingers.net:1505/?user=flag:"+c+"BCDEFGHIJKL")
    print c,len(r.cookies['auth'])
```
```
root@kali:~/hacklu/cornelius1# ./a.py 
a 60
b 60
c 60
...
K 60
L 60
M 56
N 60
...
```
Wow ok. So every letter gives us a 60 byte auth cookie except "M". Using this idea we proceed to code a solution to leak the remainder of the plaintext: 

```
#!/usr/bin/python
import requests, string
url = "https://cthulhu.fluxfingers.net:1505/"
user = "flag:"
suffix1 = "BCDEFGHIJKL"
s = requests.Session()
baseline = []
while True:
    for i in range(50):
        r = s.get(url, params={'user':user+"#"+suffix1})
        auth = r.cookies['auth']
        baseline.append(len(auth))
        before = len(user)
        for c in string.printable:
            userfield = user+c+suffix1
            r = s.get(url, params={'user':userfield})
            auth = r.cookies['auth']
            if len(auth) < baseline[i]:
                user += c
                break
        if len(user) == before:
            print "[*] Flag: flag{"+user.replace('flag:','')+"}"
            quit()
```
 Which, when we run, got us the flag: 

```
root@kali:~/hacklu/cornelius1# ./solution.py 
[*] Flag: flag{Mu7aichede} 
```