---
id: 814
title: 'WebSec CTF - Authorization Token - JWT Challenge'
date: 2016-08-07T14:22:14+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=814
permalink: /websec-ctf-authorization-token-jwt-challenge/
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
  - "1318"
categories:
  - Write-Ups
---
In this challenge we were given an string and told that it was an authorization token that had expired. We want to forge an authorization token for whatever service this token is used for. The token we're given is this:

> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY

We quickly recognize this as a JWT, Json Web Token. I headed over to the jwt.io site to check it out. There we can paste the token in and get information about it's contents pretty easily:

<img src="/images/2016/08/jwt1.png" alt="jwt1" width="1203" height="746" class="alignnone size-full wp-image-815" srcset="/images/2016/08/jwt1.png 1203w, /images/2016/08/jwt1-300x186.png 300w, /images/2016/08/jwt1-768x476.png 768w, /images/2016/08/jwt1-1024x635.png 1024w" sizes="(max-width: 1203px) 100vw, 1203px" />

In this we see that we can't validate the signature, this is expected because we don't have the correct secret. We find, as expected the token has expired also. So the first thing we think is that we need to brute force the secret so we can generate our own JWT token with a future expiration date. 

Using the JWT python library I build a quick attempt at a brute force system. Shortly after the challenge was announced a couple of hints were given.

  * The secret will be the flag, all the flags are in the "websecctf{<flag>}" format.
  * The secret will contain one underscore
  * The unknown portion of the secret is 6-7 characters
  * The charset is a-z

So we know quite a lot about the secret already. I wrote some code using itertools.product to loop through every possible 7 character secret and see if the signature will decode without raising an exception. I run the script in parallel placing the single underscore character in each of the possible positions. This gave us no result after a few hours so we were barking up the wrong tree.

The next thing we looked at were encoded keys. We tried base64 encoding all posible secrets but again no result. 

We then were stuck for a while, the challenge had not been solved by any teams yet. So could there be a fault in the challenge? It turns out there was. The challenge was using the plaintext flag (i.e. websecctf{......}) and assuming it was a base64 encoded string. Since "{" and "}" are not valid in the standard base64 alphabet, the Javascript on JWT.io, where the challenge author had generated the challenge token behaved very oddly.

An example is if we have the example flag "websecctf{12_345}". If we examine the Javascript on jwt.io and assume the checkbox shown above is ticked, the following operations are done:
```
  if(algorithm === 'HS256'){
    if (isSecretBase64Encoded) {
      try {
        key = window.b64utob64(key);
        key = window.CryptoJS.enc.Base64.parse(key).toString();
      } catch (e) {
        return {result: '', error: e};
      }
    } else {
      key = window.CryptoJS.enc.Latin1.parse(key).toString();
    }
  }
```

So we need to examine what these two transforms are doing to the key. The first is `window.b64utob64` which is short for "base64 url encoded to base64". This in simple terms does a search and replace of all "_" characters replacing them with "/" and all "-" characters with "+" characters. The former is important because we know our secret has one "_" in it.

The next transform takes the base64 key and returns a hex string of the bytes encoded. This function is slightly strange in that instead of raising an exception on a invalid character, it will instead return 0xff for the remainder of that encoded block.

When we run our test key, we get the following:

```
key = "websecctf{12_345}"; 
key = window.b64utob64(key); // returns websecctf{12/345}
key = window.CryptoJS.enc.Base64.parse(key).toString();
```

The output of this is "c1e6ec79fffffffd76ff7e39". If we re-encode this to base64 in python we have this: 
```
import base64
a = "c1e6ec79fffffffd76ff7e39"
print base64.b64encode(a.decode('hex'))

```
 
This outputs: websef////12/345

We see we lost much of the useless part of the secret here but we see the important data is still visible. To put this theory to the test we wrote a bruteforce algorithm using the pattern: websef////??/???. The following code shows our solution: 

```
#!/usr/bin/python
import jwt
import itertools
import sys
import base64
chall = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY"
prf = "websef////"
charset = "abcdefghijklmnopqrstuvwxyz"
def decodeit(secret):
    try:
        dec = jwt.decode(chall, secret, algorithms=['HS256'])
    except jwt.exceptions.DecodeError:
        return False
    except jwt.exceptions.ExpiredSignatureError:
        print "[+] Flag:" + base64.b64encode(secret).replace(prf,'websecctf{').replace('/','_') + '}'
        return True
        
slashpos = 2
for i in itertools.product(charset, repeat=5):
    secret = ''.join(i)
    secret = base64.b64decode(prf+secret[:slashpos]+"/"+secret[slashpos:])
    if decodeit(secret):
        break
```
 

Which resulted in the following: 
```
root@kali:~/websec/jwt# ./solution.py
[+] Flag:websecctf{jw_twj}

```
 
Nice. Bit strange challenge but we resolved it eventually.