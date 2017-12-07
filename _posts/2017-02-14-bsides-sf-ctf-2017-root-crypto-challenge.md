---
id: 912
title: 'BSides SF CTF 2017 - []root - Crypto Challenge'
date: 2017-02-14T08:35:22+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=912
permalink: /bsides-sf-ctf-2017-root-crypto-challenge/
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
  - "934"
image: /images/2017/02/bsideslogo.png
categories:
  - Write-Ups
---
Quick challenge for a quick 250 points. So hopefully a quick writeup! Here's the clue:

> Our guy inside e-corp was able to get that packet capture of their backend PKI you asked for. Unfortunately it seems they're using TLS to protect the modulus fetch. Now, I have been told that the best crackers in the world can do this in 60 minutes. Unfortunately I need someone who can do it in 60 seconds.
> 
> Note: Flag does not follow the "Flag:" format but is recognizable
> 
> [e\_corp\_pki.pcapng](https://github.com/sourcekris/ctf-solutions/raw/master/crypto/bsidessf17-root/e_corp_pki.pcapng)

If we examine the PCAP in wireshark to get a high level overview of the challenge here we see very little in the way of plaintext anything.

<img src="/images/2017/02/root2.png" alt="" width="1535" height="556" class="alignnone size-full wp-image-915" srcset="/images/2017/02/root2.png 1535w, /images/2017/02/root2-300x109.png 300w, /images/2017/02/root2-768x278.png 768w, /images/2017/02/root2-1024x371.png 1024w" sizes="(max-width: 1535px) 100vw, 1535px" />

The verbage in the clue about "using TLS to protect the modulus fetch" though made me think of examining the certificate used in the TLS negotiation in some detail. To do this we can use Wireshark to expert it as a DER format X509 certificate by drilling down in the "Server Hello" packet which is in frame 11 of this pcap.

If we expand the _Secure Sockets Layer_ > _TLSv1.2 Record Layer: Handshake Protocol: Certificate data_, all the way until we isolate the actual certificate content, we can then right click the record and "**Export Packet Bytes...**":

<img src="/images/2017/02/root3.png" alt="" width="1211" height="671" class="alignnone size-full wp-image-916" srcset="/images/2017/02/root3.png 1211w, /images/2017/02/root3-300x166.png 300w, /images/2017/02/root3-768x426.png 768w, /images/2017/02/root3-1024x567.png 1024w" sizes="(max-width: 1211px) 100vw, 1211px" />

We save the file as `certificate.der` and now we can examine it with the `openssl` command line tools. Let's just get the human readable form of the certificate. 
```
 root@kali:~/bsides/crypto/root# openssl x509 -inform DER -in certificate.der -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9e:6e:0d:aa:09:10:fa:fb
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=New York, L=New York, O=E Corp, CN=pki.e-corp.com/emailAddress=pki@e-corp.com
        Validity
            Not Before: Feb  1 00:39:00 2017 GMT
            Not After : Feb  1 00:39:00 2018 GMT
        Subject: C=US, ST=New York, L=New York, O=E Corp, CN=pki.e-corp.com/emailAddress=pki@e-corp.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4103 bit)
                Modulus:
                    72:6f:6f:74:00:00:00:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:00:1b:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:77:77:77:7b:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
                    00:00:00:00:00:1f:ff:ff:22:22:22:2b:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    26:52:93:c4:42:2b:e3:53:26:38:fe:eb:2a:63:5e:
                    86:5e:5b:cc:d4:86:2d:14:91:f8:e4:6e:d4:1a:fd:
                    ab:32:ab:1e:91:3c:29:6c:45:a7:23:a3:71:cc:4a:
                    d2:18:d2:73:a4:94:ac:50:1a:1c:67:75:76:b8:4d:
                    3a:17:00:b2:4e:38:f3:d7:c8:09:0c:95:27:67:f8:
                    a9:da:53:2e:b4:49:6a:95:3f:a2:b2:64:1f:93:af:
                    58:32:1e:49:1a:d6:b3:e1:f6:60:0e:a1:75:76:35:
                    a2:d4:75:62:df:f2:f2:45:bf:c8:ed:51:14:20:93:
                    1d:e2:46:d5:63:34:d8:89:7d:64:65:b2:27:f6:c0:
                    95:ec:e1:ad:99:4c:75:51:f0:8d:bc:21:f8:b4:06:
                    91:ee:51:f5:f7:2d:05:2d:93:52:06:2f:90:b0:e7:
                    c5:2c:2e:b1:81:96:c2:c9:85:10:1a:f4:ea:c6:74:
                    99:39:6c:62:41:ad:4f:24:39:ed:11:f8:7d:67:e7:
                    3a:23:9b:86:5c:45:d6:5a:61:cf:0f:56:08:2d:e8:
                    31:b9:7f:b2:8a:e8:22:2a:71:95:e0:ec:06:c0:82:
                    81:ff:c1:6e:71:06:e7:7e:68:b8:c4:51:04:24:be:
                    eb:55:82:fe:21:cc:34:5f:53:53:46:82:b7:5c:36:
                    8d:73:c9
                Exponent: 31337 (0x7a69)
        X509v3 extensions:
...

```
 

There's more information but the most interesting thing here is the modulus, it looks more like ASCII art than a proper modulus. A little bit suspicious don't you think? The exponent doesn't look to usual either but let's focus on maybe trying to factor the modulus.

To do this im going to use a [tool I worked on about a year back called RsaCtfTool](https://github.com/sourcekris/RsaCtfTool). A fork of a project to simplify attacks against RSA in CTF challenges. I added a bunch of attack types that might apply here, so let's give it a whirl.

I start by converting the DER format key into a compatible key format, to do this I extract the public key alone from the DER format key again, using `openssl`: 
```
root@kali:~/bsides/crypto/root# openssl x509 -inform DER -in certificate.der -pubkey -noout > key.pub
```
 

Then I ask `RsaCtfTool` to attempt whatever method's make sense against this public key to factor the modulus. 
```
root@kali:~/gitrepos/RsaCtfTool# ./RsaCtfTool.py --publickey ~/bsides/crypto/root/key.pub --verbose --private
[*] Performing hastads attack.
[*] Performing factordb attack.
[*] Performing pastctfprimes attack.
[*] Loaded 61 primes
[*] Performing noveltyprimes attack.
[*] Performing smallq attack.
[*] Performing wiener attack.
[*] Performing commonfactors attack.
[*] Performing fermat attack.
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```
 

And voila we have a private key using fermat factorization! If we check the particulars of the private key we understand more why this worked. We can examine it with `openssl` again: 
```
root@kali:~/bsides/crypto/root# openssl rsa -in private.key -text -noout
Private-Key: (4103 bit)
modulus:
    72:6f:6f:74:00:00:00:00:00:00:00:00:00:00:00:
...
prime1:
    0a:b2:8b:a5:db:d6:7a:4b:8b:4c:20:b7:69:58:ad:
    57:ef:55:13:ea:01:af:2a:d5:9b:16:91:a4:b6:0e:
    7e:ee:05:8a:a4:77:6b:c9:6a:3b:7b:3b:3a:b9:8a:
    74:3f:f0:e1:6c:22:03:34:81:df:d0:c8:36:54:31:
    1e:15:3b:14:d5:06:7e:a4:66:4d:41:9b:97:ba:28:
    a6:ee:56:93:b0:0a:cb:7c:70:46:76:2b:0d:8e:ce:
    2b:db:dc:4c:78:49:23:17:8b:eb:1c:8c:78:fd:12:
    30:03:f4:c1:07:f2:aa:77:2a:7f:22:f3:05:2e:e6:
    95:61:a2:65:ac:f6:18:51:3a:cd:76:32:1d:2c:3a:
    6d:cd:64:56:15:2c:40:32:d8:fd:28:5e:e0:13:74:
    6e:b1:43:9f:4c:9c:66:b9:ff:d9:03:b6:32:08:bb:
    b0:bf:82:b5:2c:fc:6b:d1:2d:f9:6f:3d:9f:a1:2c:
    96:45:6f:d9:4e:7f:5c:12:38:b3:d5:08:9e:6b:e6:
    4a:c5:55:f8:46:83:ed:e1:2c:c1:ff:a1:a6:6f:be:
    5e:4d:2c:83:0e:14:d6:95:4c:48:74:7b:c1:ce:c6:
    05:82:a3:12:ee:97:27:4a:9f:72:11:e3:21:3f:f2:
    08:1d:9f:69:b0:7a:7b:0f:a8:f8:9e:dd:03:7e:73:
    14:05
prime2:
    0a:b2:8b:a5:db:d6:7a:4b:8b:4c:20:b7:69:58:ad:
    57:ef:55:13:ea:01:af:2a:d5:9b:16:91:a4:b6:0e:
    7e:ee:05:8a:a4:77:6b:c9:6a:3b:7b:3b:3a:b9:8a:
    74:3f:f0:e1:6c:22:03:34:81:df:d0:c8:36:54:31:
    1e:15:3b:14:d5:06:7e:a4:66:4d:41:9b:97:ba:28:
    a6:ee:56:93:b0:0a:cb:7c:70:46:76:2b:0d:8e:ce:
    2b:db:dc:4c:78:49:23:17:8b:eb:1c:8c:78:fd:12:
    30:03:f4:c1:07:f2:aa:77:2a:7f:22:f3:05:2e:e6:
    95:61:a2:65:ac:f6:18:51:3a:cd:76:32:1d:2c:3a:
    6d:cd:64:56:15:2c:40:32:d8:fd:28:5e:e0:13:74:
    6e:b1:43:9f:4c:9c:66:b9:ff:d9:03:b6:32:08:bb:
    b0:bf:82:b5:2c:fc:6b:d1:2d:f9:6f:3d:9f:a1:2c:
    96:45:6f:d9:4e:7f:5c:12:38:b3:d5:08:9e:6b:e6:
    4a:c5:55:f8:46:83:ed:e1:2c:c1:ff:a1:a6:6f:be:
    5e:4d:2c:83:0e:14:d6:95:4c:48:74:7b:c1:ce:c6:
    05:82:a3:12:ee:97:27:4a:9f:72:11:e3:21:3f:f2:
    08:1d:9f:69:b0:7a:7b:0f:a8:f8:9e:dd:03:7e:73:
    0f:f5
...
```
 

We see here `prime1` and `prime2`, otherwise known as `p` and `q`, the prime factors that are multiplied together for form our modulus (`n`). Fermat factorization works on large composites well when the prime factors are close together. In this case they differ by just 16 of the least significant bits! Therefore this 4103 bit composite number was factored in less than a second.

So now we have the private key for the TLS v1.2 connection, we can setup Wireshark to be able to decrypt the session. Fantastic. Let's do that. To do it, we just open the PCAP in wireshark, go to Edit -> Preferences, expand the Protocols list and find "SSL" in the list. Next we click Edit in the RSA keys list section and fill in the details of our key.

<img src="/images/2017/02/root4.png" alt="" width="700" height="506" class="alignnone size-full wp-image-917" srcset="/images/2017/02/root4.png 700w, /images/2017/02/root4-300x217.png 300w" sizes="(max-width: 700px) 100vw, 700px" />

We specify the IP (4.3.2.1) the port (443) the protocol to decode (http) and the key filename (filename we just saved from RsaCtfTool output). Once saved, return to the Wireshark main window and you will now be able to see the HTTP decrypted traffic:

<img src="/images/2017/02/root5.png" alt="" width="1495" height="313" class="alignnone size-full wp-image-918" srcset="/images/2017/02/root5.png 1495w, /images/2017/02/root5-300x63.png 300w, /images/2017/02/root5-768x161.png 768w, /images/2017/02/root5-1024x214.png 1024w" sizes="(max-width: 1495px) 100vw, 1495px" />

If we right click this frame and select "**Follow SSL Stream**" we get the full capture of the E-corp PKI modulus we want!

<img src="/images/2017/02/root6.png" alt="" width="915" height="722" class="alignnone size-full wp-image-919" srcset="/images/2017/02/root6.png 915w, /images/2017/02/root6-300x237.png 300w, /images/2017/02/root6-768x606.png 768w" sizes="(max-width: 915px) 100vw, 915px" />

Decoding the hex bytes of the modulus into ASCII this time directly gives the flag with no fussing about: 
```
root@kali:~/bsides/crypto/root# cat modulus.txt | sed -e s/://g | tr -d '\n' | unhex
root.......www{.................."""+.................flag:when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves
```
