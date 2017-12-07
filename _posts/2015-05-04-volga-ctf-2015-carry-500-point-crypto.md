---
id: 233
title: 'Volga CTF 2015 - carry - 500 point Crypto Challenge'
date: 2015-05-04T03:00:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=233
permalink: /volga-ctf-2015-carry-500-point-crypto/
post_views_count:
  - "546"
image: /images/2015/05/carry-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/05/carry-2.png" imageanchor="1" style="clear: left; float: left; margin-bottom: 1em; margin-right: 1em;"><img border="0" src="/images/2015/05/carry-2.png" height="216" width="320" /></a>
</div>

For 500 points in the crypto category I expect a lot of time, effort and mostly math. I was surprised to find none of that was necessary for this challenge. I guess it could be down to a mistake by the organizers or maybe it was a statement in "at least give it a try". I don't know. But you might kick yourself when you read my solution to this challenge.

><i>Carry</i></b><br /><i>Here's a bunch of files. Someone has done something with these files (apparently, encrypted). To get the flag decrypt everything.</i><i><br /></i><i>files</i>

Downloading the ZIP file gives us the following files:

```
root@mankrik:~/volga/carry# ls -la
total 40
drwxr-xr-x 2 root root 4096 May  4 12:28 .
drwxr-xr-x 3 root root 4096 May  4 12:26 ..
-rw-r--r-- 1 root root 8400 May  3 13:40 data.zip
-rw-r--r-- 1 root root 6846 May  3 07:31 flag.png.bin
-rwxr-xr-x 1 root root 2111 May  4 12:27 generator.py
-rw-r--r-- 1 root root  211 May  3 07:31 test.txt
-rw-r--r-- 1 root root  211 May  3 07:31 test.txt.bin
```

Ok so we have some plaintext and two encrypted files. My mind switches to "known plaintext" attack mode for a moment. Let's check out the Python code. I look at the main function first to see what this generator is doing:

```
if __name__ == '__main__':
        key = '????????'
        with open('test.txt', 'rb') as f:
                test = f.read()
        with open('flag.png', 'rb') as f:
                flag = f.read()
        test_enc = encrypt(test, key)
        flag_enc = encrypt(flag, key)
        with open('test.txt.bin', 'wb+') as f:
                f.write(test_enc)
        with open('flag.png.bin', 'wb+') as f:
                f.write(flag_enc)
```

Ok so yeah it's the script they used to generate the encrypted binary files. Nothing out of the ordinary yet.

The first thing I wanted to test was to see happens when the script decrypted something with the wrong key. So I just quickly adjusted the script to do decryption instead. We see in the code that the decryption function is simply calling the encryption function. So the operation it's performing is reversible:

```
def encrypt(data, key):
        assert(len(key) == 8)
        assert(struct.unpack('<I', key[4:])[] != )
        assert(struct.unpack('<I', key[:4])[] != )
        state = struct.unpack('<I', key[:4])[]
        q = struct.unpack('<I', key[4:])[]
        generator = Generator(q, state)
        gamma = generator.generate_gamma(len(data))
        return ''.join([chr(ord(ch) ^ g)  for ch, g in zip(data, gamma)])

def decrypt(data, key):
        return encrypt(data, key)
```

So I don't even need to change the code I just change the inputs to the outputs:

```
if __name__ == '__main__':
        key = '????????'
        with open('test.txt.bin', 'rb') as f:
                test = f.read()
        with open('flag.png.bin', 'rb') as f:
                flag = f.read()
        test_enc = encrypt(test, key)
        flag_enc = encrypt(flag, key)
        with open('test.txt', 'wb+') as f:
                f.write(test_enc)
        with open('flag.png', 'wb+') as f:
                f.write(flag_enc)

```

Ok now, how about a key to test with. I could select something at random, but I recalled noticing a "dummy" key in the generator.py in a function called sanity_check:

```
def sanity_check():
        s = 'A'*150
        key = '324dfwer'
        s_enc = encrypt(s, key)
        s_dec = decrypt(s_enc, key)
        assert(s == s_dec)
```

Yeah, sounds as good as any other dummy key. Let's put that in:

```
if __name__ == '__main__':
        key = '324dfwer'
        with open('test.txt.bin', 'rb') as f:
                test = f.read()
        with open('flag.png.bin', 'rb') as f:
                flag = f.read()
        test_enc = encrypt(test, key)
        flag_enc = encrypt(flag, key)
        with open('test.txt', 'wb+') as f:
                f.write(test_enc)
        with open('flag.png', 'wb+') as f:
                f.write(flag_enc)
```


Ok code done, let's run it to make sure it doesn't have any errors and can decode a file (even if the key is wrong):

```
root@mankrik:~/volga/carry# ./degenerator.py 
root@mankrik:~/volga/carry# ls -la
total 52
drwxr-xr-x 2 root root 4096 May  4 12:53 .
drwxr-xr-x 3 root root 4096 May  4 12:26 ..
-rw-r--r-- 1 root root 8400 May  3 13:40 data.zip
-rwxr-xr-x 1 root root 2130 May  4 12:53 degenerator.py
-rw-r--r-- 1 root root 6846 May  4 12:53 flag.png
-rw-r--r-- 1 root root 6846 May  3 07:31 flag.png.bin
-rwxr-xr-x 1 root root 2111 May  4 12:27 generator.py
-rw-r--r-- 1 root root  211 May  4 12:53 test.txt
-rw-r--r-- 1 root root  211 May  3 07:31 test.txt.bin
```

Great we have a flag.png file, which at this time, I am positively sure is just gibberish binary data. So imagine my surprise when....

```
root@mankrik:~/volga/carry# file flag.png
flag.png: PNG image data, 1088 x 542, 8-bit/color RGB, non-interlaced
```

Oh ... Hmmm... Was that supposed to happen?

I view the PNG and sure enough, it's the flag. Guys did you really mean to include the actual production key in the sanity_check function?

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/05/approx-2.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/05/approx-2.png" height="106" width="320" /></a>
</div>