---
title: 'DeadFace CTF: Lytton Labs Cryptoware 1'
date: 2021-10-17T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/deadface/title.png
categories:
  - Write-Ups
  - Reversing
---
Another great CTF this week with a lot of variety of challenges and very helpful admins. For the second week in a row I'm writing about a solution which was not my first pathway. This challenge was in the Reverse Engineering category but if taken as a Crypto category challeng it solves much more easily.

#### <a name="cryptoware"></a>Decrypting Lytton Labs Cryptoware 1 - Reverse Engineering - 400 points

This challenge reads:

```
Decrypting Lytton Labs Cryptoware 1

DEADFACE has launched a ransomware attack against Lytton Labs. Luciafer was 
responsible for writing the Windows version, and TheZeal0t wrote the version 
for Linux.

We've recovered a file that was encrypted by Luciafer's ransomware, but 
we are unable to decrypt it. The BLUEzer's Club has been asked to help 
decrypt the file.

We haven't been able to decrypt the file, or determine what the key or 
encryption algorithm is. We are going to need your expertise on this one!

HINT: This ransomware attacks specific files used only by Lytton Labs. 
It is harmless against all others.

66 solves
```

With this challenge comes two files:

- `fkduohv-d-jhvfklfnwhu-wr-gdun-dqjho-01.oodev`
- `zealotcrypt-01.exe`

A quick check shows that the binary is a Windows PE32 originally written in Golang. 

```shell
$ file zealotcrypt-01.exe
zealotcrypt-01.exe: PE32 executable (console) Intel 80386 (stripped to 
external PDB), for MS Windows
```

Loading the binary in Ghidra shows the typical issue with reversing Golang binary but the basic program flow can still be divined. I removed a bunch of useless lines from the decompilation to show the basics:

```c
int main.main(void) {
	main.fetchKey(&key);			// Get a RC4 key from somewhere...
    main.findFilesWithExt(...);		// Find any *.llabs files in the path...
    for (filelist) {				// Loop through the llabs files
        main.rotateText(...); 		// Rot3 the filename...  aaa.llabs -> ddd.oodev
        os.ReadFile(&buf);			// Read the contents of the file.
        main.encryptRc4(buf, key);	// Encrypt the the key given using RC4
        os.WriteFile(...);			// write encrypted contents to the renamed file.
        os.Remove(...);				// remove original file.
    }
}
```

So its a typical ransomware type process. Encrypt files and ransom the owner, except this one only targets `*.llabs` files.

Our job is to:

- figure out the encryption
- somehow reverse the encryption
- recover the file given in the clue which contains a flag

#### Solving Theories

I tried a few methods at first, I knew that the `main.fetchKey()` function was worth investigating to recover the key material. Here's what it looks like:

```c
int main.fetchKey(char *key) {
	net/http.NewRequestWithContext(...);
	net/http.(*Client).do(...);
}
```

So it clearly grabs a key from the internet via Go's standard `net/http` library. We can look at the network calls it makes when we run it with Wine and find that it grabs a GIF file from the web:

```shell
$ tcpdump -w zealot.pcap -i eth0 port 80
...
```

```
GET /pretty-lady.gif HTTP/1.1
Host: insidious.deadface.io
User-Agent: DEADFACE-LLABS-CRYPTOWARE/6.66
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Mon, 18 Oct 2021 06:57:52 GMT
Server: Apache/2.4.49 (Unix)
Last-Modified: Sat, 20 Jun 2020 20:21:59 GMT
ETag: "295f3-5a889c2fe87c0"
Accept-Ranges: bytes
Content-Length: 169459
Content-Type: image/gif

GIF89a..,.....................
```

The `pretty-lady.gif` is an animated GIF with nothing specific about it. In Golang the `RC4` library can use any byte slice as a key so its possible that the ransomware just indexes into the `pretty-lady.gif ` by some integer and uses a random slice of bytes of length between 1 and 256. 

I tried writing some Go that tried to use that method to successfully encrypt a string of `AAAAAA` which possibly could have worked. I would only need to take a sliding 6 byte key stream window from `pretty-lady.gif` and see if it worked. However I didn't end up needing to because before that finished running I thought of another idea.

#### Solving in Practice

While testing out how the ransomware worked I just did a standard "run it and see what happens..."

```shell
$ echo -n "AAAA" > test.llabs
$ wine zealotcrypt-01.exe
Pinkie Print = cfa5:6af7
LYTTON LABS: Your sins have finally caught up to you!  Your files have been encrypted!
$ ls *.oodev                                                                                                                     
fkduohv-d-jhvfklfnwhu-wr-gdun-dqjho-01.oodev  whvw.oodev
$ cat whvw.oodev | hex
71a6eceb
```

So our `test.llabs` file has become `whvw.oodev` and the contents changed from `\x41\x41\x41\x41` to `\x71\xa6\xec\xeb`

Next I wanted to try 2 things:

- What happens when I re-encrypt an already encrypted file?
- What happens when I encrypto `\x00\x00\x00\x00` and XOR it with our existing encrypted file?

As it turns out, both methods work to solve this riddle because of the flawed way in which the ransomware re-uses the RC4 key. Since the key is the same every time it is invoked and RC4 is basically XOR with a fancy keystream generator the solution is rather simple.

#### Solution 1, XOR with Encrypted Null Bytes

Since the encrypted file we want is 892 bytes long, we need to encrypt 892 zeros first:

```shell
$ python -c "print('\x00' * 892, end='')" > zeros.llabs
$ wine zealotcrypt-01.exe
Pinkie Print = cfa5:6af7
LYTTON LABS: Your sins have finally caught up to you!  Your files have been encrypted!
$ ls -la *.oodev
ls -la *.oodev
-rw-r--r-- 1 root root 892 Oct 18 21:20 churv.oodev
-rw-r--r-- 1 root root 892 Oct 16 00:03 fkduohv-d-jhvfklfnwhu-wr-gdun-dqjho-01.oodev
```

Then xor these together for the flag:

```shell
$ xortool-xor -f churv.oodev -f fkduohv-d-jhvfklfnwhu-wr-gdun-dqjho-01.oodev                                                                 
Dear Dark Angel,

We need your help (again).  It seems that those pesky little twerps
at DEADFACE have targetted Lytton Labs with their hacking activities.
I'm worried that they'll get their hands on information that could
cause Lytton Labs embarrassment or financial harm.

We need your hacking and incident response skills to help us to
keep DEADFACE out or to divert them away from the really important
records of our activities, as well as to notify us of any attempts,
successful or otherwise, to breach our systems.

We will pay your standard fee, plus a 25% bonus when you have 
presented us with proof that you have managed to counter-hack one
of the DEADFACE operative's computers.

Please let me know if you have any questions.


Ever at your service,


Dr. Charles A. Geschickter
Head of MKULTRA Research
Lytton Labs

P.S. flag{RC4-IS-REVERSIBLE-BUT-AES-IS-NOT-GO-BACK-GO-BACK!!!}
```

#### Solution 2, Re-encrypt Ciphertext

This one is even easier than the first, just rename the file and run the ransomware:

```shell
$ mv fkduohv-d-jhvfklfnwhu-wr-gdun-dqjho-01.oodev win.llabs
$ wine zealotcrypt-01.exe
Pinkie Print = cfa5:6af7
LYTTON LABS: Your sins have finally caught up to you!  Your files have been encrypted!
$ cat zlq.oodev

...

P.S. flag{RC4-IS-REVERSIBLE-BUT-AES-IS-NOT-GO-BACK-GO-BACK!!!}
```

Both worked and we're faster than reversing the binary in the end.
