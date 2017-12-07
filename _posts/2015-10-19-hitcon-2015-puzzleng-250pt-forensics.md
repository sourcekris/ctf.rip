---
id: 224
title: 'HITCON 2015: PuzzleNG - 250pt Forensics Challenge'
date: 2015-10-19T10:20:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=224
permalink: /hitcon-2015-puzzleng-250pt-forensics/
post_views_count:
  - "761"
image: /images/2015/10/puzzleng-2.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
I don't mind admitting that Hitcon was HARD. Possibly some of the hardest challenges I've faced CTFing so far. Or maybe I was just rusty. Anyway here's one challenge I found particularly rewarding from Hitcon 2015.

The clue was fairly cryptic, not giving anything away. It simply delivered a compressed tarball...

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://4.bp.blogspot.com/-AXD8Vx-Rjwg/ViSZz3iPi3I/AAAAAAAAAOo/II6w0e9mZAE/s1600/puzzleng.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="154" src="/images/2015/10/puzzleng-2.png" width="640" /></a>
</div>

When extracting the tarball we are rewarded with two files: "encrypt" and "flag.puzzle":
  
```
root@mankrik:~/hitcon/puzzleng/writeup# tar -zxvf puzzleng-edb16f6134bafb9e8b856b441480c117.tgz 
flag.puzzle
encrypt
root@mankrik:~/hitcon/puzzleng/writeup# ls -la
total 288
drwxr-xr-x  2 root root    4096 Oct 19 18:21 .
drwxr-xr-x 11 root root  262144 Oct 19 18:21 ..
-rwxr-xr-x  1  501 staff   9092 Oct 17 05:01 encrypt
-rw-r--r--  1  501 staff   1135 Oct 17 01:01 flag.puzzle
-rw-r--r--  1 root root    4409 Oct 17 16:10 puzzleng-edb16f6134bafb9e8b856b441480c117.tgz
root@mankrik:~/hitcon/puzzleng/writeup# file encrypt 
encrypt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x7042def34be83440653a5031ea23059b5f5c7fb2, not stripped
root@mankrik:~/hitcon/puzzleng/writeup# file flag.puzzle 
flag.puzzle: data
```

So an ELF binary and a chunk of unidentified data which, judging by the name of the ELF binary may be "encrypted" flag file.

Sweet.

First things first, I examine the contents of flag.puzzle with a hexeditor but nothing immediate is revealed. Next I try the executable:

```
root@mankrik:~/hitcon/puzzleng/writeup# ./encrypt 
encrypt: encrypt.cpp:7: int main(int, char**): Assertion `argc == 3' failed.
Aborted
```

Ok it needs argc == 3, so we learned two things. It's written in C++ and requires two command line arguments.

```
root@mankrik:~/hitcon/puzzleng/writeup# ./encrypt 1 2
encrypt: encrypt.cpp:13: int main(int, char**): Assertion `fp != __null' failed.
Aborted
```

And so I assume one of the arguments needed is a file and the other is probably a key value.

Let's build a sample input and try and operate the encryption program against it.

I will choose a file consisting of all one character and a single byte key to observe the behavior of whatever algorithm or mechanics this encrypt program uses:

```
root@mankrik:~/hitcon/puzzleng/writeup# perl -e 'print "A" x 1000'> test.plain
root@mankrik:~/hitcon/puzzleng/writeup# ./encrypt A test.plain > test.cipher
```

The result looks ordered by blocks. We chose a 1,000 byte repeating character input and received a 1,000 byte output of ordered blocks of data of 50 bytes per block:

```
root@mankrik:~/hitcon/puzzleng/writeup# xxd test.cipher | head -10
0000000: 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c  ,,,,,,,,,,,,,,,,
0000010: 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c  ,,,,,,,,,,,,,,,,
0000020: 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c 2c2c  ,,,,,,,,,,,,,,,,
0000030: 2c2c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c  ,,..............
0000040: 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c  ................
0000050: 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c 8c8c  ................
0000060: 8c8c 8c8c 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d  ................
0000070: 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d  ................
0000080: 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d 0d0d  ................
0000090: 0d0d 0d0d 0d0d a3a3 a3a3 a3a3 a3a3 a3a3  ................
```

Repeated executions give me the same output so there's probably no random IV or other input to the algorithm being used.

Time to fire up IDA Pro and examine the encrypt binary in the decompiler. We examine the main() function and see pretty much what we expect.

```
 if ( argc != 3 )
    __assert_fail("argc == 3", "encrypt.cpp", 7u, "int main(int, char**)");
  v3 = strlen(argv[1]);
  SHA1(argv[1], v3, v11);
  stream = fopen(argv[2], "r");
  if ( !stream )
    __assert_fail("fp != __null", "encrypt.cpp", 0xDu, "int main(int, char**)");
  fseek(stream, 0LL, 2);
  v8 = ftell(stream);
  rewind(stream);
  for ( i = ; i <= 19; ++i )
  {
    for ( j = ; j < (v8 + 19) / 20; ++j )
    {
      v9 = fgetc(stream);
      if ( v9 == -1 )
        break;
      putchar(v9 ^ v11[i]);
    }
  }

```

Above you can see the important bits of the code, it takes the command line argument, hashes it with SHA1 and uses the SHA1 output as a key across the input file. It spreads the key bytes across 20 even blocks of the input, using XOR of one of the key bytes per block.

So in theory, all we need to do to solve this is:

  * Divide the input into 20 evenly sized blocks
  * Discover the single-byte XOR key for each block, decrypt the block
  * Re-assemble the file into the decrypted output

Easy?!

To begin with, we use an old trick of a known plaintext attack. We think up likely strings that might appear somewhere in the file in order to get a headstart on some of the blocks.

I try obvious ones first, JFIF, GIF and PNG as input strings, and using the "xorsearch" tool I quickly discover the encrypted file is probably a PNG:

```
root@mankrik:~/hitcon/puzzleng/writeup# xorsearch flag.puzzle PNG
Found XOR 65 position 0001: PNG....
```
So we found two pieces of information here, the file format (PNG) and the XOR key for the first block (0x65).

Next I split the file into blocks, before I do though, I use a quick Python script to double-check the actual block size being used here:

```
#!/usr/bin/python
import subprocess
open('generated.plaintext','w').write('A' * 1135)
ctext = subprocess.check_output(['./encrypt','a','generated.plaintext'])

firstbyte = ctext[]

for b in range(,len(ctext)):
        if ctext[b] != firstbyte:
                print "blocksize is " + str(b)
  quit()
```

Which returns:

```
root@mankrik:~/hitcon/puzzleng/writeup# ./c.py 
blocksize is 57
```

So we can use split to extract the chunks:
```
root@mankrik:~/hitcon/puzzleng/writeup# split -b 57 -d flag.puzzle 
```

Next we can use the known plaintext attack against further chunks. We know PNG files contain IDAT before image data chunks and end with "IEND", we use that to recover two more keys:

```
root@mankrik:~/hitcon/puzzleng/writeup# xorsearch x01 IDAT
Found XOR 30 position 0021: IDATx...A..0......5..H_v
root@mankrik:~/hitcon/puzzleng/writeup# xorsearch x19 IEND
Found XOR 1B position 002C: IEND.B`.
```

Great, getting somewhere. We have 3/20 keys. What other patterns can we use for this attack?

Well PNGs can contain several IDAT chunks, but nope we don't find any evidence of that in this image. No Exif data. Hmm. 17 files each with 256 possible keys adds up to a lot of possible image files.

I was stuck here a while, until i decided to look for non obvious patterns. Luckily I found two such patterns very quickly. Inside the final chunk, decrypted using the key we found with xorsearch above, we see the following:

```
root@mankrik:~/hitcon/puzzleng/writeup# xortool-xor -h 1b -f x19 > x19.plain
root@mankrik:~/hitcon/puzzleng/writeup# xxd x19.plain 
0000000: 6bc9 bf5b 4824 1289 4422 9148 2412 8944  k..[H$..D".H$..D
0000010: 2291 4824 1289 4422 9148 2412 795c ff00  ".H$..D".H$.y..
0000020: c3f9 b034 d9bf 3b6a 0000 0000 4945 4e44  ...4..;j....IEND
0000030: ae42 6082 0a                             .B`..
```

Repeated strings of H$ and D". Could this be re-occuring throughout the file? Worth a try.

In fact they do, each chunk of encrypted data has either H$ or D" (usually both) inside it with little variation on position:

```
root@mankrik:~/hitcon/puzzleng/writeup# xorsearch x02 H$
Found XOR 56 position 0012: H$..D".H$..D".H$..D".H....k}..{M={O}W..
Found XOR 56 position 0019: H$..D".H$..D".H....k}..{M={O}W..
Found XOR 56 position 0020: H$..D".H....k}..{M={O}W..
root@mankrik:~/hitcon/puzzleng/writeup# xorsearch x03 D"
Found XOR C3 position 0001: D".H........"..}.>.!..D"....,]...D.f.)..D"..w...
Found XOR C3 position 0017: D"....,]...D.f.)..D"..w...
Found XOR C3 position 0029: D"..w...
```

And so on throughout the file...

Using this method we are able to isolate the entire 20 byte xor key which we find to be:

653056c378ff4bbff74737e36f53264c25f4d11b

Using this Python code we quickly split and decrypt the file using our recovered key:

```
#!/usr/bin/python

thekeys = ['x65','x30','x56','xc3','x78','xff','x4b','xbf','xf7','x47','x37','xe3','x6f','x53','x26','x4c','x25','xf4','xd1','x1b']

blocksize = 57
plain = []

puzzle = open('flag.puzzle','rb').read()
whichkey = 
for i in range(,len(puzzle),blocksize):
        piece = puzzle[i:i+blocksize]
        chunklist = list(piece)
        for c in range(,len(chunklist)):
                plain.append(chr(ord(chunklist[c])^ord(thekeys[whichkey])))      
        whichkey += 1

open('output.png','wb').write("".join(plain))
```

Resulting in the following output...

<div class="separator" style="clear: both; text-align: center;"><a href="http://4.bp.blogspot.com/-QsjOF_RRiSk/ViTCccmsadI/AAAAAAAAAO8/__jXJZkladY/s1600/output.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="320" src="/images/2015/10/output-2.png" width="320" /></a></div>

Great? A purple block...

Thinking there's more to it, I switch to the trusty old Stegosolve.jar program and flip through the standard filters. On the blue plane we are lucky and find a hidden QR code:

<div class="separator" style="clear: both; text-align: center;"><a href="http://2.bp.blogspot.com/-NLXou9_ywzc/ViTDNBnDgwI/AAAAAAAAAPE/DL8liFE8sU4/s1600/puzzlengqr.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="320" src="/images/2015/10/puzzlengqr-2.png" width="295" /></a></div>

Which, THANKFULLY, stores the text of the flag:

hitcon{qrencode -s 16 -o flag.png -l H -foreground 8F77B5 -background 8F77B4}

A fun little challenge for sure.