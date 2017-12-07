---
id: 544
title: 'SharifCTF 2016 - Blocks - Forensics 400 Point Challenge'
date: 2016-02-07T01:38:49+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=544
permalink: /sharifctf-2016-blocks-forensics-400-point-challenge/
post_views_count:
  - "1175"
image: /images/2016/02/sharifctf-660x309.png
categories:
  - Write-Ups
tags:
  - forensics
  - png
  - python
  - sqlite
---
<img class="size-full wp-image-545 aligncenter" src="/images/2016/02/blocks.png" alt="blocks" width="549" height="338" srcset="/images/2016/02/blocks.png 549w, /images/2016/02/blocks-300x185.png 300w" sizes="(max-width: 549px) 100vw, 549px" />

Good fun this one, and worth a lot of points also as I solved it very early. It involves a small file of "unknown" data which we're told is probably not complete in the clue.

First things first let's grab the file and check it out:

```
root@kali:~/sharif/blocks# file data3
data3: data
```

Ok that's of no help, what about strings:

<!-- HTML generated using hilite.me -->

```
root@kali:~/sharif/blocks# strings data3 | head -7
tabledatadata
CREATE TABLE "data" (
	`ID`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Data`	BLOB NOT NULL,
	`Cat`	INTEGER NOT NULL
indexsqlite_autoindex_data_1data
Ytablesqlite_sequencesqlite_sequence
```

Ok probably SQLite3 file then? Let's try!

```
root@kali:~/sharif/blocks# sqlite3 data3
SQLite version 3.9.2 2015-11-02 18:31:45
Enter ".help" for usage hints.
sqlite> select table_name from information_schema.tables;
Error: file is encrypted or is not a database
```

Nope. How about repairing it?

```
root@kali:~/sharif/blocks# sqlite3 data3 "PRAGMA integrity_check"
Error: file is encrypted or is not a database
```

No, it's just too messed up? Let's look at the <a href="https://www.sqlite.org/fileformat2.html" target="_blank">SQLite file format</a>... The file should have the magic bytes "SQLite format 3\x00". Our file has this:

```
root@kali:~/sharif/blocks# xxd -l 16 data3
00000000: 2033 0004 0001 0100 4020 2000 0000 0b00   3......@  .....
```

So we've got a 0x20 (Space), 3, Null. Looks a lot like the ending of the proper file header, let's stick some bytes on the front and see if we can load it...

```
root@kali:~/sharif/blocks# python
Python 2.7.11 (default, Jan 11 2016, 21:04:40) 
[GCC 5.3.1 20160101] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> open('fixed','wb').write("SQLite format" + open('data3','rb').read())
>>> quit()
root@kali:~/sharif/blocks# file fixed
fixed: SQLite 3.x database
root@kali:~/sharif/blocks# sqlite3 fixed "PRAGMA integrity_check"
ok
```

Sweet. What lies within this then? I found a tool called sqlitebrowser installed. It's a bit cool. With it we can browse the structure of the SQLite db file graphically. That helped come up with a strategy for me:

This is the main UI for the browser, you can see the file loaded pretty successfully.

<img class="wp-image-547 aligncenter" src="/images/2016/02/sqlite1.png" alt="sqlite1" width="988" height="770" srcset="/images/2016/02/sqlite1.png 1234w, /images/2016/02/sqlite1-300x234.png 300w, /images/2016/02/sqlite1-768x599.png 768w, /images/2016/02/sqlite1-1024x798.png 1024w, /images/2016/02/sqlite1-660x515.png 660w" sizes="(max-width: 988px) 100vw, 988px" />

In the data browser we see what the deal is. One table has common PNG header values as category names...

<img class="size-full wp-image-548 aligncenter" src="/images/2016/02/sqlite2.png" alt="sqlite2" width="476" height="358" srcset="/images/2016/02/sqlite2.png 476w, /images/2016/02/sqlite2-300x226.png 300w" sizes="(max-width: 476px) 100vw, 476px" />

And in the Data table, we have binary blobs with category fields which relate them back to the Category table in accordance to what PNG chunk they belong to.

<img class="size-full wp-image-549 aligncenter" src="/images/2016/02/sqlite3.png" alt="sqlite3" width="477" height="548" srcset="/images/2016/02/sqlite3.png 477w, /images/2016/02/sqlite3-261x300.png 261w" sizes="(max-width: 477px) 100vw, 477px" />

So pretty much this looks straightforward for IHDR, PLTE, tRNS chunks. However the IDAT chunk (the actual image data) is split into multiple 270ish byte chunks and deposited into the database. And yes, before you ask, the blob's are in random order. So we have a total of 11 chunks of image data in a completely random order. Leaving us with a totally massive number of possible image data permutations.

Let's see if there's any hints in the blob data to see if we can reduce the permutations.

Firstly, below is the 5th row blob data. It begins with an "x" character which I often see as the first byte in IDAT chunks in PNG images. So let's try placing that first.

<img class="size-full wp-image-551 aligncenter" src="/images/2016/02/sqlite4.png" alt="sqlite4" width="621" height="410" srcset="/images/2016/02/sqlite4.png 621w, /images/2016/02/sqlite4-300x198.png 300w" sizes="(max-width: 621px) 100vw, 621px" />

Next I see the final row 14 blob data is 270 bytes while all other blobs are 274 bytes. This could mean it's the final block. Upon further inspection it contains a few null bytes towards the end, further cementing the idea this is the final blob in the IDAT chunk.

<img class="size-full wp-image-552 aligncenter" src="/images/2016/02/sqlite5.png" alt="sqlite5" width="621" height="413" srcset="/images/2016/02/sqlite5.png 621w, /images/2016/02/sqlite5-300x200.png 300w" sizes="(max-width: 621px) 100vw, 621px" />

This leaves us with 9 x 9 x 9 x 9 x 9 x 9 x 9 x 9 x 9 permutations of PNG file these could add up to. How else can we work on this problem? I figured that PNG data is compressed and so attempting to decompress a permutation of the data blobs should yield either an exception or a successful decompression. I implemented this theory in some Python code but found zero solutions resulted in successful decompression. So perhaps more work was needed on that theory.

In order to just move forward with the challenge, I decided to write some Python code that will generate PNG image candidates which I can quickly review in Windows explorer thumbnail view for likely candidates. I've done a challenge like this before so I knew that it would "work".

I used this code with a itertools.permutations() with the r value set to 9 for about 360,000 PNGs. With a very fast SSD this was actually no big deal to quickly scroll through for candidates. On the 327,600 image I found that blocks 2 & 3 were aligned and I saw a partial flag image (I could read** SharifCTF{6**).

This reduced the permutations needed down to an "r" value of 7 so I added these block markers into the Python code.

```
#!/usr/bin/python

import sqlite3
import binascii
import struct
import itertools

# limit the number of candidate PNGs to this
LIMIT = 3100

print "[*] Fixing the SQLite file..."
orig = "SQLite format"
orig += open('data3','rb').read()
open('data3.sqlite','wb').write(orig)

print "[*] Extracting the PNG Data from SQLite DB..."
conn = sqlite3.connect('data3.sqlite')
cursor = conn.cursor()

# PNG Magic bytes
png = "\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0d"

# get IHDR first
ihdr = "IHDR" 
cursor.execute("SELECT Data FROM data WHERE Cat = 4")
ihdr += str(cursor.fetchone()[])
ihdr += "\x89\xb8\x68\xee\x00\x00\x03\x00" # CRC32

# Next the PLTE
plte = "PLTE"
cursor.execute("SELECT Data FROM data WHERE Cat = 7")
plte += str(cursor.fetchone()[])
plte += "\xe2\xb0\x5d\x7d\x00\x00\x00\x02"

# Next the tRNS
trns = "tRNS"
cursor.execute("SELECT Data FROM data WHERE Cat = 8")
trns += str(cursor.fetchone()[])
trns += "\xe5\xb7\x30\x4a\x00\x00\x0b\xc3"

# finally the IDAT
idat = "IDAT"
cursor.execute("SELECT Data FROM data WHERE Cat = 2")

puzzle = []
known  = [None] * 11
for row in cursor.fetchall():
  if str(row[])[] == "\x78":    # known 1st block
    known[] = str(row[])    
  elif str(row[])[] == "\x5c":    # learned 2nd block
    known[1] = str(row[])   
  elif str(row[])[] == "\x13":    # learned 3rd block
    known[2] = str(row[])   
  elif len(str(row[])) == 270:    # known final block
    known[10] = str(row[])    
  else:
    puzzle.append(str(row[]))

idat += "".join(known[:3])

# define an IEND for later
iend = "IEND" + "\xae\x42\x60\x82"

print "[*] Building potential flag PNGs..."
 
counter = 
for i in itertools.permutations(puzzle, 7):

  if counter > LIMIT:
    quit()

  image = idat + "".join(i)
  image += known[10]
  image += "\x08\x8d\x8d\xb6\x00\x00\x00\x00"
  open(str(counter).zfill(6) + '.png','wb').write(png + ihdr + plte + trns + image + iend)
  counter += 1
```

After just 3046 more PNGs I had the flag so I stopped looking for other ways to solve this:

<img class="size-full wp-image-555 aligncenter" src="/images/2016/02/003046.png" alt="003046" width="600" height="600" />