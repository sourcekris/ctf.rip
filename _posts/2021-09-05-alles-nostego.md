---
title: 'ALLES CTF 2021: Nostego'
date: 2021-09-05T04:00:00+00:00
author: Kris
layout: post
image: /images/2021/alles/nostegotitle.png
categories:
  - Write-Ups
  - Crypto
---
Unfortunately infrastructure problems meant this CTF was quite frustrating to play. I spent most of my time refreshing a website waiting for my session to connect so I only solved two challenges before moving on to GrabCON. Anyway I solved Nostego first so here's my solution. I believe my solution is pretty wrong but it worked so /shrug.

#### <a name="nostego"></a>Nostego - Crypto - 129 points

This challenge reads:

```
It cannot be stego because the source is attached.

Challenge Files:ALLES.enc.png challenge.py

(100 solves)
```

With the challenge we get this file:

* `ALLES.enc.png`
* `challenge.py`

The Python script is the method used to "encrypt" the flag which is in a PNG file originally:

```python
from PIL import Image
import sys

if len(sys.argv) != 3:
    print("Usage: %s [infile] [outfile]" % sys.argv[0])
    sys.exit(1)

image = Image.open(sys.argv[1]).convert("F")
width, height = image.size
result = Image.new("F", (width, height))

ROUNDS = 32

for i in range(width):
    for j in range(height):
        value = 0
        di, dj = 1337, 42
        for k in range(ROUNDS):
            di, dj = (di * di + dj) % width, (dj * dj + di) % height
            value += image.getpixel(((i + di) % width, (j + dj + (i + di)//width) % height))
        result.putpixel((i, j), value / ROUNDS)

result = result.convert("RGB")
result.save(sys.argv[2])
```

I wasn't very sure how to solve it properly but I had one idea. Since the starting values of `di` and `dj` are known and they only change modulo the PNG width and height we know what each value was over time.

My idea was to replay the same transforms on the file backwards and see what happens.

So firstly I recorded all of the `di, dj` values running forward:

```python
from PIL import Image
import sys

if len(sys.argv) != 3:
    print("Usage: %s [infile] [outfile]" % sys.argv[0])
    sys.exit(1)

image = Image.open(sys.argv[1]).convert("F")
width, height = image.size
result = Image.new("F", (width, height))

ROUNDS = 32

f = open('tuples.csv', 'w')
for i in range(width):
    for j in range(height):
        value = 0
        di, dj = 1337, 42
        for k in range(ROUNDS):
            di, dj = (di * di + dj) % width, (dj * dj + di) % height
            f.write('%d,%d\n' % (di,dj))
            value += image.getpixel(((i + di) % width, (j + dj + (i + di)//width) % height))
        result.putpixel((i, j), value / ROUNDS)

f.close()
result = result.convert("RGB")
result.save(sys.argv[2])
```

Then I replayed them in reverse to the encrypted file:

```python
from PIL import Image

image = Image.open("ALLES.enc.png").convert("F")
width, height = image.size
result = Image.new("F", (width, height))

ROUNDS = 32

lines = iter(open('tuples.csv', 'r').readlines()[::-1])
for i in range(width):
    for j in range(height):
        value = 0
        for k in range(ROUNDS):
            line = next(lines)
            di = int(line.split(",")[0])
            dj = int(line.split(",")[1])
            value += image.getpixel(((i - di) % width, (j - dj + (i - di)//width) % height))
        result.putpixel((i, j), value / ROUNDS)

result = result.convert("RGB")
result.show()
result.save("out.png")
```

Which gives me this image:

![barely visible](/images/2021/alles/out.png)

Which you can barely see the outline of the ALLES! CTF logo. Underneath that its also possible to make out some of the flag. I used `gimp` to make the flag more visible using `sharpen` and this is what I got:

![sharpened flag](/images/2021/alles/nostegoflag.PNG)

Which isn't a great solution I agree but with some squinting I was able to make out the flag:

`ALLES!{why_so1v3_st3g0_wh3n_y0u_c4n_h4v3_crypto}`

It took a few guesses about some of the characters but it sure beat spending a lot more time on a perfect solution :)





