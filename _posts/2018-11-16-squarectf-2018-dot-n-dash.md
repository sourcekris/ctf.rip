---
title: 'Square CTF 2018: Dot-n-dash'
date: 2018-11-16T00:00:00+00:00
author: Kris
layout: post
image: /images/2018/squarectf.PNG
categories:
  - Write-Ups
---
Long time since my last CTF writeup. I thought I would post this one since it was the first CTF I had done in a while and I wouldn't mind getting back into them. I spent a few hours on this CTF and solved a couple of challenges. The first one had the following clue:

> ## C1: dot-n-dash

> *Intro*

> You are the last person on planet Charvis 8HD. Everyone has decided to leave because Charvis 9HD is the hipper place to live. As the last person to leave, your Captain sent you the following instructions:

> `"Make sure you enable the Charvis 8HD Defense System (CDS) after taking off in your spaceship."`

> However, you misread the instructions and activated the CDS before leaving the planet. You are now stuck on this planet. Can you figure out how to manually disable the 10 defense systems (C1 thru C10) which comprise CDS in order to safely take off?

> Thankfully, Charvis 8HD does not have [strong dust storms](https://en.wikipedia.org/wiki/The_Martian_(film)) and you will not need to travel 2,000 miles in a rover.

> The instructions to disable C1 were considered restricted. As a result, they were stored only in encoded form.
> The code to decode the instructions was regrettably lost due to cosmic radiation. However, the encoder survived.

> Can you still decode the instructions to disable C1?

The download contained a text encoder function written in Javascript that takes any input string and encodes it into dots and dashes. It looks like this:

```js
function _encode(input) {
  var a=[];
  for (var i=0; i<input.length; i++) {
    var t = input.charCodeAt(i);
    for (var j=0; j<8; j++) {
      if ((t >> j) & 1) {
        a.push(1 + j + (input.length - 1 - i) * 8);
      }
    }
  }

  var b = [];
  while (a.length) {
    var t = (Math.random() * a.length)|0;
    b.push(a[t]);
    a = a.slice(0, t).concat(a.slice(t+1));
  }

  var r = '';
  while (b.length) {
    var t = b.pop();
    r = r + "-".repeat(t) + ".";
  }
  return r;
}
```

You can see it happens to have three steps to the process:

1. Firstly it takes the ascii value of the character and calculates some numbers based on the bit values of the character and the length of the input. The resulting numbers are stored in an array called `a`
2. Secondly, the encoder shuffles the `a` array randomly into an array called `b`.
3. Finally the third part just translates the numbers in the `b` array into a set of dashes and terminated by a dot.

The solution seems to need us to figure out how to decode a second file in the archive provided called `instructions.txt`. Ok cool...

Wow well how are we going to approach this one? Lets look at the behaviour of the algorithm on some sample inputs first?

I decided to rewrite the algorithm in Python as a first step so I can play with it more easily on my Linux machine. This is what I wrote first:

```py
import random

def encode(input):
  a = []
  for i in range(len(input)):
    t = ord(input[i])
    for j in range(8):
      if ((t >> j) & 1):
        a.append(1 + j + (len(input) - 1 - i) * 8)

  b = []
  while len(a):
    t = int((random.random() * len(a)))|0
    b.append(a[t])
    a = a[:t] + a[t+1:]

  r = ''
  while len(b): 
    t = b.pop();
    r = r + ("-" * t) + "."

  return r

print encode("A")
```

Next I confirmed that, for the JavaScript and Python versions, I got the same outputs. I did so, great. Then I used the code to encode some simple inputs:

* "A": `-------.-.`
* "AA": `-------.-.---------.---------------.`
* "AAA": `-----------------------.-.---------.-------.-----------------.---------------.`

Wow the output string length really grows quickly as the input string length grows linearly. 

Remembering that the dots and dashes just encode numbers, it might make more sense to look directly at the numbers instead. That means we want to look directly at `b`:

* "A": `b = [7, 1]`
* "AA": `b = [7, 1, 15, 9]`
* "AAA": `b = [9, 23, 1, 17, 7, 15]`

Interesting, the numbers grow in size as the number of bytes increase on the input. The numbers are shuffled as we expect due to the shuffling code. How do we recover the bytes from before the shuffling?

The answer occured to us after we tried two things. First we looked at a long encoded string:

```This is a much longer encoded string and will produce a really long dots and dashes string.```

This resulted in a set of numbers that grew quite large in magnitude:

```py
b = [286, 638, 342, 111, 335, 271, 366, 575, 90, 511, 174, 470, 169, 251, 374, 69, 415, 527, 686, 626, 507, 578, 102, 223, 338, 349, 294, 118, 244, 351, 596, 265, 382, 569, 670, 582, 142, 331, 577, 419, 15, 211, 637, 673, 529, 238, 519, 719, 87, 318, 703, 327, 172, 375, 289, 49, 210, 462, 357, 28, 425, 319, 246, 588, 305, 471, 254, 543, 130, 37, 230, 599, 175, 398, 571, 505, 639, 46, 183, 307, 542, 206, 438, 86, 521, 705, 39, 623, 443, 89, 466, 45, 547, 295, 587, 431, 75, 379, 523, 662, 207, 644, 237, 385, 159, 325, 323, 631, 53, 479, 535, 586, 598, 340, 222, 614, 182, 257, 84, 311, 279, 635, 339, 393, 447, 463, 337, 550, 452, 455, 66, 534, 94, 567, 641, 372, 388, 2, 62, 123, 630, 502, 674, 654, 727, 522, 158, 43, 193, 190, 220, 314, 255, 481, 397, 679, 411, 450, 165, 457, 475, 321, 620, 132, 406, 274, 469, 199, 725, 663, 25, 711, 551, 515, 157, 594, 593, 681, 622, 538, 446, 485, 441, 414, 477, 212, 23, 166, 252, 50, 643, 540, 482, 9, 701, 487, 78, 70, 19, 607, 359, 127, 716, 422, 154, 391, 194, 239, 65, 442, 708, 604, 31, 38, 55, 203, 247, 150, 710, 657, 18, 723, 539, 603, 22, 34, 678, 326, 171, 394, 590, 423, 10, 267, 380, 54, 687, 14, 134, 71, 383, 399, 503, 131, 494, 107, 698, 143, 126, 47, 524, 526, 270, 451, 418, 263, 646, 262, 11, 558, 350, 647, 510, 697, 103, 390, 214, 702, 215, 4, 302, 179, 478, 562, 73, 6, 346, 313, 518, 163, 358, 20, 277, 135, 195, 566, 565, 460, 243, 625, 97, 278, 371, 153, 606, 3, 334, 579, 202, 591, 137, 236, 395, 167, 677, 530, 583, 420, 95, 219, 343, 595, 684, 633, 694, 310, 574, 718, 110, 198, 170, 30, 209, 430, 93, 233, 204, 79, 486, 545, 454, 499]
```

Second, we looked at the same encoded string, but before the shuffling takes place. It results in a string that looks like this:

```py
a = [723, 725, 727, 716, 718, 719, 705, 708, 710, 711, 697, 698, 701, 702, 703, 694, 681, 684, 686, 687, 673, 674, 677, 678, 679, 670, 657, 662, 663, 654, 641, 643, 644, 646, 647, 633, 635, 637, 638, 639, 625, 626, 630, 631, 620, 622, 623, 614, 603, 604, 606, 607, 593, 594, 595, 596, 598, 599, 586, 587, 588, 590, 591, 577, 578, 579, 582, 583, 569, 571, 574, 575, 562, 565, 566, 567, 558, 545, 547, 550, 551, 538, 539, 540, 542, 543, 529, 530, 534, 535, 521, 522, 523, 524, 526, 527, 515, 518, 519, 505, 507, 510, 511, 499, 502, 503, 494, 481, 482, 485, 486, 487, 475, 477, 478, 479, 466, 469, 470, 471, 457, 460, 462, 463, 450, 451, 452, 454, 455, 441, 442, 443, 446, 447, 438, 425, 430, 431, 418, 419, 420, 422, 423, 411, 414, 415, 406, 393, 394, 395, 397, 398, 399, 385, 388, 390, 391, 379, 380, 382, 383, 371, 372, 374, 375, 366, 357, 358, 359, 346, 349, 350, 351, 337, 338, 339, 340, 342, 343, 331, 334, 335, 321, 323, 325, 326, 327, 313, 314, 318, 319, 305, 307, 310, 311, 302, 289, 294, 295, 286, 274, 277, 278, 279, 265, 267, 270, 271, 257, 262, 263, 251, 252, 254, 255, 243, 244, 246, 247, 233, 236, 237, 238, 239, 230, 219, 220, 222, 223, 209, 210, 211, 212, 214, 215, 202, 203, 204, 206, 207, 193, 194, 195, 198, 199, 190, 179, 182, 183, 169, 170, 171, 172, 174, 175, 163, 165, 166, 167, 153, 154, 157, 158, 159, 150, 137, 142, 143, 130, 131, 132, 134, 135, 123, 126, 127, 118, 107, 110, 111, 97, 102, 103, 89, 90, 93, 94, 95, 84, 86, 87, 73, 75, 78, 79, 65, 66, 69, 70, 71, 62, 49, 50, 53, 54, 55, 43, 45, 46, 47, 34, 37, 38, 39, 25, 28, 30, 31, 18, 19, 20, 22, 23, 9, 10, 11, 14, 15, 2, 3, 4, 6]
```

Well that looks like a reverse sorted version of `b`? 

So we found that just sorting the shuffled `b` is enough to recover the `a` array. How do we recover the bytes of the flag from a though?

The answer lies in how they are encoded. Each character is encoded in sets of 1 - 5 integers. The catch being that each of the integers is in the range of 1 - 7 multiplied by the integers offset from the end of the array.

We tried that and were successful. Heres the code we wrote in the end:

```py
import string
import sys

def encode(input):
  a = []
  for i in range(len(input)):
    t = ord(input[i])
    for j in range(8):
      if ((t >> j) & 1):
        a.append(1 + j + (len(input) - 1 - i) * 8)
  return a

# makeb() takes a dotted and dashed string and recovers the
# integers of the b array from it.
def makeb(input):
  b_raw = input.split('.')[:-1]
  return [len(x) for x in b_raw[::-1]]

# Make a translation table for all printable chars.
ttable = {}
for i in string.printable:
  ttable[i] = encode(i)

# Create a 'b' array from the instructions.txt
b = makeb(open('instructions.txt').read().strip())

# Recover 'a' array from 'b'
a = sorted(b, reverse=True)

# Recover a list of characters from the 'a' array.
result = [[] for x in b]
for c in a:
  result[c//8].append(c)

newresult = []
for i, blah in enumerate(result):
  subresult = []
  for z in blah:
    subresult.append(z - (i * 8)  )

  if len(subresult) > 0:
    newresult.append(sorted(subresult))

final = newresult[::-1]

# Using the translation table, convert each sublist
# into printable characters.
for f in final:
  for k,v in ttable.iteritems():
    if v == f:
      sys.stdout.write(k)
```
When we run this code we get:

```
Instructions to disable C1:
1. Open the control panel in building INM035.
2. Hit the off switch.

Congrats, you solved C1! The flag is flag-bd38908e375c643d03c6.
```

Nice work! Shout outs to Bryan and Fry who worked on this with me.