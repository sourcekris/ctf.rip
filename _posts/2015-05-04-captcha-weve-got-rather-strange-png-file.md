---
id: 232
title: 'Volga CTF 2015 - Captcha - 150 point Stego challenge'
date: 2015-05-04T11:18:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=232
permalink: /captcha-weve-got-rather-strange-png-file/
post_views_count:
  - "895"
image: /images/2015/05/1-8.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/05/1-8.png" imageanchor="1" style="clear: left; float: left; margin-bottom: 1em; margin-right: 1em;"><img border="0" src="/images/2015/05/1-8.png" /></a>
</div>

>**_captcha_**
>We've got a rather strange png file. Very strange png. Something isn't right about it...

Stego challenges are not my favorite but still I gave this one a try because I felt the point value meant it would be a reasonably quick solve.

The png file when viewed just appeared to be a single 256&#215;256 image of the letter "i". Sort of like this (this is not the actual PNG from the challenge):

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/05/2-8.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/05/2-8.png" /></a>
</div>


When we investigated further though it's rather large in size to be a single image:

```
root@mankrik:~/volga/captcha# ls -lah capthca.png 
-rw-r--r-- 1 root root 1.6M Apr 30 22:56 capthca.png
root@mankrik:~/volga/captcha# file capthca.png 
capthca.png: PNG image data, 256 x 256, 8-bit/color RGB, non-interlaced
root@mankrik:~/volga/captcha# pngcheck -v capthca.png 
File: capthca.png (1622884 bytes)
  chunk IHDR at offset 0x0000c, length 13
    256 x 256 image, 24-bit RGB, non-interlaced
  chunk IDAT at offset 0x00025, length 735
    zlib: deflated, 32K window, default compression
  chunk IEND at offset 0x00310, length 0
  additional data after IEND chunk
ERRORS DETECTED in capthca.png
```

So pngcheck says there's additional data after the IEND chunk. Let's try carving the file with foremost:

```
root@mankrik:~/volga/captcha# foremost -v capthca.png 
Foremost version 1.5.7 by Jesse Kornblum, Kris Kendall, and Nick Mikus
Audit File

Foremost started at Mon May  4 19:04:58 2015
Invocation: foremost -v capthca.png 
Output directory: /root/volga/captcha/output
Configuration file: /etc/foremost.conf
Processing: capthca.png
|------------------------------------------------------------------
File: capthca.png
Start: Mon May  4 19:04:58 2015
Length: 1 MB (1622884 bytes)
 
Num  Name (bs=512)        Size  File Offset  Comment 

: 00000000.png        792 B            0    (256 x 256)
1: 00000001.png        867 B          792    (256 x 256)
2: 00000003.png        859 B         1659    (256 x 256)
3: 00000004.png        916 B         2518    (256 x 256)

...

1890: 00003166.png        781 B      1621311    (256 x 256)
1891: 00003168.png        792 B      1622092    (256 x 256)
*|
Finish: Mon May  4 19:04:58 2015

1892 FILES EXTRACTED
 
png:= 1892
------------------------------------------------------------------

Foremost finished at Mon May  4 19:04:58 2015
```

Oh cool, 1892 PNG files embedded inside. Wow, what are all those files of I wonder:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://4.bp.blogspot.com/-emIhKzs844c/VUc3h7KES7I/AAAAAAAAAJU/6SF90Rse_yM/s1600/3.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="140" src="/images/2015/05/3-5.png" width="320" /></a>
</div>

Each PNG file contained a single letter. At first I thought this was the flag, that there would be a message in this and I could just read it back and win the points. Unfortunately this was just step one. After scrolling through the image previews in my Linux file explorer it quickly made sense that these images described a base64 encoded string. The biggest give away of this was the final image in the list was an "=".

So it seemed like the next step was to decode these images, get a base64 string, decode the string into a binary and get the flag. How to do that?

I've read <a href="https://neg9.org/news/2015/5/3/volga-quals-2015-captcha-stegoppc-150-writeup" target="_blank">other writeups</a> of this challenge and saw that other people approached this in a smarter way than I did. I did this the long way, with OCR. I think if you want to know the best way to do this challenge, read <a href="https://neg9.org/news/2015/5/3/volga-quals-2015-captcha-stegoppc-150-writeup" target="_blank">those writeups</a>. If you want to know how to OCR large groups of single letter images, read on!

Having never done any OCR before, this was going to be fun. First I found that on Linux one of the accepted OCR solutions is called Tesseract OCR and a Python interface to Tesseract OCR is called PyTesser.

So I grab those things quickly and read up on using it...

```
root@mankrik:~/volga/captcha# apt-get install tesseract-ocr
root@mankrik:~/volga/captcha# wget https://pytesser.googlecode.com/files/pytesser_v0.0.1.zip
root@mankrik:~/volga/captcha# unzip pytesser_v0.0.1.zip

```
It seems to use PyTesser we just import it and use _image\_to\_string_ from a PIL image in memory. Note here that we used PyTesser 0.0.1 which uses PIL. It seems on Github there's a new version of PyTesser that uses OpenCV. I'm certain OpenCV is better but im more familiar with PIL so i'm happy to use the old version.

Our first attempt was a flop:

```
#!/usr/bin/python

from pytesser import *
import os
import Image
import subprocess

PNG_PATH='output/png/'

print "[+] Foremosting input..."
subprocess.call(['foremost','-Q','capthca.png'])

pngfiles = [ f for f in os.listdir(PNG_PATH) if os.path.isfile(os.path.join(PNG_PATH, f)) ]
pngfiles.sort()
flag = ""
print "[+] Processing image files ..."
for f in pngfiles:
 im = Image.open(PNG_PATH + f)
 flag += image_to_string(im)

flag = "".join(flag.split())
print "[+] Encoded flag is: " + flag 
```


This gave no output at all. When I looked into it I found that Tesseract is tunable and in the default mode, PyTesser has it tuned to all default settings.

```
root@mankrik:~/volga/captcha# tesseract 
Usage:tesseract imagename outputbase [-l lang] [-psm pagesegmode] [configfile...]
pagesegmode values are:
0 = Orientation and script detection (OSD) only.
1 = Automatic page segmentation with OSD.
2 = Automatic page segmentation, but no OSD, or OCR
3 = Fully automatic page segmentation, but no OSD. (Default)
4 = Assume a single column of text of variable sizes.
5 = Assume a single uniform block of vertically aligned text.
6 = Assume a single uniform block of text.
7 = Treat the image as a single text line.
8 = Treat the image as a single word.
9 = Treat the image as a single word in a circle.
10 = Treat the image as a single character.
-l lang and/or -psm pagesegmode must occur before anyconfigfile.
```

So I wanted to use "pagesegmode" 10 to treat each image as a single character. Let's modify the args value in pytesser.py to suit our needs:

`args = [tesseract_exe_name, input_filename, output_filename,'-psm','10']`

Let's try our script again:

```
root@mankrik:~/volga/captcha# python ./fail1.py 
[+] Foremosting input...
[+] Processing image files ...
[+] Encoded flag is: .VBO.W0KG90AAAANSUhEU9AAA.AAAACDCAIAAADK7dMbAAAAAXNS.0IAFS4C.QAAAA.nQU1BAACXWV8YQUAAAAJCEhZCWAADSMAAA7DACdVqGQAAAUfSU.BVHhe7dhtYt0WEEV.1SWCWA+FYTNdTOq.hTSD.NHEmSe37Z8k9.GV.T.PQBYBmBAQQEBhAQGEBAYAAB9QEEBAYQEBhAQGAAAYEBBAQGEBAYQEB9AAGBAQQEBhAQGEBAYAAB9QEEBAYQEBhAQGAAAYEBBAQGEBAYQEB9AAGBAQQEBhAQGEBAYAAB9QEEBAYQEBhAQGAAAYEBBAQGEB
```

Cool! Output! Oh but wait. It's totally wrong. Doh! Firstly base64 strings don't have "." in them. It must be interpreting the lowercase i characters as a ".". Half the other characters are similarly mangled. Ouch. So not good enough, it seems our OCR library needs more context about the letters so it can do a better job at OCR?

Firstly let's tweak tesseract a bit more. I learnt about character whitelists so I set one up containing only the base64 alphabet:

```
root@mankrik:~/volga/captcha# cat /usr/share/tesseract-ocr/tessdata/configs/base64 
tessedit_char_whitelist 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz/+=
```

Next I tweak pytesser.py to use PSM 7(Treat image as a single text line) and to include our tesseract configuration file by changing the args array:

`args = [tesseract_exe_name, input_filename, output_filename,'-psm','7','base64']`

Next I modify our script so that it imports some number of images into a single image and then OCRs them all at once. This greatly increases our OCR efficiency but still not perfect results:

```
#!/usr/bin/python

from pytesser import *
import os
import Image
import subprocess
import base64

PNG_PATH='output/png/'
BEST_WIDTH=38
BEST_HEIGHT=50

# use factors of the total number of files or this will error
CHARS_WIDE=43

print "[+] Foremosting input..."
subprocess.call(['foremost','-Q','capthca.png'])

pngfiles = [ f for f in os.listdir(PNG_PATH) if os.path.isfile(os.path.join(PNG_PATH, f)) ]
pngfiles.sort()
flag64 = ""
print "[+] Processing " + str(len(pngfiles)) + " image files " + str(CHARS_WIDE) + " characters at a time."
im = Image.new("RGB", (BEST_WIDTH * CHARS_WIDE,50), "white")
idx = 
for f in pngfiles:
 letter = Image.open(PNG_PATH + f)
 width, height = letter.size
 left = (width - BEST_WIDTH)/2
 top = (height - BEST_HEIGHT)/2
 right = (width + BEST_WIDTH)/2
 bottom = (height + BEST_HEIGHT)/2
 letter = letter.crop((left,top,right,bottom))
 im.paste(letter,(idx*BEST_WIDTH,))
 idx+=1
 if idx == CHARS_WIDE:
  thislot = image_to_string(im) 
  thislot = "".join(thislot.split())
  flag64 += thislot
  idx=

print "[+] Base64 of flag PNG: " + flag64
```

And the output:

```
root@mankrik:~/volga/captcha# python ./fail3.py 
[+] Foremosting input...
[+] Processing 1892 image files 43 characters at a time.
[+] Base64 of flag PNG: iVBORWOKGgoAAAANSUhEUQAAARAAAACDCAIAAADK7dMbAAAAAXNSROIArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAUfSURBVHhe7dhtYtowEEVR1sWCWA+rYTNdTOqRhTSjD6NHEmjSe37Z8kgaGV6T9PQBYBmBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBQAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABQQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBQAAGBAQQEBhAQGEBAYAABgQEEQmD+XM+n0+I8/ZPvB6zkcss3/53b5TQ4/fSdjMvf7zd9iOk7mw9j7/vzb3w9MOU9piZ6IqRvet
```

And when we assemble a PNG file from the output:

```
root@mankrik:~/volga/captcha# pngcheck -v fail3.png 
File: fail3.png (1418 bytes)
  File is CORRUPTED.  It seems to have suffered EOL conversion.
ERRORS DETECTED in fail3.png
```

Now i'm really unhappy because I've spent a bit of time on these 150 points and I wan't to just solve it now. Not pretty code any more, just solution. So instead of fussing more with this I resign myself to a manual process of weeding out these final byte errors using the following script.

It assembles a string of characters, OCR's the string, displays it and asks the user to proof read. If any issues are found it can correct them. This requires about 10-20 minutes of the user's time but as I said. I just wanted a solution and 10-20 minutes of focused reading seemed like a good trade off at this point:

```
#!/usr/bin/python

from pytesser import *
import os
import Image
import subprocess
import base64

PNG_PATH='output/png/'
BEST_WIDTH=38
BEST_HEIGHT=50

# use factors of the total number of files or this will error
CHARS_WIDE=43

print "[+] Foremosting input..."
subprocess.call(['foremost','-Q','capthca.png'])

pngfiles = [ f for f in os.listdir(PNG_PATH) if os.path.isfile(os.path.join(PNG_PATH, f)) ]
pngfiles.sort()
flag64 = ""
print "[+] Processing " + str(len(pngfiles)) + " image files " + str(CHARS_WIDE) + " characters at a time."
im = Image.new("RGB", (BEST_WIDTH * CHARS_WIDE,50), "white")
idx = 
for f in pngfiles:
 letter = Image.open(PNG_PATH + f)
 width, height = letter.size
 left = (width - BEST_WIDTH)/2
 top = (height - BEST_HEIGHT)/2
 right = (width + BEST_WIDTH)/2
 bottom = (height + BEST_HEIGHT)/2
 letter = letter.crop((left,top,right,bottom))
 im.paste(letter,(idx*BEST_WIDTH,))
 idx+=1
 if idx == CHARS_WIDE:
  im.show()
  thislot = image_to_string(im) 
  thislot = "".join(thislot.split())
  print "[+] OCRd: " + thislot
  check = raw_input("These ok? >> " )
  if 'n' in check:
   redo = list(thislot)
   chk = 
   for r in redo:
    ok = raw_input("Correct this " + r + "["+r+"] >> ")
    if ok <> '':
     redo[chk] = ok
    chk += 1
   thislot = "".join(redo)
   flag64 += thislot  
   print "[+] Corrected: " + thislot
   subprocess.call(['killall','-9','display'])
  else:
   flag64 += thislot
   subprocess.call(['killall','-9','display'])
   
  flag64 = "".join(flag64.split())
  idx = 
  im = Image.new("RGB", (BEST_WIDTH * CHARS_WIDE,50), "white")

subprocess.call(['rm','-fr','./output/'])

f=open('flag.b64','wb')
f.write(flag64)
f.close()
print "[+] Base64 of flag PNG: " + flag64
```


And the output looks like this, it'll throw up an image on your screen:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://1.bp.blogspot.com/-zjB7yBjiO5A/VUdFRzYILXI/AAAAAAAAAJo/f75VLbOXr2U/s1600/4.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="22" src="/images/2015/05/4-5.png" width="400" /></a>
</div>

```
root@mankrik:~/volga/captcha# ./readcaptcha.py 
[+] Foremosting input...
[+] Processing 1892 image files 43 characters at a time.
[+] OCRd: iVBORWOKGgoAAAANSUhEUQAAARAAAACDCAIAAADK7dM
These ok? >> n
Correct this i[i] >> 
Correct this V[V] >> 
Correct this B[B] >> 
Correct this O[O] >> 
Correct this R[R] >> 
Correct this W[W] >> w
Correct this O[O] >> 0
Correct this K[K] >> 
Correct this G[G] >> 
Correct this g[g] >> 
Correct this o[o] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this N[N] >> 
Correct this S[S] >> 
Correct this U[U] >> 
Correct this h[h] >> 
Correct this E[E] >> 
Correct this U[U] >> 
Correct this Q[Q] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this R[R] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this C[C] >> 
Correct this D[D] >> 
Correct this C[C] >> 
Correct this A[A] >> 
Correct this I[I] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this A[A] >> 
Correct this D[D] >> 
Correct this K[K] >> 
Correct this 7[7] >> 
Correct this d[d] >> 
Correct this M[M] >> 
[+] Corrected: iVBORw0KGgoAAAANSUhEUQAAARAAAACDCAIAAADK7dM
...
```

And so on... You get the idea. You'd think we'd be finished by now right? Noooo. There was a time bomb in this challenge that I only just now discovered. And that is the upercase letter "I" looks identical to the lowercase letter "l". The OCR and even human recognition steps have no way to tell these apart. The best I could do after the best OCR and human recognition i could do resulted in a dud file still:

```
root@mankrik:~/volga/captcha/best# pngcheck -v flag.png 
File: flag.png (1418 bytes)
  chunk IHDR at offset 0x0000c, length 13
    272 x 131 image, 24-bit RGB, non-interlaced
  chunk sRGB at offset 0x00025, length 1
    rendering intent = perceptual
  chunk gAMA at offset 0x00032, length 4: 0.45455
  chunk pHYs at offset 0x00042, length 9: 3779x3779 pixels/meter (96 dpi)
  chunk IDAT at offset 0x00057, length 1311
    zlib: deflated, 32K window, fast compression
  CRC error in chunk IDAT (computed 29d1d0fd, expected 6eb66220)
ERRORS DETECTED in flag.png
```

So I was stuck here and ready to throw in the towel, but I had one more idea. I didn't need to make the file perfect, I just needed enough image data to read a flag. So I counted the number of letter I's in the base64. There were 29 of them. So I had 2<sup>29</sup>(536,870,912 different possible file combinations here. I don't NEED a perfect image though. So here was my final idea:



  * First, only permutate the data in the obvious part of the base64 data where the actual useful image data is found. This obvious when you see all the base64 data.
  * Only try some reasonable number of permutations

So the base64 data we needed to focus on was quite obvious to the naked eye. I've highlighted it below. It's obvious because the surrounding data is repeated QEEBAYhEBAY etc which looks like it might be a repeating data, like a blank background of the image maybe?

```iVBORw0KGgoAAAANSUhEUgAAARAAAACDCAIAAADK7dMbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAUfSURBVHhe7dhtYtowEEVR1sWCWA+rYTNdTOqRhTSjD6NHEmjSe37Z8kgaGV6T9PQBYBmBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEQmD+XM+n0+I8/ZPvB6zkcss3/53b5TQ4/fSdjMvf7zd9iOk7mw9j7/vzb3w9MOU9piZ6IqRvetf+2JKnJz6IJsDvO30nBOb7NV+ALzjaemAGn283JDe09qVpjr3u6YIPITDvNvxCut+JvuBoPyIwP8T4MATmdYZfyDcGpv37Zdjf5WbD5be0O3t0t8/xIw++OmGjsvym7ajIJq71Iou3svP1tg/vIX3/SR0+X691s5V9Xc1msv6ITXTt28x8O1xkbyDfNLuOTBsert8049YfNjOzFW+rrG5qSu3Gyn1ZLdyq3FpW87CVY8uBGe1VX062N507tKf5Mkz2s7oVxmqZreTf5gNu/aPefD/p0p67zkKNa8GPhymzfdsJviZf+/UnbGapKOVhkdTNfmPj9+Gw60Ra576+2yqsU5dZaKaMzoVN3WS7HGw6WbE/3Dbi6/oC1Vpgmm3vuu3D8Wbd+cMuHsCV2eWoIzE3cdLb+NXHvtqa7Wm6bcbdpOm+7km9mq0/5SaUS7dIUu5jA21Zb6I+1lG7dGPJ0oncNuNd3apW0K/YTxts/LCXQ8s/YUZH6Mbisf1je+LcOx6tOhDL7C6sMucmTnobdxBHm+YTe9rMdbfuMu7rntSr2fpzNiOdvly0zdT72EBb1pvXN33eX/+gmaYyOdw1bup3nWy61wyG4jbbSH3sO3zWd/wNk2/q43TmMu6b7k84NC6z0QendxMPeusXiRuOa7pxN2m6r93I21ozW//IPtstHIt297GBtqw3qXed57vScr5xE8PjFW7upky3i8mmhXWYRx8ebiuQ2upJgWmb6YbiscvjcGwbLV3bzcIJBntvxu8vcBMnvXXNpctmw1DjWFnuIJWUombfWDWpGax/xKa7HfPA/c515jfaJx3vZM3Uijl59JjWce9+uz9fLm6eeqJU37+Iw00zq8mjVhEKmjbsVmhq5CWByY3v0v8mIVOVB4fnqCvZVXU4yTQt1PrQuIs0j4XHiTuBuT+sw7N/7rfR8h9um/p5xj0m6x/Yuw6F7iDhe1PGQ5MTsSKeJC/TflibQTPSifZNS5916fGm7qCbunSp9i3Hx8d9PPSpwOCd7NMPsfjJvuCrvOCIgXnNkbDqV+XINwYm7db8qP9K8ads9fCAT0/8xx2f65N5ectLO9j0BYFJu3/66ysEBgCBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBhAQGEBAYAABgQEEBAYQEBhAQGAAAYEBBAQGEBAYQEBgAAGBAQQEBlj28fEX4wPz1G62YiCAAAAASUVORK5CYll=
```

The "reasonable" number of permutated I/l combinations I settled on was 2<sup>11</sup>which is just 2,048 combinations. If I could get enough image data in the first 11 I/l substitutions, I would be super happy.

Here's the final code:

```
#!/usr/bin/python
#
# Captcha solver for VolgaCTF 2015.
# CaptureTheSwag - ctf.rip
# by dacat

from pytesser import *
import os
import Image
import subprocess
import base64
import itertools

PNG_PATH='output/png/'
ATTEMPT_PATH='attempts/'
BEST_WIDTH=38
BEST_HEIGHT=50

# use factors of the total number of files or this will error
CHARS_WIDE=43

alphabet = ('I','l')
MAXLEN=11

print "[+] Foremosting input..."
subprocess.call(['foremost','-Q','capthca.png'])

pngfiles = [ f for f in os.listdir(PNG_PATH) if os.path.isfile(os.path.join(PNG_PATH, f)) ]
pngfiles.sort()
flag64 = ""
print "[+] Processing " + str(len(pngfiles)) + " image files " + str(CHARS_WIDE) + " characters at a time."
im = Image.new("RGB", (BEST_WIDTH * CHARS_WIDE,50), "white")
idx = 
for f in pngfiles:
 letter = Image.open(PNG_PATH + f)
 width, height = letter.size
 left = (width - BEST_WIDTH)/2
 top = (height - BEST_HEIGHT)/2
 right = (width + BEST_WIDTH)/2
 bottom = (height + BEST_HEIGHT)/2
 letter = letter.crop((left,top,right,bottom))
 im.paste(letter,(idx*BEST_WIDTH,))
 idx+=1
 if idx == CHARS_WIDE:
  im.show()
  thislot = image_to_string(im) 
  thislot = "".join(thislot.split())
  print "[+] OCRd: " + thislot
  check = raw_input("These ok? >> " )
  if 'n' in check:
   redo = list(thislot)
   chk = 
   for r in redo:
    ok = raw_input("Correct this " + r + "["+r+"] >> ")
    if ok <> '':
     redo[chk] = ok
    chk += 1
   thislot = "".join(redo)
   flag64 += thislot  
   print "[+] Corrected: " + thislot
   subprocess.call(['killall','-9','display'])
  else:
   flag64 += thislot
   subprocess.call(['killall','-9','display'])
   
  flag64 = "".join(flag64.split())
  idx = 
  im = Image.new("RGB", (BEST_WIDTH * CHARS_WIDE,50), "white")

subprocess.call(['rm','-fr','./output/'])
print "[+] OCR Completed. Creating permutations"
header=flag64[:361]
body=flag64[361:]

try:
 os.makedirs(ATTEMPT_PATH)
except OSError as exc:
 pass

# fiddle with all the l/I combinations and create a lot of PNGs
for i in itertools.product(alphabet, repeat=MAXLEN):
        idx = 
        bodylist = list(body)
        for char in range(len(bodylist)):
                if 'I' in bodylist[char]:
                        bodylist[char] = i[idx]
                        idx += 1
                if idx >= MAXLEN:
                        flag = header + "".join(bodylist) 
                        flagbin = base64.b64decode(flag)
                        f=open(ATTEMPT_PATH+'attempt'+"".join(i)+".png", 'wb')
                        f.write(flagbin)
                        f.close()
                        break

print "[+] Completed, copy the png files from the " + ATTEMPT_PATH + " folder to a Windows system and find the flag!" 
```
And when we run it, we find 2,048 PNG files. Copying them to Windows 7 system allows simple browsing with Extra Large thumbnail mode right in explorer:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://2.bp.blogspot.com/-jB8uKaV7R4U/VUdTXR-zVHI/AAAAAAAAAKA/uO4VInUmkR0/s1600/6.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="298" src="/images/2015/05/6-5.png" width="320" /></a>
</div>

And finally we spot the "best" attempt:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/05/5-5.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/05/5-5.png" /></a>
</div>

Which is by no means perfect, but was enough for me to get the flag:

**_{That\_is\_incredible\_you\_have_past!}_**

Incredible indeed. That's how you do a challenge the wrong way!