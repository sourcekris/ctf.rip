---
id: 241
title: 'Backdoor CTF 2015 - qr - Challenge Response'
date: 2015-04-03T00:45:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=241
permalink: /backdoor-ctf-2015-qr-challenge-response/
post_views_count:
  - "479"
image: /images/2015/04/qr1-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
Due to the rescheduling of Backdoor 2015 (due to cricket, blegh) I only got about 2 hours to play it. It seemed like a good variety of challenges and I think I would have got 7 or 8 done had it not been on a weekday when I had a tonne of other commitments. Anyway I got started with this challenge, it was easy but fun but only worth 70 points and In my opinion there were a lot of easier challenges worth more points. Still I got stuck down the rabbit hole anyway.

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qr1-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qr1-1.png" height="145" width="400" /></a>
</div>

When you contact the host, it generates an ASCII art QR code and pauses for input. If you give any input it is not programmed to accept, it replies Oops and closes the connection:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/04/qr2-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qr2-1.png" height="400" width="365" /></a>
</div>

Given the nature of the challenge so far, I was inclined to believe it was expecting the user to decode the QR code, input the result and be rewarded somehow. Usually in CTF challenge + response situations it's never as easy as a one hit reward thing so I didn't bother trying to manually do this and dived straight into python.


For the network side of things, I again used Binjitsu. I've memorized most of the general use functions in the library now so I'm not constantly referring to documentation. Firstly I just got a client together that could retrieve one QR code and display it.

```
 #!/usr/bin/python  
from pwn import *  
conn = remote('hack.bckdr.in',8010)  
input = conn.recvlines(47)  
print str(input)  
conn.close()  
```

The output is really ugly so I wont post it, but basically it places the QR code into a list of lines of data.

Using the python image library I figured out how to write the lines of QR text data to a PNG image. The only complicating factor there was the encoding type. Since this text was not really just text, I had to ensure the encoding of my string was set to UTF-8 before passing it into the PIL. This is the key line.


```
 line = unicode(line, "utf-8")  
```


The whole code now looks like this:


```
 #!/usr/bin/python  
import PIL  
from PIL import ImageFont  
from PIL import Image  
from PIL import ImageDraw  
from pwn import *  
def qrimg(lines,filename):  
    font = ImageFont.truetype('clacon.ttf')  
    img=Image.new("RGBA", (380,380),(255,255,255))  
    draw = ImageDraw.Draw(img)  
    y_text =8   
    for line in lines:  
         line = unicode(line, "utf-8")  
         width, height = font.getsize(line)  
         draw.text((0,y_text),line,(0,0,0), font=font)  
         y_text +=height  
         draw = ImageDraw.Draw(img)  
    img.save(filename)  
conn = remote('hack.bckdr.in',8010)  
input = conn.recvlines(47)  
qrimg(input, "qrtmp.png")  
print "[+] Wrote QR code image."  
conn.close()  
```

When run it will simply fetch a single QR code and write it into a PNG image like this:


<div class="separator" style="clear: both; text-align: center;">
<a href="/images/2015/04/qrtmp-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/04/qrtmp-1.png" height="320" width="320" /></a>
</div>


Next I found the Python qr library that make decoding QR code images a snap. So quickly added a few bits and pieces of that to the mix:


```
 #!/usr/bin/python  
import PIL  
from PIL import ImageFont  
from PIL import Image  
from PIL import ImageDraw  
import qrcode  
from pwn import *  
def qrimg(lines,filename):  
    font = ImageFont.truetype('clacon.ttf')  
    img=Image.new("RGBA", (380,380),(255,255,255))  
    draw = ImageDraw.Draw(img)  
    y_text =8   
    for line in lines:  
         line = unicode(line, "utf-8")  
         width, height = font.getsize(line)  
         draw.text((0,y_text),line,(0,0,0), font=font)  
         y_text +=height  
         draw = ImageDraw.Draw(img)  
    img.save(filename)  
conn = remote('hack.bckdr.in',8010)  
input = conn.recvlines(47)  
qrimg(input, "qrtmp.png")  
thedata = qrcode.Decoder()  
if thedata.decode("qrtmp.png"):  
    conn.send(thedata.result)  
print "[+] QR Code decodes to: " + thedata.result  
conn.close()  
```

Looks like we have a good thing going here, it turned out that what happens next is you receive another QR code as a reward.... Great....

So the final solution is to place this in a loop until we discover how many challenges we need to successfully pass. Once found, we stop decoding QR codes and just receive a flag instead.

So this is our final qr code challenge client source:

```
 #!/usr/bin/python  
import PIL  
from PIL import ImageFont  
from PIL import Image  
from PIL import ImageDraw  
import qrcode  
from pwn import *  
def qrimg(lines,filename):  
    font = ImageFont.truetype('clacon.ttf')  
    img=Image.new("RGBA", (380,380),(255,255,255))  
    draw = ImageDraw.Draw(img)  
    y_text =8   
    for line in lines:  
         line = unicode(line, "utf-8")  
         width, height = font.getsize(line)  
         draw.text((0,y_text),line,(0,0,0), font=font)  
         y_text +=height  
         draw = ImageDraw.Draw(img)  
    img.save(filename)  
conn = remote('hack.bckdr.in',8010)  
for messagenum in range(1,100+1):  
    input = conn.recvlines(47)  
    print "[+] Got challenge number " + str(messagenum)  
    qrimg(input, "qrtmp.png")  
    thedata = qrcode.Decoder()  
    if thedata.decode("qrtmp.png"):  
         conn.send(thedata.result)  
flag = conn.recvall()  
print "Flag message: " + flag  
conn.close()  
```

Which when run just handles the whole thing for you until your juicy reward

```
root@mankrik:~/backdoor/qr# ./pwnqr.py  
[+] Opening connection to hack.bckdr.in on port 8010: Done  
[+] Got challenge number 1  
[+] Got challenge number 2  
[+] Got challenge number 3  
[+] Got challenge number 4  
   ...
[+] Got challenge number 97  
[+] Got challenge number 98  
[+] Got challenge number 99  
[+] Got challenge number 100  
[+] Recieving all data: Done (89B)  
[*] Closed connection to hack.bckdr.in port 8010  
Flag message: Congratulations. Flag is ca98c04be2505d686c5720675db2fe52111a52262490d0b12c158de0c96cdcd9  
```

That was cool and a bit more experience with QR codes and challenge response challenges.