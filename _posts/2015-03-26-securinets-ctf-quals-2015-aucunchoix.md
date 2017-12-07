---
id: 243
title: 'Securinets CTF Quals 2015 - aucun_choix Reversing Challenge'
date: 2015-03-26T10:32:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=243
permalink: /securinets-ctf-quals-2015-aucunchoix/
post_views_count:
  - "427"
image: /images/2015/03/aucon1-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
What a strange CTF this one was. Judging by all the comments on CTFtime a lot of people couldn't get past the registration page. I myself registered ok, it was in French but Google translate got the message across. When I began the CTF I immediately noticed that this was a challenge for beginners. That's great I do need to brush up on my basic skills.

Anyway unfortunately the website is now down so I can't get screencaps of the site but the challenge I will document from Securinets is called aucun_choix which is a reversing / cracking challenge.

First thing we do is download the binary given and examine it with file:

```
root@mankrik:~/securinets# file aucun_choix.exe   
aucun_choix.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows  
```

Ok cool, a console app. Let's run it and see what it does. I'll use Wine so I don't leave my Kali VM.

```
root@mankrik:~/securinets# wine aucun_choix.exe   
Trouvez moi si vous pouvez  
e  
ratÚ cherche encore!  
```

Ok, it doesn't do anything except for that. Let's put it in IDA Pro because we can. I immediately look at the _main function and see this jnz instruction:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/03/aucon1-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/aucon1-1.png" height="157" width="400" /></a>
</div>


So it does a strcmp, and based on the result will either tell you to try again or tell you bravo! I guess we got encore but we want bravo. So let's just flip the jnz to a jz instruction in the binary and see what happens.

The jnz instruction lives at binary offset 0x806, opcodes are 0x75 0x64 and we want a JZ instruction so the opcodes are 0x74 0x64

After patching that one byte and saving the file we run it again:

```
root@mankrik:~/securinets# wine aucun_choix_cracked.exe   
Trouvez moi si vous pouvez  
a       
oh mon dieu t'as reussi bravo ! mdp est concatene ordre est 4 2 3 1   
```

Sweet. WTF does it mean though?

Google translate helps a little, it basically says, well done, the MDP concatenation order is 4, 2, 3, 1. Great, what is MDP? A little bit of Googling tells me that MDP is a French abbreviation for "mot de passe" or "password". So the translation is really, "the password concatenation order is 4, 2, 3, 1"

Ok but what password? Back to IDA Pro and we search about for strings that we might want to concatenate. We quickly spot some likely data in the .rdata segment:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/03/aucun2-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/aucun2-1.png" height="288" width="400" /></a>
</div>

So a quick select, Right click, Edit->Export Data and we have an export with the following text in it:

  1. 123456
  2. 7891011
  3. 12131415
  4. numbers:

Ok so if we go by the concatenation order we get:

  * numbers:789101112131415123456

We submit this as the flag and collect the points.