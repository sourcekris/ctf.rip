---
id: 408
title: 'Offensive Security: OSCP - Penetration Testing With Kali - A Review'
date: 2015-12-31T05:05:18+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=408
permalink: /offensive-security-oscp-penetration-testing-with-kali-a-review/
post_views_count:
  - "7271"
image: /images/2015/12/oscp-certs.png
categories:
  - OSCP
---
<img class="aligncenter wp-image-412 size-full" src="/images/2015/12/oscp-certs.png" alt="oscp-certs" width="500" height="326" srcset="/images/2015/12/oscp-certs.png 500w, /images/2015/12/oscp-certs-300x196.png 300w" sizes="(max-width: 500px) 100vw, 500px" />

Over the past one month I have been taking a break from CTF competitions on account of studying and using the lab environment to achieve the Offensive Security Certified Professional certification. Recently I have taken the exam and passed. Now I want to give a quick review of my time in the lab and the exam and give folks considering this certification an idea of what they're getting into.

**What it is**

The <a href="https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/" target="_blank">Penetration Testing With Kali</a> (PWK) course is a video and PDF tutorial based, self paced learning course with associated practical exercises which you complete in parallel to having access to a large lab network environment. The idea is that you learn tools, techniques and theory in the course material, practice it in a guided manner in the exercises and then try it "for real" in the lab.

What results is a unique and fun learning experience where you are constantly excited to learn something because you know you get to try that technique out right now.

This contrasts pretty starkly with other pentesting / offensive security courses on the market which tend to be a lot of passive theory, reading, memorization and cramming.

**The PWK Course Material**

I've done a lot of video based, documentation based training. The quality of the Offensive Security videos is a cut above most. Firstly, the instructor is very clear in the way he speaks. He never skips steps or takes short cuts, and paces himself just right. It's possible to re-watch the PWK videos many times and you don't get bored.

One other thing, the videos are delivered in (watermarked) MP4 format. So you aren't locked into some awful flash or web based training system. This means you can use any video player you want, VLC or even put the videos on your phone to watch them on the way to work. I just find the freedom that this delivery method gives you to be great.

The other course material is delivered in a PDF, again watermarked so you don't share it, but you are able to print it if you find that more useful.

**The Lab**

The lab is the fun part. It consists of more than 50 systems of varying configurations. The span of operating systems covers everything from Windows 2000 up til Windows 8.1 and several flavours of Unix like Linux (many types), FreeBSD and Solaris. It's no secret that it's not one contiguous zone, so you need to put your pivoting skills to use. There are times where two layers of pivoting will be necessary, and that's a lot of fun when you finally successfully pop that box through a long proxychain.

The variety of attacks you need to carry out is quite vast. There's everything here from trivial Metasploit fire and forget to custom web applications and browser (client) based attacks. You spend 30+ days getting to know the lab and progressing from the low hanging fruit up to those top tier tough cookie boxes that have names like Sufferance and Humble.

**The Exam**

The exam is a 24 hour long period where you get access to a set of 5 completely new set of machines from what I guess is a big library of possible machines Offensive Security can throw at candidates. You're goal is collect trophy's which consist of the contents of local.txt and proof.txt. These are text files of either unprivileged or administrator level account (respectively) that prove you were able to get access to the systems in the exam. Once you've broken into the systems, you need to document your achievements and you have an additional 24 hours after the exam period to rap up your penetration test report on the exam systems.

**Managing Your Workflow**

I guess a full time penetration tester in a real engagement is going to probably have either processes developed by the organization they work for or their own systems. I am not currently working in the field though so I knew in advance that information management and workflow management was something important I'd need to take into account. You get a limited time in the lab and, unless you want to pay for a lab time extension (you can do this if you need more time!) you need to be organized. At the end of your time in the lab you should have copious notes, proof, data points, screenshots, hashes, credentials, scan output, and so on to show:

  * How you learnt about the various possible attack vectors, i.e. from your information gathering
  * How you successfully penetrated the systems, i.e. your exploit, your customization if any and the specifics about how you applied it
  * How you successfully escalated privileges, similar to above

I've heard stories from people successfully using software like <a href="http://keepnote.org/" target="_blank">Keepnote</a>, which I actually recommend because it works cross platform and has some good capabilities. I found the interface way too clunky and it doesn't seem to be in active development anymore (last update March 2012!).

I decided to flex my old MS Office skills and (don't laugh) built a MS Access database in Office 2016. Access doesn't feel like it's changed in a decade, all the stuff you remember from using it in school still work. This is my main form I used while in the lab:

<img class="alignnone size-full wp-image-414" src="/images/2015/12/dbapp.png" alt="dbapp" width="1567" height="956" srcset="/images/2015/12/dbapp.png 1567w, /images/2015/12/dbapp-300x183.png 300w, /images/2015/12/dbapp-768x469.png 768w, /images/2015/12/dbapp-1024x625.png 1024w, /images/2015/12/dbapp-660x403.png 660w" sizes="(max-width: 1567px) 100vw, 1567px" />

The form has 2 main tabs: Host Data and Recon Data. The host form is where I spend most of my time and has fields for most of the common stuff. Then it has a section of subtabs for quick places to dump common data points (including files, like PNG screenshots!). Finally a large note pad on the right side for things I noticed while breaking in.

Later, I built another form for typing up vulnerability writeups for each box I broke into. That form was simply six boxes where I could either type or copy/paste details. Like exploit code, or exploit output from a terminal window.

Finally, after all my data was stored in my database, I used the "Word Merge" function to basically automate my report writing. Most people tend toward the "hundreds" of pages in their lab reports, and mine was no different, but doing it with Access gave me a big chunk of 235 pages of automated report so I didn't need to futz with all that formatting and messing around when you write a large document manually.

**Conclusion and Overall Thoughts of the PWK and OSCP Exam**

Overall I think the PWK and OSCP exam represents great value for money as far as certifications go these days. For those who feel they're slightly more advanced and think the OSCP might be too easy, I still say it's worthwhile, because you'll probably learn something still. For me I learned a lot about Metasploit, it changed my opinion of this invaluable tool a lot.

I myself found that the lab was quite simple. I was able to gain admin/root access on every system in the lab in just a few weeks and the exam was also quite a breeze. But I dont view it as wasted time, i feel it was a necessary step towards whatevers next in this field. I plan to tackle the "Cracking the Perimeter" course next from the Offensive Security team since I think they do a good job overall.