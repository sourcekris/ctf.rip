---
id: 248
title: 'Boston Key Party 2015 - School Bus Flag #3'
excerpt: Testing
date: 2015-03-03T21:56:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=248
permalink: /boston-key-party-2015-school-bus-flag-3/
post_views_count:
  - "358"
image: /images/2015/03/clue_3-1.png
categories:
  - Write-Ups
tags:
  - "2015"
---
This challenge was the third on the School Bus line in Boston Key Party 2015. The clue was as below and the challenge was worth 25 points.

<a href="/images/2015/03/clue_3-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/clue_3-1.png" /></a>

<!--more-->

The link in the clue lead to a URL which, when the source was viewed lead to a second page that gave us a look at the PHP source code for the site which you can see below:

<a href="/images/2015/03/source_3-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/source_3-1.png" /></a>

At first glance it seems that the flag itself is the password and that this code is expecting you to know the flag before you get the flag. That sounds counter intuitive so there must be a deeper explanation here.

Since there's only one mechanism in place (strcmp) we decided to investigate further. As it turns out strcmp is a poor choice when used to validate user input, especially, as in this case, when combined with a loose validation (== vs. ===) as it can easily be tricked into returning NULL which will evaluate to 0 for the purposes of the above script. Firstly, according to the PHP documentation the return values of strcmp are:

`Returns < 0 if str1 is less than str2; > 0 if str1 is greater than str2, and 0 if they are equal.`

However what's missing here is that strcmp will return NULL or 0 in many other scenarios when type conversions result in something unexpected.

This is known as a strcmp bypass and there is a fairly decent writeup on this class of vulnerability over on <a href="http://danuxx.blogspot.com/2013/03/unauthorized-access-bypassing-php-strcmp.html" target="_blank">this blog linked here</a>.

So in order to bypass the strcmp we used Burpsuite to intercept the form data and modify the GET request to be: `username=a&password[]=0`

Since this comparison cannot be successfully completed by strcmp (strcmp expects a string but got an array instead), it will return a value == 0 and the test on line 12 of the code will pass and we are handed our flag.