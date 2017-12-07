---
id: 418
title: 'Realtime DNS Exfiltration and DGA C&#038;C Detection - Part 1'
date: 2016-01-03T11:57:13+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=418
permalink: /realtime-dns-exfiltration-and-dga-cc-detection-part-1/
post_views_count:
  - "1881"
image: /images/2016/01/raspberry-pi-logo.png
categories:
  - Projects
---
<img class=" wp-image-422 alignleft" src="/images/2016/01/raspberry-pi-logo.png" alt="raspberry-pi-logo" width="220" height="276" srcset="/images/2016/01/raspberry-pi-logo.png 511w, /images/2016/01/raspberry-pi-logo-239x300.png 239w" sizes="(max-width: 220px) 100vw, 220px" />I've decided to start blogging my masters project early, I'm still in the planning phases since I'm not due to start it until closer to mid-2016 however my current thinking is the topic of realtime DNS data exfiltration and DGA C&C detection.

This class of topics have been discussed in depth before, <a href="https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152" target="_blank">here's a good paper on the topic</a> which I have read. In this paper they use a commercial solution to perform data collection for later analysis.

My idea is to build an open system with open source tools, adapted for scalability from small to enterprise grade installations to perform both realtime DNS tunnel detection and realtime DGA C&C detection.

I'm going to be prototyping with Raspberry PI for the sensor cluster and ESXi for simulating the endpoints. The detection platform will be based on a Bro NSM cluster. The data analysis will take place in a layer above Splunk with splunk as an aggregation technology.

My current goals are to opensource all of the solutions.

That's all I have for now, I've placed orders for some of the hardware and am expecting deliveries to start trickling in this week. When I have some concrete evidence that the prototype environment is viable I post up some more details.

Can't wait for this project, been waiting the past two years to wrap up the masters degree classwork so we can get to what I feel is the meat of a Masters program, to build something and give something to the Information Security community.