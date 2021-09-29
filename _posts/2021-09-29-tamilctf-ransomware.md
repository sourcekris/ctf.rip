---
title: 'TamilCTF: Ransomware'
date: 2021-09-29T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/tamilctf/ransomwaretitle.png
categories:
  - Write-Ups
  - Forensics
---
Fun CTF for TamilSec Con 2021 which wasn't taking itself too seriously. This was the group's first year and it was clear they had a lot of fun trying to come up with creative new challenges. I solved quite a few and this was one that got me stuck the longest. It was a memory forensics challenge. Here's how I solved it which does not have an intended ending...

#### <a name="ransomware"></a>Ransomware - Forensics - 793 points

This challenge reads:

```
Tamil CTF is planning to organize their work, they are formatting a 
document. But a hacker got into their PC and installed a malware to 
jeopardize some important information and strip into pieces

Your senior analyst sends you to use your DFIR skills to analyse 
this file

20 solves
```

With this challenge comes a file called `ransomeware.raw` which is 1 Gb in size.

With strings we can see this file is likely a Windows OS memory capture and again using strings we can see some flags or flag components:

```shell
$ strings ransomeware.raw | grep "TamilCTF{"
TamilCTF{  I deleted it :(
TamilCTF{  I deleted it :(
TamilCTF{RaM_1s_t00
TamilCTF{v0lat1lity_1s_n0t_2_3a5y}
TamilCTF{v0lat1lity_1s_n0t_2_3a5y}
```

These are interesting (but are not the flag) so we file them away for later.

Whenever I'm looking at a memory dump the workflow I use is:

- OS Identification
- Profile selection
- Artifact collection
  - pstree - what processes are running?
  - cmd lines - what commands were executed recently?
  - clipboard - anything interesting?
  - screenshot - whats windows on the screen?
  - screen dump - visual inspection of the framebuffer
  - filescan for specific files
  - dumpfiles for specific files
  - dumpfiles everything if I'm stuck....

Lets start this and see where we end up. I use volatility 2 still because I've not gotten used to volatility3 yet. I plan on figuring it out soon though!

##### OS Identification

For this I just use strings on the raw memory dump. If I see the words `Windows` a lot I assume its some Windows OS. Linux is a bit trickier since you need to isolate the specific kernel version more carefully but since `ransomeware.raw` is a Windows OS image we can just move to step 2.

##### Profile Identification

Here I use the `imageinfo` module of volatility and it recommends the correct profile immediately:

```shell
$ volatility -f /dumps/ransomeware.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/dumps/ransomeware.raw)
                      PAE type : No PAE
                           DTB : 0x185000L
                          KDBG : 0x8295c378L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x83941000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-09-24 09:40:03 UTC+0000
     Image local date and time : 2021-09-24 15:10:03 +0530
```

Here we see its figured `Win7SP1x86_23418` which seems to be right. Next we can do basic investigation about what was going on on this machine when memory was dumped. Always keeping in mind the clues about documents and malware.

##### Processes

We use volatility's `pstree` module to get an organized overview of the processes running:

```shell
volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x8c07c030:explorer.exe                             1564   1488     31    951 2021-09-24 09:33:33 UTC+0000
. 0x8c114af8:VBoxTray.exe                            1856   1564     15    150 2021-09-24 09:33:37 UTC+0000
. 0x84400680:notepad.exe                             2852   1564      5    259 2021-09-24 09:36:37 UTC+0000
. 0x850e8030:chrome.exe                              3108   1564     32    974 2021-09-24 09:34:23 UTC+0000
.. 0x8c069bb0:chrome.exe                             2284   3108      9    171 2021-09-24 09:34:50 UTC+0000
.. 0x8c0cbd20:chrome.exe                             2132   3108     13    220 2021-09-24 09:34:46 UTC+0000
.. 0x8539fa58:chrome.exe                             3784   3108      5    108 2021-09-24 09:34:35 UTC+0000
.. 0x98a26030:chrome.exe                             3128   3108      9     90 2021-09-24 09:34:23 UTC+0000
.. 0x8c3567d8:chrome.exe                             3680   3108     12    191 2021-09-24 09:35:02 UTC+0000
.. 0x869d6d20:chrome.exe                             3284   3108     12    195 2021-09-24 09:34:25 UTC+0000
.. 0x85359d20:chrome.exe                             3556   3108     10    180 2021-09-24 09:34:28 UTC+0000
.. 0x8c38c790:chrome.exe                             3816   3108     13    190 2021-09-24 09:34:36 UTC+0000
.. 0x86b95678:chrome.exe                             3276   3108     13    257 2021-09-24 09:35:00 UTC+0000
.. 0x86b7cd20:chrome.exe                             3320   3108      5    123 2021-09-24 09:34:25 UTC+0000
. 0x8c1172d0:AnyDesk.exe                             1868   1564      9    180 2021-09-24 09:33:37 UTC+0000
. 0x84421850:notepad.exe                             1516   1564      5    262 2021-09-24 09:35:56 UTC+0000
. 0x843af4e0:AnyDesk.exe                             4080   1564      9    204 2021-09-24 09:35:22 UTC+0000
. 0x843d8d20:cmd.exe                                 1636   1564      1     22 2021-09-24 09:37:31 UTC+0000
. 0x989cb5f0:calc.exe                                2964   1564      4     77 2021-09-24 09:34:09 UTC+0000
 0x84233878:System                                      4      0     90    554 2021-09-24 09:33:17 UTC+0000
. 0x851fa8a8:smss.exe                                 272      4      2     29 2021-09-24 09:33:17 UTC+0000
 0x869cba58:csrss.exe                                 404    396     11    390 2021-09-24 09:33:23 UTC+0000
. 0x843f5680:conhost.exe                             3652    404      2     52 2021-09-24 09:37:31 UTC+0000
 0x86a0b3a0:winlogon.exe                              448    396      5    114 2021-09-24 09:33:23 UTC+0000
 0x869cc6f0:wininit.exe                               412    344      3     77 2021-09-24 09:33:23 UTC+0000
. 0x85350b60:lsm.exe                                  524    412     10    148 2021-09-24 09:33:24 UTC+0000
. 0x85351030:lsass.exe                                516    412      8    754 2021-09-24 09:33:24 UTC+0000
. 0x85349330:services.exe                             508    412      9    201 2021-09-24 09:33:24 UTC+0000
.. 0x843ac900:svchost.exe                            2952    508     13    342 2021-09-24 09:35:47 UTC+0000
.. 0x86b5a8a0:svchost.exe                             912    508     18    492 2021-09-24 09:33:27 UTC+0000
.. 0x86ba0d20:svchost.exe                            1184    508     14    377 2021-09-24 09:33:30 UTC+0000
.. 0x8c137d20:svchost.exe                            1936    508     10    147 2021-09-24 09:33:38 UTC+0000
.. 0x86b5b030:svchost.exe                             936    508     38   1038 2021-09-24 09:33:27 UTC+0000
.. 0x8539d180:VBoxService.ex                          692    508     13    124 2021-09-24 09:33:26 UTC+0000
.. 0x8c040aa0:taskhost.exe                           1468    508      9    246 2021-09-24 09:33:33 UTC+0000
.. 0x8c0183d8:spoolsv.exe                            1348    508     14    289 2021-09-24 09:33:33 UTC+0000
.. 0x86b4c8f0:svchost.exe                             840    508     23    574 2021-09-24 09:33:27 UTC+0000
... 0x86b6e8a0:audiodg.exe                           1028    840      6    130 2021-09-24 09:33:29 UTC+0000
.. 0x8c03a770:svchost.exe                            1420    508     18    298 2021-09-24 09:33:33 UTC+0000
.. 0x8c143580:svchost.exe                            1980    508     20    281 2021-09-24 09:33:38 UTC+0000
.. 0x8538a1d8:svchost.exe                             632    508     10    355 2021-09-24 09:33:26 UTC+0000
... 0x8c34e688:WmiPrvSE.exe                          2776    632      7    120 2021-09-24 09:33:52 UTC+0000
.. 0x8c07f9d8:SearchIndexer.                         2236    508     13    612 2021-09-24 09:33:45 UTC+0000
.. 0x843a7d20:sppsvc.exe                             2428    508      4    141 2021-09-24 09:35:46 UTC+0000
.. 0x8c206030:svchost.exe                            2552    508      8    348 2021-09-24 09:33:48 UTC+0000
.. 0x8c0cd030:AnyDesk.exe                            1660    508      9    221 2021-09-24 09:33:34 UTC+0000
.. 0x8c299030:wmpnetwk.exe                           2372    508     14    421 2021-09-24 09:33:46 UTC+0000
.. 0x853aeaa8:svchost.exe                             748    508      8    283 2021-09-24 09:33:27 UTC+0000
.. 0x86b4b718:svchost.exe                             888    508     27    538 2021-09-24 09:33:27 UTC+0000
... 0x8c064710:dwm.exe                               1524    888      3     91 2021-09-24 09:33:33 UTC+0000
 0x8697c030:csrss.exe                                 352    344      8    416 2021-09-24 09:33:22 UTC+0000
```

Of note here I guess are:

- cmd.exe - what commands were typed?
- notepad.exe - whats in the notepad document?
- chrome.exe - what websites were they looking at?

##### Screenshot

To understand what was on the user's mind its helpful to see a visual of what they were actually looking at. To do this I use two methods:

- volatility screenshot module
- memdump a process and peek at the framebuffer data

Lets do the easy one first because it gives us information we need for the second item:

```shell
$ volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 -D /dumps/screenshots screenshot 
Volatility Foundation Volatility Framework 2.6.1
Wrote /dumps/screenshots/session_0.msswindowstation.mssrestricteddesk.png
Wrote /dumps/screenshots/session_1.Service-0x0-efb2$.sbox_alternate_desktop_0xC24.png
Wrote /dumps/screenshots/session_1.WinSta0.Default.png
Wrote /dumps/screenshots/session_1.WinSta0.Disconnect.png
Wrote /dumps/screenshots/session_1.WinSta0.Winlogon.png
Wrote /dumps/screenshots/session_0.WinSta0.Default.png
Wrote /dumps/screenshots/session_0.WinSta0.Disconnect.png
Wrote /dumps/screenshots/session_0.WinSta0.Winlogon.png
Wrote /dumps/screenshots/session_0.Service-0x0-3e7$.Default.png
Wrote /dumps/screenshots/session_0.Service-0x0-3e4$.Default.png
Wrote /dumps/screenshots/session_0.Service-0x0-3e5$.Default.png
```

Of which all are blank except `session_1.WinSta0.Default.png ` which displays:

![screenshot](/images/2021/tamilctf/screenshot.png)

As you can see, not a lot of information but we know:

- Notepad is open with a document called `flag`
- Explorer is open
- Screen resolution is 1024x768

Lets see if we can peek a more detailed screenshot. To do this I memdump a process and inspect it in Gimp.

```shell
$ volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 -D /dumps/screenshots -p 2852 memdump
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing notepad.exe [  2852] to 2852.dmp
$ mv screenshots/2852.dmp screen.data
$ gimp screen.data
```

I set the raw data import settings as such:

![gimp settings](/images/2021/tamilctf/gimp.png)

- **Width**: 1024
- **Height**: 768
- **Image type**: RGB Alpha

Then I scrub the **Offset** slider until something interesting comes into view. At offset 208977913 i see the following image of the users screen:

![better screenshot](/images/2021/tamilctf/gimp2.png)

The colors aren't perfect but I can make out something interesting here.

- Notepad document might have a flag?
- Notepad has 2 documents open.
- malware.exe is of interest. Its 399kb according to Explorer.

Using `strings` we can rule out the "notepad might have the flag" idea...

```
$ strings ransomeware.raw | grep 'Flag is '
Flag is in this volatile universe, but not inside here
$ strings ransomeware.raw | grep 'Now you '
Now you are really finding me .. :)
```

It sounds like encouragement? I don't know lets look elsewhere for now...

##### Command Line

Next step is what the user typed. I use the `cmdscan` module first:

```shell
$ volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 cmdscan
Volatility Foundation Volatility Framework 2.6.1
**************************************************
CommandProcess: conhost.exe Pid: 3652
CommandHistory: 0x420588 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 11 LastAdded: 10 LastDisplayed: 10
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 @ 0x41e328: dir
Cmd #1 @ 0x41dd18: cd ../..
Cmd #2 @ 0x41dd38: net user
Cmd #3 @ 0x4164d0: whoami
Cmd #4 @ 0x41dd98: cd Windows
Cmd #5 @ 0x41ddb8: cd system
Cmd #6 @ 0x41e358: dir
Cmd #7 @ 0x4181e8: .\malware.exe
Cmd #8 @ 0x402190: echo "Yay Got flag!!"
Cmd #9 @ 0x4206f0: echo "Congrats(Evil Smile)"
Cmd #10 @ 0x464b80: type .\malware.exe
Cmd #19 @ 0x310030: ???.??????????.??????????.??????????.??????????.??????????.??????????.??
Cmd #29 @ 0xff82a6bc: ???????????
Cmd #36 @ 0x3f00c4: B?F??????
Cmd #37 @ 0x41d158: B?B???????A
```

Ok now we're cooking! Again `malware.exe` is mentioned and the hacker seems pretty happy about this flag business. Ok I'm convinced lets see if we can find the `malware.exe` as our next step.

##### File Scan and Dump Files for Specific Files

In this case I want `malware.exe` let's find that hopefully?

```shell
$ volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 filescan | tee filescan.txt | grep malware.exe          
0x0000000016b6aac8      9      0 R--rwd \Device\HarddiskVolume2\Windows\system\malware.exe
0x000000003fee21c8      8      0 R--rwd \Device\HarddiskVolume2\Windows\system\malware.exe
```

Oh great, lets dump that one file. We need its physical offset which is the first number in the output here `0x0000000016b6aac8`.

```shell
$ volatility -f /dumps/ransomeware.raw --profile=Win7SP1x86_23418 -D /dumps/filedump -Q 0x0000000016b6aac8 dumpfiles
Volatility Foundation Volatility Framework 2.6.1
ImageSectionObject 0x16b6aac8   None   \Device\HarddiskVolume2\Windows\system\malware.exe
DataSectionObject 0x16b6aac8   None   \Device\HarddiskVolume2\Windows\system\malware.exe
```

Great, does it look right?

```shell
$ file filedump/*
filedump/file.None.0x850e3768.dat: PE32 executable (console) Intel 80386, for MS Windows
filedump/file.None.0x8c235008.img: PE32 executable (console) Intel 80386, for MS Windows
$ ls -lah filedump/
total 456K
drwxr-xr-x 2 root root 4.0K Sep 29 18:04 .
drwxr-xr-x 7 root root 4.0K Sep 29 18:04 ..
-rw-r--r-- 1 root root 400K Sep 29 18:04 file.None.0x850e3768.dat
-rw-r--r-- 1 root root 141M Sep 29 18:04 file.None.0x8c235008.img

```

Yep the 400k file looks about right. Let's check it out in Ghidra. 

##### Reverse Engineering malware.exe

This is the `main()` function. 

```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env)
{

    ...
    
  _File = _fopen("companyleaks.txt","r");
  if (_File == (FILE *)0x0) {
    _printf("TamilCTF{v0lat1lity_1s_n0t_2_3a5y}");
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  _fscanf(_File,"%s",file_content);
  sVar1 = _strlen(file_content);
  if (sVar1 == 19) {
    flag = file_content[0] + 11;
    local_17a = 'v';
    local_179 = file_content[18];
    local_178 = file_content[4];
    local_177 = file_content[0] + -0x20;
    local_176 = 'z';
    local_175 = file_content[13];
    local_174 = file_content[4];
    local_173 = '3';
    local_172 = (file_content[7] ^ 4U) + 29;
    local_171 = 'f';
    local_170 = '0';
    local_16f = 'r';
    local_16d = 'D';
    local_16e = local_172;
    iVar2 = toupper(L'f');
    local_16c = (undefined)iVar2;
    local_16b = local_176 + -0x31;
    local_16a = file_content[9];
    local_169 = '}';
    _puts(&flag);
  }
  else {
    _printf("TamilCTF{v0lat1lity_1s_n0t_2_3a5y}");
  }
  return 0;
}
```

What its doing it seems is basically printing our flag. However the flag itself is not within this file. It must be somewhere in RAM but its not here.

What we do know is that this program:

1. Loads the `companyleaks.txt` file.
2. Checks that file is 19 bytes in length
3. Using some of the bytes from that file, creates a new string in RAM
4. Prints the resulting string.

##### Finding companyleaks.txt

Since we know this file is in RAM somewhere we should be able to find it somehow. But since I don't know exactly what I'm looking for I decided to try another option.

I implemented the above algorithm in Python and applied it across a sliding 19 byte window in the entire RAM dump. I knew the result should possibly make sense when I saw it?

We also knew:

- Second byte of flag is `v` which doesn't match the `TamilCTF{` flag format so we are not looking for the full flag. Just the 2nd half of a flag (since the last byte is given `local_169 = '}';`)
- Flag ends with `DFI?}` and its a forensics challenge so I bet the last byte is `r || R` (i.e. `DFIR`)
- Byte before `DFIR` is the same as the byte before `f0r` since these are "word like" this is probably supposed to equate to `_` the underscore which seperates words in flags.
- We have a partial flag we learned in step 1, `TamilCTF{RaM_1s_t00` what if these are connected?



So if we put together all these we guess so far the flag is:

- `TamilCTF{RaM_1s_t00?v???z??3_f0r_DFIR}`

From here we can guess more of the flag:

- Looks like the first byte should also be `_`
- words beginning with `v` and ending with `3` that are related are `volatile`

The final script I used to find the flag uses these filters:

```python
#!/usr/bin/python

import sys
fn = sys.argv[1]
data = open(fn,'rb').read()
def enc(c):
    try:
        out = ""
        out += chr(ord(chr(c[0])) + 11)
        out += 'v'
        out += chr(c[18])
        out += chr(c[4])
        out += chr(ord(chr(c[0])) - 0x20)
        out += 'z'
        out += chr(c[13])
        out += chr(c[4])
        out += '3'
        local172 = chr((ord(chr(c[7])) ^ 4)+29)
        out += local172
        out += 'f0r'
        out += local172
        out += 'DFI'
        out += chr(c[9])
        out += '}'
        return out
    except (IndexError, ValueError):
        return ""

def filter(c):
    c = enc(c)
    if len(c) < 19:
        return False
    if c[0] == '_' and c[13] == '_' and (c[17] == 'r' or c[17] == 'R'):
        return c
    
    return False

base = 'TamilCTF{RaM_1s_t00'

for i in range(len(data)):
    c = data[i:i+19]
    z = filter(c)
    if z:
        print(base + z, flush=True)
```

Which I ran over all of the strings:

```shell
$ strings ransomeware.raw > strings.txt
$ ./findflag.py strings.txt
...
... lots of strings that didn't look right ...
...
TamilCTF{RaM_1s_t00_v0l4z1l3_f0r_DFIR}
```

Which turned out to be our flag!
