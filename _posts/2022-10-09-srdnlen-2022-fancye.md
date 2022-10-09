---
title: 'srdnlen CTF 2022 - Fancy E'
date: 2021-12-13T00:00:00+00:00
author: Kris
layout: post
image: /images/2022/srdnlen/fancye-writeup.png
categories:
  - Write-Ups
  - Crypto

---

Haven't done any writeups lately as I've not been having much time to do CTFs. This CTF caught my attention on the weekend though for its approachable set of intro challenges. I ended up finishing 15th on the scoreboard.  This challenge was interesting because of the unintended solutions. I'll go through one of these below.

<a name="fancye"></a>Fancy E - Crypto - 482 points 

This challenge reads:

```
e=65537 is mainstream nowadays...so I implemented this to generate some fancier ones.

This is a remote challenge, you can connect to the service with: nc fancye.challs.srdnlen.it 15007

Author: @zaua
```

The challenge comes with two files:

- `example.txt`
- `fancy_e.py`

Let's look at the `fancy_e.py `first, its the server which is running remotely, written in Python:

```python
#!/usr/bin/env python3

import os
import random
import string

from Crypto.Util.number import getPrime, bytes_to_long


def flag_padding(flag):
    s = string.ascii_lowercase + string.ascii_uppercase + string.digits
    for i in range(random.randint(5, 10)):
        flag = random.choice(s) + flag + random.choice(s)
    return flag


def fancy_e(b, x, y):
    rand1 = random.randint(1, 5)
    rand2 = random.randint(1, 5)
    rand3 = random.randint(1, 5)

    op1 = random.choice([-1, 1])
    op2 = random.choice([-1, 1])
    op3 = random.choice([-1, 1])

    e = b + (op1 * rand1)
    f = x * y + op2 * rand2 * y + op3 * rand3 * x + 1
    k = rand1 + rand2 + rand3

    new_e = (e * f * k + 1) | 1

    assert pow(new_e, -1, (x - 1) * (y - 1))

    return new_e


flag = os.environ.get("FLAG", "srdnlen{template}")
flag = flag_padding(flag)
base = int(open('base.txt', 'r').read())
assert 300 < base < 10000

disclaimer = "Tired of using e = 65537? Would you prefer a more stylish and original e to encrypt your message?\n" \
             "Try my new software then! It is free, secure and sooooo cool\n" \
             "Everybody will envy your fancy e\n" \
             "You can have a look to up to 1000 flags encrypted with my beautiful e and " \
             "choose the one you like the most\n" \
             "How many do you want to see?"

print(disclaimer)
number = int(input("> "))
if number < 1 or number > 1000:
    print("I said up to 1000! Pay for more")
    exit(1)
print()

i = 0
while i < number:
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    try:
        e = fancy_e(base, p, q)
        ct = pow(bytes_to_long(flag.encode()), e, n)
        print("Ciphertext"+str(i)+"= " + str(ct))
        print("e"+str(i)+"=          " + str(e))
        print("Modulus"+str(i)+"=    " + str(n))
        print()
        i += 1

    except:
        continue

exit(0)
```

Reading through the script, at the beginning of each run it will ask the user how many example ciphertext / public keys combos they want to look at (up to 1000!).

It then generates RSA keys and ciphertexts but instead of using the "standard" exponents such as 65537 has an elaborate / fancy way of coming up with a public exponent which it then uses to encrypt a padded flag.

It then gives the user all of those one after the other and closes the connection, it looks like this:

```shell
$ nc fancye.challs.srdnlen.it 15007
Tired of using e = 65537? Would you prefer a more stylish and original e to encrypt your message?
Try my new software then! It is free, secure and sooooo cool
Everybody will envy your fancy e
You can have a look to up to 1000 flags encrypted with my beautiful e and choose the one you like the most
How many do you want to see?
> 2

Ciphertext0= 6073246934086304104977810626922002557905963514650037250131555997009251926287447959861787240583702060399239657175522003378745141910161700947214624158137855
e0=          400602059726441364995357764578358213683122310838610576977506549355099502607535346718427068095984927763467499185777478014299746881128961315520420240321092998145
Modulus0=    7362519706060196743220263633793869138283110232096645475685184050193885475501805319773538372138806557182940549037580408541119108032651794944623204659029629

Ciphertext1= 1135459988276561686284340382945158888688448567501181267112067674355148756671157106106467947527871461128751256140534892751015182911615821152255957284987288
e1=          726265831842884263742712719904163208385501292927924107290926956373654278661222133207172550941470084217073288761081858542460434469967175797727708498604931897729
Modulus1=    11679303869852120541340420685452257950365066462883122785458107493465429670996086379716624348575655929339910529009777921442926745155717750082292354236323091
```

Very stylish.

The first thing I observe when actually connecting to the server is the length of the public exponents. Some of you may recall that when `e` is very large it can force `d` to be small enough to attack. There are a number of attacks possible but the first one that I tried is called [Wiener's Attack on RSA Large Public Exponents](https://en.wikipedia.org/wiki/Wiener%27s_attack). 

### First Attempt at Solution

Since each ciphertext contains the flag I figured I can just try the first one to see if it is vulnerable. Unfortunately I was out of luck and MOST of the keys generated by the script are NOT vulnerable to Wiener's attack:

```shell
$ cat > key.txt
c: 6073246934086304104977810626922002557905963514650037250131555997009251926287447959861787240583702060399239657175522003378745141910161700947214624158137855
e: 400602059726441364995357764578358213683122310838610576977506549355099502607535346718427068095984927763467499185777478014299746881128961315520420240321092998145
n: 7362519706060196743220263633793869138283110232096645475685184050193885475501805319773538372138806557182940549037580408541119108032651794944623204659029629
^D
$ goRsaTool -key key.txt -attack wiener
rsatool: rsatool.go:228: wiener variant attack failed
```

I actually expected that and my idea was, *well there's a chance the script COULD make a key vulnerable to Wiener and I have 1000 attempts per connection so it's probably worth a shout*.

So thats what I did. I wrote a wrapper for my [goRsaTool](https://github.com/sourcekris/goRsaTool) program to download 1000 keys and attack them. This is the code:

```python
from pwn import *
import subprocess

pnum = 1000
conn = remote('fancye.challs.srdnlen.it', 15007)
log.info(f"Asking for {pnum} problems")
conn.sendlineafter(b"> ", str(pnum).encode())
raw = conn.recvall().decode()

problems = {}
for line in raw.splitlines():
    if line.startswith("Ciphertext"):
        ctnum = int(line.split('=')[0].replace("Ciphertext", ""))
        c = int(line.split("=")[1].lstrip().strip())
        problems[ctnum] = {"c":c}

    if line.startswith("e"):
        enum = int(line.split('=')[0].replace("e", ""))
        e = int(line.split("=")[1].lstrip().strip())
        problems[enum]["e"] = e

    if line.startswith("Modulus"):
        nnum = int(line.split('=')[0].replace("Modulus", ""))
        n = int(line.split("=")[1].lstrip().strip())
        problems[nnum]["n"] = n

log.info(f"Got {len(problems)} problems...")

pr = log.progress("Wiener attack problem")
kf = "key.txt"
for i, problem in problems.items():
    pr.status(f"{i}")
    with open(kf, "w") as f:
        f.write(f"c: {problem['c']}\n")
        f.write(f"e: {problem['e']}\n")
        f.write(f"n: {problem['n']}\n")
    
    out = subprocess.check_output(["goRsaTool","-key", "key.txt", "-attack", "wiener"], stderr=subprocess.STDOUT)
    if b"attack failed" in out:
        continue
    else:
        log.info("Got result for this combo:")
        log.info(f"c: {problem['c']}")
        log.info(f"e: {problem['e']}")
        log.info(f"n: {problem['n']}")
        
        if b"srdnlen" in out:
            log.success(f"Flag: {out}")
            input()
```

I ran it in the background while working on other challenges but it didn't take very long to find a result:

```shell
$ ./solve.py 
[+] Opening connection to fancye.challs.srdnlen.it on port 15007: Done
[*] Asking for 1000 problems
[+] Receiving all data: Done (503.64KB)
[*] Closed connection to fancye.challs.srdnlen.it port 15007
[*] Got 1000 problems...
[▗] Wiener attack problem: 12
[|] Wiener attack problem: 12
[*] Got result for this combo:
[*] c: 3351211610901731590829698105468856871206209199351368186640884673535268880114668764277536845809278212078587651181508905511014785692330691808594
[*] e: 149689995517120735226239142351885362959195198204142038170401721337198131988620826401694122032070914272169899433620640214334228762202060853768825345219750198593
[*] n: 6415102233527073593307583026994315717802142718956974293751680866426593468270532546733246126352379877079511268861339823584917090890200445248704737472214213
[+] Flag: b'-----BEGIN RSA PRIVATE KEY-----\nMIH6AgEAAkB6fF3VstPbeonuWFtZHgQ4CRJ30gYTCJhMOXOvzeJepqyT43dSICZG\nVyyv+H3X5YaqgDRjmuFir67KluaK0PTFAkIrnGPQ5EnadyM4MsmWPOX0i4rpVXFV\nquFps7ymqkgHPsyRF26FE58Z0CXF4DnntowYRjIB6FFDBjYchLUkKwNm/UECAQEC\nIQCYZHRaKICQZ3f2+VuzjCtk5HLdLJ6jdykhY79IHJSu3QIhAM3CvQwJLMsl/C0R\nx6qXqcMRZktd84RX5V0Oq62Ro5sJAgEBAgEBAiB7X89syFqp2qx7A3fVLh50Qwxd\nRkQGFp7aG0VOO9iKzw==\n-----END RSA PRIVATE KEY-----\n\nRecovered plaintext: \nFZkfNsrdnlenctf{mYe15F4ncYbUTunS3cur35oplzd0ntcR4Ck1t}uczMR\n'
```

Which did contain the (padded) flag:

`srdnlenctf{mYe15F4ncYbUTunS3cur35oplzd0ntcR4Ck1t}`

### Other unintended solution

After the CTF ended one other solver mentioned in Discord that the script had another bug where it would just not encrypt the flag sometimes. I tested that out and sure enough, it happened on the 1142nd ciphertext I tried:

```shell
$ ./unintended.py 
[+] Opening connection to fancye.challs.srdnlen.it on port 15007: Done
[*] Asking for 1000 problems
[+] Receiving all data: Done (503.49KB)
[*] Closed connection to fancye.challs.srdnlen.it port 15007
[*] Got 1000 problems...
[>] Solving problem: 142
[+] Flag: b'NJvZCsrdnlenctf{mYe15F4ncYbUTunS3cur35oplzd0ntcR4Ck1t}SygLi'
```

Woops!



