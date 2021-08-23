---
title: 'corCTF 2021: Dividing Secrets'
date: 2021-08-21T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/corctf/divsecretstitle.png
categories:
  - Write-Ups
  - Crypto
---
Fourth in line in the Crypto challenge for me was this probably math heavy challenge that I found a secondary solution to. At the heart of it was a bespoke encryption algorithm and an oracle who you can leak the secret from. More details below...

#### Dividing Secrets - Crypto - 450 Points

This challenge reads:

```
I won't give you the secret. But, I'll let you divide it.

nc crypto.be.ax 6000

(84 solves)
```

With the challenge we get this file:

* `server.py`

This file is the Python source code the service provided running at `crypto.be.ax`

```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from random import randrange
from secret import flag

LIMIT = 64

def gen():
	p = getStrongPrime(512)
	g = randrange(1, p)
	return g, p

def main():
	g, p = gen()
	print("g:", str(g))
	print("p:", str(p))
	x = bytes_to_long(flag)
	enc = pow(g, x, p)
	print("encrypted flag:", str(enc))
	ctr = 0
	while ctr < LIMIT:
		try:
			div = int(input("give me a number> "))
			print(pow(g, x // div, p))
			ctr += 1
		except:
			print("whoops..")
			return
	print("no more tries left... bye")

main()	
```

#### The Oracle

The server itself does the following:

- Generates a 512 bit prime `p` and a generator `g` where `g < p`
- Raises `g` to the power of `x` (which is the encoded flag) modulo `p`
- Tells the user all of `g`, `p` and the result of `g^x mod p`
- Offers to allow you to re-do the encryption and provide your result at a fraction of the plaintext flag: i.e. `g^(x/y) mod p` where the user controls `y`.

We then get 64 tries at this before the server says `no more...`

Thus the server is somewhat of an oracle for the plaintext. We can say that because of the properties of Python integer division operator `(//)`. When you use integer division and `x>y` the result  is `0` you can not receive some float result `< 1`

Therefore in the python code `pow(g, x // div, p)`, if we provide some number `div > x` the result will be `0`. Any number raised to the power of `0` is `1`. So the result of `g^1 mod p == 1`. An example:

```shell
$ nc crypto.be.ax 6000
g: 9469478585165202531347531237271222431820177929517646371381768151145816243787211118568001909025475282128378386587829099526813601190954200935233567225449878
p: 9502663596629776115798083086578516088914731652976004052737538621488653404676684814685767013192370554824500062660286960997310405975464753908394465234839031
encrypted flag: 5313743827419293655205241164009328528579040174069769374549906627096587894188726627536656168320152247301473040998176124056308069464086747472994558942083382
give me a number> 53137438274192936552052411640093285285790401740697693745499066270965878941887266275366561683201522473014730409981761240563080694640867474729945589420833829999999
1

```

Above I provided a number much larger than `x` could be and the result was `1`.

We can now use this as an oracle to binary search for the flag, to start with we need some good boundary conditions to make the binary search faster.

I chose the start with the known plaintext bytes `corctf{}` with the flag text bytes set to the space character (ascii `0x20`) and wrote the following script to binary search for the right flag:

```python
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from random import choice

host, port = "crypto.be.ax", 6000
startflag = b"corctf{qu4drat1                                                }"
endflag =   b"corctf{qu4drat1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz}"
assert len(startflag) == 64 and len(endflag) == 64

conn = remote(host,port)
g = int(conn.recvline().decode('utf-8').split()[1])
p = int(conn.recvline().decode('utf-8').split()[1])
encflag = int(conn.recvline().decode('utf-8').split()[2])
print("pow(%d, flag, %d) = %d" % (g,p,encflag))

ctr = 0
low = bytes_to_long(startflag)
high = bytes_to_long(endflag)

def niceflag(s):
    out = ""
    for x in s:
        try:
            if x > 32 and x < 126:
                out += chr(x)
        except:
            pass
    return out

while True:
    mid = (low + high) // 2
    print("flag so far: %s" % niceflag(long_to_bytes(mid)))
    conn.recvuntil(b"number> ")
    conn.sendline(str(mid).encode())
    z = int(conn.recvline().decode('utf-8'))

    if z == 1:
        high = mid - 1
    
    if z > 1:
        low = mid + 1
    
    ctr += 1
```

When we run it against the server it leaks only SOME of the bytes of the flag per execution.

```shell
$ ./solve.py 
[+] Opening connection to crypto.be.ax on port 6000: Done
pow(11820498977550734828653912324375560171949411037724471307368839780277434037809071119711398909668217923321263495100359890464224026792025691896215315314793797, flag, 11870657333128346379158109277268936637207808809794872279417396702265791992159688302389548612939812143143929280911989671553629439904520837863827906312317217) = 4499766221063799936326843973676576852439726329420450400618170871734793888455393422976505244926928727862648481368758494715982561691898213740999734160580391
flag so far: corctf{MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM}
flag so far: corctf{cãããããããããããããããããããããããããããããããããããããããããããããããããããããããý
flag so far: corctf{o///////////////////////////////////////////////////////=
flag so far: corctf{tÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÝ

flag so far: corctf{p
flag so far: corctf{qMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMY
flag so far: corctf{q§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§³
flag so far: corctf{qzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
flag so far: corctf{qcããããããããããããããããããããããããããããããããããããããããããããããããããããããï
flag so far: corctf{qo//////////////////////////////////////////////////////:
flag so far: corctf{qtÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔÔà
flag so far: corctf{qw§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§§³
flag so far: corctf{qv>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>I
flag so far: corctf{qu

...64 tries later...

flag so far: corctf{qu4drat1
```

Modifying the `startflag`and `endflag` variables in the script and running again further narrows down the answer:

```
startflag = b"corctf{qu4drat1                                                }"
endflag =   b"corctf{qu4drat1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz}"
```

```shell
$ ./solve.py 
[+] Opening connection to crypto.be.ax on port 6000: Done
pow(10858937186300249722450521912030830897958954663235060357469745152419530147812617947010556514576049382939234102836742154577207976027039220099856848565273761, flag, 11614849301314078887913511348704458004510422071444480074703416239074327769801024404904454687337665352764232814181191152379541050820613883993392348649821581) = 9090683722843891214570138561345563268899824283256785885869169370022974271259039714599152155301195443621906431363414969191604777878961723248653108671207942
flag so far: corctf{qu4drat1MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM}
flag so far: corctf{qu4drat1c

... cut a few lines...

flag so far: corctf{qu4drat1c_r3s1dv>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>O
flag so far: corctf{qu4drat1c_r3s1du
flag so far: corctf{qu4drat1c_r3s1du////////////////////////////////////////@
flag so far: corctf{qu4drat1c_r3s1du\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\m
```

And after about 20 attempts of narrowing this down we get the full flag:

```shell
# ./solve.py 
[+] Opening connection to crypto.be.ax on port 6000: Done
pow(3968218152742885444913628459538778664641871974276756121970175688279800451598790347675168544482545894620120356496526510968117694834393499242820278427870969, flag, 9631873719848231410020436752479012121871910466468713187192100618223604159449540203739224453842098920155126012364992181221725854103746656216239456795706257) = 3864110445840553493265040447270655296274517667095157776589032251491893722850997939751499236027899518934165973198964376248674960228555295455058851857034378
flag so far: b'corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}'
flag so far: b'corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}'
flag so far: b'corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}'
flag so far: b'corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}'
```

Certainly NOT the right way to solve it but got there nonetheless!

