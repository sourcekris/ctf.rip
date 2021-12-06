---
title: 'HTB CyberSanta 2021 - Crypto Writeups'
date: 2021-12-05T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/cybersanta/title.png
categories:
  - Write-Ups
  - Crypto
---
HTB sure have a slick new CTF platform and it was a pleasure to play this CTF. I'm not really a fan of how they released challenges though (daily, always 5 challenges, always at midnight for me). Still the challenges were fun so I can't complain.

I focused mainly on the Crypto challenges and was fortunate to solve them all this time. I did actually give up on the fourth one a few times but when there's a right solution there's sometimes a really good wrong solution that also works.

Today I'll cover 3 of my favourites.

#### <a name="xmasspirit"></a>Xmas Spirit - Crypto - 300 points

This challenge reads:

```
Now that elves have taken over Santa has lost so many letters from kids all 
over the world. However, there is one kid who managed to locate Santa and 
sent him a letter. It seems like the XMAS spirit is so strong within this 
kid. He was so smart that thought of encrypting the letter in case elves 
captured it. Unfortunately, Santa has no idea about cryptography. Can you 
help him read the letter?
```

The challenge comes with one `encrypted.bin` file and one python script file called `challenge.py` which contains the code as follows:

```python
import random
from math import gcd

def encrypt(dt):
        mod = 256
        while True:
                a = random.randint(1,mod)
                if gcd(a, mod) == 1: break
        b = random.randint(1,mod)

        res = b''
        for byte in dt:
                enc = (a*byte + b) % mod
                res += bytes([enc])
        return res

dt = open('letter.pdf', 'rb').read()

res = encrypt(dt)

f = open('encrypted.bin', 'wb')
f.write(res)
f.close()
```

The way this works is that it takes a `PDF` file from disk and generates two random integers `a` and `b` each between 1 and 256. Then it will iterate the bytes of the `PDF` and produce an encrypted version by passing each byte through the algorithm: `ctbyte = (a*plaintextbyte + b) % 256`

There's two ways to consider solving this but for both we need to discover what these two keys `a` and `b` are.

To do that we can conduct a known plaintext attack. Since we know that the input file is a PDF, we know that it should start with the PDF magic bytes which are `%PDF-`.

What we can do is, try every combination of `a` and `b` until the encryption of `%PDF-` is equal to the first 5 bytes of `encrypted.bin`. I code this in Python real quick:

```python
from pwn import *

ctfile = 'encrypted.bin'
ct = open(ctfile, 'rb').read()

mod = 256

# modified encrypt() to take a and b as args instead of generating them.
def encrypt(dt, a, b):
   res = b''
   for byte in dt:
     enc = (a*byte + b) % mod
     res += bytes([enc])
   return res

kpt = b"%PDF-"
ctsample = list(ct[:len(kpt)])

p = log.progress('finding keys')
for a in range(mod):
    p.status(f'trying all {a} combos')
    for b in range(mod):
        res = list(encrypt(kpt, a, b))
        if res == ctsample:
            p.success(f"a = {a}, b = {b}")
            quit()
```

This finds the keys in about one second:

```shell
$python getkeys.py 
[+] finding keys: a = 169, b = 160
```

Using those keys we have 2 ways to solve this challenge:

##### The Wrong Way (aka Naive brute force solution)

I first started with this method, we take every position of the ciphertext and we brute force every byte 0-255 in that position and see if our encrypted byte in that position matched our ciphertext.

If it does match, then we know what plaintext makes that ciphertext byte.

This takes on the order of a few minutes to run and produces the correct result and I began writing this solution.

##### The Actual Way

While writing the `Wrong` code I stumbled across a past writeup which made this problem click with me a lot more. The encryption used here is a very typical implementation of the Affine Cipher.

If you do not know, the [affine cipher](https://en.wikipedia.org/wiki/Affine_cipher) is a monoalphabetic substition cipher with the encryption algorithm: 

- `E(x)=(ax+b) mod m`

One other thing we know about affine ciphers is there is a mathematical way to decrypt which is:

* `D(x) = a^-1(x-b) mod m`

`a^-1` in this case is the modular multiplicative inverse of `a` modulo `m`.

So to code the solution in python we can do the following. I added in extra PDF stuff at the end to get the flag in text.

```python
from pwn import *
from Crypto.Util.number import inverse

ctfile = 'encrypted.bin'
ct = open(ctfile, 'rb').read()

mod = 256

def encrypt(dt, a, b):
   res = b''
   for byte in dt:
     enc = (a*byte + b) % mod
     res += bytes([enc])
   return res

# standard affine cipher decryption across the bytes.
def decrypt(ct, a, b):
    res = b''
    for byte in ct:
        dec = (inverse(a, mod) * (byte - b)) % mod
        res += bytes([dec])
    
    return res

# use a known plaintext attack against PDF header to find a and b
def findparams(p):
    
    kpt = b"%PDF-"c
    ctsample = list(ct[:len(kpt)])

    for a in range(mod):
        for b in range(mod):
            res = list(encrypt(kpt, a, b))
            if res == ctsample:
                p.status(f"a = {a}, b = {b}")
                return a, b
    
    return 0, 0

def main():
    p = log.progress('solving')
    p.status("finding the affine crypto parameters a and b...")
    a, b = findparams(p)
    p.status(f"decrypting ciphertext with keys a = {a} and b = {b}...")
    pt = decrypt(ct, a, b)
    p.status("writing flag.pdf to disk...")
    open('flag.pdf','wb').write(pt)
    p.status('extracting text from pdf...')
    ptt = process(['pdftotext','flag.pdf'])
    ptt.recvall()
    ptt.close()
    flag = [x.strip() for x in open('flag.txt').readlines() if 'HTB{' in x][0]
    p.success('completed, enjoy the flag!')
    log.success(f'flag: {flag}')

main()
```

And running it, we get the flag!

```shell
$ ./solve.py 
[+] solving: completed, enjoy the flag!
[+] Starting local process '/usr/bin/pdftotext': pid 4164
[+] Receiving all data: Done (0B)
[*] Process '/usr/bin/pdftotext' stopped with exit code 0 (pid 4164)
[+] flag: HTB{4ff1n3_c1ph3r_15_51mpl3_m47h5}
```



#### <a name="meethalf"></a>Meet Me Halfway - Crypto - 325 points

Next up was a bit of a struggle for me to get motivated. Let's see why. It reads:

```
Evil elves have deployed their own cryptographic service. The keys 
are unknown to everyone but them. Fortunately, their encryption 
algorithm is vulnerable. Could you help Santa break the encryption 
and read their secret message?
```



In this challenge we get the following python code:

```python

from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json

flag = b'HTB{dummyflag}'

def gen_key(option=0):
    alphabet = b'0123456789abcdef'
    const = b'cyb3rXm45!@#'
    key = b''
    for i in range(16-len(const)):
        key += bytes([alphabet[randint(0,15)]])

    if option:
        return key + const
    else:
        return const + key

def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data, 16))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct.hex()


def challenge():
    k1 = gen_key()
    k2 = gen_key(1)

    
    ct = encrypt(flag, k1, k2)
    
    
    print('Super strong encryption service approved by the elves X-MAS spirit.\n'+\
                    'Message for all the elves:\n' +ct + '\nEncrypt your text:\n> ')
    try:
            
        dt = json.loads(input().strip())
        pt = bytes.fromhex(dt['pt'])
        res = encrypt(pt, k1, k2)
        print(res + '\n')
        exit(1)
    except Exception as e:
        print(e)
        print('Invalid payload.\n')
        exit(1)
    
if __name__ == "__main__":
    challenge()
```

This is what's running on the server, connecting to the server we see:

```shell
Super strong encryption service approved by the elves X-MAS spirit.
Message for all the elves:
9a2a76a76702ee9dc5950fee507e073911bd48158b4920ec4cef8c4ec35c9f636f6c0e34f41ce45410d7b56a6a5c33036d8063cd92b6bee0bc00d3b3a9e631fe42fba8ff241385c2b5903df6c6666afc6f73e7d26f3fb67b2cd99c5a7b2f95fb
Encrypt your text:
> 
```

So now we know the encrypted version of the flag. 

At this point, I stopped, it was already late at night for me and I am typical awful at AES encryption challenges. The next day I decided to actually LOOK though and here's what I saw.

```python
def gen_key(option=0):
    alphabet = b'0123456789abcdef'
    const = b'cyb3rXm45!@#'
    key = b''
    for i in range(16-len(const)):
        key += bytes([alphabet[randint(0,15)]])

    if option:
        return key + const
    else:
        return const + key

def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data, 16))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct.hex()


def challenge():
    k1 = gen_key()
    k2 = gen_key(1)

    
    ct = encrypt(flag, k1, k2)
```

These are the interesting parts. Here's whats going on in my opinion:

- We generate 2 keys, each 16 bytes in length. Each made up of 2 different parts:
  - `key1` is `<4 x hex digits> + cyb3rXm45!@#`
  - ey 2 is: `cyb3rXm45!@# + <4x hex digits>`
- The (padded) flag is encrypted twice:
  - The first time using `key1` 
  - Then the output of round1 is re-encrypted with `key2`

My guess is that there is properties of AES-ECB which mean this is a really bad idea and that through some known plaintext attack, being able to encrypt our own payload with the same keys mean we can trivially recover the keys.

I was feeling very lazy and wasn't able to find the path way to solve it on Google. So while searching for that, I wrote some code to try a brute force solution.

For each key there are only 65,535 possibilities. So the total keyspace for a brute force attack is on the order of 4 billion attacks. This is not feasible in Python probably but in some lower level languages it is not a difficulty.

#### The wrong solution paid off this time...

To save time, I generated the key candidates in Python using itertools:

```python
import itertools

# make all possible key
def key_candidates():
    alphabet = '0123456789abcdef'

    allperms = []
    for i in itertools.product(alphabet, repeat=4):
        allperms.append(''.join(i))
    
    return allperms

# make all possible k1 and k2
def key_combos(ap):
    const = 'cyb3rXm45!@#'

    key1s = []
    key2s = []
    for k in ap:
        key1s.append(const + k)
        key2s.append(k + const)
    
    return key1s, key2s

def writethem(k1s,k2s):
    print('writing k1s')
    with open('k1s.txt', 'w') as f:
        for k in k1s:
            f.write(k + '\n')

    print('writing k2s')
    with open('k2s.txt', 'w') as f:
        for k in k2s:
            f.write(k + '\n')

    
if __name__ == "__main__":
    print('making key candidates...')
    ap = key_candidates()
    print('making key combos...')
    key1s, key2s = key_combos(ap)

    writethem(key1s, key2s)
```

This takes < 1 second to run, very surpising:

```shell
$ time python makekeys.py 
making key candidates...
making key combos...
writing k1s
writing k2s

real    0m0.045s
user    0m0.021s
sys     0m0.025s
```

Then I wrote some Golang to actually attack the ciphertext I had:

```go
package main

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

var (
	ctbytes, _ = hex.DecodeString("9a2a76a76702ee9dc5950fee507e073911bd48158b4920ec4cef8c4ec35c9f636f6c0e34f41ce45410d7b56a6a5c33036d8063cd92b6bee0bc00d3b3a9e631fe42fba8ff241385c2b5903df6c6666afc6f73e7d26f3fb67b2cd99c5a7b2f95fb")
)

func FileReadLines(filePath string) (lines []string, err error) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}

func DecryptEcb(data, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted
}

func decrypt(ciphertext []byte, k1 string, k2 string) (pt string) {
	ct := DecryptEcb(ciphertext, []byte(k2))
	return string(DecryptEcb(ct, []byte(k1)))
}

func deccheck(f *os.File, k1, k2 string) {
	pt := decrypt(ctbytes, k1, k2)
	if strings.Contains(pt, "HTB{") && strings.Contains(pt, "}") {
		fmt.Println(pt)
		f.Write([]byte(fmt.Sprintf("%s\n%s\n%s", pt, k1, k2)))
		f.Sync()
	}
}

func main() {
	k1s, err := FileReadLines("k1s.txt")
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}

	k2s, err := FileReadLines("k2s.txt")
	if err != nil {
		fmt.Printf("error %v", err)
		return
	}

	fmt.Printf("read %d k1s and %d k2s\n", len(k1s), len(k2s))

	if err != nil {
		fmt.Printf("error decodestring %v", err)
		return
	}

	f, _ := os.Create("poss_go.txt")
	defer f.Close()

	for i, k1 := range k1s {
		if i%1000 == 0 {
			fmt.Print(".")
		}
		for _, k2 := range k2s {
			go deccheck(f, k1, k2)
		}
	}
}
```

This surprised me and brute forced the solution in just **9 minutes** using 28 threads and 49% CPU on my PC:

```shell
$ go run aes.go
...
https://www.youtube.com/watch?v=DZMv9XO4Nlk
HTB{m337_m3_1n_7h3_m1ddl3_0f_3ncryp710n}
cyb3rXm45!@#46b2
02c7cyb3rXm45!@#
```

I know this is the wrong solution but it was so fast that I don't think I could have even Google'd the right solution in just 9 minutes. 

#### <a name="warehouse"></a>Warehouse Maintenance - Crypto - 325 points

The fifth and final Crypto challenge for HTB Cyber Santa 2021 was super fun for me. This challenge reads:

```
Elves are out of control! They have compromised the database of Santa's 
warehouse. We have revealed the endpoint and we need to find a way to 
execute commands in the database. Unfortunately, every command needs 
to be signed by an Elf named Frost. Can you find a way in?
```

Let's take a quick look at the challenge code. We have three files this time:

- `challenge.py`
- `sample`
- `utils.py`

Looking at `challenge.py` first we see:

```python
import signal
import subprocess
import socketserver
from random import randint
import json
import hashlib
import os
from util import executeScript


salt = os.urandom(randint(8,100))

def create_sample_signature():
	dt = open('sample','rb').read()
	h = hashlib.sha512( salt + dt ).hexdigest()

	return dt.hex(), h

def check_signature(dt, h):
	dt = bytes.fromhex(dt)
	
	if hashlib.sha512( salt + dt ).hexdigest() == h:
		return True

def challenge():
	print("Welcome to Santa's database maintenance service.\nPlease make sure to get a signature from mister Frost.\n")
	while True:
		try:
			print('1. Get a sample script\n2. Update maintenance script.\n> ')
			option = input().strip()

			if option=='1':
				data, sign = create_sample_signature()
				payload = json.dumps({'script': data, 'signature': sign})
				print(payload + '\n')
			elif option=='2':
				print('Please send your script and its signature.\n> ')
				resp = input().strip()
				resp = json.loads(resp)
				if check_signature(resp['script'], resp['signature']):
					script = bytes.fromhex(resp['script'])
					res = executeScript(script)

					print(res+'\n')
				else:
					print('Are you sure mister Frost signed this?\n')

			else:
				print('There is no such an option.\n')
				exit(1)
		except Exception as e:
			print(e)
			print('Invalid payload. Bye!')
			exit(1)


def main():
	try:
		challenge()
	except:
		pass

if __name__ == "__main__":
	main()

```

In the other files we have a `sample` script with not much in it:

```sql
USE xmas_warehouse;
#Make sure to delete Santa from users. Now Elves are in charge.
```

And a `utils.py` with the `executeScript()` function:

```python
import mysql.connector

def executeScript(script):
  mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password=""
  )

  mycursor = mydb.cursor()
  lines = script.split(b'\n')

  resp = ''
  for line in lines:
    print(line)
    line = str(line)[2:-1]
    mycursor.execute(line)
    for x in mycursor:

      resp +=str(x)
  mydb.close()
  return resp

```

Ok cool, going back to the `challenge.py` it seems like this is the critical point:

```python
			elif option=='2':
				print('Please send your script and its signature.\n> ')
				resp = input().strip()
				resp = json.loads(resp)
				if check_signature(resp['script'], resp['signature']):
					script = bytes.fromhex(resp['script'])
					res = executeScript(script)

					print(res+'\n')
				else:
					print('Are you sure mister Frost signed this?\n')
```

If we can correctly sign a MySQL script, we can convince the server to execute SQL for us. My assumption is that if we can somehow do that, the flag must be in the SQL database on the server.

But how do we forge the signature? Lets look at how it checks signatures:

```python
salt = os.urandom(randint(8,100))

def create_sample_signature():
	dt = open('sample','rb').read()
	h = hashlib.sha512( salt + dt ).hexdigest()

	return dt.hex(), h

def check_signature(dt, h):
	dt = bytes.fromhex(dt)
	
	if hashlib.sha512( salt + dt ).hexdigest() == h:
		return True
```

Ok so, for some completely random `salt` which has some random length between 8 - 100, generate a `sha512` hash of:

- `sha512(salt + scriptdata)`

This is a stereotypical incorrect way to generate a signature because, since we know so much about the length, some of the data that is being hashed and of how the hash function works, that we can conduct a **hash length extension** attack.

Since I did a full hash length extension [writeup just recently](https://ctf.rip/write-ups/crypto/tfc-jam/) I won't write all the details here. Suffice to say this one was slightly more complex since I had to brute force the secret length.

That being said it was solved rather quick and here's the code I used to do that attack. Upon successfully brute forcing the secret length, we are dropped to a `SQL>` prompt in my script which allows the user to write arbitrary SQL queries and see the results printed.

```python
from pwn import *
import json

host, port = "178.62.18.237", 31279

p = remote(host,port)

# Get a valid hash by asking the server to send me a JSON blob including the
# sample script and its digital signature.
p.sendlineafter(b'> ', b'1')
sample = json.loads(p.recvline().decode().strip())

sig = sample['signature']
dat = sample['script']

# Parameters for the hash length extension attack
secretmin = 8
secretmax = 100
appenddata = enhex(b"\nSHOW TABLES;")
cmdline = "hash_extender -s %s -f sha512 -d '%s' --data-format=hex -a '%s' --append-format=hex --secret-min=%d --secret-max=%d" % (sig, dat, appenddata, secretmin, secretmax)
log.info('cmdline: %s' % cmdline)

# Start "hash_extender" to recover all 92 possible extended hashes
hp = process(cmdline, shell=True)
allnew = hp.recvall()

newhashes = {}
current_sec_len = 0
for i, line in enumerate(allnew.splitlines()):
    line = line.decode()

    if line.startswith('Type:'):
        continue

    if line.startswith('Secret length:'):
        # allocate a dict key for it
        seclen = int(line.split()[2])
        newhashes[seclen] = {'signature':'', 'script':''}
        current_sec_len = seclen
        continue
    
    if line.startswith('New signature:'):
        newhashes[current_sec_len]['signature'] = line.split()[2]
        continue
    
    if line.startswith('New string:'):
        newhashes[current_sec_len]['script'] = line.split()[2]
        continue

hp.close()

log.info(f'collected {len(newhashes)} new scripts and hashes')

# Attempt to verify which of our extended hashes is validated by the server.
# Whatever hash is valid will help us identify the length of the secret.
correct_secret_len = 0
for newhash, val in newhashes.items():
    log.info(f'trying secret len {newhash}')
    updated = {'script':val['script'], 'signature':val['signature']}
    updated = json.dumps(updated)

    log.info('sending....')
    p.sendlineafter(b'> ', b'2') # update
    p.sendlineafter(b'> ', updated.encode()) # send my update
    result = p.recvline()

    if b'Are you sure mister Frost signed this?' in result:
        log.info('failed, trying next')
        continue
    else:
        log.info(f"correct secret length was {newhash}")
        correct_secret_len = newhash
        break

# Interactive SQL prompt section. User can type a SQL query, it will be signed and sent
# to the server and executed. The server will print back the results.
p.recvuntil(b'> ')
while True:
    sqlquery = input('SQL> ')

    appenddata = enhex(b"\n" + sqlquery.encode())

    cmdline = "hash_extender -s %s -f sha512 -d '%s' --data-format=hex -a '%s' --append-format=hex -l %d" % (sig, dat, appenddata, correct_secret_len)
    log.info('doing hash length extension with hash_extender: %s' % cmdline)
    hp = process(cmdline, shell=True)
    hp.recvuntil(b'New signature: ')
    newsig = hp.recvline().strip().decode()
    hp.recvuntil(b'New string: ')
    newscript = hp.recvline().strip().decode()
    hp.close()

    updated = {'script':newscript, 'signature':newsig}
    updated = json.dumps(updated)

    log.info('sending....')
    p.sendline(b'2') # update
    p.sendlineafter(b'> ', updated.encode()) # send my update

    res = p.recvuntil(b'> ')
    print()
    for line in res.splitlines():
        print(line.decode())
    
    print()

```

And the solve run goes very smoothly!

```shell
./solve.py 
[+] Opening connection to 178.62.123.156 on port 32660: Done
[*] cmdline: hash_extender -s 279767275239bb64fdb96c8d4dfc700c83552875e8abaadefa3ae4f131e7fc6b52efa1c091c34967a8351e57ca1e108ce1fc635d78734b15e56a092ccd1c455d -f sha512 -d '55534520786d61735f77617265686f7573653b0a234d616b65207375726520746f2064656c6574652053616e74612066726f6d2075736572732e204e6f7720456c7665732061726520696e206368617267652e' --data-format=hex -a '0a53484f57205441424c45533b' --append-format=hex --secret-min=8 --secret-max=100
[+] Starting local process '/bin/sh': pid 6660
[+] Receiving all data: Done (50.97KB)
[*] Process '/bin/sh' stopped with exit code 0 (pid 6660)
[*] collected 93 new scripts and hashes
[+] brute forcing secret length: correct secret length was 48
SQL> SHOW TABLES;
[*] doing hash length extension with hash_extender: hash_extender -s 279767275239bb64fdb96c8d4dfc700c83552875e8abaadefa3ae4f131e7fc6b52efa1c091c34967a8351e57ca1e108ce1fc635d78734b15e56a092ccd1c455d -f sha512 -d '55534520786d61735f77617265686f7573653b0a234d616b65207375726520746f2064656c6574652053616e74612066726f6d2075736572732e204e6f7720456c7665732061726520696e206368617267652e' --data-format=hex -a '0a53484f57205441424c45533b0a' --append-format=hex -l 48
[+] Starting local process '/bin/sh': pid 6815
[*] Process '/bin/sh' stopped with exit code 0 (pid 6815)
[*] sending....

('materials',)('users',)
1. Get a sample script
2. Update maintenance script.
> 

SQL> SELECT * FROM materials;
[*] doing hash length extension with hash_extender: hash_extender -s 279767275239bb64fdb96c8d4dfc700c83552875e8abaadefa3ae4f131e7fc6b52efa1c091c34967a8351e57ca1e108ce1fc635d78734b15e56a092ccd1c455d -f sha512 -d '55534520786d61735f77617265686f7573653b0a234d616b65207375726520746f2064656c6574652053616e74612066726f6d2075736572732e204e6f7720456c7665732061726520696e206368617267652e' --data-format=hex -a '0a53454c454354202a2046524f4d206d6174657269616c733b0a' --append-format=hex -l 48
[+] Starting local process '/bin/sh': pid 6844
[*] Process '/bin/sh' stopped with exit code 0 (pid 6844)
[*] sending....

(1, 'wood', 124)(2, 'sugar', 352)(3, 'love', 999)(4, 'glass', 719)(5, 'paint', 78)(6, 'cards', 1205)(7, 'boards', 1853)(8, 'HTB{h45hpump_15_50_c001_h0h0h0}', 1337)
```

And there's the flag, in the `materials` table.

Fun CTF all round!

