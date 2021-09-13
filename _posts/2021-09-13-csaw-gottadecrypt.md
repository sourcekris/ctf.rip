---
title: 'CSAW 2021: Gotta Decrypt em All'
date: 2021-09-13T04:00:00+00:00
author: Kris
layout: post
image: /images/2021/csaw/decrypttitle.png
categories:
  - Write-Ups
  - Crypto
---
Second writeup from CSAW, a Software Engineering challenge more than crypto in my opinion!

#### <a name="decryptemall"></a>Gotta Decrypt em All - Crypto - 175 points

This challenge reads:

```
Gotta Decrypt Them All

You are stuck in another dimension while you were riding Solgaleo. You 
have Rotom-dex with you to contact your friends but he won't activate 
the GPS unless you can prove yourself to him. He is going to give you 
a series of phrases that only you should be able to decrypt and you 
have a limited amount of time to do so. Can you decrypt them all?

nc crypto.chal.csaw.io 5001

(235 Solves)
```

This challenge isn't about solving tough math problems or tricky decryption, its mostly about writing some moderetely robust code to parse the problems, break them down and solve them.

Only late into the solution did I realise it was probably a lot simpler than I thought, but anyway I wrote a lot of code.

The server throws several simple decryption problems and expects you to solve them very quickly. Each code given is like an onion with layers beneath it. It seems in this order:

- Morse code which decodes to...
- Decimal ascii representation which decodes to...
- Base64 code which decodes to...
- An RSA public key including N, e and C which you can easily break and which decodes too...
- A Rot13 string which decodes to...
- Some nonsense words which you must submit the the server...

Anyway theres not much mystery here, my solution was as follows:

```python
#!/usr/bin/python3

from pwn import *
import base64
import re
import codecs
import enchant

host, port = "crypto.chal.csaw.io", 5001

morse = {'A': '.-',     'B': '-...',   'C': '-.-.', 'D': '-..',    'E': '.',      'F': '..-.', 'G': '--.',    'H': '....',   'I': '..', 'J': '.---',   'K': '-.-',    'L': '.-..',
         'M': '--',     'N': '-.',     'O': '---', 'P': '.--.',   'Q': '--.-',   'R': '.-.','S': '...',    'T': '-',      'U': '..-', 'V': '...-',   'W': '.--',    'X': '-..-',
         'Y': '-.--',   'Z': '--..','0': '-----',  '1': '.----',  '2': '..---', '3': '...--',  '4': '....-',  '5': '.....','6': '-....',  '7': '--...',  '8': '---..','9': '----.'}
inversemorse = {value:key for key,value in morse.items()}

exceptions = ["Wobbuffet", "Arctovish", "Bouffalant", "Froakie", "Arctozolt"]

justDidRot13 = False

def decode_morse(s):
    log.info("decoding as morse")
    res = ""
    morse = s.split(' /')
    for word in morse:
        letters = word.split()
        for letter in letters:
            res += inversemorse.get(letter)
        res += " "
    
    res = res.strip()
    log.info("decoded to: %s ..." % res[:min(12, len(res))])
    return res

def decode_dec(s):
    log.info("decoding as dec")
    res = ''.join([chr(int(x)) for x in s.split()])
    log.info("decoded to: %s ..." % res[:min(12, len(res))])
    return res

def decode_b64(s):
    log.info("decoding as b64")
    res = base64.b64decode(s).decode()
    log.info("decoded to: %s ..." % res[:min(12, len(res))])
    return res

def decode_rsa(s):
    log.info("conducting rsa attack")
    keyvals = s.split('\\n')
    with open('rsakey.pub', 'w') as f:
        for k in keyvals:
            f.write(k + '\n')
    pp = process('goRsaTool -key rsakey.pub -attack hastads', shell=True)
    try:
        res = pp.recvall().decode().splitlines()[1]
    except IndexError:
        log.error("rsa attack failed")

    log.info("decoded to: %s ..." % res[:min(12, len(res))])        
    return res

def decode_rot13(s):
    global justDidRot13
    log.info("decoding as rot13")
    res = codecs.encode(s, "rot_13")
    log.info("decoded to: %s ..." % res[:min(12, len(res))]) 
    justDidRot13 = True       
    return res

def is_probably_english(s):
    for e in exceptions:
        if e in s:
            return True
    d = enchant.Dict("en_US")
    words = s.split()
    wlen = len(words)
    counter = 0
    for word in words:
        if d.check(word):
            counter += 1 
    res = float(counter / wlen)
    if  res <  0.5:
        log.info("deciding that %s is not english (%0.2f)" % (s, res))
        return False
    log.info("deciding that %s is probably english(%f)" % (s, res))
    return True

def is_words(s):
    words = s.split()
    wlen = len(words)
    if wlen == 1 and len(s) > 20:
        return False
    wlens = []
    for word in words:
        wlens.append(len(word))
    
    avg = float(sum(wlens)/wlen)

    if avg > 3.0:
        log.info("decided that %s is probably words (%0.2f)" % (s, avg))
        return True
    
    log.info("decided that %s is probably NOT words(%0.2f)" % (s, avg))
    return False

def detect_attack(s):
    global justDidRot13
    log.info("type of s: %s" % type(s))
    if re.match('^[.-]+\s[.-]+', s):
        return "morse"
    
    if re.match('^N\s=\s\d+',s):
        return "rsa"
    
    if re.match('[0-9]{2}\s[0-9]{2}', s):
        return "dec"
    
    if re.match('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', s) and len(s) > 15:
        try:

            res = base64.b64decode(s)
            return "b64"
        except:
            pass
    
    if is_words(s) and not is_probably_english(s) and not justDidRot13:
        return "rot13"

    justDidRot13 = False
    #log.warn("unknown encryption for %s" % s)
    return "unk"

def get_chall(p):
    z = p.recvuntil((b'What does this mean?', b'flag{'))
    if b'flag{' in z:
        rest = p.recvline()
        log.info(z.decode() + rest.decode())
        quit()
    p.recvline()
    chal = p.recvuntil(b'>> ')
    return chal[:-3].decode().strip()

def teststuff():
    assert decode_morse('---.. ....- /.---- ----- .....') == "84 105"
    assert decode_dec('84 105') == "Ti"
    assert decode_rsa('N = 137425672556739273030748640258205210116153474880488589847281419295608608517430318444692184153927476177033566842517562867336749010217865190815622813967554329700303230164068787074096163048454066981689296885580800937011789021736936848702792528039372388949366708604807034984009711327938053861353031046439467848541\\ne = 3\\nc = 152167424273977436702890273274501734012765882487008338973232502170356375148818609621863975256') == 'Cbxrzba Anzrf'
    assert detect_attack('---.. ....- /.---- ----- .....') == "morse"
    assert detect_attack('84 105') == "dec"
    assert detect_attack('N = 137425672556739273030748640258205210116153474880488589847281419295608608517430318444692184153927476177033566842517562867336749010217865190815622813967554329700303230164068787074096163048454066981689296885580800937011789021736936848702792528039372388949366708604807034984009711327938053861353031046439467848541\\ne = 3\\nc = 152167424273977436702890273274501734012765882487008338973232502170356375148818609621863975256') == "rsa"
    assert detect_attack('aGVsbG8=') == "b64"
    assert detect_attack('0a 0d 3a 4b') == "unk"
    assert detect_attack('Cbxrzba Anzrf') == "rot13"
    assert detect_attack('Nhqvab') == "rot13"

def do_attack(s, t):
    if t == "morse":
        return decode_morse(s)
    if t == "dec":
        return decode_dec(s)
    if t == "rsa":
        return decode_rsa(s)
    if t == "b64":
        return decode_b64(s)
    if t == "rot13":
        return decode_rot13(s)
    if t == "unk":
        return s

def main():
    # teststuff()
    # quit()
    p = remote(host, port)

    while True:
        s = get_chall(p)
        t = detect_attack(s)
        log.info("got ciphertext: %s ..." % s[:min(12, len(s))])
        while t != "unk":
            s = do_attack(s, t)
            t = detect_attack(s)
            log.info("detected as: %s" % t)

        log.info("sending as plaintext: %s" % s)
        p.sendline(s.encode())


if __name__ == "__main__":
    main()
```

Which when I ran it, spat out the flag in around 60 seconds. 

It was fun to code but it took a lot of time away from other challenges worth a lot more points. Oh well!
