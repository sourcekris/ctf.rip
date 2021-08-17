---
title: 'Really Awesome CTF 2021: Military Grade'
date: 2021-08-16T04:00:00+00:00
author: Kris
layout: post
image: /images/2021/ractf/teleportt.png
categories:
  - Write-Ups
  - Crypto
---
This Web challenge category was oddly misplaced and maybe should have existed within the Reversing category instead but no matter. I class this as a reversing + crypto challenge and I also had a lot of fun solving it as it involves a Golang program which is certainly my favourite language to code in these days.

#### Military Grade - Web - 300 Points

This challenge reads:

```
Go is safe, right? That means my implementation of AES will be secure?

(40 solves)
```

With the challenge we get this file:

* `main.go`

This file is a Golang program that responds to web requests and displays the flag encrypted with AES:

```go
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const rawFlag = "[REDACTED]"

var flag string
var flagmu sync.Mutex

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func encrypt(plaintext string, bKey []byte, bIV []byte, blockSize int) string {
	bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		log.Println(err)
		return ""
	}
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	return hex.EncodeToString(ciphertext)
}

func changer() {
	ticker := time.NewTicker(time.Millisecond * 672).C
	for range ticker {
		rand.Seed(time.Now().UnixNano() & ^0x7FFFFFFFFEFFF000)
		for i := 0; i < rand.Intn(32); i++ {
			rand.Seed(rand.Int63())
		}

		var key []byte
		var iv []byte

		for i := 0; i < 32; i++ {
			key = append(key, byte(rand.Intn(255)))
		}

		for i := 0; i < aes.BlockSize; i++ {
			iv = append(iv, byte(rand.Intn(255)))
		}

		flagmu.Lock()
		flag = encrypt(rawFlag, key, iv, aes.BlockSize)
		flagmu.Unlock()
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	flagmu.Lock()
	fmt.Fprint(w, flag)
	flagmu.Unlock()
}

func main() {
	log.Println("Challenge starting up")
	http.HandleFunc("/", handler)

	go changer()

	log.Fatal(http.ListenAndServe(":80", nil))
}
```

#### The Bug

The catch with the Golang code above is that it generates both the IV and Key using the Golang `math/rand` package which is not intended to provide cryptographically secure random numbers. It is a fully deterministic PRNG and when seeded with the current time is entirely breakable.

All we need to recover the flag here is:

- An example ciphertext
- Knowledge of when the ciphertext was generated

While the use of `time.Now().UnixNano()` in the `rand.Seed()` function does provide some increase in scope of the keyspace, it is damped by applying the bitmask and this effectively reduces the keyspace down quite a lot. We can show this with the following Go code.

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	for i := 0; i < 20; i++ {
		fmt.Println(time.Now().UnixNano() & ^0x7FFFFFFFFEFFF000)
	}
}
```

Which shows us the scope of the keyspace reduction, these are small seeds to be using for the random number generator:

```shell
$ go run maskcheck.go 
16778071
16780900
16778034
16778694
16779274
16779854
16780434
16780994
16777458
16778008
...
```

So to satisfy our need of ciphertext and knowledge about when it was generated, the CTF is running the go code here as a service so we can simple connect to the service and get both:

```shell
$ nc 193.57.159.27 50633
GET / HTTP/1.0

HTTP/1.0 200 OK
Date: Mon, 16 Aug 2021 04:47:06 GMT
Content-Length: 64
Content-Type: text/plain; charset=utf-8

fc779506a353cba4582dc2935c68c48069cab35524234becd3a640d805bcd673
```

To solve this I re-used the challenge's own Golang though and wrote this:

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func decrypt(ciphertext []byte, bKey []byte, bIV []byte, blockSize int) string {
	block, err := aes.NewCipher(bKey)
	if err != nil {
		log.Println(err)
		return ""
	}
	pt := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks(pt, ciphertext)
	return string(pt)
}

func attack(ciphertext []byte) {
	seed := time.Now().UnixNano() & ^0x7FFFFFFFFEFFF000
	for delta := seed - 1000; delta < seed+1000; delta++ {
		rand.Seed(delta)
		for i := 0; i < rand.Intn(32); i++ {
			rand.Seed(rand.Int63())
		}

		var key []byte
		var iv []byte

		for i := 0; i < 32; i++ {
			key = append(key, byte(rand.Intn(255)))
		}

		for i := 0; i < aes.BlockSize; i++ {
			iv = append(iv, byte(rand.Intn(255)))
		}

		flag = decrypt(ciphertext, key, iv, aes.BlockSize)
		if strings.HasPrefix(flag, "ractf") {
			fmt.Printf("flag: %s\n", flag)
			return
		}
	}
}

func main() {
	// Get ciphertext from website.
	resp, err := http.Get("http://193.57.159.27:46796")
	if err != nil {
		log.Fatalf("failed getting ciphertext via http: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed reading http body response: %v", err)
	}

	c := make([]byte, 32)
	_, err = hex.Decode(c, []byte(body))
	if err != nil {
		log.Fatalf("failed decoding ciphertext: %v", err)
	}

	fmt.Printf("got ciphertext %v (len %d) from web...\n", string(body), len(body))
	fmt.Println("trying attack...")
	attack(c)
}

```

Which solves the challenge very quickly:

```shell
 $ go run main.go 
got ciphertext 2b29f405d754c4ad4593f76bcb4e9303ab64b6f85ec2f500a20fa402439ad1db (len 64) from web...
trying attack...
flag: ractf{int3rEst1ng_M4sk_paTt3rn}
```



