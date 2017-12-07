---
id: 229
title: 'Defcon CTF 2015 - Access Control - Reverse Engineering - 1 Point challenge'
date: 2015-05-19T05:54:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=229
permalink: /defcon-ctf-2015-access-control-reverse/
post_views_count:
  - "514"
image: /images/2015/05/1-7.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
Another one pointer, this time in the RE category. For this one I am going to give an example of solving something "just enough" to get the points so you can move on to the next flag. I've read other writeups about this and notice some people reversed very precisely to get a perfectly working exploit. I, on the other hand, was willing to cut corners!

The clue for this one is again brief,

_**accesscontrol**_
  
_  
_ 
  
_It's all about who you know and what you want. access\_control\_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me:17069_
  
_  
_ 
  
With the clue is a binary file which you can find <a href="https://github.com/smokeleeteveryday/CTF_WRITEUPS/blob/master/2015/DEFCONCTF/reversing/accesscontrol/challenge/client" target="_blank">archived here</a>.

First up I just connected to the server with netcat to see what it looked like:

```
root@mankrik:~/defcon/access# nc access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me 17069
connection ID: ZP]j[OD6|t9IMa


*** Welcome to the ACME data retrieval service ***
what version is your client?
```

Ok neat, no idea what it wants yet but check out that "Connection ID". I bet that's useful later right?

Let's examine the binary:

```
root@mankrik:~/defcon/access# file client_197010ce28dffd35bf00ffc56e3aeb9f 
client_197010ce28dffd35bf00ffc56e3aeb9f: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xcf260fd5e12b4ccf789d77ac706a049d83df4f05, stripped


root@mankrik:~/defcon/access# strings client_197010ce28dffd35bf00ffc56e3aeb9f 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
socket
exit
htons
sprintf
perror
connect
strncpy
puts
__stack_chk_fail
stdin
fgets
send
strstr
recv
inet_addr
__libc_start_main
GLIBC_2.4
GLIBC_2.0
PTRhP
D$tf
[^_]
VUUU
UWVS
[^_]
need IP
Could not create socket
Socket created
connect failed. Error
Enter message : 
hack the world
nope...%s
what version is your client?
version 3.11.54
hello...who is this?
grumpy
grumpy
enter user password
hello %s, what would you like to do?
list users
deadwood
print key
the key is:
challenge:
answer?
recv failed
<< %s
connection ID:
connection ID: 
challenge: 
Send failed
;*2$",
```

Standard stuff. There's a version string "version 3.11.54" so that's needed to answer the question to the server I bet.

Let's try running the client...

```
root@mankrik:~/defcon/access# ./client_197010ce28dffd35bf00ffc56e3aeb9f 
need IP

root@mankrik:~/defcon/access# host access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me
access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me has address 54.84.39.118

root@mankrik:~/defcon/access# ./client_197010ce28dffd35bf00ffc56e3aeb9f 54.84.39.118
Socket created
Enter message : go?
nope...go?
```

Ok time for more reversing... In IDA we find this tidbit quickly:

```
          printf("Enter message : ");
          fgets(byte_804B080, 1000, stdin);
          v6 = 16;
          v7 = byte_804B080;
          v8 = "hack the worldn";
          do
          {
            if ( !v6 )
              break;
            v4 = *v7 < *v8;
            v5 = *v7++ == *v8++;
            --v6;
          }
          while ( v5 );
          if ( (!v4 && !v5) != v4 )
          {
            printf("nope...%sn", byte_804B080);
            result = -1;
            goto LABEL_54;
          }
```

So the "message" is probably "hack the world"? Back to the client:

```
root@mankrik:~/defcon/access# ./client_197010ce28dffd35bf00ffc56e3aeb9f 54.84.39.118
Socket created
Enter message : hack the world
<< connection ID: m:to/#$w'x6DYy


*** Welcome to the ACME data retrieval service ***
what version is your client?

<< hello...who is this?
<< 

<< enter user password

<< hello grumpy, what would you like to do?

<< grumpy
<< 
mrvito
gynophage
selir
jymbolia
sirgoon
duchess
deadwood
hello grumpy, what would you like to do?

<< the key is not accessible from this account. your administrator has been notified.
<< 
hello grumpy, what would you like to do?

hello



^C
```

Alrighty, thats cool. We get logged in, we see a user list, and we see theres some kind of key although we don't have privs to get the key yet. The client is not interactive either, so we can't try more stuff. It's looking like we need to build our own client... So we need to reverse how this one works so we can do that.

Let's look at the network layer to watch what it sends:

<div class="separator" style="clear: both; text-align: center;">
  <a href="http://4.bp.blogspot.com/-farQWvMVui0/VVnT6tf064I/AAAAAAAAAK4/wjX7e7NC9rw/s1600/1.PNG" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" height="282" src="/images/2015/05/1-7.png" width="400" /></a>
</div>


</div>


  Ok all normal, we got:
</div>


</div>

  * the version number string (as expected)
  * the username
  * the two commands "list users" and "print key".
  * What's up with the password though. Is that the user password?




  I capture a few connections and the response to the password prompt changes each time. So this is somehow ciphered. So if we're going to write a client, we need to encrypt the password correctly...
</div>


</div>


  Back to IDA! We find this code naming two functions "sub_8048EAB" and "sub_8048F67":
</div>


</div>

```
          sub_8048CFA("enter user password");
          if ( sub_8048CFA("enter user password") )
          {
            v28 = ;
            v29 = ;
            sub_8048EAB("grumpy", &v28);
            sub_8048F67(&v28);
            HIBYTE(v29) = ;
            sprintf(&v28, "%sn", &v28);
            sub_8048E3E(&v28);
          }
```

sub\_8048EAB XORs the first 5 bytes of the given plaintext password with a key. The key is based on the connection ID (dword\_804B04C) and an offset into the connection ID string is chosen based on (dword_804BC80 % 3):

```
char *__cdecl sub_8048EAB(int a1, int a2)
{
  char *result; // eax@1
  int v3; // ebx@4
  signed int i; // [sp+2Ch] [bp-1Ch]@1
  char dest[5]; // [sp+37h] [bp-11h]@1
  int v6; // [sp+3Ch] [bp-Ch]@1

  v6 = *MK_FP(__GS__, 20);
  result = strncpy(dest, &::dest[dword_804B04C] + dword_804BC80 % 3, 5u);
  for ( i = ; i <= 4; ++i )
  {
    result = (a2 + i);
    *(a2 + i) = dest[i] ^ *(a1 + i);
  }
  v3 = *MK_FP(__GS__, 20) ^ v6;
  return result;
}
```

So what do we know, in plain language:

  * The ciphered password string really can only be 5 characters long
  * The key (connection ID) is public and given to us at the start of the connection
  * The offset of the connection ID where the key begins is possible to calculate by deriving how dword_804BC80 is generated then computing it modulo 3.

The first two are easy, the third item requires more reversing. When you think about it, what is the point of reversing more here? So we know exactly the offset for the key? Does it matter? Let's try something in the server with netcat:

```
root@mankrik:~/defcon/access# nc access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me 17069
connection ID: )Y<AH{"5mgnZU8


*** Welcome to the ACME data retrieval service ***
what version is your client?
version 3.11.54
hello...who is this?
grumpy
enter user password
nottherightpassword
wrong password, fat fingers
hello...who is this?
grumpy
enter user password
grumpy
wrong password, fat fingers
hello...who is this?
```
  
  <p>
    So the server, for 1 connection ID gives us multiple attempts at the password. So since the correct offset modulo 3 can only ever be 0,1,2,3 we have only a maximum of 4 password attempts before we will get the right password.
  </p>
  
  <p>
    Long story short, I didn't bother reversing that bit and moved on to the second function that operates on the password before sending it:
  </p>
  
  <p>
    This function is simpler, it just parses the output of the first function looking for characters <= 31 and if found, adds 32 to them. If the character == 127 it does other things.
  </p>
  
 ```
 root@mankrik:~/defcon/access# nc access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me 17069
connection ID: )Y<AH{"5mgnZU8


*** Welcome to the ACME data retrieval service ***
what version is your client?
version 3.11.54
hello...who is this?
grumpy
enter user password
nottherightpassword
wrong password, fat fingers
hello...who is this?
grumpy
enter user password
grumpy
wrong password, fat fingers
hello...who is this?
``` 

Again I got lazy here, I don't care about the edge case single character == 127 so I completely ignored implementing that!

For both of these "optimizations" I made up front, I paid a price though. We'll see that later

So now I have the makings of a client that can login, let's try it:

```
root@mankrik:~/defcon/access# ./m1.py 
[+] Opening connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me on port 17069: Done
[+] Connection ID: /Sn]9;INS1Y~*P
[+] Sending username: grumpy
[+] Sending password attempt 0...
[+] Retrying...
[+] Sending username: grumpy
[+] Sending password attempt 1...
[+] Login success with offset 1
[*] Switching to interactive mode
$ list users
grumpy
mrvito
gynophage
selir
jymbolia
sirgoon
duchess
deadwood
hello grumpy, what would you like to do?
$  
```

Cool it works! And now I'm interactive I can try more commands. Except there aren't any! Poop. Well let's try these other users eh? Hope they all picked silly passwords like Mr Grumpy did.

  
```
root@mankrik:~/defcon/access# ./m1.py 
[+] Opening connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me on port 17069: Done
[+] Connection ID: vB_Ydfnq}/m|"L
[+] Sending username: sirgoon
[+] Sending password attempt 0...
[+] Retrying...
[+] Sending username: sirgoon
[+] Sending password attempt 1...
[+] Retrying...
[+] Sending username: sirgoon
[+] Sending password attempt 2...
[+] Retrying...
[+] Sending username: sirgoon
[+] Sending password attempt 3...
[+] Login success with offset 3
[*] Switching to interactive mode
$ print key
the key is not accessible from this account. your administrator has been notified.
hello sirgoon, what would you like to do?
```
  
  <p>
    Ok fine. We go on this way for a while. Finally we get to the user "duchess":
  </p>
  
  <p>
    <!-- HTML generated using hilite.me -->
  </p>
  
```
[+] Opening connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me on port 17069: Done
[+] Connection ID: Xo/Wug;}erP'PQ
[+] Sending username: duchess
[+] Sending password attempt 0...
[+] Retrying...
[+] Sending username: duchess
[+] Sending password attempt 1...
[+] Retrying...
[+] Sending username: duchess
[+] Sending password attempt 2...
[+] Retrying...
[+] Sending username: duchess
[+] Sending password attempt 3...
[+] Login success with offset 3
[*] Switching to interactive mode
$ print key
challenge: _(&:5
answer?
$ nope
you are not worthy
hello...who is this?
```
  
  <p>
    Ok neat. The user duchess can get the key, but first they must answer the challenge!
  </p>
  
  <p>
    The challenge looks to be a 5 byte string, encrypted in the same way our password was when it was sent over the wire.
  </p>
  
  <p>
    If we get the answer wrong we get dropped, but we don't lose our connection. We just have to relogin. That's pretty important because we keep our connection ID.
  </p>
  
  <p>
    So this is the code I came up with as a "test" client to solve the challenge. I didn't continue coding past this point because my first attempt got me the flag:
  </p>
  
  ```
#!/usr/bin/python

from pwn import *

HOST='access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me'
PORT=17069

username = 'duchess'
password = username[:5]
version = 'version 3.11.54'

def cipherpw(connectionid, password, offset):
 connectionid = connectionid[offset:]
 pl = list(password)
 cl = list(connectionid)
 result = ""
 for p in range(len(pl)):
  result += chr(ord(pl[p]) ^ ord(cl[p]))

 a1 = list(result)
 r2 = ""
 for i in range(5):
  if ord(a1[i]) <= 31:
   a1[i] = chr(ord(a1[i]) + 32)
  r2 += a1[i]
 return r2

conn = remote(HOST,PORT)

connectionid = conn.recvline().split(" ")[2]
print "[+] Connection ID: " + connectionid,
conn.recvlines(4) # banner
conn.sendline(version)

o = 
while True:
 conn.recvline()  # login prompt
 print "[+] Sending username: " + username
 conn.sendline(username)
 conn.recvline()  # password prompt
 print "[+] Sending password attempt " + str(o) + "..."
 conn.sendline(cipherpw(connectionid,password,o))
 result = conn.recvline()
 if 'what would you like to do' in result:
  print "[+] Login success with offset " + str(o)
  break
 else:
  print "[+] Retrying..."
 o += 1

conn.sendline('print key')
challenge = conn.recvline().split(" ")[1]
print "[+] Challenge received: " + challenge
conn.recvline() # answer prompt
for i in range(8):
 answer = cipherpw(connectionid, challenge, i)
 print "[+] Possible answer: " + answer

print "[+] Challenge response: " + answer
conn.sendline(answer)
print "[+] Result: " + conn.recvline()
conn.close()
  ```
  
  <p>
    Here's what it looks like when run.
  </p>

```
[+] Opening connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me on port 17069: Done
[+] Connection ID: J2*mO()uQAMp7d
[+] Sending username: duchess
[+] Sending password attempt 0...
[+] Retrying...
[+] Sending username: duchess
[+] Sending password attempt 1...
[+] Login success with offset 1
[+] Challenge received: +]J=4

[+] Possible answer: ao`P{
[+] Possible answer: 9w'r<
[+] Possible answer: !0%5=
[+] Possible answer: F2b4A
[+] Possible answer: ducHe
[+] Possible answer: #t?lu
[+] Possible answer: "(;|y
[+] Possible answer: ^,+pD
[+] Challenge response: ^,+pD
[+] Result: the key is: The only easy day was yesterday. 44564

[*] Closed connection to access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me port 17069
```

To be fair, this client is not complete. The logic which selects the real correct answer is not in place. It was only by luck that my solution finds the correct answer some times. I have rerun the exploit about 10 times now and it solved it correctly 3 times out of those 10 attempts.

Since we're not about perfect execution, just about CTF, we leave it open ended but happy we solved it in time.