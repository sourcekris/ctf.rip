---
title: 'TMUCTF 2021: Foreign Student'
date: 2021-09-10T01:00:00+00:00
author: Kris
layout: post
image: /images/2021/tmuctf/fstitle.png
categories:
  - Write-Ups
  - OSINT
---
Fun OSINT challenge that I solved in the last hour of the CTF today. In contrast to many OSINT challenges in CTFs I've done lately where the flag consists of a bunch of sub fields that I spend a lot of time with wrong guesses, this challenge wanted just one thing. An email address. How hard could that be?

#### <a name="foreignstudent"></a>Foreign Student - OSINT - 397 points

This challenge reads:

```
The Foreign Student

Tarbiat Modares University has a foreign student. His name is Zedmondo. He has a 
very shady character. He always walks alone, eats alone, and never talks much. 
There are some rumors about him. Some people say he is a genius sociopath; 
some say he is just too self-involved. But one thing is obvious; he has a secret. 
Once, one of the students heard that he was talking about receiving some 
important documents via a private email. Maybe if we find his email, we can 
learn about his secret.

Note: The flag format is TMUCTF{emailaddress}.

(49 Solves)
```

So we're starting with:

- Tarbiat Modares University (TMU) student
- Zedmondo is the person's first name.

And we're hunting for their `private email` address.

Firstly a bit of Googling leads us to this person's [LinkedIn profile](https://ir.linkedin.com/in/zedmondo-zaberini-203b33206):

![Zedmondo LinkedIn](/images/2021/tmuctf/fslinkedin.PNG)

This doesn't have much but a link to a GitHub profile: https://github.com/ZedZini . Here we find 17 [repositories](https://github.com/ZedZini?tab=repositories) including some created by Zedmondo themselves.

![Zedmondo Github](/images/2021/tmuctf/fsgithub.PNG)

I read through each and every one of the repositories created by Zedmondo himself, I skip over any repo they have forked from elsewhere. When I got to the `secretkey` [repo](https://github.com/ZedZini/secretkey) I paused for a moment. Something about the `README.md`description drew my attention:

```
# secretkey
It is a public key. Not really a secret, right?!
```

Along with the README.md is one file, a [PGP Public key](https://github.com/ZedZini/secretkey/blob/main/0xEB0B6528-pub.asc) with a comment:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xsFNBGAqSQ8BEADZtFG6grS2QP9afsA7SmT85TpxcSmG5LGLmSHKgI47ZwS+dPrO
SzChR0Jt3vI7BjA3WVlxQp94XTqRqFrjtJkS2I3nO3I94jhLu0AwfoiskKzyl+tQ
lexhE31arP/MEYV9VfPSxqR23rm+shIdeKP+9G9XR3ZlrpO0+lP78o7uvRG/7oPR
POw6CAh0eXLpM3P18irvjnH3VekSOg9a/d/7hhyVkRtsH4vAd8O38Z3QB2dWWs5J
... cut ...
=oo5F
-----END PGP PUBLIC KEY BLOCK-----
```

This https://keybase.io/crypto comment made me double take. This is a PGP key that Zedmondo is using for keybase. If they wanted to use email privately they might leverage KeyBase's service. I head over the the link which has the following helpful guide:

![Keybase Howto](/images/2021/tmuctf/fs1.PNG)

I follow it's advice but take the key from GitHub:

```shell
$ curl https://raw.githubusercontent.com/ZedZini/secretkey/main/0xEB0B6528-pub.asc | gpg --import
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  6139  100  6139    0     0   193k      0 --:--:-- --:--:-- --:--:--  193k
gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: key 586DD615EB0B6528: public key "Zedmondo Zaberini (Nothing to say...) <Z3dm0nd0_Z4b3r1n5k1_15_My_R34l_N4m3@zaberini.com>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Which was the right step because Z3dm0nd0_Z4b3r1n5k1_15_My_R34l_N4m3@zaberini.com was the email we we're chasing and the flag was: `TMUCTF{Z3dm0nd0_Z4b3r1n5k1_15_My_R34l_N4m3@zaberini.com}`

Nice fun challenge and glad I solved it with limited time left.
