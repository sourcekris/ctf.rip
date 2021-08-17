---
title: 'Really Awesome CTF 2021: Teleport'
date: 2021-08-16T05:00:00+00:00
author: Kris
layout: post
image: /images/2021/ractf/militarygradet.png
categories:
  - Write-Ups
  - Reversing
---
Really Awesome CTF is back in 2021 with some very interesting challenges. This RSFPWS challenge category was particularly fun as it was a 3d game client hacking adventure in 3 parts. I was able to solve all of them and here's a writeup of the one that had the fewest solvers "Teleport".

#### RSFPWS Teleport - Misc - 350 Points

This challenge reads:

```
This game i'm playing is fun! There's this cube i'm trying to get into in the game though, and I just can't figure it out. Maybe you can help...?

NOTE: You'll have to trigger a Unity Collider for the flag to show.

(27 solves)
```

With the challenge we get these files:

* `windows_client.zip`
* `linux_client.zip`

These files when unzipped are a 3D game client written in Unity that drop you into a basic 3d multi-player world with other players running around represented as capsule shapes:

![Game world](/images/2021/ractf/teleport1.PNG)

Inside the game world we find a grey box with a message that reads `This box is hollow. Find a way inside to get the flag.`

![Hollow box](/images/2021/ractf/teleport1a.PNG)

Other than that there are two other cubes in the world, the first one will deduct 5 health from the player (you start with 100) and the other one will instakill the player.

![Danger Cubes](/images/2021/ractf/teleport1b.PNG)

These cubes are part of the previous challenges, one of which is called `Invulnerable` which you had to cheat in the game to prevent the deadly cube from killing you. 

I learned during that challenge that when you die in the game it respawns you back at the start. An idea struck me during that solution; What if I could convince the game to respawn me inside the cube?

So first I needed to learn where the respawn code was. I decided to use [Cheat Engine](https://www.cheatengine.org/) and do this live in game. I figured that the easiest route to that was understanding where the player health code was in memory. Since we know that respawning resets our player health to 100 I might be able to figure out something from there.

To locate player health in memory I loaded Cheat Engine, attached it to the running game process and searched RAM for all locations that stored the integer `100`. This found almost 3000 locations.

![Cheat Engine: Search for 100](/images/2021/ractf/teleport2.PNG)

Next I ran myself into the damaging cube and took `5` damage reducing my health to `95` and ran another search for values in RAM that changed from `100 -> 95`

![Cube damage](/images/2021/ractf/teleport3.PNG)

This successfully located the exact address of the player health in memory. I stored that address in my list.

![Found player health address](/images/2021/ractf/teleport4.PNG)

I then used the Cheat Engine debugger to monitor what calling addresses write to that memory location:

![Player health writers](/images/2021/ractf/teleport5.PNG)

I then jumped into the killer cube and looked at the debugger output and found only 2 addresses that write here. The second one on the list was a specific write to set it to 0x64 which is 100 in decimal. 

![Reset player health to 100](/images/2021/ractf/teleport6.PNG)

This looks exactly like what we wanted. Lets look at what the code in the disassembler looks like there. We can right click the code and take ourselves directly to the disassembly right in Cheat Engine

![Go to disassembler](/images/2021/ractf/teleport7.PNG)

This is the code we see.

![Disassembly](/images/2021/ractf/teleport8.PNG)

Observant among us might notice that, right before that there are three other interesting instructions which are placing zero onto the stack twice and calling into another subroutine. Hmmm...

![Interesting instructions](/images/2021/ractf/teleport9.PNG)

If we right click and follow that call we see the subroutine sets up a call to a very interesting function called `UnityEngine.Transform::set_position_Injected()` which takes a vector argument. `Set position` sounds a lot like exactly what we want.

![Call to set_position_Injected](/images/2021/ractf/teleport10.PNG)

At this point I hypothesised that the two instructions placing 0x00 on the stack were actually placing the `X` and `Y` co-ordinates of the spawn location`(x=0, y=0)`and passing those directly into the Unity API. So if I could modify those coordinates I might be able to respawn anywhere on the map. Cheat Engine is great, it lets you modify instructions in RAM so thats what I did. I right clicked and `Assembled new instructions` here:

![Assembling new instructions](/images/2021/ractf/teleport11.PNG)

I experimented a little and found I needed only a negative X offset. These numbers are stored as float types and I needed to teleport to the coordinates`x=-14.0, y=0` . As a float, `-14` is `0xc1600000` so I changed one instruction  as follows:

![Setting respawn location](/images/2021/ractf/teleport12.PNG)

And the disassembler confirmed the instructions looked right:

![Looks ready to go](/images/2021/ractf/teleport13.PNG)

So then I threw myself into the killed cube and died. When I respawned, sure enough I was inside the grey cube and could read the flag:

![Flag](/images/2021/ractf/teleport15.PNG)

Fun challenge and its great to play around with tools like Cheat Engine which is a fantastically powerful tool.



