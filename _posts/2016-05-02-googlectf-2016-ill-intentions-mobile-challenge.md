---
id: 699
title: 'GoogleCTF 2016 - Ill Intentions - Mobile Challenge'
date: 2016-05-02T11:14:56+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=699
permalink: /googlectf-2016-ill-intentions-mobile-challenge/
themepixels_post_link_target:
  - 'yes'
themepixels_enable_post_header:
  - default
themepixels_enable_post_meta_single:
  - default
themepixels_enable_post_featured_content:
  - default
themepixels_enable_post_categories:
  - default
themepixels_enable_post_tags:
  - default
themepixels_enable_post_share:
  - default
themepixels_enable_post_author_info_box:
  - default
themepixels_enable_related_posts:
  - default
themepixels_enable_post_next_prev_links:
  - default
themepixels_enable_topbar:
  - default
themepixels_enable_sticky_header:
  - default
themepixels_header_layout:
  - default
themepixels_site_layout:
  - default
themepixels_sidebar_position:
  - default
post_views_count:
  - "1665"
image: /images/2016/05/feature.png
categories:
  - Write-Ups
tags:
  - android
  - apk
  - google
---
Here's something new for my blog. I finally tackled a mobile challenge. In the past I basically ignored them or at most, decompiled them to Java source and did a little fiddling. No way, not anymore, time to tackle one!

<img class="alignnone size-full wp-image-700" src="/images/2016/05/clue.png" alt="clue" width="606" height="270" srcset="/images/2016/05/clue.png 606w, /images/2016/05/clue-300x134.png 300w" sizes="(max-width: 606px) 100vw, 606px" />

There is no clue really, just the APK named illintentions.apk. We download and do all the normal APK style things which includes:

  * Unzip the APK, inspect the contents.
  * Inspect the AndroidManifest.xml
  * Convert the classes.dex to a Java archive (JAR) with d2j-dex2jar
  * Unzip the resulting JAR file and inspect the contents.
  * Use apktool on the APK to extract relevant objects from the APK
  * Use a decompiler (jd-gui) to read the Java class source

So let's go through some of this as it's a bit of a minefield for me. The first thing I found was that Kali was pretty crappy for mobile RE but fortunately I had recently found out about [Santoku mobile forensics/RE Linux](https://santoku-linux.com/) distribution. I already had Santoku in my VMWare so I fired that up and built an AVD (Android virtual device?) and started learning about debugging Android.

On Santoku the apktool worked well so I extracted the contents:


```
santoku@santokuvm:~/apktool$ apktool d illintentions.apk 
I: Using Apktool 2.0.0-RC2 on illintentions.apk
I: Loading resource table...
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/santoku/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

```


I browse the output and happened upon the strings.xml, there was a few suspect strings here:


```
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="android.permission._msg">Msg permission for this app</string>
    <string name="app_name">SendAnIntentApplication</string>
    <string name="dev_name">Leetdev</string>
    <string name="flag">Qvq lbh guvax vg jbhyq or gung rnfl?</string>
    <string name="git_user">l33tdev42</string>
    <string name="str1">`wTtqnVfxfLtxKB}YWFqqnXaOIck`</string>
    <string name="str2">IIjsWa}iy</string>
    <string name="str3">TRytfrgooq|F{i-JovFBungFk</string>
    <string name="str4">H0l3kwjo1|+kdl^polr</string>
    <string name="test">Test String for debugging</string>
</resources>

```


I found that "flag" string is just a red-herring being the ROT13 version of `Did you think it would be that easy?`. Very funny! However I did make more use of the `dev_name` string which is short for Developer Name? 

The third (5 point) challenge in the mobile category was `Can you repo me?`. This challenge prodded us to look for online repos where our mobile developer may have stashed the source code for this application. How might that help us? The obvious first step would be to search `leetdev` on Github and we're in luck, there were only two results for that word and they both point us to <a href="https://github.com/l33tdev42/testApp" target="_blank">this testApp repo</a>. When we check the commit history we see this juicy detail. 

<img src="/images/2016/05/oldcommit.png" alt="oldcommit" width="1026" height="723" class="alignnone size-full wp-image-703" srcset="/images/2016/05/oldcommit.png 1026w, /images/2016/05/oldcommit-300x211.png 300w, /images/2016/05/oldcommit-768x541.png 768w, /images/2016/05/oldcommit-1024x722.png 1024w" sizes="(max-width: 1026px) 100vw, 1026px" />

So firstly, **yay 5 points** (this is a 2 for 1 writeup guys!) and secondly, awesome now we have a keystore password. Browsing around the repo we find <a href="https://github.com/l33tdev42/testApp/blob/master/app/leetdev_android.keystore" target="_blank">a keystore file</a>. That might be useful later so I downloaded that too. Great!

Next we don't see immediate use of anything else in the files we extracted so we move to reading the source code in the decompiler so we can see what we're up against. First I notice the `MainActivity` does not do very much, just sets up something called a _Broadcast Receiver_ listening for an _Intent_ called `com.ctf.INCOMING_INTENT`.


```
public class MainActivity extends Activity
{
  public void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    TextView localTextView = new TextView(getApplicationContext());
    localTextView.setText("Select the activity you wish to interact with.To-Do: Add buttons to select activity, for now use Send_to_Activity");
    setContentView(localTextView);
    IntentFilter localIntentFilter = new IntentFilter();
    localIntentFilter.addAction("com.ctf.INCOMING_INTENT");
    registerReceiver(new Send_to_Activity(), localIntentFilter, "ctf.permission._MSG", null);
  }
}
```


I guess now we know where the name "Ill Intentions" comes from. Sweet. So what is a broadcast? It's a way for apps to communicate to each other or even between activities of the same application. When they want to communicate that they want to do something they "Broadcast" their "Intent" to do it. Then other apps/activities that are expecting to receive such "intents" can do something with that information. Intents can also carry data between applications. These data components are called "extras". Sorry Android people if I murdered this explanation. I just made it up based on my experience over the course of 1 day.

So what does our APK do once it receives a broadcast intent? It uses the `Send_to_Activity` class to decide what to do:


```
public class Send_to_Activity extends BroadcastReceiver
{
  public void onReceive(Context paramContext, Intent paramIntent)
  {
    String str = paramIntent.getStringExtra("msg");
    if (str.equalsIgnoreCase("ThisIsTheRealOne"))
    {
      paramContext.startActivity(new Intent(paramContext, ThisIsTheRealOne.class));
      return;
    }
    if (str.equalsIgnoreCase("IsThisTheRealOne"))
    {
      paramContext.startActivity(new Intent(paramContext, IsThisTheRealOne.class));
      return;
    }
    if (str.equalsIgnoreCase("DefinitelyNotThisOne"))
    {
      paramContext.startActivity(new Intent(paramContext, DefinitelyNotThisOne.class));
      return;
    }
    Toast.makeText(paramContext, "Which Activity do you wish to interact with?", 1).show();
  }
}
```


In this class we take the Intent as an argument and then extract the "extras" from the intent. In this case its a "String" extra with the label `msg`. String extras are key value pairs so there are 3 valid key/value pairs for this application:

  * `{msg: "ThisIsTheRealOne"}`
  * `{msg: "IsThisTheRealOne"}`
  * `{msg: "DefinitelyNotThisOne"}`

Each one of these will start an activity with the same name. Let's look at one:


```
public class ThisIsTheRealOne extends Activity
{

...

  public void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    new TextView(this).setText("Activity - This Is The Real One");
    Button localButton = new Button(this);
    localButton.setText("Broadcast Intent");
    setContentView(localButton);
    localButton.setOnClickListener(new View.OnClickListener()
    {
      public void onClick(View paramAnonymousView)
      {
        Intent localIntent = new Intent();
        localIntent.setAction("com.ctf.OUTGOING_INTENT");
        String str1 = ThisIsTheRealOne.this.getResources().getString(2130903046) + "YSmks";
        String str2 = Utilities.doBoth(ThisIsTheRealOne.this.getResources().getString(2130903042));
        String str3 = Utilities.doBoth(getClass().getName());
        localIntent.putExtra("msg", ThisIsTheRealOne.this.orThat(str1, str2, str3));
        ThisIsTheRealOne.this.sendBroadcast(localIntent, "ctf.permission._MSG");
      }
    });
  }
```


This activity sets up a large button which, when clicked, extracts some of the strings from the `strings.xml` and finally builds a new intent of it's own. This new intent has a string "extras" component of it's own which is the return value of a Java native (JNI) function called `orThat`.

This JNI component is a C++ shared library that is compiled and shipped inside the APK in the form of this `libhello-jni.so` file. The challenge authors thankfully shipped versions of this shared libraries for many platforms including ARM and x86. I used IDA Pro to examine this shared library but found that it wasn't a necessary step so I won't detail my findings here.

Anyway, once it builds the intent it goes ahead and broadcasts it. There's a catch though. It only broadcast's this intent to applications that share the custom permission `ctf.permission._MSG`. 

Wow, still with us? Great! Sounds easy right, here was my plan of attack:

  * Run the app
  * Send it a broadcast intent (somehow?)
  * Receive the broadcast reply with a flag in it
  * Have pancakes

Suffice to say I didn't get pancakes very quickly.

Firstly, I started my virtual android device and when it was running I installed the illintentions.apk:


```
santoku@santokuvm:~$ adb devices
List of devices attached
emulator-5554	device

santoku@santokuvm:~$ adb install illintentions.apk 
675 KB/s (51856 bytes in 0.074s)
	pkg: /data/local/tmp/illintentions.apk
Success

```


Next I start the application and send it a broadcast intent of the correct type. I found the following `adb` command can help us run the shell command line on the Android device that can spam this for us:


```
santoku@santokuvm:~$ adb shell am broadcast -a com.ctf.INCOMING_INTENT --es msg "IsThisTheRealOne" 
Broadcasting: Intent { act=com.ctf.INCOMING_INTENT (has extras) }
Broadcast completed: result=0

```


On the Android VM's screen, when I broadcast this intent, I see it changes like this:

<img src="/images/2016/05/intent.png" alt="intent" width="1303" height="642" class="alignnone size-full wp-image-705" srcset="/images/2016/05/intent.png 1303w, /images/2016/05/intent-300x148.png 300w, /images/2016/05/intent-768x378.png 768w, /images/2016/05/intent-1024x505.png 1024w" sizes="(max-width: 1303px) 100vw, 1303px" />

The center of the screen is a giant button, so I click it but I get nothing. Not sure what I expected. I search around for a while looking into "how to receive broadcasts on Android" but I find very little except tutorials on how to build one. After some hair pulling I give up and decide to do exactly that except I cheated and just downloaded one someone else had already built. I used <a href="https://github.com/JimSeker/BroadCastReceiver/tree/master/BroadCastDemo1" target="_blank">this project</a> and placed it into Android studio. I made the following modifications so that it would maybe work:

In `MainActivity` I changed the `ACTIONx` strings to capture the relevant Intents:


```
public static final String ACTION1 = "com.ctf.OUTGOING_INTENT";
	public static final String ACTION2 = "com.ctf.OUTGOING_INTENT";
```


I configured the `MyReceiver` class to extract the "extras" from the received intents and log them to the Android log:


```
String str = intent.getStringExtra("msg");
    Log.v("CTFIncoming", "Received: "+str);
```


Finally I told Android that I wanted to use the permission `ctf.permission._MSG` by adding this link to my AndroidManifest.xml:


```
<uses-permission android:description="@string/android.permission._msg" android:name="ctf.permission._MSG" />
```


I built the APK and installed what is sort of "my first APK". I ran my app, ran the "Ill Intentions" app, sent my broadcast and checked the logs:


```
santoku@santokuvm:~/BroadCastReceiver/BroadCastDemo1$ adb install -g app-release.apk 
2982 KB/s (1118501 bytes in 0.366s)
	pkg: /data/local/tmp/app-release.apk
Success
santoku@santokuvm:~/BroadCastReceiver/BroadCastDemo1$ adb shell am start -n edu.cs4730.broadcastdemo1/.MainActivity
Starting: Intent { cmp=edu.cs4730.broadcastdemo1/.MainActivity }
santoku@santokuvm:~/BroadCastReceiver/BroadCastDemo1$ adb logcat -d | grep CTF
santoku@santokuvm:~/BroadCastReceiver/BroadCastDemo1$ 
```


Nothing! Bah! What's wrong? I check the logs for ideas and find this:


```
05-01 13:27:12.646   234   251 W BroadcastQueue: Permission Denial: broadcasting Intent { act=com.ctf.INCOMING_INTENT flg=0x10 (has extras) } from edu.cs4730.broadcastdemo1 (pid=2002, uid=10058) requires ctf.permission._MSG due to registered receiver BroadcastFilter{bbef783 u0 ReceiverList{3af8e32 1888 com.example.hellojni/10053/u0 remote:664a63d}}
```


Permissions Errors?? But I was sure I gave it the correct permission? I look into it in more detail. Permissions an app use or create are defined in AndroidManifest.xml. Ill Intentions defines these:


```
<permission android:description="@string/android.permission._msg" android:name="ctf.permission._MSG" android:protectionLevel="signature"/>
    <permission android:description="@string/android.permission._msg" android:name="ctf.permission._SEND"/>

```


Hang on, what's an `android protectionLevel` and what is the implication of it being set to "signature". A short google later it dawns on me what I've been forgetting so far:

> "signature" A permission that the system grants **only if the requesting application is signed with the same certificate as the application that declared the permission**. If the certificates match, the system automatically grants the permission without notifying the user or asking for the user's explicit approval.

Thinking back to the 5 pointer from earlier, I realise we have everything we need to sign our APK as "Leetdev". So I rebuild my APK using the `leetdev_android.keystore` we found earlier with <a href="https://github.com/l33tdev42/testApp/commit/5b315cbbfaa2da9502ffae73f283d36d89f92194" target="_blank">the password provided in the old commit</a> we saw earlier.

I repeat the steps from before but this time I see this in the logs:


```
santoku@santokuvm:~/BroadCastReceiver/BroadCastDemo1$ adb logcat -d | grep CTF
05-02 20:56:49.032  1334  1334 V CTFIncoming: Received: Congratulation!YouFoundTheRightActivityHereYouGo-CTF{IDontHaveABadjokeSorry}

```


Woohoo, very satisfying to tackle this as my first serious mobile CTF solution.

Thanks for reading all and thanks to Google for putting on this shindig.