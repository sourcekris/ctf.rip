---
id: 923
title: 'BSides SF CTF 2017 – Flag Receiver - Mobile Reverse Engineering'
date: 2017-02-14T12:37:39+00:00
author: Kris
layout: post
guid: https://ctf.rip/?p=923
permalink: /bsides-sf-ctf-2017-flag-receiver-mobile-reverse-engineering/
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
  - "2320"
image: /images/2017/02/flagstorelogo.png
categories:
  - Write-Ups
---
The second mobile reversing challenge of BSides SF CTF. Slightly harder than the first but only just. Here's the clue and APK:

> **Flag Receiver - 200**
> Here is a simple mobile application that will hand you the flag.. if you ask for it the right way.
> 
> P.S, it is meant to have a blank landing activity  <img src="https://ctf.rip/images/classic-smilies/icon_smile.gif" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />Use string starting with Flag:
> 
> <a href="https://github.com/sourcekris/ctf-solutions/raw/master/re/bsidessf17-flagstore/flagstore.apk" target="_blank">flagstore.apk</a>

Upon examining the code using Jadx-Gui (my new favourite Java decompiler since [SANS Holiday Hack Challenge 2016](http://holiday.ctf.rip/)) we get a feeling right away as to why the MainActivity is blank with no UI. It's expecting interaction via "other" methods. See this code snippet: 
```
public class MainActivity extends Activity {
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(getApplicationContext());
        tv.setText("To-do: UI pending");
        setContentView(tv);
        IntentFilter filter = new IntentFilter();
        filter.addAction("com.flagstore.ctf.INCOMING_INTENT");
        registerReceiver(new Send_to_Activity(), filter, permission._MSG, null);
    }
}
```

It's expecting to receive an "intent" called **com.flagstore.ctf.INCOMING_INTENT**. If it receives the intent it will handle it with the **Send\_to\_Activity** which does a check for the "extras" field msg for a "magic word":
```
public class Send_to_Activity extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        if (intent.getStringExtra("msg").equalsIgnoreCase("OpenSesame")) {
            Log.d("Here", "Intent");
            context.startActivity(new Intent(context, CTFReceiver.class));
            return;
        }
        Toast.makeText(context, "Ah, ah, ah, you didn't say the magic word!", 1).show();
    }
}
``` 

Once that check is passed, the **CTFReceiver** class is called to display a button, which, when clicked will call a JNI library function called **getPhrase()** with three arguments. The return value from **getPhrase()** then gets broadcast as an outgoing intent.

```            
public void onClick(View v) {
    Intent intent = new Intent();
    intent.setAction("com.flagstore.ctf.OUTGOING_INTENT");
    String a = CTFReceiver.this.getResources().getString(R.string.str3) + "fpcMpwfFurWGlWu`uDlUge";
    String b = Utilities.doBoth(CTFReceiver.this.getResources().getString(R.string.passphrase));
    String name = getClass().getName().split("\\.")[4];
    intent.putExtra("msg", CTFReceiver.this.getPhrase(a, b, Utilities.doBoth(name.substring(0, name.length() - 2))));
    CTFReceiver.this.sendBroadcast(intent);
} 
```

The content of this intent is what we assume to be the flag? 

So in order to get the flag it should be as simple as broadcasting an intent with a extras msg field of "OpenSesame". Then somehow receiving that broadcast outgoing intent. We've done this [before last year for Google CTF](https://ctf.rip/googlectf-2016-ill-intentions-mobile-challenge/). So we give this a try.

The first step is to boot an AVD (Android Virtual Device) in the Android SDK. I tend to use my Santoku Linux VM for this it's a handy place to lock all my mobile RE tools away in. If you extract the shared library files from the APK you notice they've kindly provided .so files for ARM and x86 so almost any AVD should work. I use an x86 one for speed.

Once booted, I validate adb can see it and install the APK: 
```
santoku@santokuvm:~/bsides$ adb devices
List of devices attached
emulator-5554  device
santoku@santokuvm:~/bsides$ adb install flagstore.apk 
[100%] /data/local/tmp/flagstore.apk
  pkg: /data/local/tmp/flagstore.apk
Success
```
 
Once the app is installed, I load it and, sure enough, no UI:

<img src="/images/2017/02/flagstore1.png" alt="" width="1345" height="1039" class="alignnone size-full wp-image-925" srcset="/images/2017/02/flagstore1.png 1345w, /images/2017/02/flagstore1-300x232.png 300w, /images/2017/02/flagstore1-768x593.png 768w, /images/2017/02/flagstore1-1024x791.png 1024w" sizes="(max-width: 1345px) 100vw, 1345px" />

I use adb to broadcast the correct intent with the correct msg field: 
```
santoku@santokuvm:~/bsides$ adb shell am broadcast -a com.flagstore.ctf.INCOMING_INTENT --es msg "OpenSesame" 
Broadcasting: Intent { act=com.flagstore.ctf.INCOMING_INTENT (has extras) }
Broadcast completed: result=0
```

Which we predictably get a big "Broadcast" button in-app:

<img src="/images/2017/02/flagstore2.png" alt="" width="1262" height="972" class="alignnone size-full wp-image-926" srcset="/images/2017/02/flagstore2.png 1262w, /images/2017/02/flagstore2-300x231.png 300w, /images/2017/02/flagstore2-768x592.png 768w, /images/2017/02/flagstore2-1024x789.png 1024w" sizes="(max-width: 1262px) 100vw, 1262px" />

Clicking the button dashes our hopes as the app crashes...

<img src="/images/2017/02/flagstore3.png" alt="" width="438" height="239" class="alignnone size-full wp-image-927" srcset="/images/2017/02/flagstore3.png 438w, /images/2017/02/flagstore3-300x164.png 300w" sizes="(max-width: 438px) 100vw, 438px" />

Examining the logs using **adb logcat -d** we see a Java stacktrace of why it failed, apparently the **getPhrase()** JNI library returned invalid characters. Given this is a congratulatory message, perhaps we're close? 
```
02-14 22:41:40.834  1089  1089 F art     : art/runtime/java_vm_ext.cc:410] JNI DETECTED ERROR IN APPLICATION: input is not valid Modified UTF-8: illegal continuation byte 0xd1
02-14 22:41:40.834  1089  1089 F art     : art/runtime/java_vm_ext.cc:410]     string: 'CongratsGoodWorkYouFoundIy^Pp<E0><8C><D1>^P<E1><A4>Ve^Q<A5>̼'
02-14 22:41:40.834  1089  1089 F art     : art/runtime/java_vm_ext.cc:410]     in call to NewStringUTF
02-14 22:41:40.835  1089  1089 F art     : art/runtime/java_vm_ext.cc:410]     from java.lang.String com.flagstore.ctf.flagstore.CTFReceiver.getPhrase(java.lang.String, java.lang.String, java.la
ng.String)
```

Time to break out IDA Pro and examine this shared library function which is stored within the APK file in the lib/x86/ path. We can extract it using APK tool or unzip, like so: 
```
santoku@santokuvm:~/bsides$ apktool d flagstore.apk 
I: Using Apktool 2.1.1 on flagstore.apk
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
santoku@santokuvm:~/bsides$ cd flagstore/lib/x86/
santoku@santokuvm:~/bsides/flagstore/lib/x86$ file libnative-lib.so 
libnative-lib.so: ELF 32-bit LSB  shared object, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=3614bf743b9b0565a9109432080e2b32fd861f30, stripped
```

If we open it in IDA Pro, we can see the getPhrase() function becomes **Java\_com\_flagstore\_ctf\_flagstore\_CTFReceiver\_getPhrase()** and the three arguments get shifted to the right by two places due to the peculiarities of the JNI. So the arguments from the Java code are now **a3**, **a4**, and **a5** in the partial psuedocode below. 
```
int __cdecl Java_com_flagstore_ctf_flagstore_CTFReceiver_getPhrase(int a1, int a2, int a3, int a4, int a5)
{
 
 ...
 
  v21 = '^';
  v20 = 'v}rl';
  v19 = 'PijM';
  v18 = 'e_oB';
  v17 = 'wdAD';
  v16 = 'NEHf';
  *v15 = 'H~A@';
  strncat(v15, v6, 51u);
  strncpy(v23, v7, 76u);
  strncpy(v22, v8, 76u);
  v9 = 0;
  do
  {
    v10 = v15[v9] ^ v23[v9] ^ v22[v9];
    v13[v9] = v10;
    printf("%c\n", v10);
    ++v9;
  }
  while ( v9 != 76 );
  v14 = 0;
  printf("Here is your Reply: %s", v13);
  result = (*(*a1 + 668))(a1, v13);
  v12 = *MK_FP(__GS__, 20);
  return result;
}

```

All this is really doing is, appending a hardcoded string from the library itself to `a3`, and then XOR'ing a3, a4, and a5 together and returning the result. Why isn't it working? I'm not really sure. Time for debugging Davlik with IDA Pro to capture our arguments to `getPhrase()` so we can try doing this XOR operation ourselves.

IDA Pro's Davlik debugger is pretty awesome. It works by simply opening the APK file in IDA Pro and selecting the `classes.dex` file when prompted. You can now set breakpoints withing the Davlik bytecode and it will communicate via ADB to your running Android Virtual Device. 

Since we know we want to check the arguments to `getPhrase()` we find the `CTFReceiver` class in IDA Pro by searching in the functions window:

<img src="/images/2017/02/flagstore4.png" alt="" width="400" height="209" class="alignnone size-full wp-image-929" srcset="/images/2017/02/flagstore4.png 400w, /images/2017/02/flagstore4-300x157.png 300w" sizes="(max-width: 400px) 100vw, 400px" />

If we double click this `CTFReceive$1_onClick`, we can eventually come across the code at offset 0xf46be which is an invoke-virtual call of CTFReceiver.getPhrase(). We right click and set a breakpoint here:

<img src="/images/2017/02/flagstore6.png" alt="" width="1354" height="216" class="alignnone size-full wp-image-931" srcset="/images/2017/02/flagstore6.png 1354w, /images/2017/02/flagstore6-300x48.png 300w, /images/2017/02/flagstore6-768x123.png 768w, /images/2017/02/flagstore6-1024x163.png 1024w" sizes="(max-width: 1354px) 100vw, 1354px" />

Next we start debugging the app. First we need to set the debugger options properly under the _Debugger -> Debugger Options -> Set Specific Options_ menu.

  * Set the path to adb.exe
  * Populate the Package Name and Activity from the AndroidManfiest.xml

It should look something like this when ready. The APK must also already be installed on the AVD. 

<img src="/images/2017/02/flagstore7.png" alt="" width="499" height="383" class="alignnone size-full wp-image-932" srcset="/images/2017/02/flagstore7.png 499w, /images/2017/02/flagstore7-300x230.png 300w" sizes="(max-width: 499px) 100vw, 499px" />

Once ready click Play in IDA Pro to begin the debugger. The app should run on the phone, you may need to click play a few times but you want to get to the point where IDA Pro has a "_Please wait... Running_" popup box with a "_Suspend_" button.

Send the intent to the AVD like we did before. This time I'm doing it from within Windows 
```
C:\Program Files (x86)\Android\android-sdk\platform-tools>adb shell am broadcast -a com.flagstore.ctf.INCOMING_INTENT --es msg "OpenSesame"
Broadcasting: Intent { act=com.flagstore.ctf.INCOMING_INTENT (has extras) }
Broadcast completed: result=0

```

And again, click the Broadcast button in the app. This should allow us to reach our code path where our breakpoint is set. The app wont crash this time instead, the debugger should show the instruction pointer is at our breakpoint.

<img src="/images/2017/02/flagstore8.png" alt="" width="1339" height="410" class="alignnone size-full wp-image-933" srcset="/images/2017/02/flagstore8.png 1339w, /images/2017/02/flagstore8-300x92.png 300w, /images/2017/02/flagstore8-768x235.png 768w, /images/2017/02/flagstore8-1024x314.png 1024w" sizes="(max-width: 1339px) 100vw, 1339px" />

Open the "locals" window to view the local variables in the current context (Debugger -> Debugger Windows -> Locals). We should now see the current state of the three important variables: a, b and c which correspond to our a3, a4, and a5 respectively in the native library psuedocode we saw above. The values are:

  * `a = "wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge"`
  * `b = "NTYxMDdjZTljZTkeYhQwNmRhMDhmMzZkOGNlZTRkMjEhNGUyZDhmNDEtZTVmMhYhODAeMGMyZTU?\n"`
  * `c = "MzIWYmUWYzgyOTFkMmMaMjAzZGFmMDViNDMyODkiODYzMDEyMzMWZmFjMjghNhYtYmIwYTAiYTA?\n"`

Nice. Don't forget, to get the full length value of a we need to prepend that static string from the native library binary. We use the "Strings Window" in IDA Pro to get the correct byte order and full value of that string: "@A~HfHENDAdwBo_eMjiPlr}v^"

So now our 3 values are:

  * `a = "@A~HfHENDAdwBo_eMjiPlr}v^wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge"`
  * `b = "NTYxMDdjZTljZTkeYhQwNmRhMDhmMzZkOGNlZTRkMjEhNGUyZDhmNDEtZTVmMhYhODAeMGMyZTU?\n"`
  * `c = "MzIWYmUWYzgyOTFkMmMaMjAzZGFmMDViNDMyODkiODYzMDEyMzMWZmFjMjghNhYtYmIwYTAiYTA?\n"`

Now we can apply the transformation from the shared library ourselves with a little bit of Python: 
```
a = "@A~HfHENDAdwBo_eMjiPlr}v^"
a = a + "wgHoNi[nvVfptxF@hpsd9DhrM@sz]fpcMpwfFurWGlWu`uDlUge"
b = "NTYxMDdjZTljZTkeYhQwNmRhMDhmMzZkOGNlZTRkMjEhNGUyZDhmNDEtZTVmMhYhODAeMGMyZTU?"
c = "MzIWYmUWYzgyOTFkMmMaMjAzZGFmMDViNDMyODkiODYzMDEyMzMWZmFjMjghNhYtYmIwYTAiYTA?"
out = ""
for i in range(len(a)):
    out += chr(ord(a[i]) ^ ord(b[i]) ^ ord(c[i]))
    
print out

```

Which reveals the flag! 
```
root@kali:~/bsides/re/flagstore# python flagstore.py
CongratsGoodWorkYouFoundItIHopeYouUsedADBFlag:TheseIntentsAreFunAndEasyToUse

```
