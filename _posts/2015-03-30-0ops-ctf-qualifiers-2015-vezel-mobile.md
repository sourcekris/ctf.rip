---
id: 242
title: '0ops CTF Qualifiers 2015 - Vezel - Mobile Challenge'
date: 2015-03-30T07:08:00+00:00
author: Kris
layout: post
guid: http://ctf.rip/?p=242
permalink: /0ops-ctf-qualifiers-2015-vezel-mobile/
post_views_count:
  - "872"
image: /images/2015/03/vezel-1.png
categories:
  - Uncategorized
  - Write-Ups
tags:
  - "2015"
---
I haven't ever done a mobile challenge before so I thought I'd give this a try as it was one of the earliest challenges made available on the 0ctf site when it began. The clue was only this:

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/03/vezel-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/vezel-1.png" height="85" width="400" /></a>
</div>

So firstly we download the file, it's an Android APK which is really just a ZIP file package of all the necessary goodness for a Android device to install

```
 -rwxrw-rw- 1 root root 907004 Mar 30 11:00 vezel.apk  
 root@mankrik:~/0ctf/vezel# file vezel.apk   
 vezel.apk: Zip archive data, at least v2.0 to extract  
```

So let's just unzip it and examine the contents really quick, this challenge is only worth 100 points so maybe it's easy.

```
root@mankrik:~/0ctf/vezel/zip# unzip -qq vezel.apk   
root@mankrik:~/0ctf/vezel/zip# ls -la  
total 3136  
drwxr-xr-x 4 root root  4096 Mar 30 11:04 .  
drwxr-xr-x 3 root root  4096 Mar 30 11:03 ..  
-rw-r--r-- 1 root root  1804 Mar 27 11:29 AndroidManifest.xml  
-rw-r--r-- 1 root root 2135512 Mar 27 11:29 classes.dex  
drwxr-xr-x 2 root root  4096 Mar 30 11:04 META-INF  
drwxr-xr-x 24 root root  4096 Mar 30 11:04 res  
-rw-r--r-- 1 root root 142212 Mar 27 11:29 resources.arsc  
-rwxr--r-- 1 root root 907004 Mar 30 11:03 vezel.apk  
```

Cool, all the normal Android stuff I guess. I don't know much about Android files so lets just strings everything and look for a flag!

```
root@mankrik:~/0ctf/vezel/zip# strings `find .` | grep -i 0ctf  
0ctf0  
0ctf0  
0ctf  
0CTF{  
root@mankrik:~/0ctf/vezel/zip# grep -i 0ctf `find . -type f`  
Binary file ./META-INF/CERT.RSA matches  
Binary file ./classes.dex matches  
```

Ok the RSA cert and the classes.dex file match but not trivially, as in, I don't see a flag just lying about!

Next step is more research, I found that a classes.dex file is a Dalvik Executable which contains compiled Dalvik bytecode. These can usually be pulled apart by things like dexdump and apktool to get to the Dalvik code which, when you look at it looks like someone took all the worst bits of Java and jammed it into assembly code, and then turned a blender on. But worse. I decompiled that anyway and tried to read the Dalvik byte code. Using that method I did figure out basically what it was doing but it was a horrible way to go about it so I will save you the time.

The proper way to do this is to convert the Dalvik executable (classes.dex) into Java binaries using a tool called dex2jar (there are others, but I used dex2jar for this).

```
root@mankrik:~/0ctf/vezel/zip# dex2jar classes.dex   
this cmd is deprecated, use the d2j-dex2jar if possible  
dex2jar version: translator-0.0.9.15  
dex2jar classes.dex -> classes_dex2jar.jar  
Done.  

root@mankrik:~/0ctf/vezel/zip# ls -la  
total 4292  
drwxr-xr-x 4 root root  4096 Mar 30 13:46 .  
drwxr-xr-x 3 root root  4096 Mar 30 11:03 ..  
-rw-r--r-- 1 root root  1804 Mar 27 11:29 AndroidManifest.xml  
-rw-r--r-- 1 root root 2135512 Mar 27 11:29 classes.dex  
-rw-r--r-- 1 root root 1179969 Mar 30 13:46 classes_dex2jar.jar  
drwxr-xr-x 2 root root  4096 Mar 30 11:04 META-INF  
drwxr-xr-x 24 root root  4096 Mar 30 11:04 res  
-rw-r--r-- 1 root root 142212 Mar 27 11:29 resources.arsc  
-rwxr--r-- 1 root root 907004 Mar 30 11:03 vezel.apk  
```

This results in a classes_dex2jar.jar file which, as all .jar files are, is just a .zip file containing the compiled Java classes. You can just unzip that file to get at the Java binaries:

```
root@mankrik:~/0ctf/vezel/zip# file classes_dex2jar.jar   
classes_dex2jar.jar: Zip archive data, at least v2.0 to extract  
root@mankrik:~/0ctf/vezel/zip# unzip -qq classes_dex2jar.jar   
root@mankrik:~/0ctf/vezel/zip# ls -la  
total 4300  
drwxr-xr-x 6 root root  4096 Mar 30 14:29 .  
drwxr-xr-x 3 root root  4096 Mar 30 11:03 ..  
drwxr-xr-x 3 root root  4096 Mar 30 13:46 <b>android  </b>
-rw-r--r-- 1 root root  1804 Mar 27 11:29 AndroidManifest.xml  
-rw-r--r-- 1 root root 2135512 Mar 27 11:29 classes.dex  
-rw-r--r-- 1 root root 1179969 Mar 30 13:46 classes_dex2jar.jar  
drwxr-xr-x 3 root root  4096 Mar 30 13:46 com  
drwxr-xr-x 2 root root  4096 Mar 30 11:04 META-INF  
drwxr-xr-x 24 root root  4096 Mar 30 11:04 res  
-rw-r--r-- 1 root root 142212 Mar 27 11:29 resources.arsc  
-rwxr--r-- 1 root root 907004 Mar 30 11:03 vezel.apk  
```

The Java binaries for the Vezel program live in the com/ctf/vezel/ folder after extraction from the .jar file:

```
root@mankrik:~/0ctf/vezel/zip# cd com/  
root@mankrik:~/0ctf/vezel/zip/com# cd ctf  
root@mankrik:~/0ctf/vezel/zip/com/ctf# cd vezel/  
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# ls -la  
total 104  
drwxr-xr-x 2 root root 4096 Mar 30 13:46 .  
drwxr-xr-x 3 root root 4096 Mar 30 13:46 ..  
-rw-r--r-- 1 root root  415 Mar 30 13:46 BuildConfig.class  
-rw-r--r-- 1 root root 2579 Mar 30 13:46 MainActivity.class  
-rw-r--r-- 1 root root  453 Mar 30 13:46 R$anim.class  
-rw-r--r-- 1 root root 7191 Mar 30 13:46 R$attr.class  
-rw-r--r-- 1 root root  582 Mar 30 13:46 R$bool.class  
-rw-r--r-- 1 root root  765 Mar 30 13:46 R.class  
-rw-r--r-- 1 root root 3373 Mar 30 13:46 R$color.class  
-rw-r--r-- 1 root root 2714 Mar 30 13:46 R$dimen.class  
-rw-r--r-- 1 root root 2976 Mar 30 13:46 R$drawable.class  
-rw-r--r-- 1 root root 2633 Mar 30 13:46 R$id.class  
-rw-r--r-- 1 root root  266 Mar 30 13:46 R$integer.class  
-rw-r--r-- 1 root root 1472 Mar 30 13:46 R$layout.class  
-rw-r--r-- 1 root root  247 Mar 30 13:46 R$menu.class  
-rw-r--r-- 1 root root  253 Mar 30 13:46 R$mipmap.class  
-rw-r--r-- 1 root root 1258 Mar 30 13:46 R$string.class  
-rw-r--r-- 1 root root 15495 Mar 30 13:46 R$styleable.class  
-rw-r--r-- 1 root root 14911 Mar 30 13:46 R$style.class  
```

And these files are listed as Java binaries by file:

```
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# file MainActivity.class   
MainActivity.class: compiled Java class data, version 50.0 (Java 1.6)  
```

Ok so I want to check what this program is doing, but I don't want to emulate it and I don't have Android SDK. I could get all those things but first there's a simpler way. A Java decompiler.

I looked around very briefly and found <a href="http://jd.benow.ca/" target="_blank">a nice Linux supporting one called JD-GUI at jd.benow.ca</a>. I grabbed that and installed it quickly. It needs 32bit GTK libraries so I made sure those were installed on my Kali VM also...

```
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# wget -q http://jd.benow.ca/jd-gui/downloads/jd-gui-0.3.5.linux.i686.tar.gz  
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# apt-get install ia32-libs-gtk  
Reading package lists... Done  
Building dependency tree      
Reading state information... Done  
ia32-libs-gtk is already the newest version.  
0 upgraded, 0 newly installed, 0 to remove and 27 not upgraded.  
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# tar -zxf jd-gui-0.3.5.linux.i686.tar.gz   
root@mankrik:~/0ctf/vezel/zip/com/ctf/vezel# ./jd-gui   
```

When it fires up, I opened the MainActivity.class file because it seemed.... pretty ... main .... I guess... The decompiler GUI is really nice and easy and fast to move around in. The Java code is very easy to read versus the Dalvik byte code!

<div class="separator" style="clear: both; text-align: center;">
  <a href="/images/2015/03/vezel2-1.png" imageanchor="1" style="margin-left: 1em; margin-right: 1em;"><img border="0" src="/images/2015/03/vezel2-1.png" height="456" width="640" /></a>
</div>

The main crux of the program comes once the user clicks "Confirm" which is a button in the Android app. The button fires up this function:

```
public void confirm(View paramView)  
{  
 String str1 = String.valueOf(getSig(getPackageName()));  
 String str2 = getCrc();  
 if (("0CTF{" + str1 + str2 + "}").equals(this.et.getText().toString()))  
 {  
  Toast.makeText(this, "Yes!", 0).show();  
  return;  
 }  
 Toast.makeText(this, "0ops!", 0).show();  
}  
```

Which is a hell of a lot like a flag string. So yay, we got a strong lead: The flag consists of the strings

  * "0CTF{"
  * str1 - a string made up of the return value of getSig(getPackageName())
  * str2 - a string made up of the return value of getCrc()
  * "}"

Ok so we need to find the return values of these functions to build the flag. Let's focus on str1 first.

This string is returned by this function:

```
private int getSig(String paramString)  
{  
 PackageManager localPackageManager = getPackageManager();  
 try  
 {  
  int i = localPackageManager.getPackageInfo(paramString, 64).signatures[0].toCharsString().hashCode();  
  return i;  
 }  
 catch (Exception localException)  
 {  
  localException.printStackTrace();  
 }  
 return 0;  
}  
```

So it uses the localPackageManager to getPackageInfo about the hashcode of the signature of the package. Brilliant. WTF is that... This needed quite a bit of research but I was able to retrieve the package signature via two methods.

  1. Installed an APK tool inside an Android emulator that had the vezel.apk installed. There are so many APK extractors/tools/etc on the android store but almost all of them are horrible applications. Only one of them was able to give me a package signature and I can't remember which of the 10 or so apps it was. Suffice to say this option was a bit of a waste of time.
  2. Derive it from the APK itself. This needs more research.

I went with option 1 for a while, got a signature (turned out to be correct but I didnt know at the time) but it wasn't what I used to beat the challenge. I <a href="http://androidcracking.blogspot.com.au/2010/12/getting-apk-signature-outside-of.html" target="_blank">stumbled across this link</a> in my research which turned out to be the right idea. What the function returns is the hashCode() of the getPackageInfo().signatures[0].toCharsString().


```
In the Java programming language, every class implicitly or explicitly provides a hashCode() 
method, which digests the data stored in an instance of the class into a single hash value 
(a 32-bit signed integer).  
```

Great so we combine our knowledge of what a hashcode is and the source code from the link above which parses APK file certificates, specifically to get package signatures to get this part of the challenge done.

We use this Java code (snippet below) to get the signature hashcode. Notice it is the same Java code from the link except the hashcode calculation is changed to be the one we need and some of the extraneous output we don't need was removed:

```
   if (certs != null && certs.length > 0) {  
   final int N = certs.length;  
   for (int i = 0; i < N; i++) {  
    String charSig = new String(toChars(certs[i].getEncoded()));  
    System.out.println("Cert#: " + i + " Type:" + certs[i].getType()  
   <b> + "nstr1 is: " + charSig.hashCode());  </b>
   }  
   } else {  
   System.err.println("Package has no certificates; ignoring!");  
   return;  
   }  
```

When we run it we get this output:

 ```
root@mankrik:~/0ctf/vezel# javac Main.java   
root@mankrik:~/0ctf/vezel# java Main   
Usage: java -jar GetAndroidSig.jar <apk/jar>  
root@mankrik:~/0ctf/vezel# java Main vezel.apk   
vezel.apk  
classes.dex 1189242199  
Cert#: 0 Type:X.509  
<b>str1 is: -183971537</b>  
```


Great so thats the first half of the flag, now let's look at str2. This is returned by the following function:

```
 private String getCrc()  
  {  
   try  
   {  
    String str = String.valueOf(new ZipFile(getApplicationContext().getPackageCodePath()).getEntry("classes.dex").getCrc());  
    return str;  
   }  
   catch (Exception localException)  
   {  
    localException.printStackTrace();  
   }  
   return "";  
  }  
```

So this just looks through it's own APK file looking for the file classes.dex and then returns the CRC value of that file. Too easy.

I wanted to do this a few ways but I settled on strictly doing this in Java so my results aligned exactly with the Vezel program. There are a lot of Java tutorials on the net about doing exactly that so all I needed to do was integrate it into my existing Java code from before.

I did this and my final result was this code:

```
 import java.io.IOException;  
 import java.io.InputStream;  
 import java.lang.ref.WeakReference;  
 import java.security.Signature;  
 import java.security.cert.*;  
 import java.util.Enumeration;  
 import java.util.jar.JarEntry;  
 import java.util.jar.JarFile;  
 import java.util.logging.Level;  
 import java.util.logging.Logger;  
 import java.util.zip.ZipEntry;  
 import java.util.zip.ZipFile;  
 public class Main {  
  private static final Object mSync = new Object();  
  private static WeakReference<byte[]> mReadBuffer;  
  public static void main(String[] args) {  
  if (args.length < 1) {  
   System.out.println("Usage: java -jar GetAndroidSig.jar <apk/jar>");  
   System.exit(-1);  
  }  
  long mycrc = 0;  
  System.out.println(args[0]);  
  String mArchiveSourcePath = args[0];  
  try {  
  ZipFile zipFile = new ZipFile(args[0]);  
  Enumeration o = zipFile.entries();  
  while(o.hasMoreElements())   
  {  
      ZipEntry entry = (ZipEntry)o.nextElement();  
      String entryName = entry.getName();  
      long crc = entry.getCrc();  
      if(entryName.startsWith("classes.dex")) {  
           System.out.print(entryName + " " + crc + "n");  
           mycrc = crc;       
     }  
  }  
  zipFile.close();  
  }  
  catch(IOException ioe)  
  {  
      System.out.println("Error opening Zip."+ioe);  
  }  
  WeakReference<byte[]> readBufferRef;  
  byte[] readBuffer = null;  
  synchronized (mSync) {  
   readBufferRef = mReadBuffer;  
   if (readBufferRef != null) {  
   mReadBuffer = null;  
   readBuffer = readBufferRef.get();  
   }  
   if (readBuffer == null) {  
   readBuffer = new byte[8192];  
   readBufferRef = new WeakReference<byte[]>(readBuffer);  
   }  
  }  
  try {  
   JarFile jarFile = new JarFile(mArchiveSourcePath);  
   java.security.cert.Certificate[] certs = null;  
   Enumeration entries = jarFile.entries();  
   while (entries.hasMoreElements()) {  
   JarEntry je = (JarEntry) entries.nextElement();  
   if (je.isDirectory()) {  
    continue;  
   }  
   if (je.getName().startsWith("META-INF/")) {  
    continue;  
   }  
   java.security.cert.Certificate[] localCerts = loadCertificates(jarFile, je, readBuffer);  
   if (false) {  
    System.out.println("File " + mArchiveSourcePath + " entry " + je.getName()  
      + ": certs=" + certs + " ("  
      + (certs != null ? certs.length : 0) + ")");  
   }  
   if (localCerts == null) {  
    System.err.println("Package has no certificates at entry "  
      + je.getName() + "; ignoring!");  
    jarFile.close();  
    return;  
   } else if (certs == null) {  
    certs = localCerts;  
   } else {  
    // Ensure all certificates match.  
    for (int i = 0; i < certs.length; i++) {  
    boolean found = false;  
    for (int j = 0; j < localCerts.length; j++) {  
     if (certs[i] != null  
       && certs[i].equals(localCerts[j])) {  
     found = true;  
     break;  
     }  
    }  
    if (!found || certs.length != localCerts.length) {  
     System.err.println("Package has mismatched certificates at entry "  
       + je.getName() + "; ignoring!");  
     jarFile.close();  
     return; // false  
    }  
    }  
   }  
   }  
   jarFile.close();  
   synchronized (mSync) {  
   mReadBuffer = readBufferRef;  
   }  
   if (certs != null && certs.length > 0) {  
   final int N = certs.length;  
   for (int i = 0; i < N; i++) {  
    String charSig = new String(toChars(certs[i].getEncoded()));  
    System.out.println("Cert#: " + i + " Type:" + certs[i].getType()  
    + "nYour flag sir: 0CTF{" + charSig.hashCode()  
     + mycrc  
     + "}");  
   }  
   } else {  
   System.err.println("Package has no certificates; ignoring!");  
   return;  
   }  
  } catch (CertificateEncodingException ex) {  
   Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);  
  } catch (IOException e) {  
   System.err.println("Exception reading " + mArchiveSourcePath + "n" + e);  
   return;  
  } catch (RuntimeException e) {  
   System.err.println("Exception reading " + mArchiveSourcePath + "n" + e);  
   return;  
  }  
  }  
  private static char[] toChars(byte[] mSignature) {  
   byte[] sig = mSignature;  
   final int N = sig.length;  
   final int N2 = N*2;  
   char[] text = new char[N2];  
   for (int j=0; j<N; j++) {  
    byte v = sig[j];  
    int d = (v>>4)&0xf;  
    text[j*2] = (char)(d >= 10 ? ('a' + d - 10) : ('0' + d));  
    d = v&0xf;  
    text[j*2+1] = (char)(d >= 10 ? ('a' + d - 10) : ('0' + d));  
   }  
   return text;  
   }  
  private static java.security.cert.Certificate[] loadCertificates(JarFile jarFile, JarEntry je, byte[] readBuffer) {  
  try {  
   // We must read the stream for the JarEntry to retrieve  
   // its certificates.  
   InputStream is = jarFile.getInputStream(je);  
   while (is.read(readBuffer, 0, readBuffer.length) != -1) {  
   // not using  
   }  
   is.close();  
   return (java.security.cert.Certificate[]) (je != null ? je.getCertificates() : null);  
  } catch (IOException e) {  
   System.err.println("Exception reading " + je.getName() + " in "  
     + jarFile.getName() + ": " + e);  
  }  
  return null;  
  }  
 }  
```

Which I ran and which gave me this output.

```
root@mankrik:~/0ctf/vezel# javac Main.java   
root@mankrik:~/0ctf/vezel# java Main vezel.apk   
vezel.apk  
classes.dex 1189242199  
Cert#: 0 Type:X.509  
<b> Your flag sir: 0CTF{-1839715371189242199}  </b>
```

I was initially upset that the hashcode was a negative number. The flag looked pretty dumb to me. I would have preferred the hex value of these but oh well. We submitted the flag and it was correct.

Writeup: Dacat