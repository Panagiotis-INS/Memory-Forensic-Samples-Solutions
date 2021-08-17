# Author:Panagiotis Fiskilis/Neuro

# Challenge name: MemLabs:Lab1/Beginner's Luck

## Description: ##

```
My sister's computer crashed. We were very fortunate to recover this memory dump. Your job is get all her important files from the system. From what we remember, we suddenly saw a black window pop up with some thing being executed. When the crash happened, she was trying to draw something. Thats all we remember from the time of crash.

Note: This challenge is composed of 3 flags.
```

Link for challenge image:

```
https://mega.nz/file/6l4BhKIb#l8ATZoliB_ULlvlkESwkPiXAETJEF7p91Gf9CWuQI70
```

# Solution:

We start with our standard reconnaissance to find out if we deal with a Windows or Linux image (probably Windows again)

```bash
strings MemoryDump_Lab1.raw |grep -i "Linux"
strings MemoryDump_Lab1.raw |grep "Welcome"
```

It's Windows again so let's start with volatility

```bash
volatility -f MemoryDump_Lab1.raw imageinfo
```

It's Windows 7 so most common plugins will work

**NOTE:**

```--profile=Win7SP1x64```

Enumeration time:

```bash
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 pslist
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 pstree
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 cmdscan
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 cmdline
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 consoles #has flag
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 netscan
```

**1st Flag**

After the basic enumeration we get the first flag from the <code>consoles</code> plugin

From a base64, when decoded we get the flag

When I did the enumeration <code>pslist,pstree</code>

I found a weird/suspicious process: <code>TCPSVCS.EXE</code> with pid:1416

The challenge description said something about black windows that's how most users describe shells

So I suspect that the attack somehow got a shell from the <code>TCPSVCS.EXE</code> which is a windows process that gives shell access

```bash
cat netscan.log |grep -i "TCPSVCS"
```

And I was probably right. Note that this is an image from a personal computer and not a server so it should not listen to that many connections

Let's dump the memory from the suspicious process

```bash
mkdir dump
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 memdump -p 1416 -D dump/
```
But we found nothing.

The description talked about:

- shells
- important files
- draw

We only found the shell so we need the files and the mspaint process and the important files from the <code>filescan</code> plugin.

```bash
cat pslist.log |grep -i "paint"
```
We found mspaint:

```
0xfffffa80022bab30 mspaint.exe            2424    604      6      128      1      0 2019-12-11 14:35:14 UTC+0000
```
Let's dump it's memory

```bash
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 memdump -p 2424 -D dump/
cd dump/
2424.dmp 2424.raw
```

**2nd flag**

I found a very interesting article on how to get the flag:

```
https://w00tsec.blogspot.com/2015/02/extracting-raw-pictures-from-memory.html
```
I also found the required plugin to open raw images:

```
http://www.darktable.org/
```

After a small fight with the app I found the second flag

Now let's find the important files:

```bash
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 filescan |tee filescan.log
cat filescan.log |grep -i "important"
```

We get:

- 0x000000003fa3ebc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
- 0x000000003fac3bc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar
- 0x000000003fb48bc0      1      0 R--r-- \Device\HarddiskVolume2\Users\Alissa Simpson\Documents\Important.rar

```bash
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fa3ebc0 -D dump
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fac3bc0 -D dump
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb48bc0 -D dump
```

We get the rar file and of course it has a password.

```bash
rar2john file.None.0xfffffa8001034450.dat.rar >hash.txt
volatility -f MemoryDump_Lab1.raw --profile=Win7SP1x64 hashdump |tee hashdump.log
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab1.raw --profile=Win7SP1x64 mimikatz
```
**3rd flag**

I finally read the unrar hint that the password for the rar is <code>Password is NTLM hash(in uppercase) of Alissa's account passwd.</code>

So rar passwd:<code>F4FF64C8BAAC57D22F22EDC681055BA6</code>

# Flags:

1. ```ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0= -> flag{th1s_1s_th3_1st_st4g3!!}```

2. ```flag{G00d_BoY_good_girL}```

3. ```flag{w3ll_3rd_stage_was_easy}```
