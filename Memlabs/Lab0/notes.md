# Author: Panagiotis Fiskilis/Neuro

# Challenge name: MemLabs:Lab0/Never Too Late Mister

## Description: ##

```
My friend John is an "environmental" activist and a humanitarian. He hated the ideology of Thanos from the Avengers: Infinity War. He sucks at programming. He used too many variables while writing any program. One day, John gave me a memory dump and asked me to find out what he was doing while he took the dump. Can you figure it out for me?
```

Link with the Challenge file:

```
https://drive.google.com/file/d/1MjMGRiPzweCOdikO3DTaVfbdBK5kyynT/view
```

# Solution:

We start with some basic reconnaissance to find if we have to deal with a Windows or Linux image (possibly Windows):

```bash
strings Challenge.raw |grep -i "Linux"
strings Challenge.raw |grep -i "Welcome"
```
We see that we deal with a Windows image

Let's start with volatility

```bash
volatility -f Challenge.raw imageinfo
```
We have a Windows 7 machine so most common volatility plugins will just work

**NOTE:**

```--profile=Win7SP1x86_23418```

```bash
volatility -f Challenge.raw --profile=Win7SP1x86_23418 pslist
volatility -f Challenge.raw --profile=Win7SP1x86_23418 pstree
volatility -f Challenge.raw --profile=Win7SP1x86_23418 cmdscan
volatility -f Challenge.raw --profile=Win7SP1x86_23418 cmdline
volatility -f Challenge.raw --profile=Win7SP1x86_23418 filescan
```
From the <code>cmdscan</code> we can see some peculiar python2.7 activity

```
CommandProcess: conhost.exe Pid: 2104
CommandHistory: 0x300498 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 1 LastAdded: 0 LastDisplayed: 0
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 @ 0x2f43c0: C:\Python27\python.exe C:\Users\hello\Desktop\demon.py.txt
Cmd #12 @ 0x2d0039: ???
Cmd #19 @ 0x300030: ???
Cmd #22 @ 0xff818488: ?
Cmd #25 @ 0xff818488: ?
Cmd #36 @ 0x2d00c4: /?0?-???-
Cmd #37 @ 0x2fd058: 0?-????
```

We try to find the <code>demon.py.txt</code> file from filescan and dump it with <code>dump files</code>

```bash
cat filescan.log |grep "demon.py.txt"
```
We get the offset

```
0x000000003d4d1dc8      1      0 R--rw- \Device\HarddiskVolume2\Users\hello\Desktop\demon.py.txt
```

dump time:

```bash
mkdir dump
volatility -f Challenge.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003d4d1dc8 -D dump/
```

The file is empty so we have to dig deeper

```bash
volatility -f Challenge.raw --profile=Win7SP1x86_23418 consoles
```

From the <code>consoles</code> plugin we get a hash:

```
335d366f5d6031767631707f
```

Let's try and correlate it to some envars

```bash
volatility -f Challenge.raw --profile=Win7SP1x86_23418 envars
cat envars.log |grep "335d366f5d6031767631707f"
```

Still nothing.

Let's try <code>mimikatz</code> and <code>hasdump</code>

```bash
volatility --plugin=/opt/volatility/volatility/plugins -f Challenge.raw --profile=Win7SP1x86_23418 mimikatz |tee mimikatz.log
volatility -f Challenge.raw --profile=Win7SP1x86_23418 hashdump
```

We find some hashes and we start cracking with john

```bash
john --format=NT hashdump.log
```

And get the flag

# Flag:
```flag{you_are_good_but1_4m_b3tt3r}```
