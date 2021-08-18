# Author: Panagiotis Fiskilis/Neuro

# Challenge name:MemLabs:Lab3/The Evil's Den

## Description: ##

```
A malicious script encrypted a very secret piece of information I had on my system. Can you recover the information for me please?

Note-1: This challenge is composed of only 1 flag. The flag split into 2 parts.

Note-2: You'll need the first half of the flag to get the second.
```

Link for challenge image:

```
https://mega.nz/file/2ohlTAzL#1T5iGzhUWdn88zS1yrDJA06yUouZxC-VstzXFSRuzVg
```

# Solution:

This challenge comes from Inctf

```bash
strings MemoryDump_Lab3.raw|grep -i "Linux"
strings MemoryDump_Lab3.raw|grep "Welcome"
```
We have Windows again

```bash
volatility -f MemoryDump_Lab3.raw imageinfo
```

**Note:**

```--profile=Win7SP1x86_23418```

Let's start the enumeration:

```bash
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 pslist
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 pstree
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 cmdline
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 cmdscan
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 consoles
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 hashdump
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 mimikatz
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 filescan |tee filescan.log
```
From <code>pslist,pstree,cmdline</code> plugins we find out that something went 'wrong' the notepad process

Let's start grepping and dumping

```bash
cat cmdline.log |grep -i "notepad"
cat filescan.log |grep "evilscript.py\|vip.txt"
mkdir dump
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D dump/
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e727e50 -D dump/
```

We dump the 2 files and get a malicious python script that xors the vip.txt file

So I wrote the <code>rev_mal.py</code> script to reverse the effects of the script (I could also use cyber chef but I was lazy)

```python3
import sys
from base64 import *
ct="am1gd2V4M20wXGs3b2U="
deced=(b64decode(ct)).decode('utf-8')
a = ''.join(chr(ord(i)^3) for i in deced)
print(a)
```

After the execution of the script we get the first part of the flag.

In the challenge description we have a hint talking about:

- Steghide
- Need the first half of the flag to get the second

So I set my mind into finding an image from <code>filescan</code> plugin and use <code>steghide</code> with the first part of the flag as the password to get the last part

After some trial and error I found it:

```bash
cat filescan.log |grep -i "jpeg"
0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\suspision1.jpeg
volatility -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x0000000004f34148 -D dump/
mv file.None.0x843fcf38.dat file.None.0x843fcf38.dat.jpeg
steghide extract -sf file.None.0x843fcf38.dat.jpeg
cat secret\ text
```

And got the second part

# Flag:

Part1:```inctf{0n3_h4lf```

Part2:```_1s_n0t_3n0ugh}```

Full flag:```inctf{0n3_h4lf_1s_n0t_3n0ugh}```
