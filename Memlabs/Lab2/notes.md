# Author: Panagiotis Fiskilis/Neuro

# Challenge name:MemLabs:Lab2/A New World

## Description: ##

```
One of the clients of our company, lost the access to his system due to an unknown error. He is supposedly a very popular "environmental" activist. As a part of the investigation, he told us that his go to applications are browsers, his password managers etc. We hope that you can dig into this memory dump and find his important stuff and give it back to us.

Note: This challenge is composed of 3 flags.
```

Link for challenge image:

```
https://mega.nz/file/ChoDHaja#1XvuQd49c7-7kgJvPXIEAst-NXi8L3ggwienE1uoZTk
```

# Solution:

We start with the classic recon:

```bash
strings MemoryDump_Lab2.raw |grep -i "Linux"
strings MemoryDump_Lab2.raw |grep "Welcome"
```

Again we have a Windows patient

```bash
volatility -f MemoryDump_Lab2.raw imageinfo
```

We have a Windows 7 image so most common plugins will work

**Note:**

```--profile=Win7SP1x64```

Let's start the enumeration:

```bash
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 pslist
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 pstree
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 netscan
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 hashdump
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab2.raw --profile=Win7SP1x64 mimikatz
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 cmdline # Looks like find me from root me
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 cmdscan
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 consoles
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 filescan
```

Let's sum up the evidence:

- The description talked about browsers and in the <code>pslist,sptree</code> plugins we found chrome
- We also learnt about password managers,etc and in the <code>pslist,pstree,cmdline</code> plugins we find the KeePass application
  - There is also:0x000000003fce1c70      1      0 R--r-d \Device\HarddiskVolume2\Users\Alissa Simpson\Pictures\Password.png
- Finally the description says <code>"environmental" activist</code> as a hint for the <code>envars</code> plugin

Let's start:

```bash
mkdir dump
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fce1c70 -D dump/
stegsolve
```

We use stegsolve on Password.png with the Red plane 7 and the the password:

<code>P4SSw0rd_123</code>

Possibly for the KeePass application

```bash
cat cmdline.log|grep "Kee"
cat filescan.log |grep "Hidden.kdbx"
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D dump/
```

We dump the <code>Hidden.kdbx</code> file and get:

```
file file.None.0xfffffa8001593ba0.dat
file.None.0xfffffa8001593ba0.dat: Keepass password database 2.x KDBX
```

And we get the second flag

**1st Flag**

```bash
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 envars
```

We find a random base64 we decode it and get the first/stage1 flag

**2nd flag**

```bash
cat pslist.log | grep "explorer.exe"
volatility -f MemoryDump_Lab2.raw --profile=Win7SP1x64 iehistory -p 1064,2664
```
Let's download <code>chromehistory</code> plugin from:

```
https://github.com/superponible/volatility-plugins/blob/master/chromehistory.py
```

```bash
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab2.raw --profile=Win7SP1x64 chromehistory
```

From the <code>chromehistory</code> plugin we see that he visited:

```
https://mega.nz/#F!TrgSQQTS!H0ZrUzF0B-ZKNM3y9E76lg
```

There is a file named <code>Important.zip</code>

The zip file has a password and a hint: <code>Password is SHA1(stage-3-FLAG) from Lab-1. Password is in lowercase.</code>

We sha1sum the flag from Lab1

```bash
echo -n "flag{w3ll_3rd_stage_was_easy}" |sha1sum
```

and get:<code>6045dd90029719a039fd2d2ebcca718439dd100a</code>

# Flags:

1. ```flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}```

2. ```flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}```

![much_wow](./Images/wow.jpg)

3. ```flag{oK_So_Now_St4g3_3_is_DoNE!!}```
