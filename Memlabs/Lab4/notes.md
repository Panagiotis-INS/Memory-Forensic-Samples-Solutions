# Author:Panagiotis Fiskilis/Neuro

# Challenge name:MemLabs:Lab4/Obsession

## Description: ##

```
My system was recently compromised. The Hacker stole a lot of information but he also deleted a very important file of mine. I have no idea on how to recover it. The only evidence we have, at this point of time is this memory dump. Please help me.

Note: This challenge is composed of only 1 flag.

The flag format for this lab is: inctf{s0me_l33t_Str1ng}
```

Link for the challenge image:

```
https://mega.nz/file/Tx41jC5K#ifdu9DUair0sHncj5QWImJovfxixcAY-gt72mCXmYrE
```

# Solution:

This challenge comes from the inctf

We start with the basic recon:

```bash
strings MemoryDump_Lab4.raw |grep -i "Linux"
strings MemoryDump_Lab4.raw |grep "Welcome"
```

Windows image again

```bash
volatility -f MemoryDump_Lab4.raw imageinfo
```

**Note:**

```--profile=Win7SP1x64```

Let's start the enumeration:

```bash
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 pslist
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 pstree
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 cmdline
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 cmdscan
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 consoles
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 hashdump
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab4.raw --profile=Win7SP1x64 mimikatz |tee mimikatz.log
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 netscan |tee netscan.log
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 filescan |tee filescan.log
```

After all the enumeration from the <code>filescan</code> plugin we find an 'Important.txt' file

```bash
cat filescan.log |grep -i "important"
0x000000003f939720      2      0 RW-rw- \Device\HarddiskVolume2\Users\SlimShady\AppData\Roaming\Microsoft\Windows\Recent\Important.lnk
0x000000003fc398d0     16      0 R--rw- \Device\HarddiskVolume2\Users\SlimShady\Desktop\Important.txt
mkdir dump
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fc398d0 -D dump
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003f939720 -D dump
```

We  only managed to dump the link/shortcut to the important file now let's recover the file

I want to see if I can find anything on the clipboard

```bash
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 clipboard
```

And nothing......

We will use the <code>mftparser</code> plugin

```bash
volatility -f MemoryDump_Lab4.raw --profile=Win7SP1x64 mftparser |tee mftparser.log
cat mftparser.log |grep -A 20 -B 10 "Important.txt"
```

And get the flag

# Flag:

```inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}```
