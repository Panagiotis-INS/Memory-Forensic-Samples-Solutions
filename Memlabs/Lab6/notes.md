# Author:Panagiotis Fiskilis/Neuro

# Challenge name:MemLabs:Lab6/The Reckoning

## Description: ##

```
We received this memory dump from the Intelligence Bureau Department. They say this evidence might hold some secrets of the underworld gangster David Benjamin. This memory dump was taken from one of his workers whom the FBI busted earlier this week. Your job is to go through the memory dump and see if you can figure something out. FBI also says that David communicated with his workers via the internet so that might be a good place to start.

Note: This challenge is composed of 1 flag split into 2 parts.

The flag format for this lab is: inctf{s0me_l33t_Str1ng}
```

Link for challenge image:

```
https://mega.nz/file/C0pjUKxI#LnedePAfsJvFgD-Uaa4-f1Tu0kl5bFDzW6Mn2Ng6pnM
```

# Solution:

This challenge comes from inctf

We start with basic recon

```bash
strings MemoryDump_Lab6.raw|grep -i "Linux"
strings MemoryDump_Lab6.raw|grep "Welcome"
volatility -f MemoryDump_Lab6.raw imageinfo
```

**Note:**

```--profile=Win7SP1x64```

Let's enumerate:

```bash
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 pslist
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 pstree
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 cmdline
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 cmdscan
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 consoles
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 hashdump |tee hashdump.log
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab6.raw --profile=Win7SP1x64 mimikatz| tee mimikatz.log
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 netscan |tee netscan.log
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 filescan |tee filescan.log
```

The description mention something about starting on the internet from the <code>pslist,pstree</code> plugins we see that the 'gangster' used chrome so we will use the <code>chromehistory</code> plugin.

Also from the <code>cmdline</code> plugin we find this:

```
WinRAR.exe pid:   3716
Command line : "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
```

```bash
cat filescan.log |grep "flag.rar"
0x000000005fcfc4b0     16      0 R--rwd \Device\HarddiskVolume2\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar
mkdir dump
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000005fcfc4b0 -D dump
mv file.None.0xfffffa800138d750.dat file.None.0xfffffa800138d750.dat.rar
```

We found the second part of the flag but we need a password for the rar file

Let's investigate the browser:

```bash
volatility --plugin=/opt/volatility/volatility/plugins -f MemoryDump_Lab6.raw --profile=Win7SP1x64 chromehistory |tee chromehistory.log
```

From <code>chromehistory</code> we found a pastebin link:

```
https://pastebin.com/RSGSi1hk
```

With a google docks link with a Lorem ipsum psudo text

Inside the the psudo text we find a link for mega.nz:

```
https://mega.nz/#!SrxQxYTQ
```

But we don't have the decryption key for the link

We know that the key is inside the dump so we start grepping:

```bash
strings MemoryDump_Lab6.raw |grep "Mega Drive Key" |grep "IS"
```

After some search we find the key and dowload the first part of the flag

Mega Drive Key:zyWxCjCYYSEMA-hZe552qWVXiPwa5TecODbjnsscMIU

Let's find the password for the second part of the flag inside the rar file

```bash
volatility -f MemoryDump_Lab6.raw --profile=Win7SP1x64 memdump -p 3716 -D dump
strings 3716.dmp |grep -i "passw" |head
```

rar password:easypeasyvirus

And we get the last part

# Flag:

- Part1:```inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_```
- Part2:```aN_Am4zINg_!_i_gU3Ss???_}```

Full flag:```inctf{thi5_cH4LL3Ng3_!s_g0nn4_b3_?_aN_Am4zINg_!_i_gU3Ss???_}```
