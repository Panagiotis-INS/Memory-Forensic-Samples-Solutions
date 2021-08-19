# Author: Panagiotis Fiskilis/Neuro

# Challenge name:13 Cubed Mini Memory CTF

## Description: ##

```
The CTF has 4 Flags/Questions in the form of a md5 hash
```

Link for challenge image:

```
https://drive.google.com/drive/folders/1E-i2RTUBXBGUd_Xz0k67kFOpHcr6WX8J
```

# Solution:

We know from the creator that this is a Windows image

The task also tells us that the profile is:

```--profile=Win10x64_17134```

```bash
volatility -f memdump.mem imageinfo
volatility -f memdump.mem --profile=Win10x64_17134 pslist |tee pslist.log
volatility -f memdump.mem --profile=Win10x64_17134 pstree |tee pstree.log
cat pstree.log |grep "svchost.exe"
cat pstree.log |grep "svchost.exe" |grep "4824"
```

We get 8 suspicious processes:

- 0xffffc20c6ddad580:svchost.exe                   8560   4824     10      0 2018-08-01 20:13:10 UTC+0000
- 0xffffc20c6ab70080:svchost.exe                   8852   4824      0 ------ 2018-08-01 19:59:49 UTC+0000
- 0xffffc20c6d5ac340:svchost.exe.ex                5528   4824      0 ------ 2018-08-01 19:52:20 UTC+0000
- 0xffffc20c6ab2b580:svchost.exe.ex                6176   4824      0 ------ 2018-08-01 19:52:19 UTC+0000
- 0xffffc20c6d6fc580:svchost.exe                  10012   4824      0 ------ 2018-08-01 19:49:19 UTC+0000
- 0xffffc20c6dbc5340:svchost.exe                   7852   4824      0 ------ 2018-08-01 19:49:21 UTC+0000
- 0xffffc20c6d82e080:svchost.exe                   1404   4824      0 ------ 2018-08-01 19:54:55 UTC+0000
- 0xffffc20c6d99b580:svchost.exe.ex                8140   4824      0 ------ 2018-08-01 19:52:16 UTC+0000

For timestamp reasons the best candidate is the process with pid:8560

**1st Flag**

```bash
echo -n "8560" |md5sum
```

Let's dump it's memory and get the second flag:

```bash
mkdir dump
volatility -f memdump.mem --profile=Win10x64_17134 memdump -p 8560 -D dump
strings 8560.dmp |less
strings 8560.dmp |grep "="
```

M2ExOTY5N2YyOTA5NWJjMjg5YTk2ZTQ1MDQ2Nzk2ODA=

**2nd Flag**

```bash
volatility -f memdump.mem --profile=Win10x64_17134 netscan |tee netscan.log
volatility -f memdump.mem --profile=Win10x64_17134 hivelist|grep -i "network"
volatility -f memdump.mem --profile=Win10x64_17134 hivelist |tee hivelist.log
0xffffd38985eb3000 0x0000000105738000 \SystemRoot\System32\Config\SOFTWARE
volatility -f memdump.mem --profile=Win10x64_17134 printkey -o 0xffffd38985eb3000
volatility -f memdump.mem --profile=Win10x64_17134 printkey -o 0xffffd38985eb3000 -K "Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
volatility -f memdump.mem --profile=Win10x64_17134 printkey -o 0xffffd38985eb3000 -K "Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\010103000F0000F0080000000F0000F0E3E937A4D0CD0A314266D2986CB7DED5D8B43B828FEEDCEFFD6DE7141DC1D15D"
```

The bytes for the Flag are:

```
00 50 56 fe d8 07 ->00-50-56-FE-D8-07
```
Do an md5sum and get the Flags

**3rd Flag**

Let's go file hunting:

```bash
volatility -f memdump.mem --profile=Win10x64_17134 mftparser |tee mftparser.log
cat mftparser.log |grep -i "13cubed"
```

And we get the final flag:

```
2018-08-01 19:29:27 UTC+0000 2018-08-01 19:29:27 UTC+0000   2018-08-01 19:29:27 UTC+0000   2018-08-01 19:29:27 UTC+0000   Users\CTF\AppData\Local\Packages\MICROS~1.MIC\AC\#!001\MICROS~1\Cache\AHF2COV9\13cubed[1].htm
```

**4th Flag**

# Flags/Questions:

- Question #1
Find the running rogue (malicious) process. The flag is the MD5 hash of its PID.

<b>Flag1:bc05ca60f2f0d67d0525f41d1d8f8717</b>

- Question #2
Find the running rogue (malicious) process and dump its memory to disk. You'll find the 32-character flag within that process's memory.

<b>Flag2:3a19697f29095bc289a96e4504679680</b>

- Question #3
What is the MAC address of this machine's default gateway? The flag is the MD5 hash of that MAC address in uppercase with dashes (-) as delimiters. Example: 01-00-A4-FB-AF-C2.

<b>Flag3:6496d43b622a2ad241b4d08699320f4e</b>

- Question #4
Find the full path of the browser cache created when an analyst visited "www.13cubed.com." The path will begin with "Users\." Convert the path to uppercase. The flag is the MD5 hash of that string.

<b>Flag4:b5bdd048030cd26ab2d0e7f7e351224d</b>
