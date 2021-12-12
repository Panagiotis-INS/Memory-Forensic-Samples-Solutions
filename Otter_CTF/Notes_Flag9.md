# Author: Panagiotis Fiskilis/Neuro #

## Challenge name: OtterCTF 2018:Forensics: Question 9 – Path to Glory 2 ##

### Description: ###

```
Continue the search after the way the malware got in.
```

#### Solution: ####

<i>NOTE:</i> Win7SP1x64

Now we need to find the broser history of Rick:

```bash
cat filescan.log |grep -i "history"
cat filescan.log |grep -i "history" |head -1
volatility -f ./OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q 0x000000007d45dcc0 -D dump
strings dump/file.None.0xfffffa801a5193d0.dat
strings dump/file.None.0xfffffa801a5193d0.dat |grep -B 10 "download.exe.torrent"
strings dump/file.None.0xfffffa801a5193d0.dat |grep -B 10 "download.exe.torrent" |grep "mail.com" #Found email rickopicko@mail.com
strings ./OtterCTF.vmem |grep "mail.com" |grep "rickopicko@mail.com"
```
