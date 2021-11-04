# Author: Panagiotis Fiskilis/Neuro #

## Challenge name: OtterCTF 2018:Forensics: Question 6 – Silly Rick ##

### Description: ###

```
Silly rick always forgets his email's password, so he uses a Stored Password Service online to store his password.He always copy and paste the password so he will not get it wrong. What is Rick's email password?
```

#### Solution: ####

<i>NOTE:</i> Win7SP1x64

The task mentioned that Rick <u>always copy and paste the password</u>, hopefully the password is still on the user's clipboard

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 clipboard |tee clipboard.log
```

![](./Images/Flag6.png)

# Flag: #

<code>CTF{M@il_Pr0vid0rs}</code>
