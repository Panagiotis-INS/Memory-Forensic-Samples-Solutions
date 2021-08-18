import sys
from base64 import *
ct="am1gd2V4M20wXGs3b2U="
deced=(b64decode(ct)).decode('utf-8')
a = ''.join(chr(ord(i)^3) for i in deced)
print(a)
