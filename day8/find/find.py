from pwn import *

p = remote('34.64.159.111', 12780)


for i in range(1000):
	try :
		p.recvuntil('Num : ')
	except:
		p.interactive()

	a = p.recvline().replace('\n','').split()
	print(a)
	m = a[0]
	for i in a:
		m = max(i,m)

	p.sendline(m)

p.interactive()