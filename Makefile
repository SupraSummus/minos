all:
	$(MAKE) -C musl all
	$(MAKE) -C minos all
	$(MAKE) -C programs all

clean:
	$(MAKE) -C musl clean
	$(MAKE) -C minos clean
	$(MAKE) -C programs clean

test: all
	cat programs/hello.asm.bin | minos/minos | ./stdin-eq 'hello world\n'
	cat programs/hello.c.bin | minos/minos | ./stdin-eq 'hello world\n'
	cat programs/thread.c.bin | minos/minos | sort | ./stdin-eq '0\n0\n0\n0\n0\n0\n0\n0\n1\n1\n1\n1\n2\n2\n3\n'
	#test/cnew
