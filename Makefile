all:
	make -C minos all
	make -C internal all

clean:
	make -C minos clean
	make -C internal clean

test: all
	cat internal/hello.asm.bin | minos/minos | ./stdin-eq 'hello world\n'
	cat internal/hello.c.bin | minos/minos | ./stdin-eq 'hello world\n'
	cat internal/thread.c.bin | minos/minos | sort | ./stdin-eq '0\n0\n0\n0\n0\n0\n0\n0\n1\n1\n1\n1\n2\n2\n3\n'
	cat internal/cnew.c.bin | minos/minos
