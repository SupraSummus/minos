CC = cc
CFLAGS = -Wall -Wextra -Imusl/include -Imusl/obj/include -Imusl/arch/x86_64 -mno-tls-direct-seg-refs
LD = ld
LDFLAGS = -static -nostdlib --section-start .init=0
CLDFLAGS = -e __setup_stack_and_start

all: hello.asm.elf hello.c.elf hello.asm.bin hello.c.bin thread.c.elf thread.c.bin

%.bin: %.elf
	cp $< $@; objcopy -O binary $@

%.asm.elf: %.asm.o
	$(LD) $(LDFLAGS) -o $@ $^

%.c.elf: jump_start.asm.o musl/lib/Scrt1.o musl/lib/crti.o %.c.o musl/lib/libc.a musl/lib/crtn.o
	$(LD) $(LDFLAGS) $(CLDFLAGS) -o $@ $^

%.asm.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $^

%.c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f *.o *.elf *.bin
