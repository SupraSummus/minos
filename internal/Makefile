CC = cc
CFLAGS = -Wall -Wextra
LD = ld
LDFLAGS = -static -nostdlib --section-start .init=0
CLDFLAGS = -e __setup_stack_and_start

all: hello.asm.elf hello.c.elf hello.asm.bin hello.c.bin

%.bin: %.elf
	cp $< $@; objcopy -O binary $@

%.asm.elf: %.asm.o
	$(LD) $(LDFLAGS) -o $@ $^

%.c.elf: jump_start.asm.o musl/lib/Scrt1.o %.c.o musl/lib/libc.a
	$(LD) $(LDFLAGS) $(CLDFLAGS) -o $@ $^

%.asm.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $^

%.c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f *.o *.elf *.bin
