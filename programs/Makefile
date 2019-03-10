MUSLDIR = ../musl/

CC = cc
CFLAGS = -Wall -Wextra \
	-I$(MUSLDIR)include/ \
	-I$(MUSLDIR)obj/include/ \
	-I$(MUSLDIR)arch/generic/ \
	-I$(MUSLDIR)arch/x86_64/ \
	-I../include/
LD = ld
LDFLAGS = -static -nostdlib --section-start .init=0x10000
CLDFLAGS = -e __setup_stack_and_start

all: hello.asm.bin hello.c.bin thread.c.bin cnew.c.bin

%.bin: %.elf
	cp $< $@; objcopy -O binary -R .note.gnu.property $@

%.asm.elf: %.asm.o
	$(LD) $(LDFLAGS) -o $@ $^

%.c.elf: jump_start.asm.o $(MUSLDIR)lib/Scrt1.o $(MUSLDIR)lib/crti.o %.c.o libminos.c.o $(MUSLDIR)lib/libc.a $(MUSLDIR)lib/crtn.o
	$(LD) $(LDFLAGS) $(CLDFLAGS) -o $@ $^

%.asm.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $^

%.c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f *.o *.elf *.bin
