CC = gcc
CFLAGS = -Wall -Wextra -I../include
LDFLAGS =

all: minos

minos: main.o purge.o thread.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f minos *.o
