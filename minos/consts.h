#ifndef CONSTS_H
#define CONSTS_H

#define ENTRY_POINT (0x10000)
#ifndef PAGE_SIZE
	// pagesize for asm code
	#define PAGE_SIZE (0x1000)
#endif

#define MAX_ADDR (0x7ffffffff000)

#endif
