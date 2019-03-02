#include <unistd.h>
#include <stdlib.h>

int main() {
	write(STDOUT_FILENO, "hello world\n", 12);
	return EXIT_SUCCESS;
}
