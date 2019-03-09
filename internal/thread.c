#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>

void * thread_main(void * arg) {
	printf("%lld\n", (long long)arg);
	if ((long long)arg > 0) {
		pthread_t threads[2];
		if (
			pthread_create(&(threads[0]), NULL, thread_main, arg - 1) != 0 ||
			pthread_create(&(threads[1]), NULL, thread_main, arg - 1) != 0
		) {
			err(EXIT_FAILURE, "failed to create thread");
		}
		if (
			pthread_join(threads[0], NULL) != 0 ||
			pthread_join(threads[1], NULL) != 0
		) {
			err(EXIT_FAILURE, "failed to join the thread");
		}
	}
	return NULL;
}

int main(void) {
	thread_main((void *)3);
	return EXIT_SUCCESS;
}
