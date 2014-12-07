/* vim: set noet ts=8 sw=8 : */

/* cc -static -O0 ralloc-example.c -o ralloc-example */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define __NR_ralloc  321
#define __NR_rfree   322

void *ralloc(unsigned long size)
{
	return (void *) syscall(__NR_ralloc, size, "10.0.2.2", 8700);
}

int rfree(void *addr)
{
	return syscall(__NR_rfree, (unsigned long) addr);
}

int main(int argc, char **argv)
{
	char *p, *addr;

	addr = ralloc(0x10000);

	if (!addr) {
		printf("could not allocate memory\n");
		return 1;
	}

	memset(addr, 1, 0x10000);
	memset(addr+0x1000, 2, 0x1000);
	memset(addr+0x2000, 3, 0x1000);
	memset(addr+0x5000, 6, 0x1000);

	addr[0] = 12;
	addr[0x2fff] = 21;

	for (p = addr+1; p < addr+0x1000; ++p)
		assert(*p == 1);
	for (p = addr+0x1000; p < addr+0x2000; ++p)
		assert(*p == 2);

	assert(addr[0x2fff] = 21);

	addr[0x2fff] = 3;

	for (p = addr+0x2000; p < addr+0x3000; ++p)
		assert(*p == 3);
	for (p = addr+0x8888; p < addr+0x8888+0x6666; ++p)
		assert(*p == 1);
	for (p = addr+0x5000; p < addr+0x6000; ++p)
		assert(*p == 6);

	assert(addr[0] == 12);

	rfree(addr);
	printf("OK\n");
	return 0;
}
