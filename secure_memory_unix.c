/*
  secure_memory_unix.c - secure memory implementation for UNIX systems
  (c) 2004-2005 Zeljko Vrba <zvrba@globalnet.hr>

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include "secure_random.h"
#include "secure_memory.h"
#include "exceptions.h"

static char rcsid[] = "$Id: secure_memory_unix.c 1 2005-11-13 20:23:40Z zvrba $";

#ifndef MAP_ANON
#define MAP_ANON	MAP_ANONYMOUS
#endif

struct secure_memory *G_secure_memory;
unsigned int G_secure_memory_size;
static long G_pagesize;

static int allocate_secure_memory(void)
{
	int retval = 1;

	if((G_pagesize = sysconf(_SC_PAGESIZE)) < 0) {
		perror("sysconf");
		Throw(system_call_failed_exception);
	}

	G_secure_memory_size = 16*G_pagesize;
	G_secure_memory = mmap(NULL, G_secure_memory_size, PROT_READ | PROT_WRITE,
			MAP_ANON | MAP_PRIVATE, -1, 0);
	if(G_secure_memory == MAP_FAILED) {
		perror("mmap");
		Throw(out_of_memory_exception);
	}

	/* This is to guarantee segfault on buffer overrun. */
	if(mprotect((char*)G_secure_memory + 15*G_pagesize, G_pagesize,
				PROT_NONE) < 0) {
		perror("mprotect");
		Throw(system_call_failed_exception);
	}

#ifdef DISABLE_MLOCKALL
	/*
	 * On some OSes (most notably some Linux 2.6 kernels versions), some
	 * libraries try to allocate too much space and then crash (because
	 * the allocation would exceed the maximum allowed number of locked
	 * pages). Which results in a crash.
	 *
	 * However, this gives lower security since the stack pages are not
	 * locked in memory.
	 */
	if(mlock(G_secure_memory, G_secure_memory_size) < 0) {
		perror("mlock");
		retval = 0;
	}
#else
	if(mlockall(MCL_FUTURE) < 0) {
		perror("mlockall");
		retval = 0;
	}
#endif

	return retval;
}

static void drop_privileges(void)
{
	if(seteuid(getuid()) < 0) {
		perror("seteuid");
		Throw(system_call_failed_exception);
	}
}

static int disable_core_file(void)
{
	int retval = 1;
	struct rlimit rlim = { 0, 0 };

	if(setrlimit(RLIMIT_CORE, &rlim) < 0) {
		perror("setrlimit");
		retval = 0;
	}

	return retval;
}

int secure_memory_init(void)
{
	int success;

	success  = allocate_secure_memory();
	drop_privileges();
	success &= disable_core_file();

	if(!success)
		fprintf(stderr, "WARNING: using insecure memory.\n");

	return success;
}

void secure_memory_destroy(void)
{
	printf("INFO: zeroing memory.\n");
	memset(G_secure_memory, 0, G_secure_memory_size - G_pagesize);
}
