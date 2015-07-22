/*
  secure_memory.h - definitions of data structures residing in secure memory
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
#ifndef SECURE_MEMORY_H__
#define SECURE_MEMORY_H__

/**
 * @file
 * This defines the contents of the secure memory.
 */

/** Maximum size of random state. */
#define	MAX_RANDOM_STATE_SIZE	8192

struct secure_memory {
	unsigned char random_state[MAX_RANDOM_STATE_SIZE];
	unsigned int  random_numbers[64];
	char          passphrase[1];
};

extern struct secure_memory *G_secure_memory;
extern unsigned int G_secure_memory_size;

/**
 * Set up a chunk of secure memory.
 *
 * @return	0 if at least one operation failed, 1 otherwise. In either case
 * the program execution can continue. There may be other side-effects such
 * as printing warnings. If there was a fatal error, this function will
 * terminate the program.
 */
int secure_memory_init(void);

/** Destroy secure memory. Zeroes it before destruction. */
void secure_memory_destroy(void);

#endif	/* SECURE_MEMORY_H__ */
