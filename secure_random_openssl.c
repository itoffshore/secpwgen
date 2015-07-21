/*
  secure_random_openssl.c - secure random number generator using OpenSSL
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
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include "exceptions.h"

static char rcsid[] = "$Id: secure_random_openssl.c 1 2005-11-13 20:23:40Z zvrba $";

/**
	@file
	This implementation uses the Blowfish cipher and low-level interfaces
	usable both in SSLEay and OpenSSL (the latter is interesting in porting
	to e.g. PalmOS).
	
	The generator gathers a small amount of true randomness from the system and
	uses it to initialize the blowfish key and the randomness buffer. Further
	random bytes are obtained by encrypting the previous contents of the
	random buffer.
*/

/* Blowfish parameters. */
#define	KEY_SIZE	16	/* 128-bit key size */
#define BLOCK_SIZE	8	/* 64-bit block size */

struct SRNG_st {
	BF_KEY key;
	unsigned char rnd[2*BLOCK_SIZE];
	unsigned int idx;
	unsigned char keydata[KEY_SIZE];
};

unsigned int SRNG_init(struct SRNG_st *st)
{
	if(!st)
		goto end;

	if(!RAND_bytes(st->keydata, sizeof(st->keydata))
	|| !RAND_bytes(st->rnd, sizeof(st->rnd))) {
		ERR_print_errors_fp(stderr);
		Throw(lib_crypto_exception);
	}

	BF_set_key(&st->key, sizeof(st->keydata), st->keydata);
	st->idx = 0;

end:
	return sizeof(struct SRNG_st);
}

void SRNG_bytes(
	struct SRNG_st *st,
	void *buf,
	unsigned int n)
{
	unsigned char *out = buf, *src, *dst;

	while(1) {
		/*
		 * this swaps src and dst to point to differenct halves of st->rnd on
		 * each iteration. st->idx is either 0 or BLOCK_SIZE. it is initialized
		 * to 0 in SRNG_init.
		 */
		src = st->rnd + st->idx;
		dst = st->rnd + (BLOCK_SIZE - st->idx);
		st->idx = BLOCK_SIZE - st->idx;

		BF_ecb_encrypt(src, dst, &st->key, BF_ENCRYPT);

		if(n < BLOCK_SIZE) {
			memcpy(out, dst, n);
			break;
		}

		memcpy(out, dst, BLOCK_SIZE);
		n -= BLOCK_SIZE; out += BLOCK_SIZE;
	}
}

void SRNG_destroy(struct SRNG_st *st)
{
	printf("INFO: destroying random number generator.\n");
	memset(st, 0, sizeof(*st));
}

