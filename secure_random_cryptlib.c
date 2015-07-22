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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <cryptlib.h>
#include "exceptions.h"

static char rcsid[] = "$Id: secure_random_cryptlib.c 1 2005-11-13 20:23:40Z zvrba $";

/**
	@file
	Cryptlib random number generator.
*/

struct SRNG_st {
	CRYPT_CONTEXT ctx;
	char rnd[64];
};

#define	CALL_CL(func, ...) do { \
	int ret__ = func(__VA_ARGS__); \
	if(ret__ != CRYPT_OK) { \
		fprintf(stderr, "cryptlib error: %d\n", ret__); \
		Throw(lib_crypto_exception); \
	} \
} while(0)

unsigned int SRNG_init(struct SRNG_st *st)
{
	if(!st)
		goto end;

	CALL_CL(cryptInit);
	CALL_CL(cryptAddRandom, NULL, CRYPT_RANDOM_SLOWPOLL);
	CALL_CL(cryptCreateContext, &st->ctx, CRYPT_UNUSED, CRYPT_ALGO_RC4);
	CALL_CL(cryptGenerateKey, st->ctx);

end:
	return sizeof(struct SRNG_st);
}

void SRNG_bytes(
	struct SRNG_st *st,
	void *buf,
	unsigned int n)
{
	assert(n < sizeof(st->rnd));
	CALL_CL(cryptEncrypt, st->ctx, st->rnd, sizeof(st->rnd));
	memcpy(buf, st->rnd, n);
}

void SRNG_destroy(struct SRNG_st *st)
{
	printf("INFO: destroying random number generator.\n");
	CALL_CL(cryptDestroyContext, st->ctx);
	if(cryptEnd() != CRYPT_OK) {
		fprintf(stderr, "ERROR: some garbage left to cryptlib.");
	}
	memset(st, 0, sizeof(*st));
}
