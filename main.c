/*
  main.c - main program
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
#include <unistd.h>
#include <math.h>
#include "secure_memory.h"
#include "secure_random.h"
#include "pwgen.h"
#include "exceptions.h"

static char rcsid[] = "$Id: main.c 1 2005-11-13 20:23:40Z zvrba $";

static struct exception_context exception_context;
struct exception_context *the_exception_context = &exception_context;

static void exit_cleanup(void)
{
	SRNG_destroy((struct SRNG_st*)G_secure_memory->random_state);
	secure_memory_destroy();
}

static void usage(const char *argv0)
{
	fprintf(stderr, "USAGE: %s <-p[e] | -A[adhsy] | -r | -s[e]> N\n", argv0);
	fprintf(stderr,
	    "\nPASSPHRASE of N words from Diceware dictionary\n"
		"  -p    generate passphrase\n"
		"  -pe   generate enhanced (with symbols) passphrase\n"
		"\nSKEY PASSWORD of N words from S/Key dictionary\n"
		"  -s    generate passphrase\n"
		"  -se   generate enhanced (with symbols) passphrase\n"
		"\nASCII RANDOM of N elements (at least one option MUST be present)\n"
		"  -A    Each letter adds the following random elements in output:\n"
	    "    a    alphanumeric characters\n"
		"    d    decimal digits\n"
		"    h    hexadecimal digits\n"
		"    s    special characters\n"
		"    y    3-4 letter syllables\n"
		"\nRAW RANDOM\n"
		"  -r    output BASE64 encoded string of N random BITS\n"
		"  -k    output koremutake encoding of N random BITS\n");
	exit(1);
}

static unsigned int get_allowed_characters(const char *p)
{
	unsigned int characters = 0;

	while(*p) {
		switch(*p) {
		case 'a':
			characters |= chr_alphanumeric;
			break;
		case 'd':
			characters |= chr_dec_digits;
			break;
		case 'h':
			characters |= chr_hex_digits;
			break;
		case 's':
			characters |= chr_special;
			break;
		case 'y':
			characters |= chr_syllables;
			break;
		default:
			return 0;
		}
		++p;
	}

	/* filter out some combinations for correct entropy estimation */
	if(characters & chr_alphanumeric)
		characters &= ~(chr_dec_digits | chr_hex_digits);
	if(characters & chr_hex_digits)
		characters &= ~chr_dec_digits;
	if((characters & chr_syllables)
	&& (characters & (chr_alphanumeric | chr_dec_digits | chr_hex_digits))) {
		characters &= ~(chr_alphanumeric | chr_dec_digits | chr_hex_digits);
		characters |= chr_dec_digits;
	}

	return characters;
}

int main(int argc, char **argv)
{
	const char *getDiceWd(unsigned int);
	const char *getSkeyWd(unsigned int);
	unsigned int n;
	unsigned int srng_state_len;
	float entropy;
	enum exception_code exception;
	int retval = 0;

	init_exception_context(&exception_context);

	if(argc != 3)
		usage(argv[0]);

	n = atoi(argv[2]);
	if(n < 1) {
		fprintf(stderr, "ERROR: N must be an integer > 0\n");
		usage(argv[0]);
	}

	srng_state_len = SRNG_init(NULL);
	if(srng_state_len > MAX_RANDOM_STATE_SIZE) {
		fprintf(stderr, 
				"FATAL: too small MAX_RANDOM_STATE_SIZE "
				"(must be at least %u)\n", srng_state_len);
		return 1;
	}

	Try {
		secure_memory_init();
		SRNG_init((struct SRNG_st*)G_secure_memory->random_state);

		if(atexit(exit_cleanup) < 0) {
			fprintf(stderr, "FATAL: can't register cleanup handlers: \n");
			perror("atexit");
			return 1;
		}

		if(!strcmp(argv[1], "-p"))
			entropy = pwgen_diceware(
					(struct SRNG_st*)G_secure_memory->random_state, n, 0,
					getDiceWd, 8192, G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strcmp(argv[1], "-pe"))
			entropy = pwgen_diceware(
					(struct SRNG_st*)G_secure_memory->random_state, n, 1,
					getDiceWd, 8192, G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strcmp(argv[1], "-r"))
			entropy = pwgen_raw(
					(struct SRNG_st*)G_secure_memory->random_state, n,
					G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strcmp(argv[1], "-k"))
			entropy = pwgen_koremutake(
					(struct SRNG_st*)G_secure_memory->random_state, n,
					G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strcmp(argv[1], "-s"))
			entropy = pwgen_diceware(
					(struct SRNG_st*)G_secure_memory->random_state, n, 0,
					getSkeyWd, 2048, G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strcmp(argv[1], "-se"))
			entropy = pwgen_diceware(
					(struct SRNG_st*)G_secure_memory->random_state, n, 1,
					getSkeyWd, 2048, G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		else if(!strncmp(argv[1], "-A", 2)) {
			unsigned int characters = get_allowed_characters(argv[1]+2);

			if(!characters)
				usage(argv[0]);
			entropy = pwgen_ascii(
					(struct SRNG_st*)G_secure_memory->random_state, n,
					characters, G_secure_memory->random_numbers,
					G_secure_memory->passphrase);
		} else {
			usage(argv[0]);
		}
	} Catch(exception) {
		switch(exception) {
		case out_of_memory_exception:
			fprintf(stderr, "FATAL: out of memory.\n");
			retval = 1;
			break;
		case lib_crypto_exception:
			fprintf(stderr, "FATAL: crypto library error.\n");
			retval = 1;
			break;
		case system_call_failed_exception:
			fprintf(stderr, "FATAL: system call failed.\n");
			retval = 1;
			break;
		default:
			fprintf(stderr, "FATAL: unhandled exception %u.\n", exception);
			retval = 1;
		}
	}

	if(!retval) {
		printf("----------------\n");
		/*
		 * SECURITY NOTE
		 * I have no idea how printf(3) is implemented and it just MIGHT copy
		 * some sensitive data to its own stack.
		 */
		printf("%s ;ENTROPY=%.2f bits\n", G_secure_memory->passphrase,
				entropy);
		printf("----------------\n");
	}
	return retval;
}
