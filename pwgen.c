/*
  pwgen.c - actual password generation
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
#include <string.h>
#include <math.h>
#include "secure_random.h"
#include "pwgen.h"
#include "exceptions.h"

static char rcsid[] = "$Id: pwgen.c 1 2005-11-13 20:23:40Z zvrba $";

/**
 * @file
 * This is intended to be the UI-independent part of password generation.
 *
 * @note	On the programming style in this code: I'm aware that strcat()
 * in a loop has quadratic performance, but here I just don't care and it
 * makes my life easier.
 */

/******************************************************************************
 * Tables and entropy constants.
 *****************************************************************************/
static const char *t_alphanumeric[36] = {
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
	"M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X",
	"Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
};

static const char *t_dec_digits[36] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	NULL, NULL, NULL, NULL, NULL, NULL
};

static const char *t_hex_digits[36] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F",
	NULL, NULL, NULL, NULL
};

static const char *t_special[36] = {
	"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_",
	"+", "=", "[", "]", "{", "}", ";", ":", "'", "\"", ",", ".",
	"<", ">", "/", "?", "`", "~", "|", "\\", "--", "==", "..", "//"
};

static const char *t_syllables_lm[36] = {
	"B", "C", "D", "F", "G", "H",
	"J", "K", "L", "M", "N", "P",
	"QU", "R", "S", "T", "V", "W",
	"X", "Z", "CH", "CR", "FR", "ND",
	"NG", "NK", "NT", "PH", "PR", "RD",
	"SH", "SL", "SP", "ST", "TH", "TR"
};

static const char *t_syllables_r[6] = {
	"A", "E", "I", "O", "U", "Y"
};

static const char *koremutake_syllables[128] = {
	"BA", "BE", "BI", "BO", "BU", "BY", "DA", "DE",
	"DI", "DO", "DU", "DY", "FA", "FE", "FI", "FO",
	"FU", "FY", "GA", "GE", "GI", "GO", "GU", "GY",
	"HA", "HE", "HI", "HO", "HU", "HY", "JA", "JE",
	"JI", "JO", "JU", "JY", "KA", "KE", "KI", "KO",
	"KU", "KY", "LA", "LE", "LI", "LO", "LU", "LY",
	"MA", "ME", "MI", "MO", "MU", "MY", "NA", "NE",
	"NI", "NO", "NU", "NY", "PA", "PE", "PI", "PO",
	"PU", "PY", "RA", "RE", "RI", "RO", "RU", "RY",
	"SA", "SE", "SI", "SO", "SU", "SY", "TA", "TE",
	"TI", "TO", "TU", "TY", "VA", "VE", "VI", "VO",
   	"VU", "VY", "BRA", "BRE", "BRI", "BRO", "BRU", "BRY",
	"DRA", "DRE", "DRI", "DRO", "DRU", "DRY", "FRA", "FRE",
	"FRI", "FRO", "FRU", "FRY", "GRA", "GRE", "GRI", "GRO",
	"GRU", "GRY", "PRA", "PRE", "PRI", "PRO", "PRU", "PRY",
	"STA", "STE", "STI", "STO", "STU", "STY", "TRA", "TRE"
};

#define	N_CHARACTER_CLASSES 5
static struct {
	enum character_classes	chr;		/* character class */
	const char 				**dice12;	/* first two dice throws */
	const char 				**dice3;	/* possibly 3rd dice or NULL */
	float 					entropy;	/* entropy per element */
} character_classes[N_CHARACTER_CLASSES] = {
	{ chr_alphanumeric, t_alphanumeric, NULL, 5.17 },
	{ chr_dec_digits, t_dec_digits, NULL, 3.32 },
	{ chr_hex_digits, t_hex_digits, NULL, 4 },
	{ chr_special, t_special, NULL, 5.17 },
	{ chr_syllables, t_syllables_lm, t_syllables_r, 7.75 }
};

/* This is ONLY for passphrase enhancement. */
static const char t_passphrase_enh[36] = {
	'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_',
	'+', '=', '[', ']', '{', '}', ';', ':', '\'', '\'', ',', '.',
	'<', '>', '/', '?', '`', '~', '|', '\\', 'U', 'O', 'E', 'Y'
};

/******************************************************************************
 * Methods for password generation.
 *****************************************************************************/

float pwgen_diceware(
		struct SRNG_st	*random_state,
		unsigned int 	number_of_words,
		int 			is_enhanced,
		const char *	(*get_word)(unsigned int),
		unsigned int 	dictionary_size,
		unsigned int 	*random_buffer,
		char 			*password_buffer)
{
	unsigned int i, word_length, output_index = 0;
	const char *word;
	float entropy = 0;

	*password_buffer = 0;
	for(i = 0; i < number_of_words; i++) {
		SRNG_bytes(random_state, random_buffer, sizeof(*random_buffer));
		word = get_word(*random_buffer);
		word_length = strlen(word);

		sprintf(password_buffer + output_index, "%s ", word);
		entropy += log(dictionary_size) / log(2);

		if(is_enhanced) {
			unsigned int char_pos, char_idx;

			/* add a random symbol at random position into each word */
			SRNG_bytes(random_state, random_buffer, 2*sizeof(*random_buffer));
			char_pos = random_buffer[0] % word_length;
			char_idx = random_buffer[1] % sizeof(t_passphrase_enh);
			password_buffer[output_index+char_pos] =
				t_passphrase_enh[char_idx];

			/* 5.17 = log2(36) for each symbol plus the position randomness */
			entropy += 5.17 + log(word_length) / log(2);
		}
		output_index += word_length+1;
	}

	return entropy;
}

//*********************************************************************
//* Base64 - a simple base64 encoder and decoder.
//*
//*     Copyright (c) 1999, Bob Withers - bwit@pobox.com
//*
//* This code may be freely used for any purpose, either personal
//* or commercial, provided the authors copyright notice remains
//* intact.
//*
//* Converted to C in 2005 by Zeljko Vrba <zvrba@globalnet.hr>
//*********************************************************************
static void base64_encode(
		const unsigned char *in,
		unsigned int len,
		char *out)
{
	static const char fillchar = '=';
	static const char *cvt =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";
	unsigned int i;
	unsigned char c;

	/*
	 * SECURITY NOTE: single byte from the in string gets copied to the
	 * local stack in each iteration of the loop.
	 */

    for (i = 0; i < len; ++i) {
		c = (in[i] >> 2) & 0x3f;
		*out++ = cvt[c];
		c = (in[i] << 4) & 0x3f;
		if(++i < len)
			c |= (in[i] >> 4) & 0x0f;
		*out++ = cvt[c];
		if(i < len) {
			c = (in[i] << 2) & 0x3f;
			if(++i < len)
				c |= (in[i] >> 6) & 0x03;
			*out++ = cvt[c];
		} else {
			++i;
			*out++ = fillchar;
		}

		if(i < len) {
			c = in[i] & 0x3f;
			*out++ = cvt[c];
		} else {
			*out++ = fillchar;
		}
	}
	*out++ = 0;
}

float pwgen_raw(
		struct SRNG_st 	*random_state,
		unsigned int 	number_of_bits,
		unsigned int 	*random_buffer,
		char 			*password_buffer)
{
	unsigned int number_of_bytes = ((number_of_bits-1)>>3)+1;

	SRNG_bytes(random_state, random_buffer, number_of_bytes);
	base64_encode((unsigned char*)random_buffer, number_of_bytes,
			password_buffer);
	return number_of_bytes << 3;
}

/*
 * This rounds the number of bits to the next higher multiple of 7 (since
 * there are 128=2^7 syllables in the koremutake list).
 */
float pwgen_koremutake(
		struct SRNG_st 	*random_state,
		unsigned int 	number_of_bits,
		unsigned int 	*random_buffer,
		char 			*password_buffer)
{
	unsigned int i, number_of_bytes = ((number_of_bits-1)/7)+1;
	unsigned char *u8buf = (unsigned char*)random_buffer;

	SRNG_bytes(random_state, random_buffer, number_of_bytes);
	*password_buffer = 0;
	for(i = 0; i < number_of_bytes; i++)
		strcat(password_buffer, koremutake_syllables[u8buf[i] & 127]);
	return number_of_bytes * 7;
}

static void select_class(
		struct SRNG_st	*random_state,
		unsigned int	allowed_classes,
		unsigned int	*random_buffer)
{
	do {
		SRNG_bytes(random_state, random_buffer, sizeof(*random_buffer));
		*random_buffer %= N_CHARACTER_CLASSES;	/* not a LCG, so % is OK */
	} while(!(allowed_classes & character_classes[*random_buffer].chr));
}

float pwgen_ascii(
		struct SRNG_st	*random_state,
		unsigned int 	number_of_components,
		unsigned int 	allowed_classes,
		unsigned int 	*random_buffer,
		char 			*password_buffer)
{
	unsigned int i;
	unsigned int *character_class = random_buffer;
	unsigned int *dice12 = character_class + 1;
	unsigned int *dice3  = character_class + 2;
	float entropy = 0;

	password_buffer[0] = 0;
	for(i = 0; i < number_of_components; i++) {
retry:
		/* select character class and throw 3 dice */
		select_class(random_state, allowed_classes, character_class);
		SRNG_bytes(random_state, dice12, 2);
		*dice12 %= 36;	/* 1st and 2nd dice */
		*dice3  %= 6;	/* 3rd dice */

		if(character_classes[*character_class].dice12[*dice12]) {
			strcat(password_buffer,
					character_classes[*character_class].dice12[*dice12]);
			if(!character_classes[*character_class].dice3)
				entropy += character_classes[*character_class].entropy;
		} else {
			goto retry;
		}

		if(character_classes[*character_class].dice3) {
			if(character_classes[*character_class].dice3[*dice3]) {
				strcat(password_buffer,
						character_classes[*character_class].dice3[*dice3]);
				entropy += character_classes[*character_class].entropy;
			} else {
				goto retry;
			}
		}
	}

	return entropy;
}
