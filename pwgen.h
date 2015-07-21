/*
  pwgen.h - interface to platform-independent password generation
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
#ifndef PWGEN_H__
#define PWGEN_H__

/**
 * @file
 * This defines the interface to platform-independent secure password
 * generation routines.
 */

/**
 * Generate passphrase by the 'diceware' method: a number of words selected
 * from a fixed list.
 *
 * @param	random_state	
 * @param	number_of_words	
 * @param	is_enhanced		If non-0, generates an enhanced passhprase.
 * @param	get_word		Pointer to the 'get word' function.
 * @param	dictionary_size	Number of words in the dictionary.
 * @param	random_buffer	Buffer into which to generate random numbers.
 * @param	password_buffer	Buffer to output passphrase to.
 *
 * @note	rndbuf and pwbuf are provided so that all sensitive output can
 * 			be put into the secure memory, if available. There are no sizes
 * 			specified, but generally rndbuf should have at least 64 bytes,
 * 			and pwbuf at least 512 bytes.
 *
 * @return	Estimated password entropy.
 */
float pwgen_diceware(
		struct SRNG_st	*random_state,
		unsigned int 	number_of_words,
		int 			is_enhanced,
		const char *	(*get_word)(unsigned int),
		unsigned int 	dictionary_size,
		unsigned int 	*random_buffer,
		char 			*password_buffer);

/**
 * Generate a raw random passphrase of n bits encoded into base64.
 *
 * @param	random_state	Random state.
 * @param	number_of_bits	Number of bits.
 * @param	random_buffer	Buffer into which to generate random numbers.
 * @param	password_buffer	Buffer to output passphrase to.
 *
 * @todo	Use our own base64 encoder so we don't have to use mlockall()
 * 			and OpenSSL.
 *
 * @return	Estimated password entropy.
 */
float pwgen_raw(
		struct SRNG_st *random_state,
		unsigned int number_of_bits,
		unsigned int *random_buffer,
		char *password_buffer);

/**
 * Generate a raw random passphrase of n bits encoded by koremutake encoding
 * into a pronouncable word.
 *
 * @param	random_state	Random state.
 * @param	number_of_bits	Number of bits.
 * @param	random_buffer	Buffer into which to generate random numbers.
 * @param	password_buffer	Buffer to output passphrase to.
 *
 * @todo	Use our own base64 encoder so we don't have to use mlockall()
 * 			and OpenSSL.
 *
 * @return	Estimated password entropy.
 */
float pwgen_koremutake(
		struct SRNG_st *random_state,
		unsigned int number_of_bits,
		unsigned int *random_buffer,
		char *password_buffer);

/** Allowable character classes for pwgen_ascii. */
enum character_classes {
	chr_alphanumeric = 1,
	chr_dec_digits = 2,
	chr_hex_digits = 4,
	chr_special = 8,
	chr_syllables = 16
};

/**
 * Generate alphanumeric password generated from various 'classes'.
 *
 * @param	random_state			Random state.
 * @param	number_of_components	Number of components.
 * @param	character_classes		Bit-set of allowed character classes.
 * @param	random_buffer			Buffer into which to generate random
 * 									numbers.
 * @param	password_buffer			Buffer to output passphrase to.
 *
 * @see		character_classes.
 *
 * @return	Estimated password entropy.
 */
float pwgen_ascii(
		struct SRNG_st *random_state,
		unsigned int number_of_components,
		unsigned int character_classes,
		unsigned int *random_buffer,
		char *password_buffer);

#endif	/* PWGEN_H__ */
