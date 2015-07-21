/*
  secure_random.h - interface for secure random number generator
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
#ifndef SECURE_RANDOM_H__
#define SECURE_RANDOM_H__

/**
	@file
	This file defines the SRNG interface.
*/

/** Opaque structure used to hold secure random generator state. */
struct SRNG_st;

/**
	Initialize the secure random number generator.
	@param	st	The state variable which should be initialized. The behaviour
				depends whether this is NULL or not.
	@return	The size of the initialized state.

	An exception is thrown on error.

	@note	The interface is designed such that it is possible to provide a
			secure (e.g. memory-locked) buffer for the state. If \e st is
			NULL, the function does nothing, but still returns the size that
			needs to be reserved for the state.
*/
unsigned int SRNG_init(struct SRNG_st *st);

/**
	Obtain \e n bytes of randomness from the generator.

	@param	st		Pointer to generator state.
	@param	buf		Buffer to store random bytes.
	@param	n		Number of random bytes to retrieve.

	An exception is thrown on error.
*/
void SRNG_bytes(
	struct SRNG_st *st,
	void *buf,
	unsigned int n);

/**
 * Destroy the RNG state. \e st is pointer returned by SRNG_init().
 */
void SRNG_destroy(struct SRNG_st *st);

#endif	/* SECURE_RANDOM_H__ */
