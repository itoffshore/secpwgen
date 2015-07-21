/*
  diagnostics.h - standard error codes and messages
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
#ifndef DIAGNOSTICS_H__
#define DIAGNOSTICS_H__

#define	I01	"destroying secure memory"
#define	W01	"using insecure memory"
#define	E01	"N must be an integer > 0"
#define F01	"out of memory"
#define	F02	"system call failed"
#define F03	"unhandled exception"
#define F04	"can't drop privileges"

#define IWDIAG(x, ...) fprintf(stderr, "%s: %s:\n", #x, x, __VA_ARGS__)
#define EFDIAG(x, ...) do { \
	fprintf(stderr, "%s: %s\n", #x, __VA_ARGS__);\
	exit(EXIT_FAILURE);\
}

#endif	/* DIAGNOSTICS_H__ */
