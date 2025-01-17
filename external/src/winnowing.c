// SPDX-License-Identifier: MIT
/*
 * src/main.c
 *
 * Winnowing algorithm implementation
 *
 * Copyright (C) 2022, SCANOSS
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
//#include "external/crc32c/crc32c.c"
#include "crc32c.h"
#include "winnowing.h"


uint8_t GRAM  = 30;   // Winnowing gram size in bytes
uint8_t WINDOW = 64;  // Winnowing window size in bytes
uint32_t MAX_UINT32 = 4294967295;

/* Convert case to lowercase, and return zero if it isn't a letter or number
   Do it fast and independent from the locale configuration (avoid string.h) */
static uint8_t normalize (uint8_t byte)
{
	if (byte < '0')  return 0;
	if (byte > 'z')  return 0;
	if (byte <= '9')  return byte;
	if (byte >= 'a') return byte;
	if ((byte >= 'A') && (byte <= 'Z')) return byte + 32 ;
	return 0;
}

/* Left shift one window */
static void shift_window(uint32_t *window)
{
	for (uint32_t i = 0; i < (WINDOW - 1); i++)
	{
		window[i] = window[i + 1];
	}
	window[WINDOW - 1] = 0;
}

/* Left shift one gram */
static void shift_gram(uint8_t *gram)
{
	for (uint32_t i = 0; i < (GRAM - 1); i++)
	{
		gram[i] = gram[i + 1];
	}
	gram[GRAM - 1] = 0;
}

/* Select smaller hash for the given window */
static uint32_t smaller_hash(uint32_t *window)
{
	uint32_t hash = MAX_UINT32;
	for (uint32_t h = 0; h < WINDOW; h++)
	{
		if (window[h] < hash) hash = window[h];
	}
	return hash;
}

/* Add the given "hash" to the "hashes" array and the corresponding "line" to the "lines" array
   updating the hash counter and returning the last added hash */
static uint32_t add_hash(uint32_t hash, uint32_t line, uint32_t *hashes, uint32_t *lines, uint32_t last, uint32_t *counter)
{

	/* Consecutive repeating hashes are ignored */
	if (hash != last)
	{
		/* 	Hashing the hash will result in a better balanced resulting data set
			as it will counter the winnowing effect which selects the "minimum"
			hash in each window */

		hashes [*counter] = calc_crc32c((char *)&hash, 4);
		lines  [*counter] = line;

		last = hash;
		(*counter)++;
	}

	return last;
}

/* Performs winning on the given FILE, limited to "limit" hashes. The provided array
   "hashes" is filled with hashes and "lines" is filled with the respective line numbers.
   The function returns the number of hashes found */

uint32_t winnowing (char *src, uint32_t *hashes, uint32_t *lines, uint32_t limit)
{

	uint32_t line = 1;
	uint32_t counter = 0;
	uint32_t hash = MAX_UINT32;
	uint32_t last = 0;
	uint8_t *gram = malloc (GRAM);
	uint32_t gram_ptr = 0;
	uint32_t *window = malloc (WINDOW * sizeof(uint32_t));
	uint32_t window_ptr = 0;

	/* Process one byte at a time */
	uint32_t src_len = strlen(src);
	for (uint32_t i = 0; i < src_len; i++)
	{
		if (src[i] == '\n') line++;

		uint8_t byte = normalize(src[i]);
		if (!byte) continue;

		/* Add byte to the gram */
		gram[gram_ptr++] = byte;

		/* Got a full gram? */
		if (gram_ptr >= GRAM)
		{

			/* Add fingerprint to the window */
			window[window_ptr++] = calc_crc32c((char *) gram, GRAM);

			/* Got a full window? */
			if (window_ptr >= WINDOW)
			{

				/* Add hash */
				hash = smaller_hash(window);
				last = add_hash(hash, line, hashes, lines, last, &counter);

				if (counter >= limit) break;

				shift_window(window);
				window_ptr = WINDOW - 1;
			}

			shift_gram(gram);
			gram_ptr = GRAM - 1;
		}
	}

	free (gram);
	free (window);
	return counter;
}
