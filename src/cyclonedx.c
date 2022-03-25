// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cyclonedx.c
 *
 * CycloneDX output handling
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
#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <time.h>
#include <stdlib.h>

#include "cyclonedx.h"


/* Returns the current date stamp */

static void print_serial_number(FILE * output)
{
	/* Get hostname and time stamp */
	char *stamp = datestamp();
	char hostname[MAX_ARGLN] = "SCANNER - SCANOSS CLI";
	strcat(stamp,hostname);

	/* Calculate serial number */
	uint8_t md5sum[16]="\0";
	MD5((uint8_t *) stamp, strlen(stamp), md5sum);
	char *md5hex = md5_hex(md5sum);

	/* Print serial number */
	fprintf(output,"  \"serialNumber\": \"scanoss:%s-%s\",\n",hostname, md5hex);

	free(stamp);
	free(md5hex);
}

void cyclonedx_open(FILE * output)
{
    fprintf(output,"{\n");
    fprintf(output,"  \"bomFormat\": \"CycloneDX\",\n");
    fprintf(output,"  \"specVersion\": \"1.2\",\n");
    print_serial_number(output);
    fprintf(output,"  \"version\": 1,\n");
    fprintf(output,"  \"components\": [\n");
}

void cyclonedx_close(FILE * output)
{
    fprintf(output,"  ]\n}\n");
}

void print_json_match_cyclonedx(FILE * output, component_item * comp_item)
{
    fprintf(output,"    {\n");
    fprintf(output,"      \"type\": \"library\",\n");
    fprintf(output,"      \"name\": \"%s\",\n", comp_item->component);
    fprintf(output,"      \"publisher\": \"%s\",\n", comp_item->vendor);

    if (strcmp(comp_item->version, comp_item->latest_version))
        fprintf(output,"      \"version\": \"%s-%s\",\n", comp_item->version, comp_item->latest_version);
    else
        fprintf(output,"      \"version\": \"%s\",\n", comp_item->version);

		if (*comp_item->license)
		{
			fprintf(output,"      \"licenses\": [\n");
			fprintf(output,"        {\n");
			fprintf(output,"          \"license\": {\n");
			fprintf(output,"             \"id\": \"%s\"\n", comp_item->license);
			fprintf(output,"          }\n");
			fprintf(output,"        }\n");
			fprintf(output,"      ],\n");
		}
		fprintf(output,"      \"purl\": \"%s@%s\"\n", comp_item->purl, comp_item->version);
		fprintf(output,"    }\n");
		fflush(stdout);
}

