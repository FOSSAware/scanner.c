// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/cyclonedx.c
 *
 * CycloneDX output handling
 *
 * Copyright (C) 2018-2021 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

