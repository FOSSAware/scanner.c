// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/spdx.c
 *
 * SPDX output handling
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
#include "spdx.h"

void spdx_open(FILE * output)
{
	fprintf(output,"{\n");
	fprintf(output,"  \"Document\": {\n");
	fprintf(output,"    \"specVersion\": \"SPDX-2.0\",\n");
	fprintf(output,"    \"creationInfo\": {\n");
	fprintf(output,"      \"creators\": [\n");
	fprintf(output,"        \"Tool: SCANOSS Inventory Engine\",\n");
	fprintf(output,"        \"Organization: http://scanoss.com\"\n");
	fprintf(output,"      ],\n");
	fprintf(output,"      \"comment\": \"This SPDX report has been automatically generated\",\n");
	fprintf(output,"      \"licenseListVersion\": \"1.19\",\n");

	fprintf(output,"      \"created\": \"");
	fprintf(output,"%s",datestamp());
	fprintf(output,"\"\n");

	fprintf(output,"    },\n");
	fprintf(output,"    \"spdxVersion\": \"SPDX-2.0\",\n");
	fprintf(output,"    \"dataLicense\": \"CC0-1.0\",\n");
	fprintf(output,"    \"id\": \"SPDXRef-DOCUMENT\",\n");
	fprintf(output,"    \"name\": \"SPDX-Tools-v2.0\",\n");
	fprintf(output,"    \"comment\": \"This document was automatically generated with SCANOSS.\",\n");
	fprintf(output,"    \"externalDocumentRefs\": [],\n");
	fprintf(output,"    \"Packages\": [\n");
}

void spdx_close(FILE * output)
{
	fprintf(output,"       ]\n");
	fprintf(output,"      }\n");
	fprintf(output,"}\n");
}

void print_json_match_spdx(FILE * output, component_item * comp_item)
{
	fprintf(output,"         {\n");
	fprintf(output,"          \"name\": \"%s\",\n", comp_item->component);

	if (strcmp(comp_item->version, comp_item->latest_version))
	{
		fprintf(output,"          \"versionInfo\": \"%s-%s\",\n", comp_item->version, comp_item->latest_version);
	}
	else
	{
		fprintf(output,"          \"versionInfo\": \"%s\",\n", comp_item->version);
	}

	fprintf(output,"          \"supplier\": \"%s\",\n", comp_item->vendor);
	fprintf(output,"          \"downloadLocation\": \"%s\",\n", comp_item->purl);
	fprintf(output,"          \"description\": \"Detected by SCANOSS Inventorying Engine.\",\n");
	fprintf(output,"          \"licenseConcluded\": \"\",\n");
	fprintf(output,"          \"licenseInfoFromFiles\": \"%s\"\n", comp_item->license);
	fprintf(output,"         }\n");

	fflush(stdout);
}
