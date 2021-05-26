#ifndef __SPDX_H
    #define __SPDX_H

#include "format_utils.h"

void spdx_open(FILE * output);
void spdx_close(FILE * output);
void print_json_match_spdx(FILE * output, component_item * comp_item);

#endif
