#ifndef __CYCLONEDEX_H
    #define __CYCLONEDEX_H

#include "format_utils.h"

void cyclonedx_open(FILE * output);
void cyclonedx_close(FILE * output);
void print_json_match_cyclonedx(FILE * output, component_item * comp_item);

#endif
