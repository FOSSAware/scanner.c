#ifndef __FORMAT_UTILS_H
#define  __FORMAT_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "json.h"

#define CRC_LIST_LEN 256 // list of crc checksums to avoid metadata duplicates
#define MAX_FIELD_LN 64
#define MAX_FILE_PATH 1024
#define MD5_LEN 16
#define MD5_CHAR_LEN 34
#define PURL_LEN 512
#define MAX_ARGLN 512       // Max command line argument length

#define SCANNER_FORMAT_PLAIN "plain"
#define SCANNER_FORMAT_CYCLONEDX "cyclonedx"
#define SCANNER_FORMAT_SPDX "spdx"

typedef enum {none, url, file, snippet} matchtype;

typedef struct match_data
{
  char filename[MAX_FILE_PATH];
  char size[MAX_FIELD_LN];
  char idtype[MAX_FIELD_LN];
	char vendor[MAX_FIELD_LN];
	char component[MAX_FIELD_LN];
	char version[MAX_FIELD_LN];
	char release_date[MAX_FIELD_LN];
	char latest_version[MAX_FIELD_LN];
	char purl[MAX_FIELD_LN];
	char license[MAX_FIELD_LN];
	char url[MAX_FILE_PATH];
  char lines[MAX_FIELD_LN];
  char oss_lines[MAX_FIELD_LN];
  char md5_file[MD5_CHAR_LEN];
  char md5_comp[MD5_CHAR_LEN];
  char matched[MAX_FIELD_LN];
} match_data;

typedef struct match_data_list
{
	match_data ** match_list;
	int count;
    
} match_data_list;



// fileid, filename, vendor, component, version, latest_version, url, license, lines, matched, size, idtype
/*
typedef struct scan_match
{
  long fileid;
  char filename[MAX_URL];
  char vendor[MAX_VENDOR];
  char component[MAX_COMPONENT];
  char version[MAX_VERSION];
  char latest_version[MAX_VERSION];
  char url[MAX_URL];
  char license[MAX_LICENSE];
  char lines[MAX_LINE_RANGE];
  char oss_lines[MAX_LINE_RANGE];
  char matched[MAX_COMPONENT];
  char size[MAX_SIZE];
  char idtype[MAX_IDTYPE];
  char md5_file[34];
  char md5_comp[34];
  char purl[10000];
} scan_match;
*/

typedef struct f_contents
{
  char *contents;
  int size;
} f_contents;

typedef struct component_item
{
  char purl[MAX_FIELD_LN];
  char vendor[MAX_FIELD_LN];
  char component[MAX_FIELD_LN];
  char version[MAX_FIELD_LN];
  char latest_version[MAX_FIELD_LN];
  char license[MAX_FIELD_LN];
} component_item;

char *md5_hex(uint8_t *md5);

int scan_parse_v2(char *filename);

f_contents *scan_parse_read_file(char *filename);

void free_f_contents(f_contents *c);

void process_scan_result(json_value *result);

void process_match(json_object_entry value);
void print_matches(FILE * output, char * format);
char *datestamp(void);

#endif