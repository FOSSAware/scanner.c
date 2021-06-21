// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scanner.h
 *
 * A simple SCANOSS client in C for direct file scanning
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
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



#ifndef __SCANNER_H
#define __SCANNER_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define VERSION "1.3.5"
#define MAX_HEADER_LEN 1024 * 1024 * 1024 * 10
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MIN_FILE_SIZE 256

#define SCAN_STATUS_MAX_SIZE 512

enum 
{
    API_REQ_GET,
    API_REQ_POST
};

typedef enum
{
    SCANNER_FLAG_DISABLE_SNIPPET_MATCHING = 1,
    SCANNER_FLAG_ENABLE_SNIPPET_ID = 1<<1,
    SCANNER_FLAG_DISABLE_DEPENDENCIES = 1<<2,
    SCANNER_FLAG_DISABLE_LICENSES = 1<<3,
    SCANNER_FLAG_DISABLE_COPYRIGHTS = 1<<4,
    SCANNER_FLAG_DISABLE_VULNERABILITIES = 1<<5,
    SCANNER_FLAG_DISABLE_QUALITY = 1<<6,
    SCANNER_FLAG_DISABLE_CRIPTOGRAPHY = 1<<7,  
    SCANNER_FLAG_DISABLE_BEST_MATCH_ONLY= 1<<8,
    SCANNER_FLAG_DEFAULT = 0,
} scanner_flags_t;

typedef enum
{
    SCANNER_STATE_OK = 0,
    SCANNER_STATE_INIT,
    SCANNER_STATE_WFP_CALC,
    SCANNER_STATE_ANALIZING,
    SCANNER_STATE_FORMATING,
    SCANNER_STATE_ERROR
} scanner_state_t;

#define MAX_ID_LEN 256

#define MAX_COMPONENT_SIZE 128
typedef struct scanner_status_t
{
    char id[MAX_ID_LEN];
    scanner_state_t state;    
    unsigned int wfp_files;
    unsigned int scanned_files;
    long wfp_total_time;
    long last_chunk_response_time;
    char component_last[MAX_COMPONENT_SIZE];
    long total_response_time;
    char message[SCAN_STATUS_MAX_SIZE];
} scanner_status_t;

typedef enum
{
    SCANNER_EVT_START = 0,
    SCANNER_EVT_WFP_CALC_IT,
    SCANNER_EVT_WFP_CALC_END,
    SCANNER_EVT_CHUNK_PROC,
    SCANNER_EVT_CHUNK_PROC_END,
    SCANNER_EVT_END,
    SCANNER_EVT_ERROR_CURL,
    SCANNER_EVT_ERROR
}scanner_evt_t;

/**
 * scanner_id_t: Identifies an scan. A scan is identified by scan code and project ID.
 */
typedef void (*scanner_evt_handler) (const scanner_status_t * p_scanner, scanner_evt_t evt);

typedef struct scanner_object_t
{
    char API_host[32];
    char API_port[5];
    char API_session[33];
    char format[16];
    char * scan_path;
    char *output_path;
    char *wfp_path;
    char * curl_temp_path;
    FILE *output;
    FILE * curl_temp;
    unsigned int files_chunk_size;
    scanner_flags_t flags;
    scanner_status_t status;
    scanner_evt_handler callback;
} scanner_object_t;

#define API_HOST_DEFAULT "osskb.org/api"
#define API_PORT_DEFAULT "443"
#define API_SESSION_DEFAULT "\0"
#define CHUNK_SIZE_DEFAULT (64 * 1024)

#define __SCANNER_OBJECT_INIT(path,file) {.API_host = API_HOST_DEFAULT, .API_port = API_PORT_DEFAULT, .API_session = API_SESSION_DEFAULT, .format = "plain", .files_chunk_size = CHUNK_SIZE_DEFAULT,.scan_path = path, .output_path = file, .status.state = SCANNER_STATE_INIT, .flags = SCANNER_FLAG_DEFAULT , .callback = NULL,\
                                            .status.component_last="none"}

void scanner_set_log_level(int level);
void scanner_set_verbose(bool in);
void scanner_set_buffer_size(unsigned int size);
void scanner_set_format(scanner_object_t *s, char * form);
void scanner_set_host(scanner_object_t *s, char * host);
void scanner_set_port(scanner_object_t *s, char * port);
void scanner_set_session(scanner_object_t *s, char *session);
void scanner_set_output(scanner_object_t *s, char * f);
int scanner_print_output(scanner_object_t *scanner);
void scanner_set_log_file(char *log);
scanner_object_t * scanner_create(char * id, char * host, char * port, char * session, char * format, char * path, char * file, scanner_flags_t flag, scanner_evt_handler callback);
void scanner_wfp_capture(char *path, char **md5, char *wfp_buffer);
int scanner_recursive_scan(scanner_object_t *scanner, bool wfp_only);
int scanner_wfp_scan(scanner_object_t * scanner);
bool scanner_get_attribution(scanner_object_t *scanner, char * path);
int scanner_get_file_contents(scanner_object_t *scanner, char * hash);
int scanner_get_license_obligations(scanner_object_t *scanner, char * license_name);
void scanner_object_free(scanner_object_t * scanner);
#endif
