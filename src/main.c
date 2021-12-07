// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/main.c
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
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include "scanner.h"
#include "format_utils.h"

enum
{
    SCAN = 0,
    SCAN_WFP,
    CONVERT,
};

void scanner_evt(const scanner_status_t * p_scanner, scanner_evt_t evt)
{
 switch(evt)
  {
    case SCANNER_EVT_START:
      break;
    case SCANNER_EVT_WFP_CALC_IT:
        fprintf(stderr,"\r             \rCalculating fingerprints: %u",p_scanner->wfp_files);      
        break;
    case SCANNER_EVT_WFP_CALC_END:
        fprintf(stderr,"\n\r             \r%u Fingerprints collected in %lu ms\n",p_scanner->wfp_files, p_scanner->wfp_total_time);      
        fprintf(stderr,"\r             \rScanning, please be patient...\n");
        break;
    case SCANNER_EVT_CHUNK_PROC:
        fprintf(stderr,"\r             \rProcessing %u files: %u%%",p_scanner->wfp_files,((p_scanner->scanned_files*100/p_scanner->wfp_files)));
        break;
    case SCANNER_EVT_END:
        fprintf(stderr,"\n\r             \rScan completed in: %lu ms\n",p_scanner->total_response_time);
      break;
    case SCANNER_EVT_ERROR_CURL:
      break;
    case SCANNER_EVT_ERROR:
      break;
    default:
      break;
  }
}

int main(int argc, char *argv[])
{
    int proc = SCAN;
    int param = 0;
    bool print_output = true;
    char * file = NULL;
    char format[20] = "plain";
    char host[32] = API_HOST_DEFAULT;
    char port[5] = API_PORT_DEFAULT;
    char session[64] = API_SESSION_DEFAULT;
    char path[512];
    int flags = 0;
    bool wfp_only = false;

    while ((param = getopt (argc, argv, "F:H:p:f:o:L:cluwWhdtv")) != -1)
        switch (param)
        {
            case 'c':
                proc = CONVERT;
                break;
            case 'F':
                flags = atol(optarg);
                break;
            case 'H':
                strcpy(host,optarg);
                break;
            case 'p':
                strcpy(port,optarg);
                break;
            case 'f':
                strcpy(format,optarg);
                break;
            case 'o':
                asprintf(&file,"%s",optarg);
                print_output = false;
                break;
            case 'L':
                scanner_set_log_file(optarg);
                break;
            case 'd':
                scanner_set_log_level(1);
                break;
            case 't':
                scanner_set_log_level(0);
                break;
            case 'w':
                proc = SCAN_WFP;
                break;
            case 'W':
                wfp_only = true;
                break;
            case 'v':
                fprintf(stderr,"%s\n",VERSION);
                exit(EXIT_FAILURE);
                break;
            case 'h':
            default:
                fprintf(stderr, "SCANOSS C CLI. Ver: %s, License GPL 2.0-or-later\n", VERSION);
                fprintf(stderr, "Usage: scanner FILE or scanner DIR\n");
                fprintf(stderr, "Option\t\t Meaning\n");
                fprintf(stderr, "-h\t\t Show this help\n");
                fprintf(stderr, "-v\t\t Show CLI version\n");
                fprintf(stderr, "-F<flags>\t Scanning engine flags (1: disable snippet matching, 2: enable snippet ids, 4: disable dependencies,\n"
                                              "\t\t 8: disable licenses, 16: disable copyrights, 32: disable vulnerabilities, 64: disable quality,\n"
                                              "\t\t 128: disable cryptography,256: disable best match, 512: Report identified files)\n");
                fprintf(stderr, "-f<format>\t Output format, could be: plain (default), spdx or cyclonedx.\n");
                fprintf(stderr, "-w\t\t Scan a wfp file\n");
                fprintf(stderr, "-W\t\t Create a wfp file from path\n");
                fprintf(stderr, "-o<file_name>\t Save the scan results in the specified file\n");
                fprintf(stderr, "-L<file_name>\t Set logs filename\n");
                fprintf(stderr, "-d\t\t Enable debug messages\n");
                fprintf(stderr, "-t\t\t Enable trace messages, enable to see post request to the API\n");
                fprintf(stderr, "\nFor more information, please visit https://scanoss.com\n");
                exit(EXIT_FAILURE);
            break;
        }
    
    if(argv[optind]) 
    {
        strcpy(path,argv[optind]);
        char id[MAX_ID_LEN];
        sprintf(id,"scanoss CLI,%u", rand());
        scanner_object_t * scanner = scanner_create(id, host,port,session,format,path,file,flags,scanner_evt);
        int err = EXIT_SUCCESS;

        switch (proc)
        {
        case SCAN:
            err = scanner_recursive_scan(scanner, wfp_only);
            break;
        case SCAN_WFP:
            err = scanner_wfp_scan(scanner);
            break;
        case CONVERT:
            err = scan_parse_v2(path);
            if (!err)
            {
                FILE * f = fopen(file,"w+");
                print_matches(f,format);
                fclose(f);
            }
            break;
        default:
            break;
        }
        
        if (print_output)
            scanner_print_output(scanner);
        if(file)
            free(file);

        if (err)
            fprintf(stderr, "Scanner exit with msg: %d - %s\n", err, scanner->status.message);
        
        scanner_object_free(scanner);
        return err;
    }
    fprintf(stderr, "Missing parameter, run with -h for help\n");
    
    return EXIT_FAILURE;
}
