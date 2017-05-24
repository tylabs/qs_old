/* Copyright (c) 2016, 2017 Tyler McLellan  TyLabs.com
 * @tylabs
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand.c   May 24 2017
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 * Commercial licensing is available for the full version.
 */
// Dependencies: libzip, yara, zlib
//
#define _CRT_SECURE_NO_WARNINGS

#include "libqs.c"
#include <stdarg.h>
#include "tinydir.h"


#define QS_MAX_BUFFER 1000000
#define DEBUG 0



void qs_do_directory (const char *path, int raw, int json, int drop, int objects) {
    FILE *f;
    
    tinydir_dir dir;
    tinydir_open(&dir, path);
    
    while (dir.has_next)
    {
        tinydir_file file;
        tinydir_readfile(&dir, &file);
        
        //printf("%s\n", file.name);
        
        if (file.is_dir)
        {
            if (file.name[0] != '.') {
                qs_do_directory(file.path, raw, json, drop, objects);
            }
            
        } else {
            //run file
            printf("Scanning %s...\n", file.path);
            f = fopen(file.path, "rb");
            
            
            if( f == NULL )
            {
                perror("Error while opening the file.\n");
                exit(EXIT_FAILURE);
            }
            
            
            fseek(f, 0, SEEK_END);
            long fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            unsigned char *string = malloc(fsize + 1);
            fread(string, fsize, 1, f);
            fclose(f);
            
            struct qs_file *qs_root = NULL;
            
            quicksand_do(string, fsize, quicksand_build_message("root", NULL, &qs_root, QS_FILE_CHILD), &qs_root);
            
            if (qs_root == NULL) {
                printf("skip\n");
                tinydir_next(&dir);
                continue;
            }
            
            
            
            assert(qs_root != NULL);
            

            if (raw == 1 || json == 0) {
                char *buffer = malloc(QS_MAX_BUFFER);
                buffer[0] = '\0';
                quicksandGraph(buffer, QS_MAX_BUFFER, 0, qs_root);
                printf("%s\n", buffer);
            }
            
            if (json == 1) {
                char *buffer2 = malloc(QS_MAX_BUFFER);
                buffer2[0] = '\0';
                jwOpen( buffer2, QS_MAX_BUFFER, JW_OBJECT, JW_PRETTY );
                quicksand_json(buffer2, QS_MAX_BUFFER, 0, qs_root, FALSE);
                //jwEnd();
                int err;
                err=jwClose();
                if( err != JWRITE_OK )
                    printf( "Error: %s at function call %d\n", jwErrorToString(err), jwErrorPos() );
                
                printf("%s\n", buffer2);
            }
            
            
            if (drop == 1)
                quicksandDropFiles(qs_root, &qs_root);

            if (objects == 1)
                quicksandDropObjects(qs_root, &qs_root);
            


            //quicksandGraph(0, qs_root);
            quicksandReset(&qs_root);

            printf("\n");
            free(string);
        }
        tinydir_next(&dir);
        
    }
    //quicksandDestroy();
    tinydir_close(&dir);

    
    
    
    
    
}

void printHelp(char *self) {
    printf("Please specify a file or directory to process:\n");
    printf("  > %s [options] malware.doc | dir\n\n", self);
    printf("  Options:\n");
    printf("     -h or --help: this message\n");
    printf("     -j or --json: output json data\n");
    printf("     -m or --math: try math ciphers\n");
    printf("     -n or --not: try bitwise not\n");
    printf("     -r or --raw: output proprietary text\n");
    printf("     -d or --drop: drop extracted executables\n");
    printf("     -o or --objects: drop all objects\n");
    printf("     -p or --out: [dir] directory to write dropped files\n");
    printf("     -y or --yara: skip yara scan for general / malware identification\n");
    printf("\n");
    
    printf("\nUse the QS environment variable to point to directory\nwith the quicksand-X.yara files:\n");
    printf(" > export QS=/users/analyst/quicksand\n");
    printf("\nRule filenames:\n   quicksand_exe.yara: Executable detection\n");
    printf("   quicksand_exploits.yara: CVE Signatures and active content\n   quicksand_general.yara: Malware families on decoded executables\n");

}


int main (int argc, char *argv[])
{
    FILE *f;
    struct stat *s=malloc(sizeof(struct stat));
    
    //printf("argv[0] = %s\n",argv[0]);
    
    //printf("getenv(QS) = %s\n", getenv("QS"));
    if (getenv("QS") != NULL) {
        char *expyara = malloc(4096);
        snprintf(expyara, 4096, "%s%s%s", getenv("QS"), "/", QUICKSAND_EXPLOITS_YARA);
        QUICKSAND_EXPLOITS_YARA = expyara;
        
        char *exeyara = malloc(4096);
        snprintf(exeyara, 4096, "%s%s%s", getenv("QS"), "/", QUICKSAND_EXE_YARA);
        QUICKSAND_EXE_YARA = exeyara;

        char *generalyara = malloc(4096);
        snprintf(generalyara, 4096, "%s%s%s", getenv("QS"), "/", QUICKSAND_GENERAL_YARA);
        QUICKSAND_GENERAL_YARA = generalyara;

        if (!file_exists(QUICKSAND_EXPLOITS_YARA) || !file_exists(QUICKSAND_EXE_YARA)) {
            printf("Yara path in QS env variable does not exist.\n%s\n%s\n", QUICKSAND_EXPLOITS_YARA, QUICKSAND_EXE_YARA);
            exit(1);
        }
    
    } else if (!file_exists(QUICKSAND_EXPLOITS_YARA) || !file_exists(QUICKSAND_EXE_YARA)) {
        printf("Unable to locate yara signatures. Use QS environment variable to set directory path.\n%s\n%s\n", QUICKSAND_EXPLOITS_YARA, QUICKSAND_EXE_YARA);
        exit(1);
    }
    
    if (getenv("QSDIR") != NULL) {
        char *qsdir = malloc(4096);
        snprintf(qsdir, 4096, "%s", getenv("QSDIR"));
        QUICKSAND_OUT_DIR = qsdir;
    }

    
    int i,json=0,raw=0,drop=0,objects=0;
    char *target = NULL;
    

    for (i=1; i < argc; i++) {
        if (strstr(argv[i], "-h") || strstr(argv[i], "--help") ) {
            printHelp(argv[0]);
        } else if (strstr(argv[i], "-j") || strstr(argv[i], "--json") ) {
            json=1;
        } else if (strstr(argv[i], "-r") || strstr(argv[i], "--raw") ) {
            raw=1;
        } else if (strstr(argv[i], "-d") || strstr(argv[i], "--drop") ) {
            drop=1;
        } else if (strstr(argv[i], "-o") || strstr(argv[i], "--objects") ) {
            objects=1;
        } else if (strstr(argv[i], "-n") || strstr(argv[i], "--not") ) {
            QUICKSAND_NOT = 1;
        } else if (strstr(argv[i], "-m") || strstr(argv[i], "--math") ) {
            QUICKSAND_MATH = 1;
        } else if (strstr(argv[i], "-y") || strstr(argv[i], "--yara") ) {
            QUICKSAND_GENERAL_YARA_RUN = 0;
        } else if (strstr(argv[i], "-p") || strstr(argv[i], "--out") ) {
            if (i+1 < argc) {
                
                char *qsdir = calloc(4096, 1);
                snprintf(qsdir, 4096, "%s", argv[i+1]);
                QUICKSAND_OUT_DIR = qsdir;
                i++;
            }
        
        } else {
            target = argv[i];
        }
        
    }
    
    


    
    if (argc > 1) {
        
        quicksandInit();

        if(target != NULL && stat(target,s) == 0 )
        {

            if( s->st_mode & S_IFDIR )
            {
                //handle directory
                qs_do_directory(target, raw, json, drop, objects);

                
            }
            else if( s->st_mode & S_IFREG )
            {
                //run file
                f = fopen(target, "rb");
                
           
                if( f == NULL )
                {
                    perror("Error while opening the file.\n");
                    exit(EXIT_FAILURE);
                }
                setbuf(stdout, NULL);
                
                fseek(f, 0, SEEK_END);
                long fsize = ftell(f);
                fseek(f, 0, SEEK_SET);
                
                unsigned char *string = malloc(fsize + 1);
                fread(string, fsize, 1, f);
                fclose(f);
                
                struct qs_file *qs_root = NULL;

                
                quicksand_do(string, fsize, quicksand_build_message("root", NULL, &qs_root, QS_FILE_CHILD), &qs_root);
                if (qs_root != NULL) {
                
                    if (raw == 1 || json == 0) {
                        char *buffer = malloc(QS_MAX_BUFFER);
                        buffer[0] = '\0';
                        quicksandGraph(buffer, QS_MAX_BUFFER, 0, qs_root);
                        printf("%s\n\n\n", buffer);
                    }

                    if (json == 1) {
                        char *buffer2 = malloc(QS_MAX_BUFFER);
                        buffer2[0] = '\0';
                        jwOpen( buffer2, QS_MAX_BUFFER, JW_OBJECT, JW_PRETTY );
                        quicksand_json(buffer2, QS_MAX_BUFFER, 0, qs_root, FALSE);
                        //jwEnd();
                        int err;
                        err=jwClose();
                        if( err != JWRITE_OK )
                            printf( "Error: %s at function call %d\n", jwErrorToString(err), jwErrorPos() );

                        printf("%s\n", buffer2);
                    }
                

                    if (drop == 1)
                        quicksandDropFiles(qs_root, &qs_root);

                    if (objects == 1)
                        quicksandDropObjects(qs_root, &qs_root);
                    
                    

                    quicksandReset(&qs_root);


                    free(string);
                    free(s);
                   
                }
            }
        } else {
            printf("nothing to do\n");
        }
        quicksandDestroy();

    } else {
        printHelp(argv[0]);
    }

    return 0;
}


