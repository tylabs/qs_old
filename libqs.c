/* Copyright (c) 2016, 2017 Tyler McLellan  TyLabs.com
 * @tylabs
 * QuickSand.io - Document malware forensics tool
 *
 * File libqs.c   May 24 2017
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


#include "libqs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include <zip.h>
#include <zlib.h>
#include "sha2.c"
#include "sha1.c"
#include "md5.c"
#include "jWrite.c"
#include <yara.h>

//#include <libolecf.h> //2.0 macro decompression
//#include "lznt1.c" //2.0 macro decompression


#define KMP_MAX 1024


#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
#endif

#ifndef CHUNK
#define CHUNK 16384
#endif

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

#pragma GCC diagnostic ignored "-Wdeprecated-declarations" //for macosx use of openssl libs

#define QS_FILE_CHILD 1
#define QS_FILE_NEXT 2

//#define DEBUG 1



size_t snprintfcat(char* buf, size_t bufSize, char const* fmt, ...) {
    size_t result;
    va_list args;
    size_t len = strnlen( buf, bufSize);
    
    va_start( args, fmt);
    result = vsnprintf( buf + len, bufSize - len, fmt, args);
    va_end( args);
    return result + len;
}


/* Converts a hex character to its integer value */
char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(const char *str) {
    char *pstr = (char *) str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
        *pbuf++ = *pstr;
        else if (*pstr == ' ')
        *pbuf++ = '+';
        else
        *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

char *str_escape(const char *str) {
    char *pstr = (char *) str, *buf = malloc(strlen(str) * 2 + 1), *pbuf = buf;
    while (*pstr) {
        if (*pstr == '\\') {
            *pbuf++ = '\\';
            *pbuf++ = *pstr;
        } else
            *pbuf++ = *pstr;
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}


/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(const char *str) {
    char *pstr = (char *) str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}



struct qs_message* quicksand_build_message(const char* identifier, struct qs_file *parent, struct qs_file **qs_root, int rel) {
    
    struct qs_message *newone = malloc(sizeof(struct qs_message));
    newone->identifier = identifier;
    newone->parent = parent;
    newone->qs_root = *qs_root;
    newone->rel = rel;
    return newone;
}

int quicksandDedup(struct qs_file *qs_file_iterator, const char *sha256) {
    if (qs_file_iterator == NULL)
        return FALSE;
    
    
    if (qs_file_iterator->sha256 != NULL && strstr(qs_file_iterator->sha256, sha256))
        return TRUE;
        
    if (qs_file_iterator->next != NULL)
        if (quicksandDedup(qs_file_iterator->next, sha256))
            return TRUE;
    if (qs_file_iterator->child != NULL)
        if (quicksandDedup(qs_file_iterator->child, sha256))
            return TRUE;
    
    return FALSE;
}


void quicksandGraph(char *buffer, int buf_len, int depth, struct qs_file *qs_file_iterator) {
    if (qs_file_iterator == NULL)
        snprintfcat(buffer, buf_len, "iterator is null\n");
    if (qs_file_iterator->identifier == NULL)
        snprintfcat(buffer, buf_len, "identifier is null\n");
    if (qs_file_iterator->count > 0) {
    
        snprintfcat(buffer, buf_len, "%*s" "-%d> %s {%d}\n", depth+1, " ", depth, qs_file_iterator->identifier, qs_file_iterator->count);
        
    
        if (qs_file_iterator->hits != NULL) {
            struct qs_hit *qs_hit_iterator;
            snprintfcat(buffer, buf_len, "%*s" "md5:%s\n", depth+2, " ", qs_file_iterator->md5);
            snprintfcat(buffer, buf_len, "%*s" "sha1:%s\n", depth+2, " ", qs_file_iterator->sha1);
            snprintfcat(buffer, buf_len, "%*s" "sha256:%s\n", depth+2, " ", qs_file_iterator->sha256);
            snprintfcat(buffer, buf_len, "%*s" "sha512:%s\n", depth+2, " ", qs_file_iterator->sha512);
            snprintfcat(buffer, buf_len, "%*s" "head:%s\n", depth+2, " ", qs_file_iterator->head);
            if(qs_file_iterator->parent != NULL)
                snprintfcat(buffer, buf_len, "%*s" "parentsha256:%s\n", depth+2, " ", qs_file_iterator->parent->sha256);
                
            snprintfcat(buffer, buf_len, "%*s" "size:%lu\n", depth+2, " ", qs_file_iterator->data_len);
    
            for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                snprintfcat(buffer, buf_len, "%*s" "%s:%s\n", depth+2, " ",qs_hit_iterator->name, qs_hit_iterator->value);
            }
            snprintfcat(buffer, buf_len, "%*s" "%s:%s\n\n", depth+2, " ",qs_hit_iterator->name, qs_hit_iterator->value);
        }
    }

    if (qs_file_iterator->next != NULL)
        quicksandGraph(buffer, buf_len, depth, qs_file_iterator->next);
    if (qs_file_iterator->child != NULL)
        quicksandGraph(buffer, buf_len, depth+1, qs_file_iterator->child);
    
    
}


char hashString(const char *str, const char *content) {
    char set[62] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    int i, t=0, l;
    
    for(i=0; i < strlen(str); i++){
        t += str[i];
    }
    for(i=0; i < strlen(content); i++){
        t += content[i];
    }
    
    return set[t % 62];
}

char hashSize(long unsigned s) {
    char set[62] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    int i, t=0, l;
    
    
    t = s / 49999;
    return set[t % 62];
}


void quicksandStructural(char *buffer, int buf_len, int depth, struct qs_file *qs_file_iterator) {
    if (qs_file_iterator == NULL)
        snprintfcat(buffer, buf_len, "iterator is null\n");
    if (qs_file_iterator->identifier == NULL)
        snprintfcat(buffer, buf_len, "identifier is null\n");
    
    //if (qs_file_iterator->count > 0) {
        if (strcmp(qs_file_iterator->identifier,"xor") == 0) {
            struct qs_hit *qs_hit_iterator;
            const char *xor="0";
            for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                 if (strcmp(qs_hit_iterator->name,"xorkey") == 0 || strcmp(qs_hit_iterator->name,"xortkey") == 0)
                     xor = qs_hit_iterator->value;
            }

            snprintfcat(buffer, buf_len, "%c", hashString(qs_file_iterator->identifier,xor));
        } else if (strcmp(qs_file_iterator->identifier,"rol") == 0) {
            struct qs_hit *qs_hit_iterator;
            const char *rol="0";
                for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                    if (strcmp(qs_hit_iterator->name,"rol") == 0)
                        rol = qs_hit_iterator->value;
                }
                
                snprintfcat(buffer, buf_len, "%c", hashString(qs_file_iterator->identifier,rol));
        } else
            snprintfcat(buffer, buf_len, "%c", hashString(qs_file_iterator->identifier, qs_file_iterator->head));
        
        
     //}
    
    if (qs_file_iterator->next != NULL)
        quicksandStructural(buffer, buf_len, depth, qs_file_iterator->next);
    if (qs_file_iterator->child != NULL)
        quicksandStructural(buffer, buf_len, depth+1, qs_file_iterator->child);
    
    
}



void quicksand_json(char *buffer, int buflen, int depth, struct qs_file *qs_file_iterator, int inarray) {
    int b=0, c=0, d=0;
    
    if (qs_file_iterator == NULL) {
        //jwObj_null( "iterator is null");
        return;
    }
    if (qs_file_iterator->identifier == NULL) {
        //jwObj_null( "identifier is null");
        return;
    }
    
    if (inarray)
        jwArr_object();
    jwObj_string("identifier", str_escape(qs_file_iterator->identifier));
    if (qs_file_iterator->md5 != NULL)
        jwObj_string("md5", (char *)qs_file_iterator->md5);
    if (qs_file_iterator->sha1 != NULL)
        jwObj_string("sha1", (char *)qs_file_iterator->sha1);
    if (qs_file_iterator->sha256 != NULL)
        jwObj_string("sha256", (char *)qs_file_iterator->sha256);
    if (qs_file_iterator->sha512 != NULL)
        jwObj_string("sha512", (char *)qs_file_iterator->sha512);
    if (qs_file_iterator->head != NULL)
        jwObj_string("head", (char *)qs_file_iterator->head);
    jwObj_int( "size",  (int)qs_file_iterator->data_len);
    if(qs_file_iterator->parent != NULL && qs_file_iterator->parent->sha256 != NULL)
        jwObj_string("parentsha256", (char *)qs_file_iterator->parent->sha256);
    
    
    if (qs_file_iterator->count > 0) {
        if (qs_file_iterator->hits != NULL) {
            struct qs_hit *qs_hit_iterator;
            
            
            
            for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                if (strstr(qs_hit_iterator->name, "yara:exploits") != NULL)
                    b=1;
                else if (strstr(qs_hit_iterator->name, "yara:executable") != NULL)
                    c=1;
                else if (strstr(qs_hit_iterator->name, "yara:general") != NULL)
                    d=1;
            }
            if (strstr(qs_hit_iterator->name, "yara:exploits") != NULL)
                b=1;
            else if (strstr(qs_hit_iterator->name, "yara:executable") != NULL)
                c=1;
            else if (strstr(qs_hit_iterator->name, "yara:general") != NULL)
                d=1;
            
            if (b == 1){
                
                jwObj_array( "yara:exploits" );
                for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                    if (strstr(qs_hit_iterator->name, "yara:exploits") != NULL)
                        jwArr_string((char *)qs_hit_iterator->value);
                }
                if (strstr(qs_hit_iterator->name, "yara:exploits") != NULL)
                    jwArr_string((char *)qs_hit_iterator->value);
                jwEnd();
            }
            if (c == 1){
                
                jwObj_array( "yara:executable" );
                for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                    if (strstr(qs_hit_iterator->name, "yara:executable") != NULL)
                        jwArr_string((char *)qs_hit_iterator->value);
                }
                if (strstr(qs_hit_iterator->name, "yara:executable") != NULL)
                    jwArr_string((char *)qs_hit_iterator->value);
                jwEnd();
            }

            if (d == 1){
                
                jwObj_array( "yara:general" );
                for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                    if (strstr(qs_hit_iterator->name, "yara:general") != NULL)
                        jwArr_string((char *)qs_hit_iterator->value);
                }
                if (strstr(qs_hit_iterator->name, "yara:general") != NULL)
                    jwArr_string((char *)qs_hit_iterator->value);
                jwEnd();
            }

            for (qs_hit_iterator = qs_file_iterator->hits; qs_hit_iterator->next != NULL;   qs_hit_iterator = qs_hit_iterator->next) {
                if (strstr(qs_hit_iterator->name, "yara:exploits") == NULL && strstr(qs_hit_iterator->name, "yara:executable") == NULL && strstr(qs_hit_iterator->name, "yara:general") == NULL)
                    jwObj_string((char * )qs_hit_iterator->name, (char *)qs_hit_iterator->value);
            }
            if (strstr(qs_hit_iterator->name, "yara:exploits") == NULL && strstr(qs_hit_iterator->name, "yara:executable") == NULL && strstr(qs_hit_iterator->name, "yara:general") == NULL)
                jwObj_string((char *)qs_hit_iterator->name, (char *)qs_hit_iterator->value);
            
        }
    }
    
    
    if (qs_file_iterator->child != NULL) {
        //if (qs_file_iterator->child->hits == NULL)
        jwObj_array( "child" );
        quicksand_json(buffer, buflen, depth+1, qs_file_iterator->child, 1);
        
        //if (qs_file_iterator->child->hits == NULL)
        jwEnd();
        
    }
    
    //if (inarray && qs_file_iterator->count > 0 && qs_file_iterator->hits != NULL ) {
    if (inarray)
        jwEnd();
    //}
    
    
    if (qs_file_iterator->next != NULL) {
        quicksand_json(buffer, buflen, depth, qs_file_iterator->next, 1);
        
    }
    
    
}


const char* quicksandsha256(const unsigned char *data, unsigned long data_len) {
    SHA256_CTX	ctx256;
    
    SHA256_Init(&ctx256);
    SHA256_Update(&ctx256, data, data_len);
    
    char *sha256 = malloc(QUICKSAND_SHA256_SIZE*2+1);
    SHA256_End(&ctx256, sha256);
    return sha256;
}


void quicksandUnallocateHits(struct qs_hit *qs_hit_iterator) {
    
    if (qs_hit_iterator == NULL)
        return;
    
    if (qs_hit_iterator->next != NULL)
        quicksandUnallocateHits(qs_hit_iterator->next);

    qs_hit_iterator->next = NULL;
    
}


void quicksandUnallocateFiles(struct qs_file *qs_file_iterator) {
    
    if (qs_file_iterator == NULL)
        return;
    
    if (qs_file_iterator->next != NULL)
        quicksandUnallocateFiles(qs_file_iterator->next);
    if (qs_file_iterator->child != NULL)
        quicksandUnallocateFiles(qs_file_iterator->child);
    
    ////if (qs_file_iterator->data != NULL)
    ////    free((char *)  qs_file_iterator->data);
    ////if (qs_file_iterator->identifier != NULL)
    ////    free((char *) qs_file_iterator->identifier);
    qs_file_iterator->next = NULL;
    qs_file_iterator->child = NULL;
}


int intcmp(const void *aa, const void *bb)
{
    const int *a = aa, *b = bb;
    return (*a < *b) ? -1 : (*a > *b);
}


//dump drop files to disk
void quicksandDropFiles(struct qs_file *qs_file_iterator, struct qs_file **qs_root) {
    int c, locations[KMP_MAX], confirmed[KMP_MAX], conf=0, k, i;

    

    unsigned const char heads[6][32] = {"\xCA\xFE\xBA\xBE",
        "\xCE\xFA\xED\xFE",
        "\x7F\x45\x4C\x46",
        "\x7B\x5crt",
        ".vbs\x00",
        "\x25\x50\x44\x46",
        //"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    };
    
    unsigned const char eofs[3][32] = {"\x0A\x25\x25\x45\x4F\x46\x0A",
        "\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A",
        "\x0D\x25\x25\x45\x4F\x46\x0D"};
    
    
    if (qs_file_iterator == NULL)
        return;
    
    //scan current
    if (qs_file_iterator->data != NULL) {
        //printf("doing %s\n", qs_file_iterator->identifier);
        
        
        //MZ header
        unsigned const char header[] = "MZ";
        c = KMPSearch(header, 2, qs_file_iterator->data, (int) qs_file_iterator->data_len, locations);
        if (c > 0) {
            //printf ("%s: found %d MZ hits\n", qs_file_iterator->identifier, c);
            for (i=0; i < c; i++) {
    
                if (qs_file_iterator->data[locations[i]+78] == 'T' && qs_file_iterator->data[locations[i]+79] == 'h' && qs_file_iterator->data[locations[i]+80] == 'i' && qs_file_iterator->data[locations[i]+81] == 's') {
                    //printf ("good hit for executable header @%d - begin drop sequence alpha 001\n", locations[i]);
                    confirmed[conf++] = locations[i];
                }
            }
        }
                
        
        //MZ header transposed
        unsigned const char headertr[] = "ZM";
        c = KMPSearch(headertr, 2, qs_file_iterator->data, (int) qs_file_iterator->data_len, locations);
        if (c > 0) {
            //printf ("%s: found %d ZM hits\n", qs_file_iterator->identifier, c);
            for (i=0; i < c; i++) {
            
                if (qs_file_iterator->data[locations[i]+78] == 'h' && qs_file_iterator->data[locations[i]+79] == 'T' && qs_file_iterator->data[locations[i]+80] == 's' && qs_file_iterator->data[locations[i]+81] == 'i') {
                    //printf ("good hit for transposed exe header @%d - begin drop sequence alpha 001\n", locations[i]);
                    confirmed[conf++] = locations[i];
                }
            }
        }
        
        
        
        for ( i = 0;  i < (sizeof(heads)/sizeof(heads[0]) ) ; i++ ) {
            //printf("start\n");
            c = KMPSearch(heads[i], (int) strnlen((char *) heads[i],32), qs_file_iterator->data, (int) qs_file_iterator->data_len, locations);
            //printf("true key %d %s [%d]\n", i, key_db[i], c);
            
            for(k=0; k < c; k++) {
                if (locations[k] != 0 || qs_file_iterator != *qs_root) {
                    //printf("sub header location is %d for %d\n", locations[k], i);
                    confirmed[conf++] = locations[k];
                }
            }
        
        }

        
        for ( i = 0;  i < (sizeof(eofs)/sizeof(eofs[0]) ) ; i++ ) {
            //printf("ends\n");
            c = KMPSearch(eofs[i], (int) strnlen((char *) eofs[i], 32), qs_file_iterator->data, (int) qs_file_iterator->data_len, locations);
            
        }


        qsort(confirmed, conf, sizeof(int), intcmp);
        
        //take list of all hits
        for (i=0; i < conf; i++) {
            //printf("xheader at %d\n", confirmed[i]);

            char *nname = malloc(256);
            snprintf(nname, 256, "%s%s_%s_%d.qsdump", QUICKSAND_OUT_DIR, (*qs_root)->sha256, qs_file_iterator->sha256, i+1);
            
            FILE *out = fopen(nname,"wb");
            
            int end = (int ) qs_file_iterator->data_len;
            
            if (i + 1 < conf)
                end = confirmed[i+1];
            end -= confirmed[i];
            if (QUICKSAND_MAX_DROP > 0 && end  > QUICKSAND_MAX_DROP)
                end = QUICKSAND_MAX_DROP;
            //printf("%s dump %s of %d bytes\n", qs_file_iterator->identifier, nname, end);
            fwrite(qs_file_iterator->data+confirmed[i], 1, end, out);
            fclose(out);
        }

        
    }
    
    //drop decoded executables

    if (qs_file_iterator->next != NULL)
        quicksandDropFiles(qs_file_iterator->next, qs_root);
    if (qs_file_iterator->child != NULL)
        quicksandDropFiles(qs_file_iterator->child, qs_root);
    
}


void quicksandDropObjects(struct qs_file *qs_file_iterator, struct qs_file **qs_root) {
   
    
    if (qs_file_iterator == NULL)
        return;
    
    //scan current
    if (qs_file_iterator->data != NULL) {
        //printf("doing %s\n", qs_file_iterator->identifier);
        
        
        if (qs_file_iterator != *qs_root) {
            
            char *nname = malloc(256);
            snprintf(nname, 256, "%s%s_%s.qsobj", QUICKSAND_OUT_DIR, (*qs_root)->sha256, qs_file_iterator->sha256);
            
            FILE *out = fopen(nname,"wb");
            
            int end = (int ) qs_file_iterator->data_len;
            if (QUICKSAND_MAX_DROP > 0 && end > QUICKSAND_MAX_DROP)
                end = QUICKSAND_MAX_DROP;
       
            //printf("%s obj %s of %d bytes\n", qs_file_iterator->identifier, nname, end);
            
            fwrite(qs_file_iterator->data, 1, end, out);
            fclose(out);
            
            
            
        }
        
        
    }
    
    //drop object
    
    if (qs_file_iterator->next != NULL)
        quicksandDropObjects(qs_file_iterator->next, qs_root);
    if (qs_file_iterator->child != NULL)
        quicksandDropObjects(qs_file_iterator->child, qs_root);
    
}


void quicksandGeneralScan(struct qs_file *qs_file_iterator, struct qs_file **qs_root) {
    
    
    if (qs_file_iterator == NULL)
        return;
    
    //scan current
    if (qs_file_iterator->data != NULL) {
        quicksand_yara_mem(qs_file_iterator->data, qs_file_iterator->data_len, QUICKSAND_GENERAL_YARA, "general", quicksand_build_message(qs_file_iterator->identifier,qs_file_iterator,(qs_root),QS_FILE_CHILD) );
    }
    
    
    if (qs_file_iterator->next != NULL)
        quicksandGeneralScan(qs_file_iterator->next, qs_root);
    if (qs_file_iterator->child != NULL)
        quicksandGeneralScan(qs_file_iterator->child, qs_root);
    
}



void quicksandInit() {
    //malware_score=0;
    int result = yr_initialize();
    //qs_root = NULL;
    
    
    if (result != ERROR_SUCCESS)
        printf("error 1\n");

}

void quicksandReset(struct qs_file **qs_root) {
    quicksandUnallocateFiles(*qs_root);
    if (*qs_root != NULL)
        free(*qs_root);
    *qs_root = NULL;
    
}


void quicksandDestroy() {
    yr_finalize();

}

struct qs_hit* quickSandHit(const char *name, const char *value, long unsigned offset) {

    struct qs_hit *newHit = malloc(sizeof(struct qs_hit));
    newHit->name = name;
    newHit->value = value;
    newHit->offset = offset;
    newHit->next = NULL;
    
    return newHit;
}


                            

void quicksandStore(struct qs_file *target, const char *name1, const char *value1, long unsigned offset) {
    const char *name = strdup(name1);
    const char *value = strdup(value1);
    if (target == NULL)
        printf("warning target for store hit is null");
    else {
        
        if (target->hits == NULL) {
            target->hits = quickSandHit(name, value, offset);
            target->count++;
        } else {
            struct qs_hit *qs_hit_iterator;
            for(qs_hit_iterator = target->hits; qs_hit_iterator->next != NULL; qs_hit_iterator = qs_hit_iterator->next) {

                if (qs_hit_iterator == NULL) {
                    printf("warning target iterator for store hit is null");
                    break;
                }
                
            }

            qs_hit_iterator->next = quickSandHit(name, value, offset);
            target->count++;
        }
        
    }
    
}




int base64decode (char *in, size_t inLen, unsigned char *out, size_t *outLen) {
    char *end = in + inLen;
    char iter = 0;
    size_t buf = 0, len = 0;
    
    while (in < end) {
        unsigned char c = db64[*in++];
        
        switch (c) {
            case WHITESPACE: continue;   /* skip whitespace */
            case INVALID:    return 1;   /* invalid input, return error */
            case EQUALS:                 /* pad character, end of data */
                in = end;
                continue;
            default:
                buf = buf << 6 | c;
                iter++; // increment the number of iteration
                /* If the buffer is full, split it into bytes */
                if (iter == 4) {
                    if ((len += 3) > *outLen) return 1; /* buffer overflow */
                    *(out++) = (buf >> 16) & 255;
                    *(out++) = (buf >> 8) & 255;
                    *(out++) = buf & 255;
                    buf = 0; iter = 0;
                    
                }
        }
    }
    
    if (iter == 3) {
        if ((len += 2) > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 10) & 255;
        *(out++) = (buf >> 2) & 255;
    }
    else if (iter == 2) {
        if (++len > *outLen) return 1; /* buffer overflow */
        *(out++) = (buf >> 4) & 255;
    }
    
    *outLen = len; /* modify to reflect the actual output size */
    return 0;
}



int inf(const unsigned char *src, int srcLen, unsigned char *dst, int dstLen) {
    z_stream strm  = {0};
    strm.total_in  = strm.avail_in  = srcLen;
    strm.total_out = strm.avail_out = dstLen;
    strm.next_in   = (Bytef *) src;
    strm.next_out  = (Bytef *) dst;
    
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;
    
    int err = -1;
    int ret = -1;
    
    err = inflateInit2(&strm, -MAX_WBITS);
    if (err == Z_OK) {
        err = inflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END) {
            ret = strm.total_out;
        }
        else {
            inflateEnd(&strm);
            return err;
        }
    }
    else {
        inflateEnd(&strm);
        return err;
    }
    
    inflateEnd(&strm);
    return ret;
}

int unc(const unsigned char *src, int srcLen, unsigned char *dst, int dstLen) {
    z_stream strm  = {0};
    strm.total_in  = strm.avail_in  = srcLen;
    strm.total_out = strm.avail_out = dstLen;
    strm.next_in   = (Bytef *) src;
    strm.next_out  = (Bytef *) dst;
    
    strm.zalloc = Z_NULL;
    strm.zfree  = Z_NULL;
    strm.opaque = Z_NULL;
    
    int err = -1;
    int ret = -1;
    
    err = inflateInit(&strm);
    if (err == Z_OK) {
        err = inflate(&strm, Z_FINISH);
        if (err == Z_STREAM_END) {
            ret = strm.total_out;
        }
        else {
            inflateEnd(&strm);
            return err;
        }
    }
    else {
        inflateEnd(&strm);
        return err;
    }
    
    inflateEnd(&strm);
    return ret;
}


unsigned char* quicksand_parse_rtf(const unsigned char *data, unsigned long data_len, unsigned long *new_len)
{
    unsigned char* entity = malloc(data_len);
    int i, j=0;
    unsigned long k=0;
    //printf("looking for hex blocks\n");
    for (i = 0; i < data_len; i++) {
        
        if (data[i] == '\\') {
            //store this and next
            //advance
            
            //follow the white rabbit and remove control words
            j = 0;
            for (j = i+1; j < data_len; j++){
                if (isspace(data[j])) {
                    break;
                } else if ((data[j] == '{' || data[j] == '}') && data[j-1] != '\\' ) {
                    j--;
                    break;
                }
            }
            i = j;
            
            
            // for {\* ignore non standard control words
        } else if (data[i] == '{' && data[i+1] == '\\' && data[i+2] == '*' ) {
            //follow the white rabbit and remove control words
            if (data[i+1] == '\\') {
                j = 0;
                for (j = i+2; j < data_len; j++){
                    if ((data[j] == '{' || data[j] == '}') && data[j-1] != '\\' ) {
                        j--;
                        break;
                    }
                }
                i = j;
            }
        } else if (data[i] == '{' ) {
            //follow the white rabbit and remove control words
            if (data[i+1] == '\\') {
                j = 0;
                for (j = i+2; j < data_len; j++){
                    if (isspace(data[j])) {
                        break;
                    } else if ((data[j] == '{' || data[j] == '}') && data[j-1] != '\\' ) {
                        j--;
                        break;
                    }
                }
                i = j;
            }
        } else if (data[i] == '}' ) {
            //do nothing
            
        } else if (iscntrl(data[i]) && data[i] != 0x0a && data[i] != 0x09 && data[i] != 0x0d &&  data[i] != '\\' ) {
            //do nothing
            j = 0;
            for (j = i+2; j < data_len; j++){
                if ((data[j] == '{' || data[j] == '}') && data[j-1] != '\\' ) {
                    j--;
                    break;
                }
            }
            i = j;
            
        } else if (!isgraph(data[i])) {
            //do nothing
            
        } else {
            //store this
            entity[k] = data[i];
            k++;
        }
        
        
        
    }
    *new_len = k;
    return (entity);
    
}





void quicksand_extract_blocks(const unsigned char *data, unsigned long data_len, struct qs_message *source, struct qs_file **qs_root)
{
    unsigned char* entity = malloc(data_len);
    int i, j=0,k=0;;
    //printf("looking for hex blocks\n");
    for (i = 0; i < data_len; i++) {
        if (isxdigit(data[i]) ) {
            entity[j] = data[i];
            j++;
        } else if (data[i] == 0x0a || data[i] == 0x09 || data[i] == 0x0d ||  data[i] == '\\' || data[i] == '\'') { //data[i] == 0x20 ||
            //no nothing
            k++;
        } else {
            if (j / 2 >= QUICKSAND_MIN_FILE_SIZE) {
                //printf("found hex block of %d size at %d\n", j, i-j-k);
                //send here
                unsigned char *decoded_rtf = malloc(j+1);
                hex2str(entity, j, decoded_rtf);
                char *str = malloc(20);
                snprintf(str, 20, "%s%d", "hex@", i-j-k);
                
                
                quicksand_do(decoded_rtf, j/2, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
                //free(decoded_rtf);
            }
            j=0;
            k=0;
        }
    }
    //check if still in block and send here too
    if (j / 2 >= QUICKSAND_MIN_FILE_SIZE) {
        //printf("found hex block of %d size at %d\n", j, data_len-j-k);
        unsigned char *decoded_rtf = malloc(j+1);
        hex2str(entity, j, decoded_rtf);
        char *str = malloc(20);
        snprintf(str, 20, "%s%lu", "hex@", data_len-j-k);
        
        quicksand_do(decoded_rtf, j/2, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
        //free(decoded_rtf);
    }
    free(entity);

}


void quicksand_extract_ezip(const unsigned char *data, unsigned long data_len, struct qs_message *source, struct qs_file **qs_root)
{
    unsigned char* entity = malloc(data_len+1);
    int i, j=0,start=0, noheader=0;
    
    
    //printf("looking for ezip blocks\n");
    if(data_len < 1024)
    return;
    
    for (i = 0; i < 1024; i++) {
        if (data[i] == 0xD0 && data[i+1] == 0xCF && data[i+2] == 0x11) {
            //printf("found docfile header at %d\n",i);
            start = i;
            noheader = 1;
            break;
        }
        
        if (i == 1023)
        start = 0;
    }
    
    //if (!noheader) {
    
    for (i = start; i < data_len; i++) {
        
        
        if (data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 0x03 && data[i+3] == 0x04) {
            
            for (j = 0; j < data_len-i-3; j++) {
                entity[j] = data[i+j];
            }
            //printf("Found ezip block in %s at %d of %d bytes\n", source->identifier, i, j);
            entity[j+1] = '\0';
            char *str = malloc(20);
            snprintf(str, 20, "%s%d", "zip@", i);
            quicksand_do(entity, j, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
            break;
            
        }
    }
    /*} else {
     for (i = start; i < data_len; i+=512) {
     
     
     if (data[i] == 'P' && data[i+1] == 'K' && data[i+2] == 0x03 && data[i+3] == 0x04) {
     
     for (j = 0; j < data_len-i-1; j++) {
     entity[j] = data[i+j];
     }
     //printf("Found ezip block in %s at %d of %d bytes\n", source->identifier, i, j);
     entity[j+1] = '\0';
     char *str = malloc(20);
     snprintf(str, 20, "%s%d", "zip@", i);
     quicksand_do(entity, j, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
     
     
     }
     }
     
     
     
     
     }*/
    //free(entity);
    
}

void quicksand_extract_zlib78(const unsigned char *data, unsigned long data_len, const struct qs_message *source, struct qs_file **qs_root)
{
    unsigned char *marker = malloc(5);
    int c = 0,k,j,res;
    int locations[KMP_MAX];
    FILE *fp;
    
    unsigned char marker_hex[]= "0000789c";
    
    //check for d0cf11 oleheader
    if (data_len < 500 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11)
        return;
    
    //printf("looking for zlib header blocks\n");
    hex2str(marker_hex, 8, marker);
    marker[4] = '\0';
    
    
    //find positions of 0000789c
    c = KMPSearch(marker, 4, data, (int) data_len, locations);
    
    //looop through and decode
    for(k=0; k < c; k++) {
        //printf("zlib location is %d\n", locations[k]);
        int end = (int) data_len;
        if (k+2 < c)
            end = locations[k+2];
        //printf("block ends at %d\n", end);
        //take from +4 to 54 and write to file and try decode
        for(j=4; j < 5; j++){
            unsigned char *buffer = malloc(end-locations[k]-3);
            buffer = memcpy(buffer, data+locations[k]+j, end-locations[k]-j); //j is at least 4
            
            unsigned char *destbuffer  = malloc(QUICKSAND_MAX_EXPAND);
            res = inf((const unsigned char*)buffer, end-locations[k]-4, destbuffer, QUICKSAND_MAX_EXPAND);
            
            free(buffer);
            if(res > 64) {
                //printf("deflate worked %d\n", j);
                //printf("zlib location is %d\n", locations[k]);
                
                
                char *str = malloc(20);
                snprintf(str, 20, "%s%d", "zlib@", locations[k]);
                
                quicksand_do(destbuffer, res, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
                
                continue;
                
            }
        }
        
    }
    
    
    free(marker);
}




void quicksand_extract_ExOleObjStgCompressedAtom(const unsigned char *data, unsigned long data_len, const struct qs_message *source, struct qs_file **qs_root)
{
    unsigned char *marker = malloc(5);
    int c = 0,k,j,res;
    int locations[KMP_MAX];
    //marker 10001110 ExOleObjStgCompressedAtom
    unsigned char marker_hex[]= "10001110";
    
    //check for d0cf11 oleheader
    if (data_len < 500 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11)
        return;
    
    //printf("looking for ExOleObjStgCompressedAtom blocks\n");
    hex2str(marker_hex, 8, marker);
    marker[4] = '\0';
    
    
    //find positions of 10001110
    c = KMPSearch(marker, 4, data, (int) data_len, locations);
    
    //loop through and decode
    for(k=0; k < c; k++) {
        //printf("ExOleObjStgCompressedAtom location is %d\n", locations[k]);
        int end = (int) data_len;
        if (k+1 < c)
            end = locations[k+1];
        //printf("block ends at %d\n", end);
        //take from +4 to 54 and write to file and try decode
        for(j=4; j < 54; j++){
            unsigned char *buffer = malloc(end-locations[k]-3);
            buffer = memcpy(buffer, data+locations[k]+j, end-locations[k]-j); //j is at least 4
            
            unsigned char *destbuffer  = malloc(QUICKSAND_MAX_EXPAND);
            res = inf((const unsigned char*)buffer, end-locations[k]-4, destbuffer, QUICKSAND_MAX_EXPAND);
            
            free(buffer);
            if(res > 64) {
                //printf("deflate worked got %d\n", res);
                //printf("ok ExOleObjStgCompressedAtom location is %d\n", locations[k]);
                
                
                char *str = malloc(20);
                snprintf(str, 20, "%s%d", "atom@", locations[k]);
                
                quicksand_do(destbuffer, res, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
                
                continue;
                
            } else
                free(destbuffer);
        }
        
    }
    free(marker);
}



int quicksand_unzip(const unsigned char *data, unsigned long data_len, struct qs_message *source, struct qs_file **qs_root)
{
    struct zip *za;
    struct zip_file *zf;
    struct zip_stat sb;
    char buf[100];
    int i;
    unsigned long len;
    struct zip_source *src;
    struct zip_error error;
    
    zip_error_init(&error);
    // create source from buffer
    if ((src = zip_source_buffer_create((void *)data, data_len, 1, &error)) == NULL) {
        //fprintf(stderr, "can't create source: %s\n", zip_error_strerror(&error));
        zip_error_fini(&error);
        return 1;
    }
    //open zip archive from source
    if ((za = zip_open_from_source(src, 0, &error)) == NULL) {
        //fprintf(stderr, "can't open zip from source: %s\n", zip_error_strerror(&error));
        zip_source_free(src);
        zip_error_fini(&error);
        return 1;
    }
    zip_error_fini(&error);
    
    
    for (i = 0; i < zip_get_num_entries(za, 0); i++) {
        if (zip_stat_index(za, i, 0, &sb) == 0) {
            //printf("==================\n");
            len = strnlen(sb.name, 256);
            //printf("Name: [%s], ", sb.name);
            //printf("Size: [%llu], ", sb.size);
            //printf("mtime: [%u]\n", (unsigned int)sb.mtime);
            
            zf = zip_fopen_index(za, i, 0);
            if (!zf) {
                //fprintf(stderr, "can't open file\n");
                continue;
            }
            
            
            unsigned char * zcontent = malloc(sb.size);
            zip_fread(zf, zcontent, sb.size);
            
            char* str = malloc(261);
            snprintf(str, 261, "%s%s", "zip:", sb.name);
            
            quicksand_do(zcontent, sb.size, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
            zip_fclose(zf);
            
        }
    }
    zip_source_close(src);
    
    return 0;
}




short getMax(int a[])
{
    int i, max=0;
    short key = 0;
    for (i=0; i < 256; i++)
    {
        if (a[i] > max)
        {
            max = a[i];
            key = i;
        }
    }
    return(key);
}

int get_substr_count(unsigned char * haystack, unsigned char *needle)
{
    int count = 0;
    const char *tmp = (char *)haystack;
    while( (tmp = (char *) strstr( (char *) tmp, (char *) needle) )){
        printf( "Position: %d\n", (int)(tmp-(char*)haystack));
        ++count;
    }
    return count;
}


unsigned hex2dec(unsigned char *hex)
{
    int a;
    int b=0;
    
    while (1)
    {
        a=*hex++;
        if (a >= '0' && a <= '9') a-='0';
        else if (a >= 'a' && a <= 'f') a-='a'-10;
        else if (a >= 'A' && a <= 'F') a-='A'-10;
        else return b;
        
        if (*hex) b=(b + a) * 16;
        else return (b + a);
    }
}




void xor_crypt(const unsigned char *key, int key_len, unsigned char *data, unsigned long data_len)
{
    int i;
    for (i = 0; i < data_len; i++)
        data[i] ^= key[ i % key_len ];
}


void xor_crypt_out(const unsigned char *key, int key_len, const unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;
    for (i = 0; i < data_len; i++)
        dataout[i] = data[i] ^ key[ i % key_len ];
}


void xorla_crypt(unsigned char *data, unsigned long data_len)
{
    int i;

    for (i = 0; i < data_len-1; i++)
        data[i] ^= data[i+1];
}


void xorla_crypt_out(unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;
    for (i = 0; i < data_len-1; i++)
        dataout[i] = data[i] ^ data[i+1];
}



void rol_crypt_out(int offset, const unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;
    for (i = 0; i < data_len; i++)
        dataout[i] = data[i] << offset | data[i] >> invert[offset];
}


void rol_crypt(int offset, unsigned char *data, unsigned long data_len)
{
    int i;

    for (i = 0; i < data_len; i++)
        data[i] =   data[i] << offset | data[i] >> invert[offset];
}

void ror_crypt_out(int offset, const unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;

    for (i = 0; i < data_len; i++)
        dataout[i] = (unsigned char) (data[i] >> offset) | (unsigned char) (data[i] >> invert[offset]);
}


void ror_crypt(int offset, unsigned char *data, unsigned long data_len)
{
    int i;

    for (i = 0; i < data_len; i++)
        data[i] =   (unsigned char) (data[i] >> offset) | (unsigned char) (data[i] >> invert[offset]);
}


void untranspose_out(int offset, unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;

    for (i = 0; i < data_len - data_len % 2 ; i+=2) {
        dataout[i] = data[i+1];
        dataout[i+1] = data[i];
    }

}


void untranspose(int offset, unsigned char *data, unsigned long data_len)
{
    unsigned char a;
    int i;

    for (i = 0; i < data_len - data_len % 2 ; i+=2) {
        a = data[i];
        data[i] = data[i+1];
        data[i+1] = a;
    }
}


void add_crypt_out(int offset, const unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;
    for (i = 0; i < data_len; i++)
        dataout[i] = (data[i] + offset) % 256;
}


void add_crypt(int offset, unsigned char *data, unsigned long data_len)
{
    int i;
    
    for (i = 0; i < data_len; i++)
        data[i] = (data[i] + offset) % 256;
}



//xor lookahead alg
unsigned char * xorAheadString(const unsigned char *data, unsigned long data_len) {
    unsigned char * tryit = malloc(data_len);
    int i;
    
    for (i = 0; i < data_len-1; i++) {
        tryit[i] =  (unsigned char) (data[i] ^ data[i+1]) ;
    }
    
    return tryit;
}






void not_crypt_out(const unsigned char *data, unsigned long data_len, unsigned char *dataout)
{
    int i;

    for (i = 0; i < data_len; i++)
        dataout[i] = (unsigned char) ~data[i] ;
}


void not_crypt(unsigned char *data, unsigned long data_len)
{
    int i;

    for (i = 0; i < data_len; i++)
        data[i] =   (unsigned char) ~data[i] ;
}





int quicksand_rol(const unsigned char *data, unsigned long data_len, struct qs_message *source)
{
    int i;
    
    for (i = 1; i <=7; i++){
        unsigned char * tryit = malloc(data_len);
        
        rol_crypt_out(i, data, data_len, tryit);
        
        char *str = malloc(256);
        snprintf(str, 256, "%s:rol", source->identifier);
        char *str2 = malloc(256);
        snprintf(str2, 256, "%d", i);
        
        struct qs_file *tryfile = malloc(sizeof(struct qs_file));
        tryfile->next = NULL;
        tryfile->parent = source->parent;
        tryfile->child = NULL;
        tryfile->hits = NULL;
        tryfile->md5 = NULL;
        tryfile->sha1 = NULL;
        tryfile->sha256 = NULL;
        tryfile->sha512 = NULL;
        tryfile->head = NULL;
        
        tryfile->count = 0;
        struct qs_message *trymessage = quicksand_build_message("rol", tryfile, (&source->qs_root), QS_FILE_CHILD);
        tryfile->identifier = trymessage->identifier;
        int before =  tryfile->count;

        
        quicksand_yara_mem(tryit, data_len, QUICKSAND_EXE_YARA, "executable", quicksand_build_message(str,tryfile,(&source->qs_root),QS_FILE_CHILD) );
        
        if (tryfile->count > before) {
            char *keyla = "1";
            
            if (source->qs_root != NULL && quicksandDedup(source->qs_root, quicksandsha256(tryit, data_len)))
                return 0;
            
            
            insertQSFile(tryfile, tryit, data_len, source);
            quicksand_hash(tryit, data_len, trymessage);
            
            quicksandStore(tryfile, "rol", str2, i);
            return i;

        } else
            free(tryit);
        
        
    }

    return 0;
}


int quicksand_addition(const unsigned char *data, unsigned long data_len, struct qs_message *source)
{
    int i;
    
    for (i = 1; i <=255; i++){
        unsigned char * tryit = malloc(data_len);
        
        add_crypt_out(i, data, data_len, tryit);
        
        char *str = malloc(256);
        snprintf(str, 256, "%s:add", source->identifier);
        char *str2 = malloc(256);
        snprintf(str2, 256, "%d", i);
        
        struct qs_file *tryfile = malloc(sizeof(struct qs_file));
        tryfile->next = NULL;
        tryfile->parent = source->parent;
        tryfile->child = NULL;
        tryfile->hits = NULL;
        tryfile->md5 = NULL;
        tryfile->sha1 = NULL;
        tryfile->sha256 = NULL;
        tryfile->sha512 = NULL;
        tryfile->head = NULL;
        
        tryfile->count = 0;
        struct qs_message *trymessage = quicksand_build_message("add", tryfile, (&source->qs_root), QS_FILE_CHILD);
        tryfile->identifier = trymessage->identifier;
        int before =  tryfile->count;
        
        
        quicksand_yara_mem(tryit, data_len, QUICKSAND_EXE_YARA, "executable", quicksand_build_message(str,tryfile,(&source->qs_root),QS_FILE_CHILD) );
        
        if (tryfile->count > before) {
            char *keyla = "1";
            
            if (source->qs_root != NULL && quicksandDedup(source->qs_root, quicksandsha256(tryit, data_len)))
                return 0;
            
            
            insertQSFile(tryfile, tryit, data_len, source);
            quicksand_hash(tryit, data_len, trymessage);
            
            quicksandStore(tryfile, "add", str2, i);
            return i;
            
        } else
            free(tryit);
        
        
    }
    
    return 0;
}



void hex2str(unsigned char *hex, int hexlen, unsigned char *str)
{
    unsigned char a[4];
    int i,k=0;
    
    for(i=0; i < hexlen; i+=2)
    {
        a[0]=hex[i];
        a[1]=hex[i+1];
        a[2]='\0';
        str[k++]=hex2dec(a);
        
        
    }
    str[k]='\0';
    
}

/*Knuth-Morris-Pratt algorithm - textbook example slightly modified, source unknown*/

int KMPSearch(const unsigned char *pat, int M, const unsigned char *txt, int N, int locations[])
{
    int c= 0;
    
    // create lps[] that will hold the longest prefix suffix values for pattern
    int *lps = (int *)malloc(sizeof(int)*M);
    int j  = 0;  // index for pat[]
    
    // Preprocess the pattern (calculate lps[] array)
    computeLPSArray(pat, M, lps);
    
    int i = 0;  // index for txt[]
    while (i < N)
    {
        if (pat[j] == txt[i])
        {
            j++;
            i++;
        }
        
        if (j == M)
        {
            //printf("Found pattern at index %d [offset %d]\n", i-j, (i-j) % 256);
            locations[c] = i-j;
            c++;
            ////i+=M;
            if (c == KMP_MAX)
                return c;
            j = lps[j-1];
        }
        
        // mismatch after j matches
        else if (i < N && pat[j] != txt[i])
        {
            // Do not match lps[0..lps[j-1]] characters,
            // they will match anyway
            if (j != 0)
                j = lps[j-1];
            else
                i = i+1;
        }
    }
    free(lps); // to avoid memory leak
    return c;
}

void computeLPSArray(const unsigned char *pat, int M, int *lps)
{
    int len = 0;  // lenght of the previous longest prefix suffix
    int i;
    
    lps[0] = 0; // lps[0] is always 0
    i = 1;
    
    // the loop calculates lps[i] for i = 1 to M-1
    while (i < M)
    {
        if (pat[i] == pat[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else // (pat[i] != pat[len])
        {
            if (len != 0)
            {
                // This is tricky. Consider the example AAACAAAA and i = 7.
                len = lps[len-1];
                
                // Also, note that we do not increment i here
            }
            else // if (len == 0)
            {
                lps[i] = 0;
                i++;
            }
        }
    }
}

int findn(int num)
{
    int n = 0;
    while(num) {
        num /= 10;
        n++;
    }
    return n;
}

int trueKeySearch(const unsigned char *data, unsigned long data_len, struct qs_message *source)
{
    int i,c,k,j,m;
    unsigned char *str = malloc(513);
    int locations[KMP_MAX];
    unsigned char *outstring;

    unsigned char *key;
    unsigned char *newkey = malloc(257);
    int klen;
    char *key_len;

    for ( i = 0;  i < (sizeof(key_db)/sizeof(key_db[0]) ) ; i++ ) {
        //printf("start\n");
        key = key_db[i];
        klen = strlen((char*)key) / 2;
	 key_len = malloc(findn(klen) + 1);
    	 snprintf(key_len, findn(klen)+1, "%d", klen);
	key_len[findn(klen)] = '\0';
        hex2str(key, klen*2, str);
        

         c = KMPSearch( str, klen, data, (int) data_len, locations);
        //printf("true key %d %s [%d]\n", i, key_db[i], c);
        
        for(k=0; k < c; k++) {
            //printf("key location is %d\n", locations[k]);
            //printf("from %d  to %d [%d]\n", klen-locations[k] % klen, klen, locations[k] % klen);
            memcpy(newkey, str+klen-locations[k] % klen, locations[k] % klen); //no more than klen
            //printf("from %d  to %d [%d]\n", klen -locations[k] % klen, klen -locations[k] % klen+locations[k] % klen, locations[k] % klen);
            memcpy(newkey + locations[k] % klen, str, klen-locations[k] % klen); //no more than klen
            //printf("then from 0 to %d\n", klen-locations[k] % klen);
            newkey[klen] = '\0';
            //printf("new key=%s\n",newkey);
            outstring = malloc(data_len);
            xor_crypt_out((const unsigned char *) newkey, klen, data, data_len, outstring);
            
            struct qs_file *tryfile = malloc(sizeof(struct qs_file));
            tryfile->next = NULL;
            tryfile->parent = NULL;
            tryfile->child = NULL;
            tryfile->hits = NULL;
            tryfile->md5 = NULL;
            tryfile->sha1 = NULL;
            tryfile->sha256 = NULL;
            tryfile->sha512 = NULL;
            tryfile->head = NULL;

            tryfile->count = 0;
            struct qs_message *trymessage = quicksand_build_message("xor", tryfile, (&source->qs_root), QS_FILE_CHILD);
            tryfile->identifier = trymessage->identifier;
            char *keyst = malloc(513);
            for(m = 0,j=0; m < klen; m++, j+=2)
                snprintf(keyst+j, klen*2+1-j, "%02x", newkey[m]);
            keyst[j] = '\0';
           
            
            quicksand_yara_mem(outstring, data_len, QUICKSAND_EXE_YARA, "executable",trymessage);
            if (tryfile->count > 0) {
                
                ///doafilehere
                insertQSFile(tryfile, outstring, data_len, source);
                quicksand_hash(outstring, data_len, trymessage);

                quicksandStore(tryfile, "xortkey", keyst, 0);
                quicksandStore(tryfile, "xorlen", key_len, 0);
                return tryfile->count;
            } else {
                int rol = 0;
                if (QUICKSAND_ROL == 1) {
                    rol = quicksand_rol(outstring, data_len, quicksand_build_message("xortkey",tryfile, (&source->qs_root), QS_FILE_CHILD));
                }
                if (rol > 0) {
                    
                    ///doafilehere
                    insertQSFile(tryfile, outstring, data_len, source);
                    quicksand_hash(outstring, data_len, trymessage);

                    
                    quicksandStore(tryfile, "xortkey", keyst, 0);
                    quicksandStore(tryfile, "xorlen", key_len, 0);
                    return tryfile->count;
                }
                int add = 0;
                if (rol == 0 && QUICKSAND_MATH == 1){
                    int add = quicksand_addition(outstring, data_len, quicksand_build_message("xor", tryfile, (&source->qs_root), QS_FILE_CHILD));
                    
                    if (add > 0) {
                        
                        if (source->qs_root != NULL && quicksandDedup(source->qs_root, quicksandsha256(outstring, data_len)))
                            return 0;
                        insertQSFile(tryfile, outstring, data_len, source);
                        quicksand_hash(outstring, data_len, trymessage);
                        
                        
                        quicksandStore(tryfile, "xortkey", keyst, 0);
                        quicksandStore(tryfile, "xorlen", key_len, 0);
                        return tryfile->count;
                    }
                }
                int not = 0;
                if (add == 0 && QUICKSAND_NOT == 1){
                    not = quicksand_not(outstring, data_len, quicksand_build_message("xor", tryfile, (&source->qs_root), QS_FILE_CHILD));
                    
                    if (not == 1) {
                        
                        if (source->qs_root != NULL && quicksandDedup(source->qs_root, quicksandsha256(outstring, data_len)))
                            return 0;
                        insertQSFile(tryfile, outstring, data_len, source);
                        quicksand_hash(outstring, data_len, trymessage);
                        
                        
                        quicksandStore(tryfile, "xortkey", keyst, 0);
                        quicksandStore(tryfile, "xorlen", key_len, 0);
                        return tryfile->count;
                    }
                    
                }
                
            }
            free(outstring);
            free(keyst);
        }
    }
    return 0;

}





int file_exists (char *filename)
{
    struct stat   buffer;
    return (stat (filename, &buffer) == 0);
}


void report_error(
                  int error_level,
                  const char* file_name,
                  int line_number,
                  const char* message,
                  void* user_data)
{
    if (error_level == YARA_ERROR_LEVEL_ERROR)
    {
        fprintf(stderr, "%s(%d): error: %s\n", file_name, line_number, message);
    }
    else
    {
        
            fprintf(stderr, "%s(%d): warning: %s\n", file_name, line_number, message);
    }
}


void print_string(
                  uint8_t* data,
                  int length)
{
    char* str = (char*) (data);
    int i;
    
    for (i = 0; i < length; i++)
    {
        if (str[i] >= 32 && str[i] <= 126)
            printf("%c", str[i]);
        else
            printf("\\x%02X", (uint8_t) str[i]);
    }
    
    printf("\n");
}


void print_hex_string(
                      uint8_t* data,
                      int length)
{
    int i;
    for (i = 0; i < min(32, length); i++)
        printf("%02X ", (uint8_t) data[i]);
    
    if (length > 32)
        printf("...");
    
    printf("\n");
}




int callback(int message, void* message_data, void* user_data)
{
    YR_RULE* rule = (YR_RULE* ) message_data;
    struct qs_message * source = (struct qs_message *) user_data;
    char *str;
    
    switch(message)
    {
        case CALLBACK_MSG_RULE_MATCHING:
            //printf("FOUND: ");
            
            //printf("%s:", rule->ns->name);
            
            //printf("%s \n", rule->identifier);
            
            
            str = malloc(261);
           
            snprintf(str, 261, "%s%s", "yara:", rule->ns->name);

            
            quicksandStore(source->parent, str, rule->identifier, 0);
            //printf("%s\n", (char*)user_data );
            
            
            
            YR_META* meta;
            
            /* rule is a YR_RULE object */
            
            yr_rule_metas_foreach(rule, meta)
            {
                
                    if (meta->type == META_TYPE_INTEGER) {
                        //printf("#%d",meta->integer);
                        if (strstr(meta->identifier, "rank"))
                            
                            source->qs_root->malware_score += meta->integer;
                    }
            }
             return CALLBACK_CONTINUE;
            
            
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            //printf("NOT FOUND: ");
            
            
            
        return CALLBACK_CONTINUE;

    }
    
    return CALLBACK_ERROR;
}


void quicksand_yara_mem(const unsigned char* data, unsigned long data_len, char * rule_filename, const char *ns, struct qs_message *source)
{
    
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    int result;
    
    
    //printf("running yara now on %s with %s\n", source->identifier, rule_filename);
    
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        printf("error 2\n");
    
  
    yr_compiler_set_callback(compiler, report_error, NULL);
    
    
    //int errors = yr_compiler_add_string(compiler, rule, "quicksand");
    //if (errors)
    //    printf("error 3\n");
    FILE* rule_file = fopen(rule_filename, "r");
    
    if (rule_file == NULL)
    {
        fprintf(stderr, "error: could not open file: %s\n", rule_filename);
        
    }
    
    int errors = yr_compiler_add_file(compiler, rule_file, ns, rule_filename);
    
    fclose(rule_file);
    if (errors)
        printf("error 3a\n");

    
    result = yr_compiler_get_rules(compiler, &rules);
    
    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "error: %d\n", result);
        printf("error 4");
    }

    
    result = yr_rules_scan_mem(rules, (uint8_t *) data, data_len, 0, &callback, (void *) source, 30);
    
    
    if (compiler != NULL)
        yr_compiler_destroy(compiler);
    
    
    if (rules != NULL)
        yr_rules_destroy(rules);

    
}

void quicksand_log(const char* item) {
    time_t rawtime;
    struct tm * timeinfo;
    
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    printf ( "%s: %s", asctime (timeinfo) , item);

}

char *getTime() {
    time_t rawtime;
    struct tm * timeinfo;
    char * buffer = malloc(26);
    
    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", timeinfo);
    return buffer;

}



int quicksand_not(const unsigned char *data, unsigned long data_len, struct qs_message *source) {
    
    int i, j, k;
    
    unsigned char * tryit = malloc(data_len);
    not_crypt_out(data, data_len, tryit);
    
    struct qs_file *tryfile = malloc(sizeof(struct qs_file));
    tryfile->next = NULL;
    tryfile->parent = source->parent;
    tryfile->child = NULL;
    tryfile->hits = NULL;
    tryfile->md5 = NULL;
    tryfile->sha1 = NULL;
    tryfile->sha256 = NULL;
    tryfile->sha512 = NULL;
    tryfile->head = NULL;
    
    tryfile->count = 0;
    struct qs_message *trymessage = quicksand_build_message("not", tryfile, (&source->qs_root), QS_FILE_CHILD);
    tryfile->identifier = trymessage->identifier;
    
    
    
    int before = tryfile->count;
    
    quicksand_yara_mem(tryit, data_len, QUICKSAND_EXE_YARA, "executable",quicksand_build_message("not",tryfile,(&source->qs_root),QS_FILE_CHILD));
    if (tryfile->count > before) {
        char *keynot = "1";
        
        if (source->qs_root != NULL && quicksandDedup(source->qs_root, quicksandsha256(tryit, data_len)))
            return 0;
        
        
        insertQSFile(tryfile, tryit, data_len, source);
        quicksand_hash(tryit, data_len, trymessage);
        
        quicksandStore(tryfile, "not", keynot, 0);
        
        
        
        return 1;
        
    }
    free(tryit);
    return 0;
    
}






void quicksand_mime(const unsigned char *data, unsigned long data_len, struct qs_message *source, struct qs_file **qs_root) {
    char* entity = malloc(data_len);
    int i, j=0,k=0,l=0,f=0, res=0;
    //printf("looking for base64 blocks\n");
    for (i = 0; i < data_len; i++) {
        if (isalnum(data[i]) || data[i] == '+' || data[i] == '/' || data[i] == '=') {
            if( !isxdigit(data[i]) ) {
                f = 1;
            }
            entity[j] = data[i];
            j++;
        } else if (data[i] == 0x0a || data[i] == 0x0d || data[i] == 0x20 ) {
            //no nothing
            if (i+4 < data_len && data[i] == 0x0d && data[i+1] == 0x0a && data[i+2] == 0x0d && data[i+3] == 0x0a) {
                if (j>= 1024) {
                    if (f == 1) { //not hex
                        //printf("found base64 block of %d size at %d\n", j, i-j-k);
                        //send here
                        unsigned char *decoded_mime = malloc(j+1);
                        size_t *sz = malloc(sizeof(size_t));
                        //printf("decode 64\n%s", entity);
                        base64decode (entity, j, decoded_mime, sz);
                        //printf("end decode 64\n", entity);
                        //check for activemime
                        if (strstr((char*) decoded_mime, "ActiveMime") ) {
                            //printf("ActiveMime detected %lu\n", *sz);
                            
                            
                            for(l=50; l < 51; l++){
                                //printf("trying gzuncompress at %d\n", l);
                                unsigned char *buffer = malloc(*sz-l+1);
                                memcpy(buffer, decoded_mime+l, *sz-l+1);
                                unsigned char *destbuffer  = malloc(QUICKSAND_MAX_EXPAND);
                                res = unc((const unsigned char*)buffer, *sz-l, destbuffer, QUICKSAND_MAX_EXPAND);
                                
                                
                                free(buffer);
                                if(res > 64) {
                                    //printf("deflate worked\n");
                                    
                                    free(decoded_mime);
                                    decoded_mime = destbuffer;
                                    
                                    continue;
                                    
                                } else
                                    free(destbuffer);
                            }
                            
                        }
                        //printf("detected %lu\n", *sz);
                        //hex2str(entity, j, decoded_mime);
                        char *str = malloc(22);
                        snprintf(str, 22, "%s%d", "base64@", i-j-k);
                        quicksand_do(decoded_mime, (int) *sz, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
                        //free(decoded_mime);
                    }
                    
                }
                
                f = 0;
                j=0;
                k=-1;
            }
            k++;
        } else {
            if (j>= 1024) {
                if (f == 1) { //not hex
                    //printf("found base64 block of %d size at %d\n", j, i-j-k);
                    //send here
                    unsigned char *decoded_mime = malloc(j+1);
                    size_t *sz = malloc(sizeof(size_t));
                    //printf("decode 64\n%s", entity);
                    base64decode (entity, j, decoded_mime, sz);
                    //printf("end decode 64\n", entity);
                    //check for activemime
                    if (strstr((char*) decoded_mime, "ActiveMime") ) {
                        //printf("ActiveMime detected %lu\n", *sz);
                    }
                    //printf("detected %lu\n", *sz);
                    //hex2str(entity, j, decoded_mime);
                    char *str = malloc(22);
                    snprintf(str, 22, "%s%d", "base64@", i-j-k);
                    quicksand_do(decoded_mime, (int) *sz, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
                    //free(decoded_mime);
                }
                
                
            }
            j=0;
            k=0;
            f = 0;
        }
    }
    //check if still in block and send here too
    if (j>= 1024) {
        //printf("found base64 block of %d size at %d\n", j, data_len-j-k);
        unsigned char *decoded_mime = malloc(j+1);
        size_t *sz = malloc(sizeof(size_t));
        
        base64decode (entity, j, decoded_mime, sz);
        if (strstr((char*) decoded_mime, "ActiveMime")) {
            //printf("ActiveMime detected %lu\n", *sz);
        }
        
        //hex2str(entity, j, decoded_mime);
        char *str = malloc(22);
        snprintf(str, 22, "%s%lu", "base64@", data_len-j-k);
        quicksand_do(decoded_mime, (int) *sz, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
        //free(decoded_mime);
    }
    free(entity);

}


//hash data

void quicksand_hash(const unsigned char *data, unsigned long data_len, struct qs_message *source) {
    int i,j;
    MD5_CTX mdContext;
    SHA1Context sha;
    SHA256_CTX	ctx256;
    SHA512_CTX	ctx512;
    
    if (data_len >= 8) {
        char *head = malloc(17);
        for(i = 0, j=0; j < 8; i+=2, j++) {
            snprintf(head+i, 3, "%02x", data[j]);
        }
        head[16] = '\0';
        source->parent->head = head;
    } else {
        char *head = "00000000";
        source->parent->head = head;
    }
    
    unsigned char *md5_raw = malloc(QUICKSAND_MD5_SIZE+1);
    MD5Init (&mdContext);
    MD5Update (&mdContext, (unsigned char*) data, (unsigned int) data_len);
    MD5Final (md5_raw, &mdContext);

    
    
    
    char *md5 = malloc(QUICKSAND_MD5_SIZE*2+1);
    
    for(i = 0,j=0; i < QUICKSAND_MD5_SIZE; i++, j+=2)
        snprintf(md5+j, QUICKSAND_MD5_SIZE*2+1-j, "%02x", md5_raw[i]);
    md5[j] = '\0';

    source->parent->md5 = md5;

    SHA256_Init(&ctx256);
    SHA256_Update(&ctx256, data, data_len);


    
    
    char *sha256 = malloc(QUICKSAND_SHA256_SIZE*2+1);
    SHA256_End(&ctx256, sha256);
    source->parent->sha256 = sha256;

    SHA512_Init(&ctx512);
    SHA512_Update(&ctx512, data, data_len);


    char *sha512 = malloc(QUICKSAND_SHA512_SIZE*2+1);
    SHA512_End(&ctx512, sha512);
    source->parent->sha512 = sha512;

    
    char *dl = malloc(32);
    snprintf(dl, 32, "%lu", data_len);
    
    SHA1Reset(&sha);
    SHA1Input(&sha, data, data_len);
    
    if (SHA1Result(&sha)) {
        char *sha1 = malloc(QUICKSAND_SHA1_SIZE*2+1);
        snprintf(sha1, QUICKSAND_SHA512_SIZE*2+1, "%08x%08x%08x%08x%08x", sha.Message_Digest[0],
                 sha.Message_Digest[1],
                 sha.Message_Digest[2],
                 sha.Message_Digest[3],
                 sha.Message_Digest[4]);
        source->parent->sha1 = sha1;
    }
}




void insertQSFile(struct qs_file *qs_file_new, const unsigned char *data, unsigned long data_len,  struct qs_message *source) {
        qs_file_new->data = data;
        qs_file_new->data_len = data_len;
        qs_file_new->malware_score = 0;
    


        struct qs_file *qs_file_iterator = NULL;
        int skip = 0;
    
        if (source->parent == NULL)
            printf("source parent was sent as null\n");
        
        if (source->rel == QS_FILE_CHILD) {
            
            if (source->parent->child == NULL) {
                source->parent->child = qs_file_new;
                qs_file_new->parent = source->parent;
                //printf("linking [%s] to [%s]\n", qs_file_new->identifier, source->parent->identifier);
                skip = 1;
            } else {
                qs_file_iterator = source->parent->child;
                
            }
        } else {
            if (source->parent->next == NULL){
                source->parent->next = qs_file_new;
                qs_file_new->parent = source->parent;
                skip = 1;
            }else {
                qs_file_iterator = source->parent->next;
                
            }
        }
        if (skip != 1) {
            for(qs_file_iterator  = qs_file_iterator; qs_file_iterator->next != NULL; qs_file_iterator = qs_file_iterator->next) {
                if (qs_file_iterator == NULL)
                    break;
            }
            
            if (qs_file_iterator == NULL)
                printf("problem qs_file_iterator\n");
            else {
                //printf("linking [%s] to [%s]\n", source->identifier, qs_file_iterator->identifier);
                qs_file_iterator->next = qs_file_new;
                qs_file_new->parent = source->parent;
            }
        }
    

    return;
}


void quicksand_set_exploits(char * path) {
    QUICKSAND_EXPLOITS_YARA = path;
}

void quicksand_set_exe(char * path) {
    QUICKSAND_EXE_YARA = path;
}

void quicksand_set_general(char * path) {
    QUICKSAND_GENERAL_YARA = path;
}


void quicksand_set_out(char * path) {
    QUICKSAND_OUT_DIR = path;
}


char* quicksand_runner(char * path) {
    FILE *f;
    
    
    f = fopen(path, "rb");
    
    
    if( f == NULL )
    {
        printf("can't find %s\n", path);
        perror("Error while opening the file.\n");
        return NULL;
    }
    
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);
    
    quicksandInit();
    struct qs_file *qs_root = NULL;
    
    printf("running\n");
    quicksand_do(string, fsize, quicksand_build_message("root", NULL, &qs_root, QS_FILE_CHILD), &qs_root);
    char *buffer = malloc(1000000);
    quicksandGraph(buffer, 1000000, 0, qs_root);
    
    //quicksand_json(buffer, 1000000, 0, qs_root, FALSE);
    
    printf("%s", buffer);
    
    quicksandReset(&qs_root);
    quicksandDestroy();
    
    return buffer;
}



struct qs_message* createQSFile(const unsigned char *data, unsigned long data_len,  struct qs_message *source, struct qs_file **qs_root) {
    struct qs_file *qs_file_new = malloc(sizeof(struct qs_file));
    qs_file_new->next = NULL;
    qs_file_new->parent = NULL;
    qs_file_new->child = NULL;
    qs_file_new->hits = NULL;
    qs_file_new->md5 = NULL;
    qs_file_new->sha1 = NULL;
    qs_file_new->sha256 = NULL;
    qs_file_new->sha512 = NULL;
    qs_file_new->head = NULL;
    qs_file_new->malware_score = 0;
    
    qs_file_new->count = 0;
    qs_file_new->data = data;
    qs_file_new->data_len = data_len;
    
    assert(qs_file_new);
    if (strcmp(source->identifier,"root") == 0) {
        *qs_root = qs_file_new;
        source->parent = qs_file_new;
        source->qs_root = *qs_root;
        source->rel = QS_FILE_CHILD;
        
    } else {
        
        struct qs_file *qs_file_iterator = NULL;
        int skip = 0;
        
        
        if (source->parent == NULL)
            printf("source parent was sent as null\n");
        
        if (source->rel == QS_FILE_CHILD) {
            
            if (source->parent->child == NULL) {
                //printf("a\n");
                source->parent->child = qs_file_new;
                qs_file_new->parent = source->parent;
                //printf("linking [%s] to [%s]\n", source->identifier, source->parent->identifier);
                skip = 1;
            } else {
                //printf("b %s\n", source->parent->child->identifier);
                qs_file_iterator = source->parent->child;
                
            }
        } else {
            if (source->parent->next == NULL){
                //printf("c\n");
                source->parent->next = qs_file_new;
                qs_file_new->parent = source->parent;
                //printf("linking [%s] to [%s]\n", source->identifier, source->parent->identifier);
                skip = 1;
            }else {
                //printf("d\n");
                qs_file_iterator = source->parent->next;
                
            }
        }
        if (skip != 1) {
            //printf("e\n");
            for(qs_file_iterator  = qs_file_iterator; qs_file_iterator->next != NULL; qs_file_iterator = qs_file_iterator->next) {
                if (qs_file_iterator == NULL)
                    break;
            }
            
            if (qs_file_iterator == NULL)
                printf("problem qs_file_iterator\n");
            else {
                //printf("linking [%s] to [%s]\n", source->identifier, qs_file_iterator->identifier);
                qs_file_iterator->next = qs_file_new;
                qs_file_new->parent = source->parent;
            }
        }
    }
    assert(*qs_root != NULL);
    assert(qs_file_new != NULL);
    if (qs_file_new != NULL)
        qs_file_new->identifier = source->identifier;
    struct qs_message *target = quicksand_build_message(qs_file_new->identifier, qs_file_new, qs_root, QS_FILE_CHILD);
    return target;
}



int quicksand_do(const unsigned char *data, unsigned long data_len,  struct qs_message *source, struct qs_file **qs_root)
{
    #ifdef DEBUG
    if (source->identifier != NULL)
    printf("debug:%s: do %s [%lu]\n", source->identifier, source->identifier, data_len);
    #endif

    
    //check content
    if (data_len < QUICKSAND_MIN_FILE_SIZE) {
        return EXIT_FAILURE;
    }

    //if (source->parent != NULL)
    //    printf("object working on %s -> [%s]\n", source->identifier, source->parent->identifier);
   
    
    if (*qs_root != NULL && quicksandDedup(*qs_root, quicksandsha256(data, data_len)))
        return 0;
    
    struct qs_message *target = createQSFile(data, data_len, source, qs_root);
    assert(*qs_root != NULL);
   
    
    
    if (data[0] == 'P' && data[1] == 'K') {
        //printf("todo handle going through each file in the zip\n");
        
        quicksand_unzip((const unsigned char *)data, data_len, source, qs_root);

    } else {
        #ifdef DEBUG
        printf("debug:%s: yara exploits\n", source->identifier);
        #endif
        quicksand_yara_mem(data, data_len, QUICKSAND_EXPLOITS_YARA, "exploits", target);
        int ebefore = target->parent->count;
        #ifdef DEBUG
        printf("debug:%s: yara exec\n", source->identifier);
        #endif
        quicksand_yara_mem(data, data_len, QUICKSAND_EXE_YARA, "executable", target);
        
        
        if (target->parent->count == ebefore) {
            int tbefore = target->parent->count;
        
            #ifdef DEBUG
            printf("debug:%s: true keys\n", source->identifier);
            #endif

            trueKeySearch(data, data_len, target);
            
        
            if (QUICKSAND_ROL == 1 && target->parent->count == tbefore){
                quicksand_rol(data, data_len, target);
            }
            if (QUICKSAND_MATH == 1 && target->parent->count == tbefore){
                quicksand_addition(data, data_len, target);
            }
            
        }
        
        #ifdef DEBUG
        printf("debug:%s: zips\n", source->identifier);
        #endif

        quicksand_extract_ezip(data, data_len, target, qs_root);
        
        #ifdef DEBUG
        printf("debug:%s: hex\n", source->identifier);
        #endif

        if (data[0] == '{' && data[1] == '\\' && data[2] == 'r' && data[3] == 't') {
            unsigned long *new_len = malloc(sizeof(unsigned long));
            int rtbefore = target->parent->count;
            unsigned char* rtdata = quicksand_parse_rtf(data, data_len, new_len);
            
            char *str = malloc(20);
            snprintf(str, 20, "%s", "rtf@");

            quicksand_do(rtdata, *new_len, quicksand_build_message(str, source->parent, qs_root, QS_FILE_CHILD), qs_root);
            
        //} else {
            quicksand_extract_blocks(data, data_len, target, qs_root);
        }
        #ifdef DEBUG
        printf("debug:%s: stgcompress\n", source->identifier);
        #endif

        quicksand_extract_ExOleObjStgCompressedAtom(data, data_len, target, qs_root);
        
#ifdef DEBUG
        printf("debug:%s: zlib78\n", source->identifier);
#endif
       
        quicksand_extract_zlib78(data, data_len, target, qs_root);
        
        #ifdef DEBUG
        printf("debug:%s: mime\n", source->identifier);
        #endif

        quicksand_mime(data, data_len, target, qs_root);
        
        #ifdef DEBUG
        printf("debug:%s: end do\n", source->identifier);
        #endif

        
    }

    quicksand_hash(data, data_len, target);

    
    if (strcmp(target->identifier,"root") == 0) {
        if (QUICKSAND_GENERAL_YARA_RUN == 1)
            quicksandGeneralScan(*qs_root, qs_root);
        
        char *bufferHash = malloc(QUICKSAND_MAX_ITEM_VALUE*4);
         bufferHash[0] = '\0';
         quicksandStructural(bufferHash, QUICKSAND_MAX_ITEM_VALUE*4, 0, *qs_root);

        quicksandStore(target->parent, "structhash", bufferHash, 0);
        quicksandStore(target->parent, "qsversion", QUICKSAND_VERSION, 0);
        quicksandStore(target->parent, "qstime", getTime(), 0);
        

        char *score = malloc(15);
        if (*qs_root != NULL) {
            snprintf(score, 15, "%d", (*qs_root)->malware_score);

            quicksandStore(target->parent, "score", score, 0);

            if ((*qs_root)->malware_score >= QUICKSAND_MALWARE_SCORE)
                quicksandStore(target->parent, "is_malware", "2", 0);
            else if ((*qs_root)->malware_score >= 1)
                quicksandStore(target->parent, "is_malware", "1", 0);
            else
                quicksandStore(target->parent, "is_malware", "0", 0);
        }
    }

    //free(current);
    return EXIT_SUCCESS;

}


