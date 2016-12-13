/* Copyright (c) 2016 Tyler McLellan  TyLabs.com
 * QuickSand.io - Document malware forensics tool
 *
 * File libqs.h   Dec 10 2016
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


#ifndef ____quicksand__
#define ____quicksand__

//#include <stdio.h>

char *QUICKSAND_VERSION = "01.05.008";


#define QUICKSAND_MAX_ITEM 512
#define QUICKSAND_MAX_ITEM_NAME 512
#define QUICKSAND_MAX_ITEM_VALUE 1024
#define QUICKSAND_MIN_FILE_SIZE 128
#define QUICKSAND_MD5_SIZE 16
#define QUICKSAND_SHA1_SIZE 20
#define QUICKSAND_SHA256_SIZE 32
#define QUICKSAND_SHA512_SIZE 64
#define QUICKSAND_MAX_DROP 12800000
#define QUICKSAND_MALWARE_SCORE 10


char *QUICKSAND_EXPLOITS_YARA = "quicksand_exploits.yara";
char *QUICKSAND_EXE_YARA = "quicksand_exe.yara";
char *QUICKSAND_GENERAL_YARA = "quicksand_general.yara";
char *QUICKSAND_OUT_DIR = "./";
int QUICKSAND_GENERAL_YARA_RUN = 1;
int QUICKSAND_MATH = 0;
int QUICKSAND_NOT = 0;
int QUICKSAND_ROL = 1;



struct quicksand_hit {
    char name[QUICKSAND_MAX_ITEM_NAME];
    char value[QUICKSAND_MAX_ITEM_VALUE];
};





unsigned char key_db[8][513] = {"00fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a898887868584838281807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a696867666564636261605f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201", "f4f3f2f182868b9aecebeae99a8e8392e4e3e2e192b6bbaadcdbdad9aabeb3a2d4d3d2d1a2a6abbacccbcac9baaea3b2c4c3c2c1b2d6dbcabcbbbab9caded3c2b4b3b2b1c2c6cbdaacabaaa9dacec3d2a4a3a2a1d2f6fbea9c9b9a99eafef3e294939291e2e6ebfa8c8b8a89faeee3f284838281f2161b0a7c7b7a790a1e13027473727102060b1a6c6b6a691a0e03126463626112363b2a5c5b5a592a3e33225453525122262b3a4c4b4a493a2e23324443424132565b4a3c3b3a394a5e53423433323142464b5a2c2b2a295a4e43522423222152767b6a1c1b1a196a7e73621413121162666b7a0c0b0a097a6e63720403020172969b8afcfbfaf98a9e9382", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "a7a6a5a4a3a2a1a05f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241407f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463624b601f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201003f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0fffefdd6fbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8", "8485868798999a9b9c9d9e9f9091929394959697e8e9eaebecedeeefe0e1e2e3e4e5e6e7f8f9fafbfcfdfefff0f1f2f3f4f5f6f7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7d8d9dadbdcdddedfd0d1d2d3d4d5d6d728292a2b2c2d2e2f202122232425262738393a3b3c3d3e3f303132333435363708090a0b0c0d0e0f000102030405060718191a1b1c1d1e1f101112131415161768696a6b6c6d6e6f606162636465666778797a7b7c7d7e7f707172737475767748494a4b4c4d4e4f404142434445464758595a5b5c5d5e5f5051525354555657a8a9aaabacadaeafa0a1a2a3a4a5a6a7b8b9babbbcbdbebfb0b1b2b3b4b5b6b788898a8b8c8d8e8f80818283",
    "cabebafe", "cafebabe", "fecabeba"};


int invert[] = {0,7,6,5,4,3,2,1};

static const unsigned char db64[] = {
    66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
};

struct qs_message {
    const char *identifier;
    struct qs_file *parent;
    struct qs_file *qs_root;
    
    int rel;
};


struct qs_hit {
    const char *name;
    const char *value;
    long unsigned offset;
    struct qs_hit *next; //linked list
};


struct qs_file {
    const char *identifier;
    struct qs_file *parent;
    struct qs_file *next; //linked list
    struct qs_file *child; //linked list
    
    struct qs_hit *hits; //linked list
    int count; //number of hits
    
    
    const char *md5;
    const char *sha1;
    const char *sha256;
    const char *sha512;
    const char *head;
    
    long unsigned data_len;
    
    const unsigned char *data;
    
    int malware_score;
    
    
};



int quicksand_do(const unsigned char *, unsigned long , struct qs_message *, struct qs_file **);

char quicksandGetStreamEntropy(unsigned char*);

int quicksand_not(const unsigned char *, unsigned long, struct qs_message *);


void hex2str(unsigned char *, int, unsigned char *);

unsigned hex2dec(unsigned char *);

void computeLPSArray(const unsigned char *, int, int *);

int KMPSearch(const unsigned char *, int, const unsigned char *, int, int[]);

void xor_crypt(const unsigned char *, int, unsigned char *, unsigned long );

int trueKeySearch(const unsigned char *, unsigned long , struct qs_message *);

void insertQSFile(struct qs_file *, const unsigned char *, unsigned long ,  struct qs_message *);

short getMax(int[]);


void quicksand_yara_mem(const unsigned char *, unsigned long, char *, const char *, struct qs_message *);

void quicksand_hash(const unsigned char *, unsigned long , struct qs_message *);

void quicksandReset();

void quicksandInit();

void quicksandDestroy();

void quicksandDropObjects(struct qs_file *, struct qs_file **);

#endif /* defined(____quicksand__) */

