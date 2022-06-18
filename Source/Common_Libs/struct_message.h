//
// Created by mirco on 18/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H
#define SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H


#include "common_parameters.h"
/*      OPCODES     */


#define REQ_OK              0

#define AUTH_INIT           1
#define AUTH                2
#define LIST                3
#define UPLOAD_INIT         4
#define UPLOAD_REQ          5
#define UPLOAD_CHUNK        6
#define RENAME_REQ          7
#define RENAME              8
#define DOWNLOAD_REQ        9
#define DOWNLOAD            10
#define DOWNLOAD_ACCEPT     11
#define DELETE_REQ          12
#define DELETE              13
#define LOGOUT_REQ          14
#define LOGOUT              15

#define WRONG_FORMAT        16
#define MISSING_USER        17
#define MAC_FAIL            18
#define DUP_NAME            19
#define INVALID_FILENAME    20
#define MISSING_LIST        21
#define MISSING_FILE        22
#define INVALID_LIST        23


struct fixed_header{
    unsigned char initialization_vector[IV_LENGTH];
    unsigned char opcode;
    unsigned int payload_length;
};

struct message{
    fixed_header header;
    unsigned char* payload;
    unsigned char hmac[DIGEST_LEN];
};

#endif //SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H