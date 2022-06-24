//
// Created by mirco on 18/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H
#define SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H


#include "common_parameters.h"
/*      OPCODES     */


#define NO_OPCODE           0

//REQUEST OPCODES
#define AUTH_INIT           1
#define LIST                2
#define DOWNLOAD            3
#define UPLOAD_REQ          4
#define UPLOAD_DATA         5
#define RENAME              9
#define DELETE              10
#define LOGOUT              11

//RESPONSE OPCODES
#define AUTH_RESPONSE       20
#define LIST_RES            21
#define LIST_DATA           22
#define DOWNLOAD_RES        23
#define DOWNLOAD_DATA       24
#define UPLOAD_RES          25
#define UPLOAD_ACK          26
#define RENAME_RES          27
#define DELETE_RES          28
#define LOGOUT_RES          29

//OUTCOME OPCODES(Encrypted)
#define REQ_OK             200
#define WRONG_FORMAT        51
#define MISSING_USER        52
#define INVALID_FILENAME    53
#define MISSING_FILE        54
#define DUP_NAME            55

struct fixed_header{
    unsigned char initialization_vector[IV_LENGTH];
    unsigned char opcode;
    unsigned int payload_length;
};

struct message{
    fixed_header header;
    unsigned char* payload;
    unsigned char hmac[DIGEST_LEN];

    ~message(){
#pragma optimize("", off)
        memset(payload, 0, header.payload_length);
#pragma optimize("", on)
        if(payload)
            free(payload);
    }
};

struct payload_field{
    unsigned short field_len;
    unsigned char* field;
};

#endif //SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H