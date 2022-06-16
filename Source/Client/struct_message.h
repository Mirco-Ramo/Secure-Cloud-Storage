//
// Created by Francesco Del Turco, Mirco Ramo.
//

#ifndef SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H
#define SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H

#endif //SECURE_CLOUD_STORAGE_STRUCT_MESSAGE_H

#include "server_include.h"

#define CIPHER              EVP_aes_128_cbc()
#define IV_LENGTH           16 //(unsigned int)EVP_CIPHER_iv_length(CIPHER)
#define OPCODE_LENGTH       sizeof(unsigned char)
#define MAX_PAYLOAD_LENGTH  UINT_MAX
#define KEY_LEN             EVP_CIPHER_key_length(CIPHER)
#define SHA_256             EVP_sha256()
#define DIGEST_LEN          32 //(unsigned int)EVP_MD_size(SHA_256)
#define HMAC_KEY_LEN        32
#define NONCE_LENGTH        IV_LENGTH
#define FIXED_HEADER_LENGTH 24
#define PAYLOAD_LENGTH_LEN  3

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
    unsigned char* initialization_vector;
    unsigned char opcode;
    unsigned int payload_length;
    bool nonceA_present;
    bool nonceB_present;
    unsigned short seq_number;
};

struct message{
    fixed_header header;
    unsigned char* nonceA;
    unsigned char* nonceB;
    unsigned char* payload;
    unsigned char* hmac;
};

