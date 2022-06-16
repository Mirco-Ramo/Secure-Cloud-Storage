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

/*                                      OPCODES                                             */
#define LOGIN               0
#define LOGOUT              1
/*
 *
 */

struct fixed_header{
    unsigned char* initialization_vector;
    unsigned char opcode;
    bool nonceA_present;
    bool nonceB_present;
};

struct message{
    fixed_header header;
    unsigned char* nonceA;
    unsigned char* nonceB;
    unsigned char* payload;
    unsigned int payload_length;
    unsigned char* hmac;
};

