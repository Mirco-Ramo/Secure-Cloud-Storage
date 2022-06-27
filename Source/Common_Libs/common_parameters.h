//
// Created by mirco on 18/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_COMMON_PARAMETERS_H
#define SECURE_CLOUD_STORAGE_COMMON_PARAMETERS_H

#endif //SECURE_CLOUD_STORAGE_COMMON_PARAMETERS_H

#define MAX_FILENAME_CHARS 30
#define MAX_USERNAME_LEN 20

#define CIPHER              EVP_aes_128_cbc()
#define IV_LENGTH           16 //(unsigned int)EVP_CIPHER_iv_length(CIPHER)
#define OPCODE_LENGTH       1
#define MAX_PAYLOAD_LENGTH  8*1024 //16 Kb
#define MAX_FETCHABLE       16*1024*1024
#define KEY_LEN             16 //EVP_CIPHER_key_length(CIPHER)
#define BLOCK_LEN           16 //(unsigned int)EVP_CIPHER_block_size(CIPHER context)
#define MAC_TYPE            EVP_sha256()
#define DIGEST_LEN          32 //(unsigned int)EVP_MD_size(SHA_256)
#define HMAC_KEY_LEN        32
#define FIXED_HEADER_LENGTH 20
#define PAYLOAD_LENGTH_LEN  3

#include <csignal>
#include <fstream>
#include <dirent.h>
#include "signal.h"
#include "string.h"
#include "cstring"
#include <iostream>
#include <sys/types.h>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <climits>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>