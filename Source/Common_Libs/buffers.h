//
// Created by mirco on 21/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_BUFFERS_H
#define SECURE_CLOUD_STORAGE_BUFFERS_H

enum types {EVP_PKEY_BUF, PKEY_CONTEXT, CLEAR_BUFFER, ENC_BUFFER, BIO_BUF, MD_CONTEXT, HMAC_CONTEXT, HASH_KEY, CIPHER_CONTEXT, ENC_KEY, DH_BUF,
        X509_BUF, X509_CRL_BUF, X509_STORE_BUF, X509_STORE_CONTEXT, MESSAGE};

struct buffer{
    types type;
    void* content;
    unsigned int nbytes;
};

#endif //SECURE_CLOUD_STORAGE_BUFFERS_H
