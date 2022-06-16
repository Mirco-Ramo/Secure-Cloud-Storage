//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H
#define SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H

#endif //SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H

/*              MACROS              */
#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 2210
#define MAX_USERNAME_LEN 20

/*              LIBRARIES           */
#include <csignal>
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

using namespace std;