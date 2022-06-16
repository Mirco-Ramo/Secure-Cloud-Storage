//
// Created by Francesco del Turco, Mirco Ramo
//

#ifndef SECURE_CLOUD_STORAGE_SERVER_LIBS_H
#define SECURE_CLOUD_STORAGE_SERVER_LIBS_H

#endif //SECURE_CLOUD_STORAGE_SERVER_LIBS_H

/*                    CONSTANT MACROS                         */
#define MAX_CONNECTIONS 20
#define LISTENING_PORT 2210
#define MAX_FILENAME_CHARS 30
#define MAX_USERNAME_CHARS 20

/*                  EXECUTION ERROR CODES           */
#define NO_EXIT_CODE 0
#define LISTENER_SOCKET_ERROR 1

/*          LIBRARIES                */
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
#include <cstdlib>
#include <vector>
#include <thread>
#include "pthread.h"
#include <climits>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
using namespace std;