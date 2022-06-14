//
// Created by Francesco del Turco, Mirco Ramo
//

#ifndef SECURE_CLOUD_STORAGE_SERVER_LIBS_H
#define SECURE_CLOUD_STORAGE_SERVER_LIBS_H

#endif //SECURE_CLOUD_STORAGE_SERVER_LIBS_H

/*                    CONSANT MACROS                         */
#define MAX_CONNECTIONS 20
#define LISTENING_PORT 2210
#define MAX_FILENAME_CHARS 30
#define MAX_USERNAME_CHARS 20

/*                  EXECUTION ERROR CODES           */
#define NO_EXIT_CODE 0
#define LISTENER_SOCKET_ERROR 1

/*          LIBRARIES                */
#include <signal.h>
#include "string.h"
#include "cstring"
#include <iostream>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
using namespace std;