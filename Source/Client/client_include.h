//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H
#define SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H

#endif //SECURE_CLOUD_STORAGE_CLIENT_INCLUDE_H

#include "../Common_Libs/common_parameters.h"

/*              MACROS              */
#define SERVER_ADDRESS "127.0.0.1"
#define SERVER_PORT 2210
#define MAX_USERNAME_LEN 20


#define PROMPT ">$ "
#define HELP_MESSAGE "***************************************************************************\n\n" \
                     "************************* SECURE CLOUD STORAGE*** *************************\n\n" \
                     "***************************************************************************\n\n" \
                     "Type one of the following commands to start:\n"                                  \
                     PROMPT "HELP: print this message\n"                                                                                                                             \
                     PROMPT "LIST: list all uploaded files\n"                                           \
                     PROMPT "DOWNLOAD: downloads requested file\n" \
                     PROMPT "UPLOAD: loads requested file into your cloud storage space\n"  \
                     PROMPT "RENAME: renames a file in the cloud\n"       \
                     PROMPT "DELETE: removes a file from the cloud\n"       \
                     PROMPT "LOGOUT: closes connection with server and exits the service\n" \

/*              LIBRARIES           */

using namespace std;