//
// Created by mirco on 16/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H
#define SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H

#endif //SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H

#include "../Common_Libs/struct_message.h"

/*              CONNECTION FUNCTIONS            */
int connect_to_server(sockaddr_in* server_addr, int* client_socket);
void shutdown(int received_signal);
bool begin_session(int socket_id);


/*              LOGIC FUNCTIONS                    */
void handle_download();
void handle_upload();
void handle_list();
void handle_rename();
void handle_delete();
void handle_logout();


/*              PROTOCOL AND CLEAN FUNCTIONS        */
void clean_counters();