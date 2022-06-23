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
bool begin_session(int socket_id, const string& username, const string& identity);


/*              LOGIC FUNCTIONS                    */
bool handle_download(int socket_id, const string& identity,  const string& filename);
bool handle_upload(int socket_id, const string& identity,  const string& filename);
bool handle_list(int socket_id, const string& identity);
bool handle_rename(int socket_id, const string& identity,  const string& old_file_name, const string& new_file_name);
bool handle_delete(int socket_id, const string& identity,  const string& file_name);
bool handle_logout(int socket_id, const string& identity);


/*              PROTOCOL AND CLEAN FUNCTIONS        */
void clean_counters();
void clean_all();