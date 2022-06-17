//
// Created by mirco on 16/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H
#define SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H

#endif //SECURE_CLOUD_STORAGE_CLIENT_FUNCTIONS_H

#include "struct_message.h"

/*              CONNECTION FUNCTIONS            */
int connect_to_server(sockaddr_in* server_addr, int* client_socket);
void shutdown(int received_signal);


/*              MESSAGE EXCHANGE                */
message* build_message(unsigned char* iv, unsigned char opcode,
                       unsigned int payload_length,
                       unsigned char* payload, bool hmac);

int send_msg_to_server(int socket_id, message* msg, bool hmac);
int recv_msg_from_server(int socket_id, message *msg, bool hmac);


/*              SECURE CODING                      */
bool check_username(const string& username);
bool check_file_name(const string& file_name);


/*              LOGIC FUNCTIONS                    */
void handle_list();