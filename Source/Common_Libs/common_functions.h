//
// Created by mirco on 18/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H
#define SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H

#endif //SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H
#include "struct_message.h"
/*          SECURE CODING           */
bool check_username(const std::string& username);
bool check_file_name(const std::string& file_name);
bool command_ok(const std::string& command);


/*          MESSAGE EXCHANGE        */
message* build_message(unsigned char* iv, unsigned char opcode, unsigned int payload_length, unsigned char* payload, bool hmac);
int send_msg(int socket_id, message* msg, bool hmac, std::string identity);
int recv_msg(int socket_id, message *msg, bool hmac, std::string identity);