//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_WORKER_H
#define SECURE_CLOUD_STORAGE_WORKER_H

#include "server_include.h"
#include "struct_message.h"

class Worker {
    int socket_id;
    //struct sockaddr_in worker_addr;   ?
    //struct sockaddr_in client_addr;   ?
    string username;
    bool logout_request;
    long worker_counter;
    long client_counter;
    //shared_key;
    //shared_mac;
    //user_nonce; ?
    //my_nonce;   ?
    //received_Command
public:
    /*      CONSTRUCTOR         */
    Worker(int socket_id);

    /*      PROTOCOL MANAGEMENT    */
    bool establish_session();
    unsigned char* initialize_iv();

    /*      SECURE CODING CHECKS    */
    static bool check_username(const string& username);
    static bool check_file_name(const string& file_name);

    /*      MESSAGE EXCHANGE        */
    message* build_message(unsigned char* iv, unsigned char opcode, unsigned int payload_length, unsigned char* payload, bool hmac);
    int send_msg_to_client(int socket_id, message msg, bool hmac);
    int recv_msg_from_client(int socket_id, message* msg, bool hmac);

    /*      LOGIC COMMANDS          */
    void* handle_commands();
    static void  *handle_commands_helper(void* context);
    void handle_download();
    void handle_upload();
    void handle_list();
    void handle_rename();
    void handle_delete();
    void handle_logout();

    /*          DESTRUCTORS         */
    ~Worker(); //destroy every sensible information, like exchanged keys

};
#endif //SECURE_CLOUD_STORAGE_WORKER_H
