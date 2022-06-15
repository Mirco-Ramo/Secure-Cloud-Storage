//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_WORKER_H
#define SECURE_CLOUD_STORAGE_WORKER_H

#include "server_include.h"

class Worker {
    int socket_id;
    //struct sockaddr_in worker_addr;   ?
    //struct sockaddr_in client_addr;   ?
    string username;
    bool logout_request;
    //shared_key;
    //shared_mac;
    //user_nonce; ?
    //my_nonce;   ?
    //received_Command;
public:
    Worker(int socket_id);
    bool establish_session();
    static bool check_username(const string& username);
    static bool check_file_name(const string& file_name);
    void* handle_commands(void);
    static void  *handle_commands_helper(void* context);
    void handle_download();
    void handle_upload();
    void handle_list();
    void handle_rename();
    void handle_delete();
    void handle_logout();
    ~Worker(); //destroy every sensible information, like exchanged keys
};
#endif //SECURE_CLOUD_STORAGE_WORKER_H
