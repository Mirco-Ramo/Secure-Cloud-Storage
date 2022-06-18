//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_WORKER_H
#define SECURE_CLOUD_STORAGE_WORKER_H

#include "server_include.h"

using namespace std;

class Worker {
    int socket_id;
    string username;
    string identity;
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
