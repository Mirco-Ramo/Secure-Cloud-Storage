//
// Created by Francesco del Turco, Mirco Ramo.
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
    unsigned char session_key[KEY_LEN];
    unsigned char hmac_key[HMAC_KEY_LEN];
    vector<buffer> allocatedBuffers;
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
    void clean_all();
    ~Worker();

    /*          UTILS               */
    void handleErrors(const string& reason, int exit_code);
    bool send_failure_message(unsigned char reason, unsigned char opcode);
};
#endif //SECURE_CLOUD_STORAGE_WORKER_H
