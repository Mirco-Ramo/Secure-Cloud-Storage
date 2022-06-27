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
    unsigned short id;
    string identity;
    bool logout_request;
    unsigned int worker_counter;
    unsigned int client_counter;
    unsigned char session_key[KEY_LEN];
    unsigned char hmac_key[HMAC_KEY_LEN];
    vector<buffer> allocatedBuffers;
    EVP_PKEY* server_privkey;
public:
    /*      CONSTRUCTOR         */
    Worker(int socket_id, EVP_PKEY* server_privkey, unsigned short id);

    /*      PROTOCOL MANAGEMENT    */
    bool establish_session();

    /*      LOGIC COMMANDS          */
    void* handle_commands();
    static void  *handle_commands_helper(void* context);
    bool handle_download(message* m1);
    bool handle_upload(message* m1);
    bool handle_list();
    bool handle_rename(message* m1);
    bool handle_delete(message* m1);
    bool handle_logout();

    /*          DESTRUCTORS         */
    void clean_all();
    ~Worker();

    /*          UTILS               */
    void handleErrors(const string& reason, int exit_code);
    bool send_failure_message(unsigned char reason, unsigned char opcode, bool multiple);
    string GetStdoutFromCommand(string cmd);
    string get_file_list_as_string();
    vector<string> get_file_list_as_vector();
    bool check_filename_already_existing(string filename);
};
#endif //SECURE_CLOUD_STORAGE_WORKER_H
