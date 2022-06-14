//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_WORKER_H
#define SECURE_CLOUD_STORAGE_WORKER_H

#include "server_include.h"

class Worker {
    int listener; //socket di ascolto
    int speaker; //socket di comunicazione
    struct sockaddr_in worker_addr; //struttura per il proprio indirizzo
    struct sockaddr_in client_addr; //struttura per l'indirizzo del client
    char username[MAX_USERNAME_CHARS];
    //shared_key;
    //shared_mac;
    //user_nonce;
    //my_nonce;
    //received_Command;
public:
    Worker();
    void establishSession();
    void handleCommand();
    void handleDownload();
    void handleUpload();
    void handleList();
    void handleRename();
    void handleDelete();
    void handleLogout();
    ~Worker(); //destroy every sensible information, like exchanged keys

};


#endif //SECURE_CLOUD_STORAGE_WORKER_H
