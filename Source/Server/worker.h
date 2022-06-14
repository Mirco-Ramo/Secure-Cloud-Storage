//
// Created by mirco on 14/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_WORKER_H
#define SECURE_CLOUD_STORAGE_WORKER_H


class Worker {
    //my_ip_addr;
    //user_ip_addr;
    //username;
    //shared_key;
    //shared_mac;
    //user_nonce;
    //my_nonce;
    //received_Command;
public:
    Worker();
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
