//
// Created by Francesco Del Turco, Mirco Ramo.
//

using namespace std;

#ifndef SECURE_CLOUD_STORAGE_SERVER_H
#define SECURE_CLOUD_STORAGE_SERVER_H

#include "server_libs.h"

class Server {
public:
    void init();
    void listen_connections();

};


#endif //SECURE_CLOUD_STORAGE_SERVER_H
