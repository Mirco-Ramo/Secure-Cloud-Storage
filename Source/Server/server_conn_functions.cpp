//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
void init();
void listen_connections();
void shutdown_server(int);

void init() {
    signal(SIGINT,shutdown_server);
}
void listen_connections() {
    cout<<"Listening for connections"<<endl;
}

void shutdown_server(int received_signal){
    signal(SIGINT, SIG_IGN);
}