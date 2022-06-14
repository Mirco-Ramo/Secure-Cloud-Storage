//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
int connectionSocketListener;
void init();
void listen_connections();
void shutdown_server(int);

void handleErrors(char* reason, int exit_code){
    cerr<<reason<<endl;
    if (exit_code)
        exit(exit_code);
}

void init() {
    signal(SIGINT,shutdown_server);
}
void listen_connections() {
    //return codes container
    int ret;
    //server listener address structure
    struct sockaddr_in listener_addr;
    //last connected client address structure
    struct sockaddr_in client_addr;
    //message output length
    socklen_t len;
    //speaker client from accept
    int clientConnectionSocket;

    if (connectionSocketListener=socket(AF_INET,SOCK_STREAM,0)==-1)
        handleErrors("Listener socket initialization failed", LISTENER_SOCKET_ERROR);

    //listener_addr initialization
    memset(&listener_addr,0,sizeof(listener_addr));

    listener_addr.sin_family=AF_INET;
    listener_addr.sin_port=htons(LISTENING_PORT);
    listener_addr.sin_addr.s_addr=INADDR_ANY;

    //bind inizialization
    if (bind(connectionSocketListener,(struct sockaddr*)&listener_addr,sizeof(listener_addr))<0)
        handleErrors("Error while binding listener socket", LISTENER_SOCKET_ERROR);

    //listen mode for listener socket
    if(listen(connectionSocketListener,MAX_CONNECTIONS)<0)
        handleErrors("Listen error", LISTENER_SOCKET_ERROR);
    cout<<"Listening for connections"<<endl;

    //while true accept connection, open new socket, spawn a process that executes worker's code
}

void shutdown_server(int received_signal){
    signal(SIGINT, SIG_IGN);
}