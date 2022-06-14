//
// Created by Francesco Del Turco, Mirco Ramo
//

#include "client_include.h"

int connect_to_server(sockaddr_in* server_addr){
    const char *ip = SERVER_ADDRESS;
    int port = SERVER_PORT;
    memset(server_addr,0,sizeof(sockaddr_in));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);
    if (inet_pton(AF_INET,ip,&server_addr->sin_addr)!=1)
        return -1;

    int client_socket = socket(AF_INET,SOCK_STREAM,0);
    if(client_socket == -1)
        return client_socket;

    //time-out attesa risposta server
    timeval timeout = {100,0};
    if (setsockopt(client_socket,SOL_SOCKET,SO_RCVTIMEO,(const char*) &timeout,sizeof(timeval))==-1)
        return -1;

    //connessione al server
    return connect(client_socket,(struct sockaddr*)server_addr,sizeof(sockaddr_in));

}
void shutdown(int received_signal){
    //TODO disconnect()
    //TODO clean_all(resources);
}