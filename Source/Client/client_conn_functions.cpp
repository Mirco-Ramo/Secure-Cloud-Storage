//
// Created by Francesco Del Turco, Mirco Ramo
//

#include "client_include.h"
#include "client_functions.h"

extern vector<buffer> allocatedBuffers;
extern unsigned char hmac_key[];
extern unsigned char session_key[];
extern unsigned int client_counter;
extern unsigned int server_counter;
extern int client_socket;


int connect_to_server(sockaddr_in* server_addr, int* c_socket){
    const char *ip = SERVER_ADDRESS;
    int port = SERVER_PORT;
    memset(server_addr,0,sizeof(sockaddr_in));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(port);
    if (inet_pton(AF_INET,ip,&server_addr->sin_addr)!=1)
        return -1;

    int sock_number = socket(AF_INET,SOCK_STREAM,0);
    if(sock_number == -1)
        return sock_number;
    *c_socket = sock_number;

    //time-out server
    timeval timeout = {80,0};
    if (setsockopt(sock_number,SOL_SOCKET,SO_RCVTIMEO,(const char*) &timeout,sizeof(timeval))==-1)
        return -1;
    //connection to server
    return connect(sock_number,(struct sockaddr*)server_addr,sizeof(sockaddr_in));

}
void shutdown(int received_signal){
    //TODO disconnect()
    //TODO clean_all(resources);
    cout<<"Shutting down client"<<endl;
    clean_counters();
    clean_all();
#pragma optimize("", off)
    memset(session_key, 0, KEY_LEN);
    memset(hmac_key, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    close(client_socket);
    exit(received_signal);
}