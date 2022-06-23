//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"
#include "server_functions.h"
using namespace std;

int connectionSocketListener;

vector<Worker*> active_workers;
vector<pthread_t> active_threads;
EVP_PKEY* server_privkey;

void handleErrors(const string& reason, int exit_code){
    cerr<<reason<<endl;
    shutdown_server(exit_code);
}

void init() {
    signal(SIGINT,shutdown_server);
}
void listen_connections() {
    //return codes container
    int ret;
    //server listener address structure
    struct sockaddr_in listener_addr{};
    //last connected client address structure
    struct sockaddr_in client_addr{};
    //message output length
    socklen_t len;
    //speaker client from accept
    int clientConnectionSocket;

    if ((connectionSocketListener=socket(AF_INET,SOCK_STREAM,0))==-1)
        handleErrors("Listener socket initialization failed", LISTENER_SOCKET_ERROR);

    //listener_addr initialization
    memset(&listener_addr,0,sizeof(listener_addr));

    listener_addr.sin_family=AF_INET;
    listener_addr.sin_port=htons(LISTENING_PORT);
    listener_addr.sin_addr.s_addr=INADDR_ANY;


    if (!read_privkey(server_privkey, "../Keys/Server/server_prvkey.pem")){
        handleErrors("Cannot read server private key", -40);
    }

    //bind initialization
    if (bind(connectionSocketListener,(struct sockaddr*)&listener_addr,sizeof(listener_addr))<0)
        handleErrors("Error while binding listener socket", LISTENER_SOCKET_ERROR);

    //listen mode for listener socket
    if(listen(connectionSocketListener,MAX_CONNECTIONS)<0)
        handleErrors("Listen error", LISTENER_SOCKET_ERROR);
    cout<<"Listening for connections"<<endl;

    len = sizeof(client_addr);
    while(true){
        if((clientConnectionSocket = accept(connectionSocketListener,(struct sockaddr*)&client_addr,&len))<0)
            handleErrors("Accept on connection listener not succeeded", LISTENER_SOCKET_ERROR);

        string client_ip;
        char buff[16];
        client_ip = inet_ntop(AF_INET,(void*)&client_addr.sin_addr,buff,sizeof(buff));
        cout <<"New connection established with " << client_ip <<endl;
        Worker* w = new Worker(clientConnectionSocket, server_privkey);
        active_workers.push_back(w);
        pthread_t pthread;
        pthread_create(&pthread, NULL, &Worker::handle_commands_helper, w);
        active_threads.push_back(pthread);
    }

}

void shutdown_server(int received_signal){
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    EVP_PKEY_free(server_privkey);

    for(auto &active_thread : active_threads){
        pthread_kill(active_thread, SIGTERM);
    }

    for (auto & active_worker : active_workers){
        if(active_worker)
            delete active_worker;
    }
    //TODO clean_all
    //
    exit(received_signal);
}