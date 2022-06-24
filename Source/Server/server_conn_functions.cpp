//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"
#include "server_functions.h"
using namespace std;

int connectionSocketListener;
struct ActiveWorker{
    unsigned short id;
    Worker* pointer;
};
vector<ActiveWorker> active_workers;
vector<pthread_t> active_threads;
EVP_PKEY* server_privkey;
int clientConnectionSocket;

void handleErrors(const string& reason, int exit_code){
    cerr<<reason<<endl;
    shutdown_server(exit_code);
}

void init() {
    signal(SIGINT,shutdown_server);
    signal(SIGTERM,shutdown_server);
    signal(SIGQUIT,shutdown_server);
    signal(SIGSTOP,shutdown_server);
    if (!read_privkey(server_privkey, "../Keys/Server/server_prvkey.pem")){
        handleErrors("Cannot read server private key", -40);
    }
}
void listen_connections() {
    //server listener address structure
    struct sockaddr_in listener_addr{};
    //last connected client address structure
    struct sockaddr_in client_addr{};
    //message output length
    socklen_t len;
    //speaker client from accept


    if ((connectionSocketListener=socket(AF_INET,SOCK_STREAM,0))==-1)
        handleErrors("Listener socket initialization failed", LISTENER_SOCKET_ERROR);

    //listener_addr initialization
    memset(&listener_addr,0,sizeof(listener_addr));

    listener_addr.sin_family=AF_INET;
    listener_addr.sin_port=htons(LISTENING_PORT);
    listener_addr.sin_addr.s_addr=INADDR_ANY;

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

        timeval timeout = {300,0};
        if (setsockopt(clientConnectionSocket,SOL_SOCKET,SO_RCVTIMEO,(const char*) &timeout,sizeof(timeval))==-1){
            cerr<<"Cannot set the timeout on the server"<<endl;
            return;
        }


        string client_ip;
        char buff[16];
        client_ip = inet_ntop(AF_INET,(void*)&client_addr.sin_addr,buff,sizeof(buff));
        cout <<"New connection established with " << client_ip <<endl;
        unsigned short id = rand()%100;
        Worker* w = new Worker(clientConnectionSocket, server_privkey, id);
        active_workers.push_back({id, w});
        pthread_t pthread;
        pthread_create(&pthread, NULL, &Worker::handle_commands_helper, w);
        active_threads.push_back(pthread);
    }

}

void shutdown_server(int received_signal){
    cout<<"Shutting down server"<<endl;
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);


    EVP_PKEY_free(server_privkey);
    close(connectionSocketListener);

    for(auto &active_thread : active_threads){
        pthread_kill(active_thread, SIGTERM);
    }

    for (auto & active_worker : active_workers){
        if(active_worker.pointer)
            delete active_worker.pointer;
    }
    //TODO clean_all
    //
    exit(received_signal);
}