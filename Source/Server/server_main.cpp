//
// Created by Francesco del Turco, Mirco Ramo
//


#include "server_conn_functions.cpp"

int main(int argc,char* argv[]){
    cout << "Initialization in progress ..."<<endl;
    Server* s = new Server();
    s->init();
    cout << "Initialization terminated ..."<<endl;

    s->listen_connections();

    return 0;
}