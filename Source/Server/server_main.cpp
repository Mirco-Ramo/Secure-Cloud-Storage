//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_conn_functions.cpp"

int main(int argc,char* argv[]){
    cout << "Initialization in progress ..."<<endl;
    init();

    cout << "Initialization terminated ..."<<endl;
    listen_connections();           //main server loop

    return 0;
}