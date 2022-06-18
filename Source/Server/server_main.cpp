//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "server_functions.h"
using namespace std;

int main(int argc,char* argv[]){
    cout << "Initialization in progress ..."<<endl;
    init();

    cout << "Initialization terminated ..."<<endl;
    listen_connections();           //main server loop

    return 0;
}