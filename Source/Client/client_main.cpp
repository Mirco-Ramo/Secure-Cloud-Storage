//
// Created by Francesco Del Turco, Mirco Ramo
//

#include "client_include.h"
#include "client_functions.h"

int client_socket;
string username;
bool exit_flag = false;

int main(int argc, char** argv) {
    sockaddr_in server_addr;

    signal(SIGINT, shutdown);     //handling termination signals
    signal(SIGHUP, shutdown);     //handling termination signals

    do {
        cout << "Please, type your username (maximum " << MAX_USERNAME_LEN << " characters): " << endl;
        getline(cin, username);
        if (!cin) {
            cerr << "Error during input\n";
            exit(-1);
        }
    } while (username.size() > MAX_USERNAME_LEN);

    int ret = check_username(username);
    if (!ret) {
        cerr << "Invalid username\n";
        exit(-1);
    }

    client_socket = connect_to_server(&server_addr);    //collateral effect: server_addr initialization
    if (client_socket < 0)
        exit(-2);

    //TODO begin_session()

    cout<<HELP_MESSAGE<<endl;
    cout<<PROMPT;

    bool logout_request = false;
    while(!logout_request) {
        //TODO logout_request = accept_commands()
        logout_request=true;
    }

    close(client_socket);

    //TODO disconnect();
    //TODO clean_all(resources);

    return 0;
}

