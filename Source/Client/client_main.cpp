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
    cout<<PROMPT << endl << PROMPT;

    bool logout_request = false;
    while(!logout_request) {
        cout << "Please, enter a command (type HELP to see a list of commands available): " << endl << PROMPT;
        string command;
        cin >> command;
        //TODO sanitize all the commands before if-else
        if(command.compare("HELP") == 0){
            cout << HELP_MESSAGE << endl << PROMPT;
        }
        else if(command.compare("LIST") == 0){
            handle_list();
        }
        //TODO consider if doing command and then request elements later for simplicity
        //TODO logout_request = accept_commands()
        message* m;
        unsigned char* iv_buf = (unsigned char*)malloc(IV_LENGTH);
        unsigned char opcode='a';
        memset(iv_buf, 0, IV_LENGTH);
        m = build_message(iv_buf, opcode, command.size()+1, (unsigned char *)(command.c_str()), false);
        cout<<"Sending new msg"<<endl;
        send_msg_to_server(client_socket, m);
    }

    close(client_socket);

    //TODO disconnect();
    //TODO clean_all(resources);

    return 0;
}

