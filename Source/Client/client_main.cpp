//
// Created by Francesco Del Turco, Mirco Ramo
//

#include "client_include.h"
#include "client_functions.h"


int client_socket;
string username;
string identity;
vector<buffer> allocatedBuffers;
unsigned char session_key[KEY_LEN];
unsigned char hmac_key[HMAC_KEY_LEN];
unsigned int client_counter;
unsigned int server_counter;

int main(int argc, char** argv) {
    sockaddr_in server_addr;

    signal(SIGINT, shutdown);     //handling termination signals
    signal(SIGHUP, shutdown);     //handling termination signals

    do {
        cout << "Please, type your username (maximum " << MAX_USERNAME_LEN << " characters): " << endl;
        getline(cin, username);
        if (!cin) {
            cerr << "Error during input"<<endl;
            exit(-1);
        }
    } while (username.size() > MAX_USERNAME_LEN);

    int ret = check_username(username);
    if (!ret) {
        cerr << "Invalid username. Only alphanumeric characters, dashes and underscores allowed"<<endl;
        exit(-1);
    }
    identity = "CLIENT " + username;
    ret = connect_to_server(&server_addr, &client_socket);    //collateral effect: server_addr initialization
    if (ret < 0)
        exit(-2);

    if (!begin_session(client_socket, username, identity)){
        cerr<<"Cannot begin session with server"<<endl;
        exit(-3);
    }

    cout<<HELP_MESSAGE<<endl;
    cout<<PROMPT << endl << PROMPT;

    bool logout_request = false;
    while(!logout_request) {
        cout << "Please, enter a command (type HELP to see a list of commands available): " << endl << PROMPT;
        string command;
        getline(cin, command);
        if (!cin) {
            cerr << "Error during command input"<<endl;
            exit(-1);
        }
        if(!command_ok(command)){
            cerr << "Please input valid commands. Only uppercase characters allowed."<<endl;
            continue;
        }
        if(command == "HELP"){
            cout << HELP_MESSAGE << endl << PROMPT;
        }
        else if(command == "LIST"){
            handle_list();
        }
        else if(command == "DOWNLOAD"){
            handle_download();
        }
        else if(command == "UPLOAD"){
            handle_upload();
        }
        else if(command == "RENAME"){
            handle_rename();
        }
        else if(command == "DELETE"){
            handle_delete();
        }
        else if(command == "LOGOUT"){
            handle_logout();
            logout_request = true;
        }
        else{
            cerr << "Invalid command."<<endl;
            continue;
        }
        //TODO consider if doing command and then request elements later for simplicity
        /*
        message* m;
        unsigned char* iv_buf = (unsigned char*)malloc(IV_LENGTH*sizeof(unsigned char));
        unsigned char opcode='a';
        for(int i=0; i<IV_LENGTH*sizeof(unsigned char); i+=sizeof(unsigned char)){
            *(iv_buf+i)=(unsigned char)(opcode+i);
            printf("%x", *(iv_buf+i));
        }
        m = build_message(iv_buf, opcode, command.size()+1, (unsigned char *)(command.c_str()), false);
        send_msg(client_socket, m, false, identity);
        if(command.size()>30)
            logout_request=true;

        m = new message();
        int ret = recv_msg(client_socket, m, false, identity);
        cout<<"Return value was: "<<ret<<endl;
        cout<<"Payload length is: "<<m->header.payload_length<<endl;

        string payload = (const char*)m->payload;
        cout<<"I received: "<<payload<<endl;
        free(m->payload);
         */
    }

    close(client_socket);

    //TODO disconnect();
    shutdown(0);

    return 0;
}

