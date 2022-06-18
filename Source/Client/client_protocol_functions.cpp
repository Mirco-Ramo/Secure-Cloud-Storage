//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"

unsigned int client_counter;
unsigned int server_counter;

/*                  CHECK TAINTED INPUT                 */
bool check_username(const string& username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(username.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

bool check_file_name(const string& file_name){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.";

    if(file_name.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

bool command_ok(const string& command){
    char ok_chars [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if(command.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

bool begin_session(int socket_id){
    client_counter=1;
    server_counter=1;

}

void clean_counters(){
    client_counter=0;
    server_counter=0;
}

