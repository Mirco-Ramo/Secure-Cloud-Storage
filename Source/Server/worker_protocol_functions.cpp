//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"

unsigned char* generate_random_nonce(){
    //TODO
    return NULL;
}

unsigned char* Worker::initialize_iv(){
    //TODO
    return NULL;
}

bool Worker::check_username(const string& passed_username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(strspn(passed_username.c_str(),ok_chars) < strlen(passed_username.c_str())){
        return false;
    }
    return true;
}

bool Worker::check_file_name(const string& file_name){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_.-";

    if(strspn(file_name.c_str(),ok_chars) < strlen(file_name.c_str())){
        return false;
    }
    return true;
}

bool Worker::establish_session() {
    //TODO
    return true;
}



