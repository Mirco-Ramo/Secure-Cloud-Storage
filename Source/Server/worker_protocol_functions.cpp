//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"


bool Worker::check_username(const string& passed_username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(strspn(passed_username.c_str(),ok_chars) < strlen(passed_username.c_str())){
        return false;
    }
    return true;
}

bool Worker::check_file_name(const string& file_name){
    return Worker::check_username(file_name);
}

bool Worker::establish_session() {
    //TODO
    return true;
}



