//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"

bool check_username(const string& username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(strspn(username.c_str(),ok_chars) < strlen(username.c_str())){
        return false;
    }
    return true;
}

bool check_file_name(const string& file_name){
    return check_username(file_name);
}

