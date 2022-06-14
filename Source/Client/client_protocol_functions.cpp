//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"

bool check_file_name(string file_name){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_";

    if(strspn(file_name.c_str(),ok_chars) < strlen(file_name.c_str())){
        return false;
    }
    return true;
}