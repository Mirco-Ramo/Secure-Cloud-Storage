//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"
#include "../Common_Libs/struct_message.h"

unsigned int client_counter;
unsigned int server_counter;


bool begin_session(int socket_id){
    client_counter=1;
    server_counter=1;

}

void clean_counters(){
    client_counter=0;
    server_counter=0;
}

