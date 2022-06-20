//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"
#include "../Common_Libs/struct_message.h"

unsigned int client_counter;
unsigned int server_counter;

bool begin_session(int socket_id, const string& username, const string& identity){
    client_counter=1;
    server_counter=1;
    EVP_PKEY *client_dhkey = NULL;
    if(!generate_dh_secret(client_dhkey)){
        cerr<<"Cannot generate dh secret"<<endl;
        EVP_PKEY_free(client_dhkey);
        return false;
    }
    EVP_PKEY* client_pub_dhkey = extract_dh_pubkey(client_dhkey);
    unsigned short encoded_client_pub_dhkey_len;
    unsigned char* encoded_client_pub_dhkey;
    if(!encode_EVP_PKEY(client_pub_dhkey, encoded_client_pub_dhkey, encoded_client_pub_dhkey_len)){
        cerr<<"Cannot encode dh pub key"<<endl;
        EVP_PKEY_free(client_dhkey);
        EVP_PKEY_free(client_pub_dhkey);
        return false;
    }
    message* m1;
    m1 = build_message(NULL, AUTH_INIT, encoded_client_pub_dhkey_len, encoded_client_pub_dhkey, false);
    if(send_msg(socket_id, m1, false, identity) < encoded_client_pub_dhkey_len+FIXED_HEADER_LENGTH){
        cerr<<"Cannot send pub key to server"<<endl;
        EVP_PKEY_free(client_dhkey);
        EVP_PKEY_free(client_pub_dhkey);
#pragma optimize("", off)
        memset(encoded_client_pub_dhkey, 0, encoded_client_pub_dhkey_len);
#pragma optimize("", on)
        free(encoded_client_pub_dhkey);
        return false;
    }

#pragma optimize("", off)
    memset(encoded_client_pub_dhkey, 0, encoded_client_pub_dhkey_len);
#pragma optimize("", on)
    free(encoded_client_pub_dhkey);
    return true;
}

void clean_counters(){
    client_counter=0;
    server_counter=0;
}

