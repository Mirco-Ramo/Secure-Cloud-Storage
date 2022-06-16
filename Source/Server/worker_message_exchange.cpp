//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"


message* Worker::build_message(unsigned char* iv, unsigned long payload_length, unsigned char* na, unsigned char* nb, unsigned char* payload, unsigned char* hmac){
    message m{};
    if (payload_length>MAX_PAYLOAD_LENGTH)
        return NULL;
    memcpy(m.header.initialization_vector, iv, IV_LENGTH);
    m.payload_length = (unsigned int)payload_length;
    if(na){
        m.header.nonceA_present=true;
        m.nonceA = na;
    }
    else
        m.header.nonceA_present=false;
    if(nb){
        m.header.nonceB_present=true;
        m.nonceB = nb;
    }
    else
        m.header.nonceB_present=false;

    m.payload=payload;

    if(hmac)
        memcpy(m.hmac, hmac, DIGEST_LEN);
    else
        m.hmac=NULL;

    return &m;
}

int Worker::send_data_to_client(int socket_id, unsigned char* data, int data_length){
    //TODO
}

int Worker::send_msg_to_client(int socket_id, message msg){
    //TODO
}
