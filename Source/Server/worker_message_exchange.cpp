//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"


message* Worker::build_message(unsigned char* iv, unsigned char opcode,
                       unsigned int payload_length, unsigned char* na,
                       unsigned char* nb, unsigned short seq_number,
                       unsigned char* payload, bool hmac){

    fixed_header h{};
    memcpy(h.initialization_vector, iv, IV_LENGTH);
    h.opcode = opcode;
    h.payload_length = payload_length;
    message m{};
    m.header = h;
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
    m.header.seq_number = seq_number;
    m.payload=payload;

    if(hmac)
        //compute hmac
        int a=0;

    return &m;
}


int Worker::send_msg_to_client(int socket_id, message msg){
    int ret;
    unsigned char* buffer_message;
    unsigned int total_len = FIXED_HEADER_LENGTH + (msg.header.nonceA_present ? NONCE_LENGTH : 0) +
            (msg.header.nonceB_present ? NONCE_LENGTH : 0) + msg.header.payload_length + (msg.hmac? DIGEST_LEN : 0);
    unsigned int len = htons(total_len);

    //send to client how many bytes to receive
    ret = send(socket_id,(void*)&len,sizeof(unsigned short),0);
    if(ret < (int)sizeof(unsigned short)){
        cout <<"Worker for: "<< this->username <<". Cannot send message through socket"<<endl;
        return -1;
    }

    if (total_len > UINT_MAX/sizeof(unsigned char)) {
        cout << "Worker for: " << this->username << ". Message size too long, cannot allocate buffer" << endl;
        return -1;
    }
    buffer_message = (unsigned char*)malloc(sizeof(unsigned char) * total_len);
    if(!buffer_message){
        cout << "Worker for: " << this->username << ". Cannot allocate buffer" << endl;
        return -1;
    }

    //Message serialization here
    unsigned int total_serialized=0;
    //iv serialization (16 Bytes)
    memcpy(buffer_message,msg.header.initialization_vector,IV_LENGTH);
    total_serialized +=IV_LENGTH;
    //opcode serialization (1 Byte)
    memcpy(buffer_message + total_serialized, &msg.header.opcode, OPCODE_LENGTH);
    total_serialized +=OPCODE_LENGTH;

    //payload_length serialization (3 Bytes)
    unsigned char* buffer_payload = (unsigned char*)malloc(PAYLOAD_LENGTH_LEN*sizeof(unsigned char));
    if(!buffer_payload){
        cout << "Worker for: " << this->username << ". Cannot allocate buffer" << endl;
        return -1;
    }
    for(int len_left=(PAYLOAD_LENGTH_LEN-sizeof(unsigned char))*8; len_left>=0; len_left-=8){
        unsigned char byte = (unsigned char)(msg.header.payload_length>>len_left);
        memcpy(buffer_payload, &byte, sizeof(unsigned char));
    }
    memcpy(buffer_message+total_serialized, &buffer_payload, PAYLOAD_LENGTH_LEN);
    total_serialized+=PAYLOAD_LENGTH_LEN;
    free(buffer_payload);

    //Na, Nb flags serialization (1 Byte each)
    memcpy(buffer_message+total_serialized, &msg.header.nonceA_present, sizeof(bool));
    total_serialized += sizeof(bool);
    memcpy(buffer_message+total_serialized, &msg.header.nonceB_present, sizeof(bool));
    total_serialized += sizeof(bool);

    //Seq Number serialization(2 Bytes)
    memcpy(buffer_message+total_serialized, &msg.header.seq_number, sizeof(unsigned short));

    //NonceA, Nonce B serialization (16 Bytes each)
    if(msg.header.nonceA_present){
        memcpy(buffer_message+total_serialized, &msg.nonceA, NONCE_LENGTH);
        total_serialized += NONCE_LENGTH;
    }
    if(msg.header.nonceB_present){
        memcpy(buffer_message+total_serialized, &msg.nonceB, NONCE_LENGTH);
        total_serialized += NONCE_LENGTH;
    }

    memcpy(buffer_message+total_serialized, &msg.payload, msg.header.payload_length);
    total_serialized +=msg.header.payload_length;

    if(msg.hmac){
        memcpy(buffer_message+total_serialized, &msg.hmac, DIGEST_LEN);
        total_serialized +=DIGEST_LEN;
    }

    ret = send(socket_id,(void*)buffer_message, total_serialized, 0);
    if(ret < total_serialized){
        cout << "Worker for: " << this->username << ". Failed to send message " << msg.header.opcode << msg.header.seq_number <<endl;
        free(buffer_message);
        return -1;
    }
    free(buffer_message);

    return ret;
}

int Worker::recv_msg_from_client(int socket_id, message *msg) {
    //TODO
}
