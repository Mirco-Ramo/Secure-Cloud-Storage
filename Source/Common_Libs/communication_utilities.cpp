//
// Created by Francesco del Turco, Mirco Ramo
//

#include "common_parameters.h"
#include "common_functions.h"
using namespace std;

message* build_message(unsigned char* iv, unsigned char opcode,
                       unsigned int payload_length, unsigned char* payload, bool hmac, unsigned char* hmac_key=NULL){

    fixed_header* h=new fixed_header();
    if(!iv)
        memset(h->initialization_vector,0,IV_LENGTH);
    else
        memcpy(h->initialization_vector, iv, IV_LENGTH);
    h->opcode = opcode;
    h->payload_length = payload_length;
    message* m = new message();
    m->header = *h;
    m->payload = payload;
    if(hmac){
        unsigned char* buffer_mac;
        unsigned short buffer_mac_len;

        unsigned char payload_len_bytes[PAYLOAD_LENGTH_LEN];
        for (int i=0; i<PAYLOAD_LENGTH_LEN; i++){
        payload_len_bytes[i]=(unsigned char)(payload_length>>((PAYLOAD_LENGTH_LEN-1-i)*8));
        }
        unsigned int input_lengths[] = {IV_LENGTH, OPCODE_LENGTH, PAYLOAD_LENGTH_LEN, payload_length};
        unsigned char* inputs[] = {iv, &opcode, payload_len_bytes, payload};
        unsigned int inputs_number=4; //iv, opcode, payload_length, payload
        if (prepare_buffer_for_hmac(buffer_mac, buffer_mac_len, inputs, input_lengths, inputs_number)!=FIXED_HEADER_LENGTH+payload_length){
            cerr<<"Impossible to create buffer for hmac: Message build aborted";
            return NULL;
        }
        unsigned char* hmac_result;
        if(!compute_hmac(buffer_mac, buffer_mac_len, hmac_result, hmac_key)){
            cerr<<"Impossible to compute hmac: Message build aborted";
            return NULL;
        }
        memcpy(m->hmac, hmac_result, DIGEST_LEN);
        free(buffer_mac);
        free(hmac_result);
    }



    return m;
}


int send_msg(int socket_id, message* msg, bool hmac, string identity){
    int ret;
    unsigned char* buffer_message;

    if(msg->header.payload_length>MAX_PAYLOAD_LENGTH){
        cout << "["+identity+"]:"<<"Payload is over maximum allowed value" << endl;
        return -1;
    }

    unsigned int total_len = FIXED_HEADER_LENGTH + msg->header.payload_length + (hmac? DIGEST_LEN : 0);

    if (total_len > UINT_MAX/sizeof(unsigned char)) {
        cout << "["+identity+"]:"<< "Message size too long, cannot allocate buffer" << endl;
        return -1;
    }
    buffer_message = (unsigned char*)malloc(sizeof(unsigned char) * total_len);
    if(!buffer_message){
        cout << "["+identity+"]:"<< "Cannot allocate buffer to send message" << endl;
        return -1;
    }

    //Message serialization here
    unsigned int total_serialized=0;
    //iv serialization (16 Bytes)
    memcpy(buffer_message,msg->header.initialization_vector,IV_LENGTH);
    total_serialized +=IV_LENGTH;

    //opcode serialization (1 Byte)
    memcpy(buffer_message + total_serialized, &msg->header.opcode, OPCODE_LENGTH);
    total_serialized +=OPCODE_LENGTH;
    //payload_length serialization (3 Bytes)
    unsigned char* buffer_payload = (unsigned char*)malloc(PAYLOAD_LENGTH_LEN*sizeof(unsigned char));
    if(!buffer_payload){
        cout << "["+identity+"]:"<< "Cannot allocate buffer" << endl;
        return -1;
    }
    for(int len_left=(PAYLOAD_LENGTH_LEN-sizeof(unsigned char)); len_left>=0; len_left--){
        unsigned int a = (msg->header.payload_length>>(len_left*8));
        unsigned char byte = (unsigned char)(a);
        memcpy(buffer_payload+(PAYLOAD_LENGTH_LEN-(len_left+1)), &byte, sizeof(unsigned char));
    }
    memcpy(buffer_message+total_serialized, buffer_payload, PAYLOAD_LENGTH_LEN);
    total_serialized+=PAYLOAD_LENGTH_LEN;
    free(buffer_payload);

    memcpy(buffer_message+total_serialized, msg->payload, msg->header.payload_length);
    total_serialized +=msg->header.payload_length;
    if(hmac){
        memcpy(buffer_message+total_serialized, msg->hmac, DIGEST_LEN);
        total_serialized +=DIGEST_LEN;
    }
    ret = send(socket_id,(void*)buffer_message, total_serialized, 0);
    if(ret < total_serialized){
        cout << "["+identity+"]:"<< "Failed to send message " << msg->header.opcode<<endl;
        free(buffer_message);
        return -1;
    }
    free(buffer_message);

    return ret;
}



int recv_msg(int socket_id, message *msg, bool hmac, string identity) {
    int ret;
    unsigned char* buffer_message, *buffer_iv;
    fixed_header h{};

    buffer_message = (unsigned char*)malloc(FIXED_HEADER_LENGTH);
    if(!buffer_message){
        cout << "["+identity+"]:"<< "Cannot allocate buffer to receive message" << endl;
        return -1;
    }

    // receive header
    ret = recv(socket_id,(void*)buffer_message, FIXED_HEADER_LENGTH,0);
    if(ret <= 0){
        free(buffer_message);
        cout << "["+identity+"]:"<< "Cannot receive data from client" << endl;
        return -1;
    }
    if(ret < FIXED_HEADER_LENGTH){
        free(buffer_message);
        cout << "["+identity+"]:"<< "Failed to receive data from client" << endl;
        return -1;
    }

    //deserialize header
    memcpy(h.initialization_vector, buffer_message, IV_LENGTH*sizeof(unsigned char));
    memcpy(&h.opcode, buffer_message+IV_LENGTH, OPCODE_LENGTH);

    unsigned int read_so_far = IV_LENGTH + OPCODE_LENGTH;
    unsigned int payload_length=0;
    unsigned char p;

    for(int i=0; i<PAYLOAD_LENGTH_LEN; i+=sizeof(unsigned char)){
        p = *(buffer_message+read_so_far+i);
        payload_length = (payload_length<<8) | p;
    }

    //check payload length
    if(payload_length>MAX_PAYLOAD_LENGTH){
        free(buffer_message);
        cout << "["+identity+"]:"<< "Payload is over maximum allowed value" << endl;
        return -1;
    }
    h.payload_length = payload_length;
    msg->header = h;
    free(buffer_message);

    if (payload_length > UINT_MAX/sizeof(unsigned char)) {
        cout << "["+identity+"]:"<< "Message size too long, cannot allocate buffer" << endl;
        return -1;
    }
    buffer_message = (unsigned char*)malloc(sizeof(unsigned char) * payload_length);
    if(!buffer_message){
        cout << "["+identity+"]:"<< "Cannot allocate buffer to receive payload" << endl;
        return -1;
    }

    ret = recv(socket_id,(void*)buffer_message, payload_length, 0);
    if(ret < payload_length){
        free(buffer_message);
        cout << "["+identity+"]:"<< "Payload receive failed" << endl;
        return -1;
    }

    msg->payload = buffer_message;

    if(!hmac)
        return FIXED_HEADER_LENGTH + ret;

    unsigned char* buffer_hmac = (unsigned char*)malloc(DIGEST_LEN);
    if(!buffer_hmac){
        cout << "["+identity+"]:"<< "Cannot allocate buffer to receive hmac" << endl;
        return -1;
    }
    ret = recv(socket_id,(void*)buffer_hmac, DIGEST_LEN, 0);
    if(ret < DIGEST_LEN){
        free(buffer_hmac);
        cout << "["+identity+"]:"<< "Hmac receive failed" << endl;
        return -1;
    }

    memcpy(msg->hmac, buffer_hmac, DIGEST_LEN);
    return FIXED_HEADER_LENGTH + payload_length + ret;
}