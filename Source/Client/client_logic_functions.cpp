//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"
#include "client_functions.h"

extern vector<buffer> allocatedBuffers;
extern unsigned char hmac_key[];
extern unsigned char session_key[];
extern unsigned int client_counter;
extern unsigned int server_counter;
extern int username;

void print_list(unsigned char *list, unsigned int list_len);

bool handle_list(int socket_id, const string& username, const string& identity){
    int ret;

    message* m1;
    m1 = build_message(NULL, LIST, 0, NULL, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, false, identity) < FIXED_HEADER_LENGTH + DIGEST_LEN){
        cerr<<"Cannot send LIST request to server"<<endl;
        return false;
    }
    delete m1;
    client_counter++;
    //TODO check overflow

    message* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        return false;
    }

    server_counter++;

    if(m2->header.opcode != LIST_RES){
        cerr<<"Received an M2 response with unexpected opcode: " << m2->header.opcode <<endl;
        return false;
    }

    unsigned int payload_len;
    unsigned char* payload;

    ret = symm_decrypt(m2->payload, m2->header.payload_length,
                       session_key, m2->header.initialization_vector,payload,payload_len);
    if(ret==0) {
        cerr << "Cannot decrypt message M2!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, payload, payload_len});
    payload_field* response = new payload_field();
    payload_field* list_size = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {response, list_size};
    if(!get_payload_fields(m2->payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, response->field, response->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, list_size->field, list_size->field_len});

    if(*(response->field) != WRONG_FORMAT || *(response->field) != REQ_OK){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(response->field)){
        cerr << "Wrong format for M2 message" << endl;
        return false;
    }

    if(list_size->field_len < 0){
        cerr << "Error in size of the list" << endl;
        return false;
    }
    else if (list_size->field_len == 0) {
        cout << "You have no files in the cloud storage! Upload something with the UPLOAD command" << endl << PROMPT;
        return true;
    }
    else{
        unsigned int list_len = MAX_PAYLOAD_LENGTH - response->field_len - list_size->field_len;
        unsigned char* list;
        memcpy(list, &payload[response->field_len + list_size->field_len + 3], list_len);

        print_list(list, list_len);

        unsigned int recvd_list = list_len;

        while(recvd_list < *(list_size->field)) {
            auto *m2i = new message();
            if (recv_msg(socket_id, m2i, true, identity) <= 0) {
                cerr << "Cannot receive M2 from server" << endl;
                return false;
            }

            ret = verify_hmac(m2i, server_counter, hmac_key);
            if(ret != 1){
                return false;
            }

            server_counter++;

            if (m2->header.opcode != LIST_DATA) {
                cerr << "Received an M2 response with unexpected opcode: " << m2->header.opcode << endl;
                return false;
            }

            unsigned int payload_len_i;
            unsigned char *payload_i;

            ret = symm_decrypt(m2i->payload, m2i->header.payload_length,
                               session_key, m2i->header.initialization_vector, payload_i, payload_len_i);
            if (ret == 0) {
                cerr << "Cannot decrypt message M2!" << endl;
                return false;
            }

            payload_field *response_i = new payload_field();
            unsigned short num_fields_i = 1;
            payload_field *fields_i[] = {response_i};
            if (!get_payload_fields(m2->payload, fields_i, num_fields_i)) {
                cerr << "Cannot unpack payload fields" << endl;
                allocatedBuffers.push_back({CLEAR_BUFFER, payload_i});
                return false;
            }

            allocatedBuffers.push_back({CLEAR_BUFFER, response_i->field});
            if (*(response_i->field) != WRONG_FORMAT || *(response_i->field) != REQ_OK) {
                cerr << "Unmatching response for M2i message" << endl;
                return false;
            }
            if (WRONG_FORMAT == *(response_i->field)) {
                cerr << "Wrong format for M2 message" << endl;
                return false;
            }

            unsigned int list_len_i = MAX_PAYLOAD_LENGTH - response_i->field_len;
            unsigned char *list_i;
            memcpy(list_i, &payload[response_i->field_len + 1], list_len_i);

            print_list(list_i, list_len_i);

            recvd_list += list_len_i;
        }
    }
    clean_all();
    return true;
}

void print_list(unsigned char *list, unsigned int list_len) {
    string app = string((const char*) list, list_len);
    cout << app;
}

void handle_download(){

}
void handle_upload(){

}
void handle_rename(){

}
void handle_delete(){

}
void handle_logout(){

}