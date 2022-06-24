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

bool handle_list(int socket_id, const string& identity){
    int ret;

    message* m1;
    m1 = build_message(NULL, LIST, 0, NULL, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, false, identity) < FIXED_HEADER_LENGTH + DIGEST_LEN){
        cerr<<"Cannot send LIST request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
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

    auto* response = new payload_field();
    auto* list_size = new payload_field();
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
        cerr << "Wrong format for M1 message" << endl;
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
        auto* list = (unsigned char*)malloc(list_len);
        memcpy(list, &payload[response->field_len + list_size->field_len + 3], list_len);

        allocatedBuffers.push_back({CLEAR_BUFFER, list, list_len});

        print_list(list, list_len);

        unsigned int recvd_list = list_len;

        while(recvd_list < *(list_size->field)) {
            auto *m2i = new message();
            if (recv_msg(socket_id, m2i, true, identity) <= 0) {
                cerr << "Cannot receive M2 from server" << endl;
                return false;
            }
            allocatedBuffers.push_back({MESSAGE, m2i});

            ret = verify_hmac(m2i, server_counter, hmac_key);
            if(ret != 1){
                cerr << "HMAC is not matching, closing connection" << endl;
                return false;
            }

            if(server_counter == UINT_MAX){
                cerr << "Maximum number of messages reached for a session, closing connection" << endl;
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

            allocatedBuffers.push_back({CLEAR_BUFFER, payload_i, payload_len_i});

            print_list(payload_i, payload_len_i);
            recvd_list += payload_len_i;
        }
    }
    clean_all();
    cout << PROMPT;
    return true;
}

bool handle_download(int socket_id, const string& identity,  const string& file_name){
    int ret;

    message* m1;
    auto* filename = (unsigned char*)malloc(file_name.size() + 1);
    memcpy(filename, file_name.c_str(), file_name.size() + 1);

    allocatedBuffers.push_back({CLEAR_BUFFER, filename, sizeof(filename)});

    unsigned int encrypted_filename_len;
    unsigned char* encrypted_filename;
    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    ret = symm_encrypt(filename, sizeof(filename), session_key,
                       IV_buffer, encrypted_filename, encrypted_filename_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_filename, encrypted_filename_len});

    if(ret==0) {
        cerr << "Cannot encrypt message M1!" << endl;
        return false;
    }

    m1 = build_message(IV_buffer, DOWNLOAD, encrypted_filename_len, encrypted_filename, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_filename_len + DIGEST_LEN){
        cerr<<"Cannot send DOWNLOAD request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m2->header.opcode != DOWNLOAD_RES){
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

    auto* response = new payload_field();
    auto* file_size = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {response, file_size};
    if(!get_payload_fields(m2->payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, response->field, response->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, file_size->field, file_size->field_len});

    if(*(response->field) != WRONG_FORMAT || *(response->field) != REQ_OK || *(response->field) != INVALID_FILENAME || *(response->field) != MISSING_FILE){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(response->field)){
        cerr << "Wrong format for M1 message" << endl;
        return false;
    }
    else if(INVALID_FILENAME == *(response->field)){
        cerr << "The filename was not valid, please input a valid filename" << endl << PROMPT;
        return true;
    }
    else if(MISSING_FILE == *(response->field)){
        cerr << "The file you asked for is not in the store! Check the files on the store with the LIST command" << endl << PROMPT;
        return true;
    }

    if(file_size->field_len < 0){
        cerr << "Error in size of the file" << endl;
        return false;
    }
    else{
        unsigned int file_len = MAX_PAYLOAD_LENGTH - response->field_len - file_size->field_len;
        auto* file_chunk = (unsigned char*)malloc(file_len);
        memcpy(file_chunk, &payload[response->field_len + file_size->field_len + 3], file_len);

        allocatedBuffers.push_back({CLEAR_BUFFER, file_chunk, file_len});

        write_file(file_chunk, file_len, file_name);

        unsigned int recvd_file = file_len;

        while(recvd_file < *(file_size->field)) {
            auto *m2i = new message();
            if (recv_msg(socket_id, m2i, true, identity) <= 0) {
                cerr << "Cannot receive M2 from server" << endl;
                if(!delete_file(file_name)){
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }
            allocatedBuffers.push_back({MESSAGE, m2i});

            ret = verify_hmac(m2i, server_counter, hmac_key);
            if(ret != 1){
                cerr << "HMAC is not matching, closing connection" << endl;
                if(!delete_file(file_name)){
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }

            if(server_counter == UINT_MAX){
                cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                if(!delete_file(file_name)){
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }
            server_counter++;

            if (m2->header.opcode != DOWNLOAD_DATA) {
                cerr << "Received an M2 response with unexpected opcode: " << m2->header.opcode << endl;
                if(!delete_file(file_name)){
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }

            unsigned int payload_len_i;
            unsigned char *payload_i;

            ret = symm_decrypt(m2i->payload, m2i->header.payload_length,
                               session_key, m2i->header.initialization_vector, payload_i, payload_len_i);
            if (ret == 0) {
                cerr << "Cannot decrypt message M2!" << endl;
                if(!delete_file(file_name)){
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }

            allocatedBuffers.push_back({CLEAR_BUFFER, payload_i, payload_len_i});

            write_file(payload_i, payload_len_i, file_name);
            recvd_file += payload_len_i;
        }
    }
    return true;
}

bool handle_upload(int socket_id, const string& identity,  const string& file_name){
    int ret;

    bool file_found;
    unsigned long file_size = get_file_size(file_name, file_found);
    if(!file_found){
        cerr << "File not found, please check the path and try again!";
        return true;
    }
    if(file_size > UINT_MAX){
        cerr << "The file is too big to be sent over the network, sorry!";
        return true;
    }
    file_size = (unsigned int)file_size;
    unsigned short file_size_len = sizeof(file_size);

    message* m1;
    auto* filename = (unsigned char*)malloc(file_name.size() + 1);
    memcpy(filename, file_name.c_str(), file_name.size() + 1);
    unsigned short file_name_size = sizeof(filename);
    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    allocatedBuffers.push_back({CLEAR_BUFFER, filename, file_name_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned short clear_payload_len = file_name_size + file_size + 2*sizeof(unsigned short);
    auto* clear_payload = (unsigned char*)malloc(clear_payload_len);
    if(!clear_payload){
        cerr<<"Cannot allocate buffer for m1"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload, clear_payload_len});

    unsigned int current_len = 0;

    memcpy(clear_payload, &file_name_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len, filename, file_name_size);
    current_len += file_name_size;

    memcpy(clear_payload + current_len, &file_size_len, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len,&file_size,file_size);

    ret = symm_encrypt(clear_payload, clear_payload_len, session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "Cannot encrypt message M1!" << endl;
        return false;
    }

    m1 = build_message(IV_buffer, UPLOAD_REQ, encrypted_payload_len, encrypted_payload, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"Cannot send UPLOAD_REQ request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m2->header.opcode != UPLOAD_RES){
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

    if(*(payload) != WRONG_FORMAT || *(payload) != REQ_OK || *(payload) != INVALID_FILENAME || *(payload) != DUP_NAME){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload)){
        cerr << "Wrong format for M1 message" << endl;
        return false;
    }
    else if(INVALID_FILENAME == *(payload)){
        cerr << "The filename was not valid, please input a valid filename" << endl << PROMPT;
        return true;
    }
    else if(DUP_NAME == *(payload)){
        cerr << "There is already a file with the same name in the storage! Check the files on the store with the LIST command" << endl << PROMPT;
        return true;
    }
    else{
        unsigned int sent_size = 0;
        while(sent_size < file_size){

            message* m3i;
            unsigned int encrypted_payload_len_i;
            unsigned char* encrypted_payload_i;

            auto* IV_buffer_i = (unsigned char*)malloc(IV_LENGTH);
            if(!IV_buffer_i){
                cerr<<"Cannot allocate buffer for IV"<<endl;
                return false;
            }
            allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i, IV_LENGTH});

            auto* clear_payload_i = read_chunk(file_name, sent_size,
                                               (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > file_size ? file_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN);
            if(!clear_payload_i){
                cerr<<"Cannot allocate buffer for m3i"<<endl;
                return false;
            }
            unsigned short clear_payload_len_i = sizeof(clear_payload_i);
            allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload_i, clear_payload_len_i});

            ret = symm_encrypt(clear_payload_i, clear_payload_len_i, session_key,
                               IV_buffer_i, encrypted_payload_i, encrypted_payload_len_i);

            allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_i, encrypted_payload_len_i});

            if(ret==0) {
                cerr << "Cannot encrypt message M3i!" << endl;
                return false;
            }

            m3i = build_message(IV_buffer_i, UPLOAD_DATA, encrypted_payload_len_i, encrypted_payload_i, true, hmac_key, client_counter);
            if(send_msg(socket_id, m3i, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len_i + DIGEST_LEN){
                cerr<<"Cannot send UPLOAD_DATA request to server"<<endl;
                return false;
            }
            delete m3i;

            if(client_counter == UINT_MAX){
                cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                return false;
            }
            client_counter++;

            sent_size += clear_payload_len_i;
        }
    }

    auto* m4 = new message();
    if(recv_msg(socket_id, m4, true, identity)<=0){
        cerr<<"Cannot receive M4 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m4});
    ret = verify_hmac(m4, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m4->header.opcode != UPLOAD_ACK){
        cerr<<"Received an M4 response with unexpected opcode: " << m4->header.opcode <<endl;
        return false;
    }

    unsigned int payload_len_m4;
    unsigned char* payload_m4;

    ret = symm_decrypt(m4->payload, m4->header.payload_length,
                       session_key, m4->header.initialization_vector,payload_m4,payload_len_m4);
    if(ret==0) {
        cerr << "Cannot decrypt message M4!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, payload_m4, payload_len_m4});

    if(*(payload_m4) != WRONG_FORMAT || *(payload_m4) != REQ_OK){
        cerr << "Unmatching response for M4 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload_m4)){
        cerr << "Wrong format for M3 message - " << endl;
        return false;
    }

    cout << "File correctly uploaded!" << endl << PROMPT;
    return true;
}

bool handle_rename(int socket_id, const string& identity,  const string& old_file_name, const string& new_file_name){
    int ret;

    message* m1;
    auto* old_filename = (unsigned char*)malloc(old_file_name.size() + 1);
    memcpy(old_filename, old_file_name.c_str(), old_file_name.size() + 1);
    unsigned short old_file_name_size = sizeof(old_filename);
    auto* new_filename = (unsigned char*)malloc(new_file_name.size() + 1);
    memcpy(new_filename, new_file_name.c_str(), new_file_name.size() + 1);
    unsigned short new_file_name_size = sizeof(new_filename);
    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    allocatedBuffers.push_back({CLEAR_BUFFER, old_filename, old_file_name_size});
    allocatedBuffers.push_back({CLEAR_BUFFER, new_filename, new_file_name_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned short clear_payload_len = old_file_name_size + new_file_name_size + 2*sizeof(unsigned short);
    auto* clear_payload = (unsigned char*)malloc(clear_payload_len);
    if(!clear_payload){
        cerr<<"Cannot allocate buffer for m1"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload, clear_payload_len});

    unsigned int current_len = 0;

    memcpy(clear_payload, &old_file_name_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len, old_filename, old_file_name_size);
    current_len += old_file_name_size;

    memcpy(clear_payload + current_len, &new_file_name_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len,new_filename,new_file_name_size);

    ret = symm_encrypt(clear_payload, clear_payload_len, session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "Cannot encrypt message M1!" << endl;
        return false;
    }

    m1 = build_message(IV_buffer, RENAME, encrypted_payload_len, encrypted_payload, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"Cannot send RENAME request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m2->header.opcode != RENAME_RES){
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

    if(*(payload) != WRONG_FORMAT || *(payload) != REQ_OK || *(payload) != INVALID_FILENAME || *(payload) != MISSING_FILE || *(payload) != DUP_NAME){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload)){
        cerr << "Wrong format for M1 message" << endl;
        return false;
    }
    else if(INVALID_FILENAME == *(payload)){
        cerr << "The filename was not valid, please input a valid filename" << endl << PROMPT;
        return true;
    }
    else if(DUP_NAME == *(payload)){
        cerr << "There is already a file with the same name in the storage! Check the files on the store with the LIST command" << endl << PROMPT;
        return true;
    }
    else if(MISSING_FILE == *(payload)){
        cerr << "The file you asked to rename is not present in the cloud storage! Check the files on the store with the LIST command" << endl << PROMPT;
        return true;
    }

    cout << "The file was renamed successfully!" << endl << PROMPT;
    return true;
}
bool handle_delete(int socket_id, const string& identity,  const string& file_name){
    int ret;

    message* m1;
    auto* filename = (unsigned char*)malloc(file_name.size() + 1);
    memcpy(filename, file_name.c_str(), file_name.size() + 1);

    allocatedBuffers.push_back({CLEAR_BUFFER, filename, sizeof(filename)});

    unsigned int encrypted_filename_len;
    unsigned char* encrypted_filename;
    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    ret = symm_encrypt(filename, sizeof(filename), session_key,
                       IV_buffer, encrypted_filename, encrypted_filename_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_filename, encrypted_filename_len});

    if(ret==0) {
        cerr << "Cannot encrypt message M1!" << endl;
        return false;
    }

    m1 = build_message(IV_buffer, DELETE, encrypted_filename_len, encrypted_filename, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_filename_len + DIGEST_LEN){
        cerr<<"Cannot send DELETE request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m2->header.opcode != DELETE_RES){
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

    if(*(payload) != WRONG_FORMAT || *(payload) != REQ_OK || *(payload) != INVALID_FILENAME || *(payload) != MISSING_FILE){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload)){
        cerr << "Wrong format for M1 message" << endl;
        return false;
    }
    else if(INVALID_FILENAME == *(payload)){
        cerr << "The filename was not valid, please input a valid filename" << endl << PROMPT;
        return true;
    }
    else if(MISSING_FILE == *(payload)){
        cerr << "The file you asked to delete is not present in the cloud storage! Check the files on the store with the LIST command" << endl << PROMPT;
        return true;
    }

    cout << "The file was deleted successfully!" << endl << PROMPT;
    return true;
}
bool handle_logout(int socket_id, const string& identity){
    int ret;

    message* m1;
    m1 = build_message(NULL, LOGOUT, 0, NULL, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + DIGEST_LEN){
        cerr<<"Cannot send LOGOUT request to server"<<endl;
        return false;
    }
    delete m1;

    if(client_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    client_counter++;

    auto* m2 = new message();
    if(recv_msg(socket_id, m2, true, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        return false;
    }

    allocatedBuffers.push_back({MESSAGE, m2});
    ret = verify_hmac(m2, server_counter, hmac_key);
    if(ret != 1){
        cerr << "HMAC is not matching, closing connection" << endl;
        return false;
    }

    if(server_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    server_counter++;

    if(m2->header.opcode != LOGOUT_RES){
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

    if(*(payload) != WRONG_FORMAT || *(payload) != REQ_OK){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload)){
        cerr << "Wrong format for M1 message" << endl;
        return false;
    }

    cout << "The logout was successful! See you next time!" << endl;
    return true;
}


/*
 *
 * UTILITY FUNCTIONS
 *
 */

void print_list(unsigned char *list, unsigned int list_len) {
    string app = string((const char*) list, list_len);
    cout << app;
    app = "";
}