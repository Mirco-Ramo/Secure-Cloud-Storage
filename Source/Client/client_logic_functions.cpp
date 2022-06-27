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
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + DIGEST_LEN){
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

    unsigned int decrypted_payload_len;
    unsigned char* decrypted_payload;

    ret = symm_decrypt(m2->payload, m2->header.payload_length,
                       session_key, m2->header.initialization_vector,decrypted_payload,decrypted_payload_len);
    if(ret==0) {
        cerr << "Cannot decrypt message M2!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, decrypted_payload, decrypted_payload_len});

    auto* response = new payload_field();
    auto* list_size = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {response, list_size};
    if(!get_payload_fields(decrypted_payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, response->field, response->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, list_size->field, list_size->field_len});

    if(*(response->field) != WRONG_FORMAT && *(response->field) != REQ_OK){
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
    unsigned int list_len = decrypted_payload_len - response->field_len - list_size->field_len -2*sizeof(unsigned short);
    auto* list = (unsigned char*)malloc(list_len);
    memcpy(list, decrypted_payload + response->field_len + list_size->field_len + 2*sizeof(unsigned short), list_len);

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
    clean_all();
    cout << PROMPT;
    return true;
}

bool handle_download(int socket_id, const string& identity,  const string& file_name){
    int ret;

    message* m1;
    auto* filename = (unsigned char*)malloc(file_name.size() + 1);
    memcpy(filename, file_name.c_str(), file_name.size() + 1);

    allocatedBuffers.push_back({CLEAR_BUFFER, filename, (unsigned int)file_name.size()+1});

    unsigned int encrypted_filename_len;
    unsigned char* encrypted_filename;
    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    ret = symm_encrypt(filename, file_name.size() + 1, session_key,
                       IV_buffer, encrypted_filename, encrypted_filename_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_filename});

    if(ret==0) {
        cerr << "Cannot encrypt message M1!" << endl;
        return false;
    }

    m1 = build_message(IV_buffer, DOWNLOAD, encrypted_filename_len, encrypted_filename, true, hmac_key, client_counter);
    if(send_msg(socket_id, m1, true, identity) < FIXED_HEADER_LENGTH + (int)encrypted_filename_len + DIGEST_LEN){
        cerr<<"Cannot send DOWNLOAD request to server"<<endl;
        return false;
    }
    allocatedBuffers.push_back({MESSAGE, m1});

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
    if(!get_payload_fields(payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, response->field, response->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, file_size->field, file_size->field_len});

    if(*(response->field) != WRONG_FORMAT && *(response->field) != REQ_OK && *(response->field) != INVALID_FILENAME && *(response->field) != MISSING_FILE){
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

    unsigned int file_data_len = payload_len - response->field_len - file_size->field_len - 2*sizeof(unsigned short);
    auto* file_chunk = (unsigned char*)malloc(file_data_len);
    memcpy(file_chunk, payload + response->field_len + file_size->field_len + 2*sizeof(unsigned short), file_data_len);

    allocatedBuffers.push_back({CLEAR_BUFFER, file_chunk, file_data_len});

    if(!write_file(file_chunk, file_data_len, file_name)){
        if(!delete_file(file_name)){
            cerr << "The file was not downloaded completely, but it was impossible to delete it."
                    "We suggest to delete the file manually for safety purposes." << endl;
        }
        return false;
    }


    unsigned int total_file_size;
    memcpy(&total_file_size, file_size->field, sizeof(unsigned int));
    cout<<"File size is: "<<total_file_size<<" bytes"<<endl;
    cout<<"Downloading..."<<endl;
    unsigned int recvd_file = file_data_len;

    unsigned char* enc_chunk_buf = (unsigned char*)malloc(2*MAX_FETCHABLE);
    unsigned char* clear_chunk_buf;
    if(!enc_chunk_buf){
        cerr << "Cannot allocate buffer to save chunks" << endl;
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, enc_chunk_buf});

    unsigned int clear_chunk_buf_len;

    unsigned int recvd_i = 0;
    while(recvd_file<total_file_size) {
        auto *m2j = new message();
        if (recv_msg(socket_id, m2j, true, identity) <= 0) {
            cerr << "Cannot receive M2 from server" << endl;
            cerr << "I downloaded: "<<recvd_file<<endl;
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        ret = verify_hmac(m2j, server_counter, hmac_key);
        if (ret != 1) {
            cerr << "HMAC is not matching, closing connection" << endl;
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if (server_counter == UINT_MAX) {
            cerr << "Maximum number of messages reached for a session, closing connection" << endl;
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }
        server_counter++;

        if (m2j->header.opcode != DOWNLOAD_DATA) {
            cerr << "Received an M2 response with unexpected opcode: " << (int) m2j->header.opcode << endl;
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if(recvd_i>0 && memcmp(IV_buffer, m2j->header.initialization_vector, IV_LENGTH)!=0){

            ret = symm_decrypt(enc_chunk_buf, recvd_i, session_key, IV_buffer, clear_chunk_buf, clear_chunk_buf_len);
            if (ret == 0) {
                cerr << "Cannot decrypt message M2!" << endl;
                if (!delete_file(file_name)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }

            if (!write_file(clear_chunk_buf, clear_chunk_buf_len, file_name)) {
                if (!delete_file(file_name)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }
#pragma optimize("", off)
            memset(clear_chunk_buf, 0, clear_chunk_buf_len);
#pragma optimze("", on)
            free(clear_chunk_buf);
            recvd_i = 0;
        }
        memcpy(IV_buffer, m2j->header.initialization_vector, IV_LENGTH);
        memcpy(enc_chunk_buf + recvd_i, m2j->payload, m2j->header.payload_length);
        recvd_file += m2j->header.payload_length;
        recvd_i +=m2j->header.payload_length;
        delete m2j;
    }

    if(recvd_i>0){
        ret = symm_decrypt(enc_chunk_buf, recvd_i, session_key, IV_buffer, clear_chunk_buf, clear_chunk_buf_len);
        if (ret == 0) {
            cerr << "Cannot decrypt message M2!" << endl;
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if (!write_file(clear_chunk_buf, clear_chunk_buf_len, file_name)) {
            if (!delete_file(file_name)) {
                cerr << "The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        cout << "Received " + to_string(recvd_file) + " bytes of " + to_string(total_file_size) << endl;

#pragma optimize("", off)
        memset(clear_chunk_buf, 0, clear_chunk_buf_len);
#pragma optimze("", on)
        free(clear_chunk_buf);
    }
    cout<<"File downloaded"<<endl;
    return true;
}

bool handle_upload(int socket_id, const string& identity,  const string& file_name){
    int ret;

    string tokenized_file_name = tokenize_string(file_name);
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
    auto* char_file_size = (unsigned char*)malloc(sizeof(unsigned int));
    if(!char_file_size){
        cerr << "Cannot allocate buffer for the file size"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, char_file_size, sizeof(unsigned int)});

    auto int_file_size = (unsigned int)file_size;
    memcpy(char_file_size, &int_file_size, sizeof(unsigned int));
    unsigned short file_size_len = sizeof(unsigned int);

    message* m1;
    auto* filename = (unsigned char*)malloc(tokenized_file_name.size());
    if(!filename){
        cerr << "Cannot allocate buffer for the filename"<<endl;
        return false;
    }
    unsigned short file_name_size = tokenized_file_name.size();
    allocatedBuffers.push_back({CLEAR_BUFFER, filename, file_name_size});
    memcpy(filename, tokenized_file_name.c_str(), file_name_size);
    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned short clear_payload_len = file_name_size + file_size_len + 2*sizeof(unsigned short);
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
    memcpy(clear_payload + current_len,char_file_size,file_size_len);

    ret = symm_encrypt(clear_payload, clear_payload_len, session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload});

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
        cerr<<"Received an M2 response with unexpected opcode: " << (int)m2->header.opcode <<endl;
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

    if(*(payload) != WRONG_FORMAT && *(payload) != REQ_OK && *(payload) != INVALID_FILENAME && *(payload) != DUP_NAME){
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

    unsigned int fetched_size=0;
    unsigned int sent_size_i=0;
    unsigned char* clear_chunk_i;
    unsigned int encrypted_chunk_len_i;
    unsigned char *encrypted_chunk_i;
    allocatedBuffers.push_back({ENC_BUFFER, encrypted_chunk_i});
    auto* payload_j = (unsigned char*)malloc(MAX_PAYLOAD_LENGTH);
    if(!payload_j){
        cerr << "Cannot allocate buffer for message" << endl;
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, payload_j, MAX_PAYLOAD_LENGTH});

    while(fetched_size<int_file_size) {
        unsigned int to_fetch = (int_file_size-fetched_size) < MAX_FETCHABLE ? (int_file_size-fetched_size) : MAX_FETCHABLE;
        clear_chunk_i = read_chunk(file_name, fetched_size, to_fetch);
        if (!clear_chunk_i) {
            return false;
        }
        ret = symm_encrypt(clear_chunk_i, to_fetch, session_key,
                           IV_buffer, encrypted_chunk_i, encrypted_chunk_len_i);
        if (ret == 0) {
            cerr << "Cannot encrypt message M2!" << endl;
            return false;
        }
        fetched_size +=to_fetch;

        sent_size_i = 0;

        while (sent_size_i < encrypted_chunk_len_i) {
            message *m3j;

            unsigned int to_send =
                    (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > encrypted_chunk_len_i - sent_size_i ? encrypted_chunk_len_i - sent_size_i :
                    MAX_PAYLOAD_LENGTH - BLOCK_LEN;

            unsigned int payload_len_j = to_send;

            memcpy(payload_j, encrypted_chunk_i+sent_size_i, payload_len_j);

            m3j = build_message(IV_buffer, UPLOAD_DATA, payload_len_j, payload_j, true,
                                hmac_key, client_counter);
            if (send_msg(socket_id, m3j, true, identity) <
                FIXED_HEADER_LENGTH + (int) payload_len_j + DIGEST_LEN) {
                cerr << "Cannot send DOWNLOAD_DATA response to client" << endl;
                return false;
            }
            delete m3j;

            if (client_counter == UINT_MAX) {
                cerr << "Maximum number of messages reached for a session, closing connection"<< endl;
                return false;
            }
            client_counter++;
            sent_size_i +=payload_len_j;
        }

#pragma optimize("", off)
        memset(clear_chunk_i, 0, to_fetch);
#pragma optimze("", on)
        free(clear_chunk_i);
        free(encrypted_chunk_i);

        cout << "Sent " + to_string(fetched_size) + " bytes of " + to_string(int_file_size) << endl;
    }

    free(payload_j);

    cout<<"Upload completed"<<endl;

    //M4
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
        cerr<<"Received an M4 response with unexpected opcode: " << (int)m4->header.opcode <<endl;
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

    if(*(payload_m4) != WRONG_FORMAT && *(payload_m4) != REQ_OK){
        cerr << "Unmatching response for M4 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload_m4)){
        cerr << "Wrong format for M4 message - " << endl;
        return false;
    }

    cout << "File correctly uploaded!" << endl << PROMPT;
    return true;
}

bool handle_rename(int socket_id, const string& identity,  const string& old_file_name, const string& new_file_name){
    int ret;

    message* m1;
    auto* old_filename = (unsigned char*)malloc(old_file_name.size());
    if(!old_filename){
        cerr << "Cannot allocate buffer for filename" << endl;
        return false;
    }
    memcpy(old_filename, old_file_name.c_str(), old_file_name.size());
    unsigned short old_file_name_size = old_file_name.size();
    auto* new_filename = (unsigned char*)malloc(new_file_name.size());
    if(!new_filename){
        cerr << "Cannot allocate buffer for filename" << endl;
        return false;
    }
    memcpy(new_filename, new_file_name.c_str(), new_file_name.size());
    unsigned short new_file_name_size = new_file_name.size();
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

    if(*(payload) != WRONG_FORMAT && *(payload) != REQ_OK && *(payload) != INVALID_FILENAME && *(payload) != MISSING_FILE && *(payload) != DUP_NAME){
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
    unsigned int file_name_size = file_name.size();
    auto* filename = (unsigned char*)malloc(file_name_size);
    memcpy(filename, file_name.c_str(), file_name_size);

    allocatedBuffers.push_back({CLEAR_BUFFER, filename, file_name_size});

    unsigned int encrypted_filename_len;
    unsigned char* encrypted_filename;
    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    ret = symm_encrypt(filename, file_name_size, session_key,
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

    if(*(payload) != WRONG_FORMAT && *(payload) != REQ_OK && *(payload) != INVALID_FILENAME && *(payload) != MISSING_FILE){
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

    if(*(payload) != WRONG_FORMAT && *(payload) != REQ_OK){
        cerr << "Unmatching response for M2 message" << endl;
        return false;
    }
    if(WRONG_FORMAT == *(payload)){
        cerr << "Wrong format for M2 message" << endl;
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
    if(app == "\n"){
        cout << "Looks like your storage is empty! Upload something using the UPLOAD command" << endl << PROMPT;
        return;
    }
    cout << app;
    app = "";
}