//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"
struct ActiveWorker{
    unsigned short id;
    Worker* pointer;
};
extern vector<ActiveWorker> active_workers;

Worker::Worker(int socket_id, EVP_PKEY* server_privkey, unsigned short id) {
    this->id = id;
    this->username = to_string(id); //temporary name, no guarantees on uniqueness
    this->socket_id = socket_id;
    this->logout_request = false;
    this->worker_counter = 0;
    this->client_counter = 0;
    this->identity = "Worker for: "+this->username;
    this->server_privkey = server_privkey;
    this->file_list = "\n";
}

void Worker::handleErrors(const string& reason, int exit_code){
    cerr<<reason<<endl;
    if (exit_code) {
        clean_all();
        delete this;
        //TODO this is a temporary function
        pthread_exit((void*)(1));
    }
}

void* Worker::handle_commands_helper(void *context)
{
    return ((Worker *)context)->handle_commands();
}

void* Worker::handle_commands() {
    if(!establish_session())
        handleErrors("["+this->identity+"]: Fatal error: cannot perform key exchange protocol with client", 10);

    cout<<"["+this->identity+"]: Session established"<<endl;
    this->logout_request = false;
    while(!this->logout_request){
        int ret;
        bool err = false;
        auto* m1 = new message();
        if(recv_msg(this->socket_id, m1, true, this->identity)<=0){
            cerr<<"["+this->identity+"]: Cannot receive request from client"<<endl;
            clean_all();
            break;
        }

        switch(m1->header.opcode){
            case LIST:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "["+this->identity+"]: HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, LIST_RES, true);
                    err = true;
                    break;
                }

                if(m1->header.payload_length != 0){
                    cerr << "["+this->identity+"]: Payload is not empty! I don't trust you!" << endl;
                    send_failure_message(WRONG_FORMAT, LIST_RES, true);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_list()){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing LIST function", 11);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case DOWNLOAD:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, DOWNLOAD_RES, true);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_download(m1)){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing DOWNLOAD function", 12);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case UPLOAD_REQ:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, UPLOAD_RES, true);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_upload(m1)){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing UPLOAD function", 12);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case RENAME:

            case DELETE:

            case LOGOUT:

            default:
                delete m1;
                clean_all();
        }
        if(err)
            break;

    }

    clean_all();
    delete this;
    return 0;
}

bool Worker::handle_list() {
    int ret;

    message* m2;

    auto* response = (unsigned char*)malloc(sizeof(unsigned short));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned short));
    unsigned short response_size = sizeof(response);

    auto* list_size = (unsigned char*)malloc(sizeof(this->file_list));
    unsigned int int_list_size = (unsigned int) sizeof(this->file_list);
    memcpy(list_size, &int_list_size, sizeof(this->file_list));
    unsigned short list_size_size = sizeof(list_size);

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});
    this->allocatedBuffers.push_back({CLEAR_BUFFER, list_size, list_size_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned int first_send = MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short) > int_list_size ?
                              int_list_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short);

    unsigned short clear_payload_len = response_size + list_size_size + first_send + 2*sizeof(unsigned short);
    auto* clear_payload = (unsigned char*)malloc(clear_payload_len);
    if(!clear_payload){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for m2"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload, clear_payload_len});

    unsigned int current_len = 0;

    memcpy(clear_payload, &response_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len, response, response_size);
    current_len += response_size;

    memcpy(clear_payload + current_len, &list_size_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len,list_size,list_size_size);
    current_len += list_size_size;

    memcpy(clear_payload + current_len,this->file_list.c_str(),first_send);

    ret = symm_encrypt(clear_payload, clear_payload_len, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    m2 = build_message(IV_buffer, LIST_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send LIST response to server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int sent_size = first_send;
    while(sent_size < int_list_size){

        message* m2i;
        unsigned int encrypted_payload_len_i;
        unsigned char* encrypted_payload_i;

        auto* IV_buffer_i = (unsigned char*)malloc(IV_LENGTH);
        if(!IV_buffer_i){
            cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i, IV_LENGTH});

        int to_send = (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > int_list_size - sent_size ? int_list_size - sent_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN;
        auto* clear_payload_i = (unsigned char*)malloc(to_send);
        memcpy(clear_payload_i, this->file_list.substr(sent_size, to_send).c_str(), to_send);
        if(!clear_payload_i){
            cerr<<"["+this->identity+"]: Cannot allocate buffer for m2i"<<endl;
            return false;
        }
        unsigned short clear_payload_len_i = sizeof(clear_payload_i);
        this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload_i, clear_payload_len_i});

        ret = symm_encrypt(clear_payload_i, clear_payload_len_i, this->session_key,
                           IV_buffer_i, encrypted_payload_i, encrypted_payload_len_i);

        this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_i, encrypted_payload_len_i});

        if(ret==0) {
            cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
            return false;
        }

        m2i = build_message(IV_buffer_i, LIST_DATA, encrypted_payload_len_i, encrypted_payload_i, true, this->hmac_key, this->worker_counter);
        if(send_msg(this->socket_id, m2i, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len_i + DIGEST_LEN){
            cerr<<"["+this->identity+"]: Cannot send LIST_DATA response to client"<<endl;
            return false;
        }
        delete m2i;

        if(this->worker_counter == UINT_MAX){
            cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
            return false;
        }
        this->worker_counter++;

        sent_size += clear_payload_len_i;
    }

    return true;
}

bool Worker::handle_download(message* m1) {
    int ret;

    unsigned int payload_len;
    unsigned char* payload;

    ret = symm_decrypt(m1->payload, m1->header.payload_length,
                       session_key, m1->header.initialization_vector,payload,payload_len);
    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot decrypt message M1!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, payload, payload_len});

    string filename = string((const char*) payload, payload_len);

    if(!check_filename_not_traversing(filename)){
        cerr << "The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, DOWNLOAD_RES, true);
        return true;
    }

    bool file_found;

    unsigned long file_size = get_file_size(filename, file_found);
    if(!file_found){
        cerr << "File not found, please check the path and try again!";
        send_failure_message(MISSING_FILE, DOWNLOAD_RES, true);
        return true;
    }

    auto* char_file_size = (unsigned char*)malloc(sizeof(unsigned int));
    auto int_file_size = (unsigned int)file_size;
    memcpy(char_file_size, &int_file_size, sizeof(unsigned int));
    unsigned short file_size_len = sizeof(char_file_size);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, char_file_size, file_size_len});

    auto* response = (unsigned char*)malloc(sizeof(unsigned short));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned short));
    unsigned short response_size = sizeof(response);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned int first_send = MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - file_size_len - 2*sizeof(unsigned short) > int_file_size ?
                     int_file_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - file_size_len - 2*sizeof(unsigned short);

    unsigned short clear_payload_len = response_size + int_file_size + first_send + 2*sizeof(unsigned short);
    auto* clear_payload = (unsigned char*)malloc(clear_payload_len);
    if(!clear_payload){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for m2a"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload, clear_payload_len});

    unsigned int current_len = 0;

    memcpy(clear_payload, &response_size, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len, response, response_size);
    current_len += response_size;

    memcpy(clear_payload + current_len, &file_size_len, sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(clear_payload + current_len,char_file_size,file_size_len);
    current_len += file_size_len;

    auto* chunk = read_chunk(filename, 0, first_send);
    if(!chunk){
        return false;
    }

    this->allocatedBuffers.push_back({CLEAR_BUFFER, chunk, first_send});

    memcpy(clear_payload + current_len, chunk,first_send);

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    ret = symm_encrypt(clear_payload, clear_payload_len, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    message* m2 = build_message(IV_buffer, DOWNLOAD_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send DOWNLOAD response to server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int sent_size = first_send;
    while(sent_size < int_file_size){

        message* m2i;
        unsigned int encrypted_payload_len_i;
        unsigned char* encrypted_payload_i;

        auto* IV_buffer_i = (unsigned char*)malloc(IV_LENGTH);
        if(!IV_buffer_i){
            cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i, IV_LENGTH});

        int to_send = (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > int_file_size - sent_size ? int_file_size - sent_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN;
        auto* clear_payload_i = read_chunk(filename, sent_size, to_send);
        if(!clear_payload_i){
            return false;
        }
        unsigned short clear_payload_len_i = sizeof(clear_payload_i);
        this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload_i, clear_payload_len_i});

        ret = symm_encrypt(clear_payload_i, clear_payload_len_i, this->session_key,
                           IV_buffer_i, encrypted_payload_i, encrypted_payload_len_i);

        this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_i, encrypted_payload_len_i});

        if(ret==0) {
            cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
            return false;
        }

        m2i = build_message(IV_buffer_i, DOWNLOAD_DATA, encrypted_payload_len_i, encrypted_payload_i, true, this->hmac_key, this->worker_counter);
        if(send_msg(this->socket_id, m2i, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len_i + DIGEST_LEN){
            cerr<<"["+this->identity+"]: Cannot send DOWNLOAD_DATA response to client"<<endl;
            return false;
        }
        delete m2i;

        if(this->worker_counter == UINT_MAX){
            cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
            return false;
        }
        this->worker_counter++;

        sent_size += clear_payload_len_i;
    }

    return true;
}

bool Worker::handle_upload(message* m1) {
    //TODO
    //open file
    //receive file length
    //open dest_file
    //unreceived=[]
    //for(counter=1; counter<file_size/chunk_size; counter++)
    //  receive_msg
    //  if(hash(msg) == msg.hmac)
    //      fwrite(payload, counter*chunk_size)
    //  else
    //      fwrite(0, counter*chunk_size)
    //      unreceived.push_back(counter)
    //while(unreceived!=empty)
    //  send(unreceived)
    //  for (unreceived.length)
    //      recv_chunk
    //  if(hash(chunk) == chunk.hmac)
    //    fwrite(chunk, chunk_index*chunk_size)
    //    unreceived.remove(index)
    //

    int ret;

    unsigned int payload_len;
    unsigned char* payload;

    ret = symm_decrypt(m1->payload, m1->header.payload_length,
                       session_key, m1->header.initialization_vector,payload,payload_len);
    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot decrypt message M1!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, payload, payload_len});

    auto* file_name = new payload_field();
    auto* file_size = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {file_name, file_size};
    if(!get_payload_fields(m1->payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, file_name->field, file_name->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, file_size->field, file_size->field_len});

    string filename = string((const char*) file_name->field, file_name->field_len);

    if(!check_filename_not_traversing(filename)){
        cerr << "The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, UPLOAD_RES, true);
        return true;
    }

    //TODO change list type and add filename to list
    if(this->file_list.find("\n" + filename + "\n") != string::npos){
        cerr << "There is already a file with the same name in the storage, please choose a different name!";
        send_failure_message(DUP_NAME, UPLOAD_RES, true);
        return true;
    }

    unsigned int filesize;
    memcpy(&filesize, file_size->field, file_size->field_len);

    auto* response = (unsigned char*)malloc(sizeof(unsigned short));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned short));
    unsigned short response_size = sizeof(response);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    ret = symm_encrypt(response, response_size, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    message* m2 = build_message(IV_buffer, UPLOAD_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send UPLOAD response to server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int recvd_size = 0;
    while(recvd_size < filesize) {
        auto *m3i = new message();
        if (recv_msg(socket_id, m3i, true, identity) <= 0) {
            cerr << "Cannot receive M3 from server" << endl;
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }
        allocatedBuffers.push_back({MESSAGE, m3i});

        ret = verify_hmac(m3i, client_counter, hmac_key);
        if(ret != 1){
            cerr << "HMAC is not matching, closing connection" << endl;
            send_failure_message(WRONG_FORMAT, UPLOAD_ACK, true);
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }

        if(client_counter == UINT_MAX){
            cerr << "Maximum number of messages reached for a session, closing connection" << endl;
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }
        client_counter++;

        if (m3i->header.opcode != UPLOAD_DATA) {
            cerr << "Received an M3 message with unexpected opcode: " << m3i->header.opcode << endl;
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }

        unsigned int payload_len_i;
        unsigned char *payload_i;

        ret = symm_decrypt(m3i->payload, m3i->header.payload_length,
                           session_key, m3i->header.initialization_vector, payload_i, payload_len_i);
        if (ret == 0) {
            cerr << "Cannot decrypt message M2!" << endl;
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }

        allocatedBuffers.push_back({CLEAR_BUFFER, payload_i, payload_len_i});

        if(!write_file(payload_i, payload_len_i, filename)) {
            if(recvd_size != 0) {
                if (!delete_file(filename)) {
                    cerr << "The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
            }
            return false;
        }
        recvd_size += payload_len_i;
    }

    auto* response_4 = (unsigned char*)malloc(sizeof(unsigned short));
    unsigned char clear_response_4 = REQ_OK;
    memcpy(response_4, &clear_response_4, sizeof(unsigned short));
    unsigned short response_size_4 = sizeof(response_4);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response_4, response_size_4});

    auto* IV_buffer_4 = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer_4){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_4, IV_LENGTH});

    unsigned int encrypted_payload_len_4;
    unsigned char* encrypted_payload_4;

    ret = symm_encrypt(response, response_size, this->session_key,
                       IV_buffer_4, encrypted_payload_4, encrypted_payload_len_4);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_4, encrypted_payload_len_4});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    message* m4 = build_message(IV_buffer, UPLOAD_ACK, encrypted_payload_len_4, encrypted_payload_4, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m4, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len_4 + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send UPLOAD response to server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    return true;
}

void Worker::handle_rename() {
    //TODO
}

void Worker::handle_delete() {
    //TODO
}

void Worker::handle_logout() {
    this->logout_request = true;
    //TODO
}

Worker::~Worker() {
    cout<<"["+this->identity+"]: Leaving..."<<endl;
#pragma optimize("", off)
    memset(this->session_key, 0, KEY_LEN);
    memset(this->hmac_key, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    clean_all();
    close(this->socket_id);
    for (auto activeWorker : active_workers){
        if (activeWorker.id == this->id)
            activeWorker.pointer = NULL;
    }
}



void Worker::clean_all(){
    for(auto pointer_elem = allocatedBuffers.begin(); pointer_elem != allocatedBuffers.end(); ++pointer_elem){
        switch(pointer_elem->type){
            case EVP_PKEY_BUF:
                EVP_PKEY_free((EVP_PKEY*)pointer_elem->content);
                break;
            case BIO_BUF:
                BIO_free((BIO*)pointer_elem->content);
                break;
            case CLEAR_BUFFER:
                if(pointer_elem->nbytes){
#pragma optimize("", off)
                    memset(pointer_elem->content,0,pointer_elem->nbytes);
#pragma optimize("", on)
                }
                if(pointer_elem->content)
                    free(pointer_elem->content);
                break;
            case ENC_BUFFER:
                if(pointer_elem->content)
                    free(pointer_elem->content);
                break;
            case PKEY_CONTEXT:
                EVP_PKEY_CTX_free((EVP_PKEY_CTX*)pointer_elem->content);
                break;
            case MD_CONTEXT:
                EVP_MD_CTX_free((EVP_MD_CTX*)pointer_elem->content);
                break;
            case CIPHER_CONTEXT:
                EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)pointer_elem->content);
                break;
            case HMAC_CONTEXT:
                HMAC_CTX_free((HMAC_CTX*)pointer_elem->content);
                break;
            case X509_BUF:
                X509_free((X509*)pointer_elem->content);
                break;
            case X509_CRL_BUF:
                X509_CRL_free((X509_CRL*)pointer_elem->content);
                break;
            case X509_STORE_BUF:
                X509_STORE_free((X509_STORE*)pointer_elem->content);
                break;
            case X509_STORE_CONTEXT:
                X509_STORE_CTX_free((X509_STORE_CTX*)pointer_elem->content);
                break;
            case DH_BUF:
                DH_free((DH*)pointer_elem->content);
                break;
            case ENC_KEY:
                if(pointer_elem->content) {
#pragma optimize("", off)
                    memset(pointer_elem->content, 0, KEY_LEN);
#pragma optimize("", on)
                    free(pointer_elem->content);
                }
                break;
            case HASH_KEY:
                if(pointer_elem->content) {
#pragma optimize("", off)
                    memset(pointer_elem->content, 0, DIGEST_LEN);
#pragma optimize("", on)
                    free(pointer_elem->content);
                }
                break;
            case MESSAGE:
                if(pointer_elem->content) {
                    delete (message *) pointer_elem->content;
                    break;
                }
            default:
                cout<<"Cannot free buffer"<<endl;
                break;
        }
    }
    allocatedBuffers.clear();
}