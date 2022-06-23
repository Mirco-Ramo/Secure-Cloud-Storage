//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"

Worker::Worker(int socket_id, EVP_PKEY* server_privkey) {
    this->username = to_string(rand() % 100); //temporary name, no guarantees on uniqueness
    this->socket_id = socket_id;
    this->logout_request = false;
    this->worker_counter = 0;
    this->client_counter = 0;
    this->identity = "Worker for: "+this->username;
    this->server_privkey = server_privkey;
    this->file_list = "";
}

void Worker::handleErrors(const string& reason, int exit_code){
    cerr<<reason<<endl;
    if (exit_code) {
        clean_all();
        delete this;
        //TODO this is a temporary function
        exit(exit_code);
    }
}

void* Worker::handle_commands_helper(void *context)
{
    return ((Worker *)context)->handle_commands();
}

void* Worker::handle_commands() {
    if(!establish_session())
        handleErrors("["+this->identity+"]: Fatal error: cannot perform key exchange protocol with client", 10);

    this->logout_request = false;
    while(!this->logout_request){
        int ret;
        auto* m1 = new message();
        if(recv_msg(this->socket_id, m1, true, this->identity)<=0){
            cerr<<"Cannot receive M2 from server"<<endl;
            break;
        }

        switch(m1->header.opcode){
            case LIST:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, LIST_RES, true);
                    break;
                }

                if(m1->header.payload_length != 0){
                    cerr << "Payload is not empty! I don't trust you!" << endl;
                    send_failure_message(WRONG_FORMAT, LIST_RES, true);
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    break;
                }
                this->client_counter++;

                if(!handle_list()){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing LIST function", 11);
                }
                clean_all();
            case DOWNLOAD:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, DOWNLOAD_RES, true);
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    break;
                }
                this->client_counter++;

                if(!handle_download(m1)){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing DOWNLOAD function", 12);
                }
                clean_all();
            case UPLOAD_REQ:

            case RENAME:

            case DELETE:

            case LOGOUT:

            default:
                delete m1;
                clean_all();
        }
    }

    clean_all();
    delete this;
    return 0;
}

bool Worker::handle_list() {
    int ret;

    message* m2;

    auto* response = (unsigned char*)malloc(sizeof(unsigned short));
    unsigned short response_size = sizeof(response);
    auto* list_size = (unsigned char*)malloc(sizeof(this->file_list));
    unsigned short list_size_size = sizeof(list_size);

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});
    this->allocatedBuffers.push_back({CLEAR_BUFFER, list_size, list_size_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned short clear_payload_len = response_size + list_size_size + sizeof(this->file_list) + 2*sizeof(unsigned short);
    auto* clear_payload = (unsigned char*)malloc(clear_payload_len);
    if(!clear_payload){
        cerr<<"Cannot allocate buffer for m2"<<endl;
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

    memcpy(clear_payload + current_len,this->file_list.c_str(),
           (MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short)) > sizeof(file_list) ? sizeof(file_list) : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short));
    current_len += list_size_size;

    ret = symm_encrypt(clear_payload, clear_payload_len, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload, encrypted_payload_len});

    if(ret==0) {
        cerr << "Cannot encrypt message M2!" << endl;
        return false;
    }

    m2 = build_message(IV_buffer, LIST_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + encrypted_payload_len + DIGEST_LEN){
        cerr<<"Cannot send LIST respose to server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int sent_size = (MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short)) > sizeof(file_list) ? sizeof(file_list) : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short);
    while(sent_size < sizeof(this->file_list)){

        message* m2i;
        unsigned int encrypted_payload_len_i;
        unsigned char* encrypted_payload_i;

        auto* IV_buffer_i = (unsigned char*)malloc(IV_LENGTH);
        if(!IV_buffer_i){
            cerr<<"Cannot allocate buffer for IV"<<endl;
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i, IV_LENGTH});

        int to_send = (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > sizeof(this->file_list) ? sizeof(this->file_list) : MAX_PAYLOAD_LENGTH - BLOCK_LEN;
        auto* clear_payload_i = (unsigned char*)malloc(to_send);
        //TODO check that the substring here is right
        memcpy(clear_payload_i, this->file_list.substr(sent_size, to_send - 1).c_str(), to_send);
        if(!clear_payload_i){
            cerr<<"Cannot allocate buffer for m2i"<<endl;
            return false;
        }
        unsigned short clear_payload_len_i = sizeof(clear_payload_i);
        this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload_i, clear_payload_len_i});

        ret = symm_encrypt(clear_payload_i, clear_payload_len_i, this->session_key,
                           IV_buffer_i, encrypted_payload_i, encrypted_payload_len_i);

        this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_i, encrypted_payload_len_i});

        if(ret==0) {
            cerr << "Cannot encrypt message M2i!" << endl;
            return false;
        }

        m2i = build_message(IV_buffer_i, LIST_DATA, encrypted_payload_len_i, encrypted_payload_i, true, this->hmac_key, this->worker_counter);
        if(send_msg(this->socket_id, m2i, true, this->identity) < FIXED_HEADER_LENGTH + encrypted_payload_len_i + DIGEST_LEN){
            cerr<<"Cannot send LIST_DATA respose to client"<<endl;
            return false;
        }
        delete m2i;

        if(this->worker_counter == UINT_MAX){
            cerr << "Maximum number of messages reached for a session, closing connection" << endl;
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
        cerr << "Cannot decrypt message M1!" << endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, payload, payload_len});

    //TODO check that file path is correct


}

void Worker::handle_upload() {
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
#pragma optimize("", off)
    memset(this->session_key, 0, KEY_LEN);
    memset(this->hmac_key, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    clean_all();
    close(this->socket_id);
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
                delete (message*)pointer_elem->content;
                break;
            default:
                cout<<"Cannot free buffer"<<endl;
                break;
        }
    }
    allocatedBuffers.clear();
}