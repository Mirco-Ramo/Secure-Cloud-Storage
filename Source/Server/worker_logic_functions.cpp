//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"

Worker::Worker(int socket_id) {
    this->username = to_string(rand() % 100); //temporary name, no guarantees on uniqueness
    this->socket_id = socket_id;
    this->logout_request = false;
    this->worker_counter = 0;
    this->client_counter = 0;
    this->identity = "Worker for: "+this->username;
}

void Worker::handleErrors(const string& reason, int exit_code){
    cerr<<reason<<endl;
    if (exit_code) {
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
        handleErrors("["+identity+"]: Fatal error: cannot perform key exchange protocol with client", 10);

    cout<<"Yeeee, you did it!"<<endl;

    delete this;
    return 0;
}

void Worker::handle_download() {
    //TODO
    //open file
    //counter=1
    //for(file.begin;file.end;16MB)
    //  read_chunck
    //  encrypt_chunck
    //  build_message(iv, payload_length, counter, na, nb, true, kmac, )
    //  send message
    //  counter++
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

void Worker::handle_list() {
    //TODO
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
#pragma optimize("", off)
                memset(pointer_elem->content,0,KEY_LEN);
#pragma optimize("", on)
                free(pointer_elem->content);
                break;
            case HASH_KEY:
#pragma optimize("", off)
                memset(pointer_elem->content,0,DIGEST_LEN);
#pragma optimize("", on)
                free(pointer_elem->content);
                break;
            case MESSAGE:
                delete (message*)pointer_elem->content;
            default:
                cout<<"Cannot free buffer"<<endl;
                break;
        }
    }
    allocatedBuffers.clear();
}