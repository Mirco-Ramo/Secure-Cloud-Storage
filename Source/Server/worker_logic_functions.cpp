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
    //for(file.begin;file.end;1MB)
    //  read_chunck
    //  encrypt_chunck
    //  build_message(iv, payload_length, counter, na, nb, true)
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
    close(this->socket_id);
}



