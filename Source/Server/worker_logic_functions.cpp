//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"

Worker::Worker(int socket_id) {
    signal(SIGTERM, SIG_IGN);

    this->socket_id = socket_id;
    this->logout_request = false;
}

void* Worker::handle_commands_helper(void *context)
{
    return ((Worker *)context)->handle_commands();
}

void* Worker::handle_commands() {
    //TODO call key exchange
    while(!this->logout_request){
        cout<<"Waiting for string: "<<endl;
        string echo;
        getline(cin, echo);
        cout<<echo<<endl;
        if (echo.length()>10)
            logout_request=true;
        //TODO wait for command
        //TODO call relative function
    }
    //TODO call logout
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
    //TODO
}



