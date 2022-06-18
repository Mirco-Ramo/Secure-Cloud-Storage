//
// Created by Francesco del Turco, Mirco Ramo
//

#include "server_include.h"
#include "worker.h"

Worker::Worker(int socket_id) {
    this->socket_id = socket_id;
    this->logout_request = false;
    this->worker_counter = 0;
    this->client_counter = 0;
}

void* Worker::handle_commands_helper(void *context)
{
    return ((Worker *)context)->handle_commands();
}

void* Worker::handle_commands() {
    //TODO call key exchange
    while(!this->logout_request){
        cout<<"Listening for requests"<<endl;
        message* m = new message();
        int ret = this->recv_msg_from_client(this->socket_id, m, false);
        cout<<"Return value was: "<<ret<<endl;
        cout<<"Payload length is: "<<m->header.payload_length<<endl;

        string payload = (const char*)m->payload;
        cout<<"You wrote: "<<payload<<endl;

        if(m->header.payload_length>30)
            logout_request=true;

        unsigned char* iv_buf = (unsigned char*)malloc(IV_LENGTH*sizeof(unsigned char));
        unsigned char opcode='d';
        for(int i=0; i<IV_LENGTH*sizeof(unsigned char); i+=sizeof(unsigned char)){
            *(iv_buf+i)=(unsigned char)(opcode+i);
        }
        free(m->payload);
        char* hello_msg = "Hello to you, my kind client!\n";
        cout<<"I send you: "<<hello_msg<<endl;
        m = build_message(iv_buf, opcode, strlen(hello_msg)+1, (unsigned char *)(hello_msg), false);
        send_msg_to_client(this->socket_id, m, false);

        //TODO wait for command

        /*
        message msg = {};
        int ret = recv_msg_from_client(this->socket_id, &msg);
        if(ret <= 0){
            cout << "Worker for: " << this->username << ". Failed to receive message " << msg.header.opcode << msg.header.seq_number <<endl;
            free(&msg);
            continue;
        }
        //TODO call relative function
        switch(msg.header.opcode){
            case LIST:
                handle_list();
            case UPLOAD_INIT:
                handle_upload();
            case RENAME_REQ:
                handle_rename();
            case DOWNLOAD_REQ:
                handle_download();
            case DELETE_REQ:
                handle_delete();
            case LOGOUT_REQ:
                handle_logout();
        }
         */
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



