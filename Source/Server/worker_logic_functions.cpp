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
}

/*          UTILITY FOR LOGIC FUNCTIONS         */
string Worker::GetStdoutFromCommand(string cmd) {

    string data;
    FILE * stream;
    const unsigned int max_buffer = 356;
    char buffer[max_buffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL)
                data.append(buffer);
        pclose(stream);
    }
    return data;
}

string Worker::get_file_list_as_string(){
    return GetStdoutFromCommand(string("ls UserData/" + this->username));
}

vector<string> Worker::get_file_list_as_vector(){
    vector<string> result;
    string files = get_file_list_as_string();
    size_t pos = 0;
    string single_file;
    string delimiter = "\n";
    while ((pos = files.find(delimiter)) != std::string::npos) {
        single_file = files.substr(0, pos);
        result.push_back(single_file);
        cout<<single_file<<endl;
        files.erase(0, pos + delimiter.length());
    }
    return result;
}

bool Worker::check_filename_already_existing(string filename){
    string find = GetStdoutFromCommand("find UserData/"+this->username +" -name  " +  filename);
    if(find.size()>0)
        return true;
    return false;
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
                    send_failure_message(WRONG_FORMAT, UPLOAD_RES, false);
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
                    handleErrors("["+this->identity+"]: Fatal error: error while completing UPLOAD function", 13);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case RENAME:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, RENAME_RES, false);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_rename(m1)){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing RENAME function", 14);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case DELETE:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, DELETE_RES, false);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_delete(m1)){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing DELETE function", 15);
                    err = true;
                    break;
                }
                clean_all();
                break;
            case LOGOUT:
                this->allocatedBuffers.push_back({MESSAGE, m1});
                ret = verify_hmac(m1, this->client_counter, this->hmac_key);
                if(ret != 1){
                    cerr << "["+this->identity+"]: HMAC is not matching, closing connection" << endl;
                    send_failure_message(WRONG_FORMAT, LOGOUT_RES, false);
                    err = true;
                    break;
                }

                if(m1->header.payload_length != 0){
                    cerr << "["+this->identity+"]: Payload is not empty! I don't trust you!" << endl;
                    send_failure_message(WRONG_FORMAT, LOGOUT_RES, false);
                    err = true;
                    break;
                }

                if(this->client_counter == UINT_MAX){
                    cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
                    err = true;
                    break;
                }
                this->client_counter++;

                if(!handle_logout()){
                    handleErrors("["+this->identity+"]: Fatal error: error while completing LOGOUT function", 16);
                    err = true;
                    break;
                }
                this->logout_request = true;
                clean_all();
                break;
            default:
                delete m1;
                clean_all();
        }
        if(err)
            break;
    }

    delete this;
    return 0;
}











bool Worker::handle_list() {
    int ret;

    message* m2;

    unsigned char clear_response = REQ_OK;
    unsigned char* response = &clear_response;
    unsigned short response_size = sizeof(unsigned char);

    string list = get_file_list_as_string();

    auto* char_list = (unsigned char*)malloc(list.size()+1);
    auto* char_list_size = (unsigned char*)malloc(sizeof(unsigned int));
    if(!char_list || ! char_list_size){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for transmitting the list"<<endl;
        return false;
    }
    unsigned int int_list_size = list.size()+1;
    memcpy(char_list_size, &int_list_size, sizeof(unsigned int));
    unsigned short list_size_size = sizeof(unsigned int);

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    this->allocatedBuffers.push_back({CLEAR_BUFFER, char_list_size, list_size_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    unsigned int first_send = MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short) > int_list_size ?
                              int_list_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - list_size_size - 2*sizeof(unsigned short);

    unsigned int clear_payload_len = response_size + list_size_size + first_send + 2*sizeof(unsigned short);
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
    memcpy(clear_payload + current_len,char_list_size,list_size_size);
    current_len += list_size_size;

    memcpy(clear_payload + current_len,list.c_str(),first_send);

    ret = symm_encrypt(clear_payload, clear_payload_len, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    m2 = build_message(IV_buffer, LIST_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send LIST response from server"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({MESSAGE, m2});

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
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
        this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i});

        unsigned int to_send = (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > int_list_size - sent_size ? int_list_size - sent_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN;
        auto* clear_payload_i = (unsigned char*)malloc(to_send);
        memcpy(clear_payload_i, list.substr(sent_size, to_send).c_str(), to_send);
        if(!clear_payload_i){
            cerr<<"["+this->identity+"]: Cannot allocate buffer for m2i"<<endl;
            return false;
        }
        unsigned int clear_payload_len_i = to_send;
        this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_payload_i, clear_payload_len_i});

        ret = symm_encrypt(clear_payload_i, clear_payload_len_i, this->session_key,
                           IV_buffer_i, encrypted_payload_i, encrypted_payload_len_i);

        this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_i});

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

    string filename = string((const char*) payload, payload_len-1);

    if(!check_filename_not_traversing(filename)){
        cerr << "["+this->identity+"]: The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, DOWNLOAD_RES, true);
        return true;
    }

    filename = "UserData/" + this->username + "/" + filename;
    bool file_found;

    unsigned long file_size = get_file_size(filename, file_found);
    cout<<"["+this->identity+"]: Requested file size is: "<<file_size<<endl;
    if(!file_found){
        cerr << "["+this->identity+"]: File not found!"<<endl;
        if (!send_failure_message(MISSING_FILE, DOWNLOAD_RES, true)){
            cerr << "["+this->identity+"]: Cannot send the failure message"<<endl;
            return false;
        }
        return true;
    }

    //M2
    auto* char_file_size = (unsigned char*)malloc(sizeof(unsigned int));
    auto int_file_size = (unsigned int)file_size;
    memcpy(char_file_size, &int_file_size, sizeof(unsigned int));
    unsigned short file_size_len = sizeof(unsigned int);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, char_file_size, file_size_len});

    auto* response = (unsigned char*)malloc(sizeof(unsigned char));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned char));
    unsigned short response_size = sizeof(unsigned char);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    unsigned int first_send = MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - file_size_len - 2*sizeof(unsigned short) > int_file_size ?
                     int_file_size : MAX_PAYLOAD_LENGTH - BLOCK_LEN - response_size - file_size_len - 2*sizeof(unsigned short);

    unsigned int clear_payload_len = response_size + file_size_len + first_send + 2*sizeof(unsigned short);
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
    };
    message* m2 = build_message(IV_buffer, DOWNLOAD_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);

    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send DOWNLOAD response from server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int fetched_size = first_send;
    unsigned int sent_size_i=0;

    while(fetched_size<int_file_size) {
        auto *IV_buffer_i = (unsigned char *) malloc(IV_LENGTH);
        if (!IV_buffer_i) {
            cerr << "[" + this->identity + "]: Cannot allocate buffer for IV" << endl;
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer_i, IV_LENGTH});
        unsigned int to_fetch = (int_file_size-fetched_size) < MAX_FETCHABLE ? (int_file_size-fetched_size) : MAX_FETCHABLE;
        auto *clear_chunk_i = read_chunk(filename, fetched_size, to_fetch);
        if (!clear_chunk_i) {
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, clear_chunk_i, to_fetch});
        unsigned int encrypted_chunk_len_i;
        unsigned char *encrypted_chunk_i;
        ret = symm_encrypt(clear_chunk_i, to_fetch, this->session_key,
                           IV_buffer_i, encrypted_chunk_i, encrypted_chunk_len_i);
        if (ret == 0) {
            cerr << "[" + this->identity + "]: Cannot encrypt message M2!" << endl;
            return false;
        }
        this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_chunk_i});
        fetched_size +=to_fetch;

        unsigned char* payload_j = (unsigned char*)malloc(MAX_PAYLOAD_LENGTH);
        if(!payload_j){
            cerr << "[" + this->identity + "]: Cannot allocate buffer for message" << endl;
            return false;
        }
        this->allocatedBuffers.push_back({CLEAR_BUFFER, payload_j, MAX_PAYLOAD_LENGTH});

        sent_size_i = 0;

        while (sent_size_i < encrypted_chunk_len_i) {
            message *m2j;

            unsigned int to_send =
                    (MAX_PAYLOAD_LENGTH - BLOCK_LEN) > encrypted_chunk_len_i - sent_size_i ? encrypted_chunk_len_i - sent_size_i :
                    MAX_PAYLOAD_LENGTH - BLOCK_LEN;

            unsigned int payload_len_j = to_send;

            memcpy(payload_j, encrypted_chunk_i+sent_size_i, payload_len_j);

            m2j = build_message(IV_buffer_i, DOWNLOAD_DATA, payload_len_j, payload_j, true,
                                this->hmac_key, this->worker_counter);
            if (send_msg(this->socket_id, m2j, true, this->identity) <
                FIXED_HEADER_LENGTH + (int) payload_len_j + DIGEST_LEN) {
                cerr << "[" + this->identity + "]: Cannot send DOWNLOAD_DATA response to client" << endl;
                return false;
            }
            delete m2j;

            if (this->worker_counter == UINT_MAX) {
                cerr << "[" + this->identity + "]: Maximum number of messages reached for a session, closing connection"
                     << endl;
                return false;
            }
            this->worker_counter++;

            sent_size_i +=payload_len_j;
        }
    }
    cout << "[" + this->identity + "]: Download correctly completed"<< endl;
    return true;
}

bool Worker::handle_upload(message* m1) {
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
    if(!get_payload_fields(payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, file_name->field, file_name->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, file_size->field, file_size->field_len});

    string filename = string((const char*) file_name->field, file_name->field_len);

    if(!check_filename_not_traversing(filename)){
        cerr << "The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, UPLOAD_RES, false);
        return true;
    }

    if(check_filename_already_existing(filename)){
        cerr << "There is already a file with the same name in the storage!"<<endl;
        send_failure_message(DUP_NAME, UPLOAD_RES, false);
        return true;
    }

    filename = "UserData/" + this->username + "/" + filename;

    unsigned int filesize;
    memcpy(&filesize, file_size->field, file_size->field_len);

    auto* response = (unsigned char*)malloc(sizeof(unsigned char));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned char));
    unsigned short response_size = sizeof(unsigned char);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response, response_size});

    auto* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+this->identity+"]: Cannot allocate buffer for IV"<<endl;
        return false;
    }
    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    unsigned int encrypted_payload_len;
    unsigned char* encrypted_payload;

    ret = symm_encrypt(response, response_size, this->session_key,
                       IV_buffer, encrypted_payload, encrypted_payload_len);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    message* m2 = build_message(IV_buffer, UPLOAD_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send UPLOAD response from server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    unsigned int recvd_file = 0;
    unsigned int clear_chunk_buf_len;

    unsigned char* enc_chunk_buf = (unsigned char*)malloc(2*MAX_FETCHABLE);
    unsigned char* clear_chunk_buf;
    if(!enc_chunk_buf){
        cerr << "["+this->identity+"]: Cannot allocate buffer to save chunks" << endl;
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, enc_chunk_buf});

    unsigned int recvd_i = 0;
    while(recvd_file<filesize) {
        auto *m3j = new message();
        if (recv_msg(socket_id, m3j, true, identity) <= 0) {
            cerr << "["+this->identity+"]: Cannot receive M3 from client" << endl;
            cerr << "["+this->identity+"]: I downloaded: "<<recvd_file<<endl;
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        ret = verify_hmac(m3j, client_counter, hmac_key);
        if (ret != 1) {
            cerr << "HMAC is not matching, closing connection" << endl;
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if (client_counter == UINT_MAX) {
            cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }
        client_counter++;

        if (m3j->header.opcode != UPLOAD_DATA) {
            cerr << "["+this->identity+"]: Received an M3 response with unexpected opcode: " << (int) m3j->header.opcode << endl;
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if(recvd_i>0 && memcmp(IV_buffer, m3j->header.initialization_vector, IV_LENGTH)!=0){
            ret = symm_decrypt(enc_chunk_buf, recvd_i, session_key, IV_buffer, clear_chunk_buf, clear_chunk_buf_len);
            if (ret == 0) {
                cerr << "["+this->identity+"]: Cannot decrypt message M2!" << endl;
                if (!delete_file(filename)) {
                    cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
                            "We suggest to delete the file manually for safety purposes." << endl;
                }
                return false;
            }

            if (!write_file(clear_chunk_buf, clear_chunk_buf_len, filename)) {
                if (!delete_file(filename)) {
                    cerr << "["+this->identity+"]: The file was not downloaded completely, but it was impossible to delete it."
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
        memcpy(IV_buffer, m3j->header.initialization_vector, IV_LENGTH);
        memcpy(enc_chunk_buf + recvd_i, m3j->payload, m3j->header.payload_length);
        recvd_file += m3j->header.payload_length;
        recvd_i +=m3j->header.payload_length;
        delete m3j;
    }

    if(recvd_i>0){
        ret = symm_decrypt(enc_chunk_buf, recvd_i, session_key, IV_buffer, clear_chunk_buf, clear_chunk_buf_len);
        if (ret == 0) {
            cerr << "["+this->identity+"]Cannot decrypt message M3!" << endl;
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }

        if (!write_file(clear_chunk_buf, clear_chunk_buf_len, filename)) {
            if (!delete_file(filename)) {
                cerr << "["+this->identity+"]The file was not downloaded completely, but it was impossible to delete it."
                        "We suggest to delete the file manually for safety purposes." << endl;
            }
            return false;
        }
#pragma optimize("", off)
        memset(clear_chunk_buf, 0, clear_chunk_buf_len);
#pragma optimze("", on)
        free(clear_chunk_buf);
    }


    //M4
    auto* response_4 = (unsigned char*)malloc(sizeof(unsigned char));
    unsigned char clear_response_4 = REQ_OK;
    memcpy(response_4, &clear_response_4, sizeof(unsigned char));
    unsigned short response_size_4 = sizeof(unsigned char);

    this->allocatedBuffers.push_back({CLEAR_BUFFER, response_4, response_size_4});

    unsigned int encrypted_payload_len_4;
    unsigned char* encrypted_payload_4;

    ret = symm_encrypt(response_4, response_size_4, this->session_key,
                       IV_buffer, encrypted_payload_4, encrypted_payload_len_4);

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload_4, encrypted_payload_len_4});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M4!" << endl;
        return false;
    }

    message* m4 = build_message(IV_buffer, UPLOAD_ACK, encrypted_payload_len_4, encrypted_payload_4, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m4, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len_4 + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send UPLOAD response from server"<<endl;
        return false;
    }
    delete m4;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;
    cerr << "["+this->identity+"]: Upload correctly completed" << endl;
    return true;
}

bool Worker::handle_rename(message* m1) {
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

    auto* char_old_filename = new payload_field();
    auto* char_new_filename = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {char_old_filename, char_new_filename};
    if(!get_payload_fields(payload, fields, num_fields)){
        cerr<<"["+this->identity+"]:Cannot unpack payload fields"<<endl;
        return false;
    }

    allocatedBuffers.push_back({CLEAR_BUFFER, char_old_filename->field, char_old_filename->field_len});
    allocatedBuffers.push_back({CLEAR_BUFFER, char_new_filename->field, char_new_filename->field_len});

    string old_filename = string((const char*) char_old_filename->field, char_old_filename->field_len);
    string new_filename = string((const char*) char_new_filename->field, char_new_filename->field_len);

    if(!check_filename_not_traversing(old_filename)){
        cerr << "["+this->identity+"]:The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, RENAME_RES, false);
        return true;
    }

    if(!check_filename_already_existing(old_filename)){
        cerr << "["+this->identity+"]:There is no file with such name in the storage!"<<endl;
        send_failure_message(MISSING_FILE, RENAME_RES, false);
        return true;
    }

    if(!check_filename_not_traversing(new_filename)){
        cerr << "["+this->identity+"]The name of the file is not acceptable!" << endl;
        send_failure_message(INVALID_FILENAME, RENAME_RES, false);
        return true;
    }

    if(check_filename_already_existing(new_filename)){
        cerr << "["+this->identity+"]There is already a file with such name in the storage!"<<endl;
        send_failure_message(DUP_NAME, RENAME_RES, false);
        return true;
    }
    old_filename = "UserData/" + this->username + "/" + old_filename;
    new_filename = "UserData/" + this->username + "/" + new_filename;

    ret = rename(old_filename.c_str(), new_filename.c_str());
    if(ret != 0){
        cerr << "["+this->identity+"]Impossible to change name to file!" << endl;
        send_failure_message(INVALID_FILENAME, RENAME_RES, false);
        return true;
    }

    auto* response = (unsigned char*)malloc(sizeof(unsigned char));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned char));
    unsigned short response_size = sizeof(unsigned char);

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

    message* m2 = build_message(IV_buffer, RENAME_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send RENAME response from server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;
    cout << "["+this->identity+"]: Rename completed" << endl;
    return true;
}

bool Worker::handle_delete(message* m1) {
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
        send_failure_message(INVALID_FILENAME, DELETE_RES, false);
        return true;
    }

    if(!check_filename_already_existing(filename)){
        cerr << "There is no file with such name in the storage!" << endl;
        send_failure_message(MISSING_FILE, DELETE_RES, false);
        return true;
    }

    filename = "UserData/" + this->username + "/" + filename;

    if(!delete_file(filename)){
        cerr << "Error in deleting the file!" << endl;
        return false;
    }

    auto* response = (unsigned char*)malloc(sizeof(unsigned char));
    unsigned char clear_response = REQ_OK;
    memcpy(response, &clear_response, sizeof(unsigned char));
    unsigned short response_size = sizeof(unsigned char);

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

    this->allocatedBuffers.push_back({ENC_BUFFER, encrypted_payload});

    if(ret==0) {
        cerr << "["+this->identity+"]: Cannot encrypt message M2!" << endl;
        return false;
    }

    message* m2 = build_message(IV_buffer, DELETE_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send DELETE response from server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]: Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;

    cout << "["+this->identity+"]: Delete completed" << endl;
    return true;
}

bool Worker::handle_logout() {
    int ret;

    cout<<"["+this->identity+"]: Logout request received"<<endl;

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

    message* m2 = build_message(IV_buffer, LOGOUT_RES, encrypted_payload_len, encrypted_payload, true, this->hmac_key, this->worker_counter);
    if(send_msg(this->socket_id, m2, true, this->identity) < FIXED_HEADER_LENGTH + (int)encrypted_payload_len + DIGEST_LEN){
        cerr<<"["+this->identity+"]: Cannot send LOGOUT response from server"<<endl;
        return false;
    }
    delete m2;

    if(this->worker_counter == UINT_MAX){
        cerr << "["+this->identity+"]; Maximum number of messages reached for a session, closing connection" << endl;
        return false;
    }
    this->worker_counter++;
    cout<<"["+this->identity+"]: Logout request accomplished"<<endl;

    return true;
}

Worker::~Worker() {
    cout<<"["+this->identity+"]: Leaving..."<<endl;
#pragma optimize("", off)
    memset(this->session_key, 0, KEY_LEN);
    memset(this->hmac_key, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    clean_all();
    close(this->socket_id);
    for (auto &activeWorker : active_workers){
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