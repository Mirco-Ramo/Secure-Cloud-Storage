//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"

bool Worker::send_failure_message(unsigned char reason, unsigned char opcode, bool multiple){
    message* failure_message;

    unsigned char* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        return false;
    }

    this->allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer, IV_LENGTH});

    unsigned char* encrypted_reason;
    unsigned int encrypted_reason_len;

    if(multiple){
        auto* error = (unsigned char*)malloc(sizeof(reason) + 4*sizeof(unsigned short));
        int current_len = 0;
        auto* app = (unsigned char*)malloc(sizeof(unsigned char));
        memset(app, 0, sizeof(&app));

        memcpy(error, (unsigned char*)sizeof(reason), sizeof(unsigned short));
        current_len += sizeof(unsigned short);
        memcpy(error + current_len, &reason, sizeof(reason));
        current_len += sizeof(reason);

        memcpy(error + current_len, (unsigned char*)sizeof(&app), sizeof(unsigned short));
        current_len += sizeof(unsigned short);
        memcpy(error + current_len,app,sizeof(&app));
        current_len += sizeof(&app);

        this->allocatedBuffers.push_back({CLEAR_BUFFER, error, sizeof(error)});
        this->allocatedBuffers.push_back({CLEAR_BUFFER, app, sizeof(app)});

        if(symm_encrypt(error,sizeof(error),session_key,
                        IV_buffer,encrypted_reason,encrypted_reason_len)!=1){
            cerr<<"Cannot encrypt signed parameters and username"<<endl;
            free(IV_buffer);
            return false;
        }
    }
    else{
        if(symm_encrypt(&reason,sizeof(reason),session_key,
                        IV_buffer,encrypted_reason,encrypted_reason_len)!=1){
            cerr<<"Cannot encrypt signed parameters and username"<<endl;
            free(IV_buffer);
            return false;
        }

        this->allocatedBuffers.push_back({CLEAR_BUFFER, encrypted_reason, encrypted_reason_len});
    }

    failure_message = build_message(IV_buffer, opcode, encrypted_reason_len, encrypted_reason, true, hmac_key, this->worker_counter);
    send_msg(socket_id, failure_message, true, identity);

    delete failure_message;

    return true;
}

bool Worker::establish_session() {
    int ret;
    //M1: receive client's g^u mod p
    message* m1 = new message();
    EVP_PKEY* client_pub_dhkey;
    ret = recv_msg(this->socket_id, m1, false, this->identity);
    if(ret<=0 || m1->header.opcode!=AUTH_INIT)
        return false;

    client_pub_dhkey = decode_EVP_PKEY(m1->payload,m1->header.payload_length);
    allocatedBuffers.push_back({EVP_PKEY_BUF, client_pub_dhkey});
    //generate s
    EVP_PKEY* server_dhkey = NULL;
    if(!generate_dh_secret(server_dhkey)){
        cerr<<"["+identity+"]: "<<"Cannot generate dh secret"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, server_dhkey});
    EVP_PKEY* server_pub_dhkey = NULL;
    server_pub_dhkey = extract_dh_pubkey(server_dhkey);
    if (server_pub_dhkey == NULL){
        cerr<<"["+identity+"]: "<<"Cannot extract dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, server_pub_dhkey});

    //derive session key, hmac_key
    unsigned char *sess_key;
    unsigned char *kmac;
    ret = generate_dh_session_key(server_dhkey,client_pub_dhkey,sess_key, KEY_LEN, kmac, HMAC_KEY_LEN);
    if(ret == 0){
        cerr<<"["+identity+"]: "<<"Session key generation failed for a buffer error"<<endl;
        clean_all();
        return false;
    }
    else if(ret<0){
        cerr<<"["+identity+"]: "<<"Session key generation failed for a security error"<<endl;
        clean_all();
        return false;
    }
    memcpy(this->session_key, sess_key, KEY_LEN);
    memcpy(this->hmac_key, kmac, HMAC_KEY_LEN);
#pragma optimize("", off)
    memset(sess_key, 0, KEY_LEN);
    memset(kmac, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    free(sess_key);
    free(kmac);

    //prepare M2
    unsigned short encoded_client_pub_dhkey_len = m1->header.payload_length;
    unsigned char* encoded_client_pub_dhkey = m1->payload;
    unsigned short encoded_server_pub_dhkey_len;
    unsigned char* encoded_server_pub_dhkey;
    if(!encode_EVP_PKEY(server_pub_dhkey, encoded_server_pub_dhkey, encoded_server_pub_dhkey_len)){
        cerr<<"["+identity+"]: "<<"Cannot encode server dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, encoded_server_pub_dhkey});
    allocatedBuffers.push_back({MESSAGE, m1});

    //sign g^u, g^s


    unsigned short to_sign_buf_len = encoded_client_pub_dhkey_len + encoded_server_pub_dhkey_len;
    unsigned char* to_sign_buffer = (unsigned char*) malloc(to_sign_buf_len);
    if(!to_sign_buffer){
        cerr<<"["+identity+"]: "<<"Cannot allocate digital signature buffer"<<endl;
        clean_all();
        return false;
    }
    memcpy(to_sign_buffer, encoded_client_pub_dhkey, encoded_client_pub_dhkey_len);
    memcpy(to_sign_buffer + encoded_client_pub_dhkey_len, encoded_server_pub_dhkey, encoded_server_pub_dhkey_len);
    allocatedBuffers.push_back({CLEAR_BUFFER, to_sign_buffer});

    unsigned int signature_len;
    unsigned char* signature_buffer;
    if(!apply_signature(to_sign_buffer,to_sign_buf_len,signature_buffer,signature_len,server_privkey)){
        cerr<<"["+identity+"]: "<<"Error on digital signature application"<<endl;
        clean_all();
        return false;
    };
    allocatedBuffers.push_back({CLEAR_BUFFER, signature_buffer});

    unsigned char* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+identity+"]: "<<"Cannot allocate buffer for IV"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    //g^u, g^s encryption
    unsigned int enc_signature_buffer_len;
    unsigned char* enc_signature_buffer;
    if(symm_encrypt(signature_buffer,signature_len,this->session_key,
                  IV_buffer,enc_signature_buffer,enc_signature_buffer_len)!=1){
        cerr<<"["+identity+"]: "<<"Cannot encrypt signed parameters"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, enc_signature_buffer});

    //certificate loading
    X509* certificate = read_certificate("../Keys/Server/server_cert.pem");
    if(certificate == NULL){
        cerr<<"["+identity+"]: "<<"Cannot read input certificate"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({X509_BUF, certificate});

    unsigned char* serialized_certificate;
    unsigned short ser_certificate_len;
    if(encode_certificate(certificate,serialized_certificate,ser_certificate_len)!=1){
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, serialized_certificate});

    //prepare message M2. In the payload, for each field, we also communicate the field size
    unsigned int m2_payload_len = encoded_server_pub_dhkey_len + enc_signature_buffer_len + ser_certificate_len;
    unsigned char* m2_payload = (unsigned char*)malloc(m2_payload_len+ 3*sizeof(unsigned short));
    if(!m2_payload){
        cerr<<"["+identity+"]: "<<"Cannot allocate buffer for m2"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, m2_payload});
    int current_len = 0;

    memcpy(m2_payload,&encoded_server_pub_dhkey_len,sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(m2_payload + current_len,encoded_server_pub_dhkey,encoded_server_pub_dhkey_len);
    current_len += encoded_server_pub_dhkey_len;

    memcpy(m2_payload + current_len,&enc_signature_buffer_len,sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(m2_payload + current_len,enc_signature_buffer,enc_signature_buffer_len);
    current_len += enc_signature_buffer_len;

    memcpy(m2_payload + current_len,&ser_certificate_len,sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(m2_payload + current_len,serialized_certificate,ser_certificate_len);
    current_len += ser_certificate_len;

    message* m2 = build_message(IV_buffer, NO_OPCODE, current_len, m2_payload, false);
    if(send_msg(socket_id, m2, false, identity) < current_len+FIXED_HEADER_LENGTH){
        cerr<<"["+identity+"]: "<<"Cannot send M2"<<endl;
        clean_all();
        return false;
    }

    message* m3 = new message();
    if(recv_msg(socket_id, m3, false, identity)<=0){
        cerr<<"["+identity+"]: "<<"Cannot receive M3 from client"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({MESSAGE, m3});
    unsigned char* decrypted_payload;
    unsigned int decrypted_len;
    ret = symm_decrypt(m3->payload, m3->header.payload_length,
                       this->session_key, m3->header.initialization_vector,decrypted_payload,decrypted_len);
    if(ret==0){
        cerr<<"["+identity+"]: "<<"Cannot decrypt m3 payload"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, decrypted_payload, decrypted_len});

    payload_field* signed_pub_dh_keys = new payload_field();
    payload_field* recv_username = new payload_field();
    unsigned short num_fields = 2;
    payload_field* fields[] = {signed_pub_dh_keys, recv_username};
    if(!get_payload_fields(decrypted_payload, fields, num_fields)){
        cerr<<"["+identity+"]: "<<"Cannot unpack received m3 payload"<<endl;
        clean_all();
        return false;
    }

    string str_username((const char*)recv_username->field, recv_username->field_len-1);
    if(!check_username(str_username)){
        cerr<<"["+identity+"]: "<<"Username does not satisfy constraints"<<endl;
        send_failure_message(MISSING_USER, AUTH_RESPONSE, false);
        clean_all();
        return false;
    }

    this->username = str_username;
    this->identity = "Worker for: "+this->username;

    DIR *dp;
    struct dirent *ep;
    string path = "../UserData/";
    dp = opendir((path + this->username).c_str());

    if(!dp) {
        cerr<<"["+identity+"]: "<<"Cannot find dedicated storage for user, considered not registered yet"<<endl;
        send_failure_message(MISSING_USER, AUTH_RESPONSE, false);
        clean_all();
        return false;
    }

    while((ep = readdir(dp)) != nullptr){
        this->file_list += ep->d_name;
        this->file_list += "\n";
    }
    closedir(dp);

    EVP_PKEY* client_pubkey;
    if (!read_pubkey(client_pubkey, string("../Keys/Server/Client_Pub_Keys/" + str_username + "_pubkey"))){
        cerr<<"["+identity+"]: "<<"Cannot read client public key"<<endl;
        send_failure_message(MISSING_USER, AUTH_RESPONSE, false);
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, client_pubkey});

    //contextually, checks that signed parameters are actually g^u and g^s
    unsigned short groundtruth_len = to_sign_buf_len;
    unsigned char* groundtruth_fields = to_sign_buffer;     //groundtruth are the same parameters server signed in m2
    ret = verify_signature(signed_pub_dh_keys->field,signed_pub_dh_keys->field_len,
                           groundtruth_fields,groundtruth_len,
                           client_pubkey);
    if(ret<=0){
        cerr<<"Unable to verify signature"<<endl;
        clean_all();
        return false;
    }

    unsigned char clear_resp = REQ_OK;
    IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"["+identity+"]: "<<"Cannot allocate buffer for IV"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    //g^u, g^s encryption
    unsigned int enc_buffer_len;
    unsigned char* enc_buffer;
    if(symm_encrypt(&clear_resp,sizeof(unsigned char),this->session_key,
                    IV_buffer,enc_buffer,enc_buffer_len)!=1){
        cerr<<"["+identity+"]: "<<"Cannot encrypt response"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, enc_buffer});

    message* m4;
    m4 = build_message(IV_buffer, AUTH_RESPONSE, enc_buffer_len, enc_buffer, true, this->hmac_key);
    send_msg(this->socket_id, m4, true, identity);
    allocatedBuffers.push_back({MESSAGE, m4});
    this->client_counter = 1;
    this->worker_counter = 1;

    clean_all();
    return true;
}



