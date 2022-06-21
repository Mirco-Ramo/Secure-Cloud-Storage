//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"

bool Worker::establish_session() {
    int ret;
    //M1: receive client's g^u mod p
    message* m1 = new message();
    EVP_PKEY* client_pub_dhkey;
    ret = recv_msg(this->socket_id, m1, false, this->identity);
    if(ret<=0)
        return false;
    client_pub_dhkey = decode_EVP_PKEY(m1->payload,m1->header.payload_length);
    delete m1;
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
    unsigned char *sess_key, *kmac;
    unsigned short key_len = KEY_LEN, kmac_len = HMAC_KEY_LEN;
    ret = generate_dh_session_key(server_dhkey,client_pub_dhkey,sess_key, key_len, kmac, kmac_len);
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
    memset(sess_key, 0, key_len);
    memset(kmac, 0, kmac_len);
#pragma optimize("", on)
    free(sess_key);
    free(kmac);

    //prepare M2
    unsigned short encoded_client_pub_dhkey_len;
    unsigned char* encoded_client_pub_dhkey;
    unsigned short encoded_server_pub_dhkey_len;
    unsigned char* encoded_server_pub_dhkey;
    if(!encode_EVP_PKEY(server_pub_dhkey, encoded_server_pub_dhkey, encoded_server_pub_dhkey_len)){
        cerr<<"["+identity+"]: "<<"Cannot encode server dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, encoded_server_pub_dhkey});
    if(!encode_EVP_PKEY(client_pub_dhkey, encoded_client_pub_dhkey, encoded_client_pub_dhkey_len)){
        cerr<<"["+identity+"]: "<<"Cannot encode client dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, encoded_client_pub_dhkey});

    //sign g^u, g^s
    EVP_PKEY* server_privkey;
    if (!read_privkey(server_privkey, "../Keys/Server/server_prv_key.pem")){
        cerr<<"["+identity+"]: "<<"Cannot read server private key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, server_privkey});

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
    unsigned short enc_signature_buffer_len;
    unsigned char* enc_signature_buffer;
    if(symm_encrypt(signature_buffer,signature_len,this->session_key,
                  IV_buffer,enc_signature_buffer,enc_signature_buffer_len)!=1){
        cerr<<"["+identity+"]: "<<"Cannot encrypt signed parameters"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, enc_signature_buffer});

    //certificate loading
    X509* certificate = read_certificate("../Keys/Server/Server_cert.pem");
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
    unsigned int current_len = 0;

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
    free(encoded_server_pub_dhkey);
    free(encoded_client_pub_dhkey);
    EVP_PKEY_free(server_privkey);
    free(to_sign_buffer);
    free(signature_buffer);
    free(IV_buffer);
    free(enc_signature_buffer);
    X509_free(certificate);
    free(serialized_certificate);
    delete m2;
    return true;
}



