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

bool begin_session(int socket_id, const string& username, const string& identity){
    int ret;
    EVP_PKEY *client_dhkey = NULL;
    if(!generate_dh_secret(client_dhkey)){
        cerr<<"Cannot generate dh secret"<<endl;
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, client_dhkey});

    EVP_PKEY* client_pub_dhkey = extract_dh_pubkey(client_dhkey);
    if (client_pub_dhkey == NULL){
        cerr<<"Cannot extract dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, client_pub_dhkey});

    unsigned short encoded_client_pub_dhkey_len;
    unsigned char* encoded_client_pub_dhkey;
    if(!encode_EVP_PKEY(client_pub_dhkey, encoded_client_pub_dhkey, encoded_client_pub_dhkey_len)){
        cerr<<"Cannot encode dh pub key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, encoded_client_pub_dhkey});

    message* m1;
    m1 = build_message(NULL, AUTH_INIT, encoded_client_pub_dhkey_len, encoded_client_pub_dhkey, false);
    if(send_msg(socket_id, m1, false, identity) < encoded_client_pub_dhkey_len+FIXED_HEADER_LENGTH){
        cerr<<"Cannot send M1 to server"<<endl;
        clean_all();
        return false;
    }
    delete m1;

    //HANDLE M2

    message* m2 = new message();
    if(recv_msg(socket_id, m2, false, identity)<=0){
        cerr<<"Cannot receive M2 from server"<<endl;
        clean_all();
        return false;
    }
    payload_field* encoded_server_pub_dhkey;
    payload_field* encoded_server_signature;
    payload_field* encoded_server_cert;
    unsigned short num_fields = 3;
    payload_field* fields[] = {encoded_server_pub_dhkey, encoded_server_signature, encoded_server_cert};
    if(!get_payload_fields(m2->payload, fields, num_fields)){
        cerr<<"Cannot unpack payload fields"<<endl;
        clean_all();
        return false;
    }

    EVP_PKEY* server_pub_dhkey = decode_EVP_PKEY(encoded_server_pub_dhkey->field,encoded_server_pub_dhkey->field_len);
    if(server_pub_dhkey == NULL){
        cerr<<"Cannot decode server public key"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, server_pub_dhkey});

    unsigned char* sess_key;
    unsigned char* kmac;
    ret = generate_dh_session_key(client_dhkey, server_pub_dhkey, sess_key, KEY_LEN, kmac, HMAC_KEY_LEN);
    if(ret == 0){
        cerr<<"Session key generation failed for a buffer error"<<endl;
        clean_all();
        return false;
    }
    else if(ret<0){
        cerr<<"Session key generation failed for a security error"<<endl;
        clean_all();
        return false;
    }
    memcpy(session_key, sess_key, KEY_LEN);
    memcpy(hmac_key, kmac, HMAC_KEY_LEN);
#pragma optimize("", off)
    memset(sess_key, 0, KEY_LEN);
    memset(kmac, 0, HMAC_KEY_LEN);
#pragma optimize("", on)
    free(sess_key);
    free(kmac);

    //check certificate, get server pub key
    X509* server_certificate = decode_certificate(encoded_server_cert->field, encoded_server_cert->field_len);
    if(server_certificate == NULL){
        cerr<<"Cannot decode server certificate"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({X509_BUF,server_certificate});

    if(verify_certificate(server_certificate,"../CertAuth/FOC_cert.pem","../CertAuth/FOC_crl.pem")<1){
        cerr<<"Cannot verify server certificate"<<endl;
        clean_all();
        return false;
    }

    //extract server pubkey
    EVP_PKEY* server_pubkey;
    server_pubkey = X509_get_pubkey(server_certificate);
    if(server_pubkey == NULL){
        cerr<<"Cannot extract server public key from certificate"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, server_pubkey});

    unsigned int clear_signature_len;
    unsigned char* clear_signature;

    ret = symm_decrypt(encoded_server_signature->field, encoded_server_signature->field_len,
                       session_key, m2->header.initialization_vector,clear_signature,clear_signature_len);
    if(ret==0){
        cerr<<"Cannot decrypt signed m2 portion"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, clear_signature});

    //sign verification, return true only if the message was signed using server's pub key, and only if it actually signed g^u and g^s
    unsigned short groundtruth_len = encoded_client_pub_dhkey_len + encoded_server_pub_dhkey->field_len;
    auto* groundtruth_fields = (unsigned char*)malloc(groundtruth_len);
    if(!groundtruth_fields){
        cerr<<"Cannot allocate buffer to verify signature"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, groundtruth_fields});
    memcpy(groundtruth_fields,encoded_client_pub_dhkey,encoded_client_pub_dhkey_len);
    memcpy(groundtruth_fields + encoded_client_pub_dhkey_len, encoded_server_pub_dhkey->field,encoded_server_pub_dhkey->field_len);
    ret = verify_signature(clear_signature,clear_signature_len,groundtruth_fields,groundtruth_len,
                           server_pubkey);
    if(ret<=0){
        cerr<<"Unable to verify signature"<<endl;
        clean_all();
        return false;
    }

    delete m2;

    // HANDLE M3
    EVP_PKEY* client_privkey;
    if (!read_privkey(client_privkey, string("../Keys/Client/") + username + string("_privkey.pem"))){
        cerr<<"Cannot read" +string("../Keys/Client/") + username + string("_privkey.pem") <<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({EVP_PKEY_BUF, client_privkey});

    unsigned int client_signed_len;
    unsigned char* client_signed_buffer;
    unsigned short to_sign_len = groundtruth_len;
    unsigned char* to_sign = groundtruth_fields;

    ret = apply_signature(to_sign,to_sign_len,client_signed_buffer,client_signed_len,client_privkey);
    if(ret==0){
        cerr<<"Cannot apply signature to message"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, client_signed_buffer});

    unsigned char* IV_buffer = (unsigned char*)malloc(IV_LENGTH);
    if(!IV_buffer){
        cerr<<"Cannot allocate buffer for IV"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, IV_buffer});

    //prepare message M3. In the payload, for each field, we also communicate the field size, then encrypt
    unsigned short username_characters = username.size() + 1;
    unsigned short m3_clear_payload_len = client_signed_len + username_characters + 2*sizeof(unsigned short);
    auto* m3_clear_payload = (unsigned char*)malloc(m3_clear_payload_len+ 3*sizeof(unsigned short));
    if(!m3_clear_payload){
        cerr<<"Cannot allocate buffer for m3"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, m3_clear_payload, m3_clear_payload_len});
    unsigned int current_len = 0;

    memcpy(m3_clear_payload,&client_signed_len,sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(m3_clear_payload + current_len,client_signed_buffer,client_signed_len);
    current_len += client_signed_len;

    memcpy(m3_clear_payload + current_len,&username_characters,sizeof(unsigned short));
    current_len += sizeof(unsigned short);
    memcpy(m3_clear_payload + current_len,username.c_str(),username_characters);

    unsigned int encrypted_m3_payload_len;
    unsigned char* encrypted_m3_payload;
    if(symm_encrypt(m3_clear_payload,m3_clear_payload_len,session_key,
                    IV_buffer,encrypted_m3_payload,encrypted_m3_payload_len)!=1){
        cerr<<"Cannot encrypt signed parameters and username"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({ENC_BUFFER, encrypted_m3_payload});

    message* m3 = build_message(IV_buffer, NO_OPCODE, encrypted_m3_payload_len, encrypted_m3_payload, false);
    if(send_msg(socket_id, m3, false, identity) < current_len+FIXED_HEADER_LENGTH){
        cerr<<"Cannot send M3"<<endl;
        clean_all();
        return false;
    }

    client_counter = 0;
    server_counter = 0;

    message* m4 = new message();
    if(recv_msg(socket_id, m4, true, identity)<=0){
        cerr<<"Cannot receive M4 from server"<<endl;
        clean_all();
        return false;
    }
    ret = verify_hmac(m4, server_counter, hmac_key);
    if(ret<0){
        cerr<<"Cannot verify M4"<<endl;
        clean_all();
        return false;
    }
    else if(ret==0){
        cerr<<"Corrupted message detected. Leaving the socket"<<endl;
        shutdown(0);
    }
    clean_all();
    return true;
}
















void clean_counters(){
    client_counter=0;
    server_counter=0;
}

void clean_all(){
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
                memset(pointer_elem->content,0,HMAC_KEY_LEN);
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
#pragma optimize("", off)
    memset(session_key,0,KEY_LEN);
    memset(hmac_key,0,HMAC_KEY_LEN);
#pragma optimize("", on)
}
