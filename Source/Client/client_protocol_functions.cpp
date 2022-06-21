//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"
#include "client_functions.h"


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

    unsigned short clear_signature_len;
    unsigned char* clear_signature;

    ret = symm_decrypt(encoded_server_signature->field, encoded_server_signature->field_len,
                       session_key, m2->header.initialization_vector,clear_signature,clear_signature_len);
    if(ret==0){
        cerr<<"Cannot decrypt signed m2 portion"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, clear_signature});

    //sign verification
    unsigned short clear_len = encoded_client_pub_dhkey_len + encoded_server_pub_dhkey->field_len;
    unsigned char* clear_fields = (unsigned char*)malloc(clear_len);
    if(!clear_fields){
        cerr<<"Cannot allocate buffer to verify signature"<<endl;
        clean_all();
        return false;
    }
    allocatedBuffers.push_back({CLEAR_BUFFER, clear_fields});
    memcpy(clear_fields,encoded_client_pub_dhkey,encoded_client_pub_dhkey_len);
    memcpy(clear_fields + encoded_client_pub_dhkey_len, encoded_server_pub_dhkey->field,encoded_server_pub_dhkey->field_len);
    ret = verify_signature(clear_signature,clear_signature_len,clear_fields,clear_len,
                           server_pubkey);
    if(ret<=0){
        cerr<<"Unable to verify signature"<<endl;
        clean_all();
        return false;
    }
    delete m2;
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
