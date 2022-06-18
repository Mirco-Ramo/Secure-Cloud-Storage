//
// Created by Francesco Del Turco, Mirco Ramo
//
#include "client_include.h"
#include "struct_message.h"

unsigned int client_counter;
unsigned int server_counter;

/*                  CHECK TAINTED INPUT                 */
bool check_username(const string& username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(username.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

bool check_file_name(const string& file_name){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.";

    if(file_name.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

bool command_ok(const string& command){
    char ok_chars [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if(command.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}


/*                          DIFFIE-HELLMAN KEY EXCHANGE                 */

static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
            0x83, 0x7B, 0x5C, 0x75, 0xBB, 0x40, 0x9B, 0x0A, 0x6B, 0xA4,
            0x1D, 0xDE, 0x78, 0xED, 0xB7, 0x08, 0xF6, 0x78, 0x84, 0x60,
            0x53, 0x0D, 0xDB, 0x4B, 0xCA, 0x11, 0xE6, 0xC7, 0x65, 0xB1,
            0xF9, 0x40, 0xF1, 0x8C, 0xD3, 0x1D, 0x3D, 0xE1, 0x0D, 0x5A,
            0xAB, 0x40, 0x7D, 0xBA, 0x5B, 0xAC, 0x9F, 0xEA, 0xA9, 0xDD,
            0xF9, 0x0B, 0x66, 0x66, 0x16, 0xE5, 0x4D, 0x59, 0x92, 0xA0,
            0x69, 0x1B, 0xE6, 0x2B, 0xDD, 0x9C, 0x5E, 0x95, 0xD3, 0x3A,
            0x0D, 0x00, 0x61, 0xAD, 0xFF, 0x11, 0x00, 0xEE, 0x53, 0x08,
            0xD5, 0x90, 0x8A, 0xA1, 0xDC, 0xD9, 0x1C, 0xA0, 0xB0, 0x06,
            0xE4, 0x3C, 0xCC, 0x28, 0xD3, 0x32, 0xA0, 0xD6, 0x0F, 0x84,
            0xDC, 0xDA, 0x1D, 0xF5, 0x59, 0x14, 0xC8, 0xA8, 0xB2, 0xC0,
            0xB0, 0x36, 0xE1, 0x4A, 0x01, 0x1A, 0x2F, 0x41, 0xEF, 0x69,
            0xA8, 0xD7, 0xC1, 0x80, 0xA5, 0xE8, 0x3E, 0x79, 0x4A, 0x02,
            0x66, 0x8E, 0xD9, 0xD5, 0xDD, 0x68, 0x41, 0x92, 0x8F, 0xD6,
            0x24, 0x6E, 0x20, 0x71, 0x94, 0x4B, 0xC5, 0xF2, 0x29, 0xEF,
            0x69, 0xC4, 0xB9, 0xC5, 0xB3, 0xA2, 0x0D, 0x13, 0xDA, 0x70,
            0x83, 0x17, 0x92, 0x3D, 0xA0, 0xEE, 0x67, 0x34, 0xE1, 0x46,
            0x75, 0x7C, 0xE0, 0x39, 0x49, 0xBD, 0x78, 0x4B, 0xCA, 0x8D,
            0xD4, 0xAF, 0xEC, 0x32, 0x54, 0xFA, 0x1E, 0x58, 0xC5, 0x37,
            0x07, 0x5C, 0x02, 0x63, 0x62, 0xB5, 0xCC, 0x56, 0x8A, 0xB0,
            0x96, 0x95, 0x61, 0x40, 0x80, 0x76, 0xF3, 0xD3, 0xF5, 0xD7,
            0xAC, 0x08, 0xF0, 0xF7, 0xA5, 0xC8, 0xBD, 0xDA, 0x0C, 0x7D,
            0x13, 0x59, 0x7C, 0xF1, 0xD4, 0x52, 0xBE, 0x1D, 0xF3, 0x7F,
            0xDD, 0x62, 0x10, 0xC0, 0x74, 0xA4, 0x42, 0x11, 0x3A, 0x82,
            0xE8, 0x22, 0x2D, 0x7A, 0x75, 0xE5, 0x06, 0x3B, 0xBF, 0xDA,
            0x57, 0xF1, 0x0E, 0x50, 0xD8, 0xF3
    };
    static unsigned char dhg_2048[] = {
            0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
        || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

//creates private and public dh ephemeral keys
unsigned short generate_dh_secret(EVP_PKEY* &my_dhkey){
    EVP_PKEY* dh_params;
    int ret;
    dh_params = EVP_PKEY_new();
    if(!dh_params){
        cerr<<"Cannot instantiate high level Diffie-Hellman parameters"<<endl;
        return 0;
    }

    DH* temp = get_dh2048();
    ret=EVP_PKEY_set1_DH(dh_params,temp);
    DH_free(temp);
    if(ret != 1){
        cerr<<"Cannot assign DH param in EVP_PKEY param"<<endl;
        EVP_PKEY_free(dh_params);
        return 0;
    }

    EVP_PKEY_CTX* DHctx;
    DHctx = EVP_PKEY_CTX_new(dh_params, NULL);

    if(!DHctx){
        cerr<<"Cannot instantiate Diffie-Hellman context"<<endl;
        EVP_PKEY_free(dh_params);
        return 0;
    }

    //Keygen (u,g^u mod p)
    ret = EVP_PKEY_keygen_init(DHctx);
    if(ret<=0){
        cerr<<"Cannot initialize context to key generation"<<endl;
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(DHctx);
        return 0;
    }

    ret = EVP_PKEY_keygen(DHctx, &my_dhkey);
    if(ret<=0){
        cerr<<"Cannot allocate memory and generate keys"<<endl;
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(DHctx);
        return 0;
    }

    EVP_PKEY_free(dh_params);
    EVP_PKEY_CTX_free(DHctx);

    return 1;
}

int generate_dh_session_key(EVP_PKEY* my_dhkey,EVP_PKEY* peer_pubkey,unsigned char* &session_key, unsigned short key_len, unsigned char* &kmac, unsigned short kmac_len){

    EVP_PKEY_CTX* derive_ctx;			//Context for symmetric key derivation
    unsigned char* skey;				//Symmetric key
    size_t skeylen;						//Symmetric key dimension

    EVP_MD_CTX* hash_context;                                       //Digest context
    unsigned char* digest;                                          //digest buffer
    unsigned int digest_len;                                        //Dim buffer

    int ret;

    derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
    if(!derive_ctx){
        cerr<<"Cannot allocate memory and generate keys"<<endl;
        return 0;
    }

    ret= EVP_PKEY_derive_init(derive_ctx);
    if(ret <= 0){
        cerr<<"Cannot initialize context to derive shared key"<<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        return 0;
    }

    ret = EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey);
    if(ret <= 0){
        cerr<<"Cannot set public key of server to derive shared key"<<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        return 0;
    }

    ret = EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
    if(ret <= 0){
        cerr<<"Cannot obtain max shared key length"<<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        return 0;
    }

    skey = (unsigned char*)(malloc(int(skeylen)));
    if(!skey){
        cerr<<"Cannot allocate a buffer for shared key\n";
        EVP_PKEY_CTX_free(derive_ctx);
        return 0;
    }

    //Symmetric key generation K=g^ab mod p
    ret = EVP_PKEY_derive(derive_ctx, skey, &skeylen);
    if(ret <= 0){
        cerr<<"Cannot generate the shared key\n";
        EVP_PKEY_CTX_free(derive_ctx);
#pragma optimize("", off)
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        return 0;
    }

    EVP_PKEY_CTX_free(derive_ctx);

    //We hash the shared key to obtain K, kMAC
    hash_context = EVP_MD_CTX_new();
    if(!hash_context){
        cerr<<"Cannot generate hash context"<<endl;
#pragma optimize("", off)
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        return 0;
    }

    //allocare memoria per il digest
    digest = (unsigned char*) malloc(DIGEST_LEN);
    if(!digest){
        cerr<<"Impossible to allocate digest buffer\n";
        EVP_MD_CTX_free(hash_context);
#pragma optimize("", off)
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        return 0;
    }


    //Init, update and finalize of digest
    ret=EVP_DigestInit(hash_context,EVP_sha256());
    if(ret == 0){
        cerr<<"Cannot init digest context\n";
        EVP_MD_CTX_free(hash_context);
#pragma optimize("", off)
        memset(digest,0,digest_len);
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        free(digest);
        return 0;
    }

    ret=EVP_DigestUpdate(hash_context, (unsigned char*) skey, skeylen);
    if(ret == 0){
        cerr<<"Cannot update digest context\n";
        EVP_MD_CTX_free(hash_context);
#pragma optimize("", off)
        memset(digest,0,digest_len);
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        free(digest);
        return 0;
    }

    ret=EVP_DigestFinal(hash_context,digest,&digest_len);
    if(ret == 0){
        cerr<<"Cannot finalize digest context\n";
        EVP_MD_CTX_free(hash_context);
#pragma optimize("", off)
        memset(digest,0,digest_len);
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        free(digest);
        return 0;
    }

    EVP_MD_CTX_free(hash_context);

    session_key= (unsigned char*)malloc(key_len);
    kmac = (unsigned char*)malloc(kmac_len);
    if(!session_key || ! kmac){
        cerr<<"Cannot allocate session key buffer\n";
#pragma optimize("", off)
        memset(digest,0,digest_len);
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(digest);
        free(skey);
        return 0;
    }

    memcpy(session_key,digest,key_len);
    memcpy(kmac, digest+key_len, kmac_len);

#pragma optimize("", off)
    memset(digest,0,digest_len);
    memset(skey,0,skeylen);
#pragma optimize("", on)

    free(digest);
    free(skey);
    return 1;
}





bool begin_session(int socket_id){
    client_counter=1;
    server_counter=1;

}

void clean_counters(){
    client_counter=0;
    server_counter=0;
}

