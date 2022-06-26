//
// Created by mirco on 18/06/2022.
//

#include "common_functions.h"
#include "common_parameters.h"
using namespace std;

/*                  TAINTED INPUT SANITIZATION                */
bool check_username(const string& username){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-";

    if(username.find_first_not_of(ok_chars)!=string::npos){
        return false;
    }
    return true;
}

char* canonicalize(const string& file_name){
    //canonicalization//
    //e.g.   ../file.txt  =>  /home/user/myfiles/file.txt
    char* canon_file_name = realpath(("./"+file_name).c_str(), NULL);
    if(!canon_file_name)
        return NULL;
    return canon_file_name;
}

string tokenize_string(string file_name){
    size_t pos = 0;
    string filename_portion;
    string delimiter = "/";
    while ((pos = file_name.find(delimiter)) != std::string::npos) {
        file_name.erase(0, pos + delimiter.length());
    }
    return file_name;
}

bool check_permissions(const string& filename){
    const char* filename_chr = canonicalize(filename.c_str());
    if(access(filename_chr, R_OK) || access(filename_chr, W_OK)){
        return false;
    }
    return true;
}

bool check_file_name(const string& file_name){
    char* canon_file_name = canonicalize(file_name);
    if(canon_file_name == NULL)
        return false;

    if(strncmp(canon_file_name, "/home/", strlen("/home/")) != 0) {
        free(canon_file_name);
        return false;
    }

    string canon_string_name(canon_file_name);
    free(canon_file_name);

    //tokenization
    //e.g.      /home/user/myfiles/file.txt  => file.txt
    size_t pos = 0;
    string filename_portion;
    string delimiter = "/";
    while ((pos = canon_string_name.find(delimiter)) != std::string::npos) {
        filename_portion = canon_string_name.substr(0, pos);
        canon_string_name.erase(0, pos + delimiter.length());
    }
    filename_portion = canon_string_name;

    //whitelisting of the final part and checking that contains a point for the extension
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.";
    if(filename_portion.find_first_not_of(ok_chars)!=string::npos && filename_portion.find('.') != string::npos){
        cerr<<"Filename does not satisfy constraints"<<endl;
        return false;
    }
    return true;
}

bool check_filename_not_traversing(const string& file_name){
    char ok_chars [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.";
    if(file_name.find_first_not_of(ok_chars)!=string::npos){
        cerr<<"Filename does not satisfy constraints"<<endl;
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
/*                          GENERATE RANDOM IV                          */
int generate_random_iv(unsigned char* &iv, const int iv_length){
    RAND_poll();
    return RAND_bytes(iv, iv_length);
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

//Generates the session key and the kmac starting from dh shared secret
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
        return -8;
    }

    ret = EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey);
    if(ret <= 0){
        cerr<<"Cannot set public key of server to derive shared key"<<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        return -7;
    }

    ret = EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
    if(ret <= 0){
        cerr<<"Cannot obtain max shared key length"<<endl;
        EVP_PKEY_CTX_free(derive_ctx);
        return -6;
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
        return -5;
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
        return -4;
    }

    digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha512()));
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
    ret=EVP_DigestInit(hash_context,EVP_sha512());
    if(ret == 0){
        cerr<<"Cannot init digest context\n";
        EVP_MD_CTX_free(hash_context);
#pragma optimize("", off)
        memset(skey,0,skeylen);
#pragma optimize("", on)

        free(skey);
        free(digest);
        return -1;
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
        return -2;
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
        return -3;
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

//reads a public key from specified file
bool read_pubkey(EVP_PKEY* &pubkey, string file_name){
    FILE* pubkey_file;
    int ret;

    file_name += ".pem";

    pubkey_file = fopen(file_name.c_str(),"r");
    if(!pubkey_file){
        cerr<< "Cannot open requested file" <<endl;
        return false;
    }

    pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    if(!pubkey){
        cerr<< "Cannot read public key"<<endl;
        fclose(pubkey_file);
        return false;
    }

    ret = fclose(pubkey_file);
    if(ret != 0){
        cerr<< "Cannot close file"<<endl;
        return false;
    }
    return true;
}

//reads the private key from a specified file
bool read_privkey(EVP_PKEY* &privkey, string privkey_file_name){
    FILE* privkey_file;
    int ret;

    privkey_file = fopen(privkey_file_name.c_str(), "r");
    if(!privkey_file){
        cerr << "Error: cannot open file '" << privkey_file_name <<"' (missing?)\n";
        return false;
    }

    privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    if(!privkey){
        cerr << "Impossible to read private key\n";
        fclose(privkey_file);
        return false;
    }

    ret = fclose(privkey_file);
    if(ret != 0){
        cerr << "File closing fails\n";
        return false;
    }

    return true;
}

//extracts the dh public key from a dh shared secret
EVP_PKEY* extract_dh_pubkey(EVP_PKEY* my_dhkey){
    EVP_PKEY* dh_pubkey;
    int ret;

    BIO* tmp = BIO_new(BIO_s_mem());
    if(!tmp){
        cerr<<"Error on instantiate BIO element\n";
        return NULL;
    }

    ret = PEM_write_bio_PUBKEY(tmp, my_dhkey);
    if(ret == 0){
        cerr << "Error on PEM_write_bio_PUBKEY\n";
        BIO_free(tmp);
        return NULL;
    }

    dh_pubkey = PEM_read_bio_PUBKEY(tmp, NULL, NULL, NULL);
    if(!dh_pubkey){
        cerr << "Error on PEM_read_bio_PUBKEY\n";
        BIO_free(tmp);
        return NULL;
    }

    BIO_free(tmp);

    return dh_pubkey;
}

int encode_EVP_PKEY (EVP_PKEY* to_encode, unsigned char* &buffer, unsigned short& buf_size){
    int ret;
    unsigned char* tmp_buf;
    BIO* mem_bio = BIO_new(BIO_s_mem());
    if(!mem_bio){
        cerr<<"Error on instantiate BIO element\n";
        return 0;
    }

    ret = PEM_write_bio_PUBKEY(mem_bio,to_encode);
    if(ret == 0){
        cerr<<"Error on PEM_write_bio_PUBKEY\n";
        BIO_free(mem_bio);
        return 0;
    }

    tmp_buf = NULL;
    buf_size = BIO_get_mem_data(mem_bio, &tmp_buf);
    buffer = (unsigned char*)malloc(buf_size);
    if(!buffer){
        cerr<<"Error on instantiate result buffer\n";
        BIO_free(mem_bio);
        return 0;
    }
    memcpy(buffer,tmp_buf,buf_size);
#pragma optimize("", off)
    memset(tmp_buf, 0, buf_size);
#pragma optimize("", on)
    BIO_free(mem_bio);

    return 1;
}

EVP_PKEY* decode_EVP_PKEY (unsigned char* to_decode, unsigned short buffer_len){
    int ret;
    EVP_PKEY* key;
    BIO* mem_bio = BIO_new(BIO_s_mem());

    if(!mem_bio){
        cerr<<"Error on instantiate BIO element\n";
        return NULL;
    }

    ret = BIO_write(mem_bio, to_decode, buffer_len);
    if(ret != (int)buffer_len){
        cerr<<"Error on BIO_write\n";
        BIO_free(mem_bio);
        return NULL;
    }

    key = PEM_read_bio_PUBKEY(mem_bio, NULL, NULL, NULL);
    if(!key){
        cerr<<"Error on PEM_read_bio_PUBKEY\n";
        BIO_free(mem_bio);
        return NULL;
    }

    BIO_free(mem_bio);
    return key;
}



/*          SYMMETRIC ENCRYPTION        */
int symm_encrypt(unsigned char* clear_buf, unsigned int clear_size, unsigned char* session_key, unsigned char* IV, unsigned char*& enc_buf, unsigned int& cipherlen){
    int outlen;
    int ret;
    EVP_CIPHER_CTX* ctx;


    ret = RAND_bytes(IV, IV_LENGTH);
    if(ret != 1){
        cerr << "Error: RAND_bytes fails. Return: "<<ret<<endl;
        return 0;
    }
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }
    int block_size = EVP_CIPHER_block_size(CIPHER);
    enc_buf = (unsigned char*)malloc(clear_size + block_size);
    if(!enc_buf) {
        cerr << "Error: malloc returned NULL\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ret = EVP_EncryptInit(ctx, CIPHER, session_key, IV);
    if(ret != 1){
        cerr << "Error: EVP_EncryptInit returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(enc_buf);
        return 0;
    }

    ret = EVP_EncryptUpdate(ctx, enc_buf,&outlen, clear_buf, clear_size);
    if(ret != 1){
        cerr << "Error: EVP_EncryptUpdate returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(enc_buf);
        return 0;
    }
    cipherlen = outlen;
    ret = EVP_EncryptFinal(ctx, enc_buf + cipherlen, &outlen);
    if(ret != 1){
        cerr << "Error: EVP_EncryptFinal returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(enc_buf);
        return 0;
    }
    cipherlen += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}


int symm_decrypt(unsigned char* enc_buf, unsigned int enc_size, unsigned char* session_key, unsigned char* IV, unsigned char*& clear_buf, unsigned int& clearlen){
    int outlen;
    int ret;
    EVP_CIPHER_CTX* ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n";
        return 0;
    }
    clear_buf = (unsigned char*)malloc(enc_size);
    if(!clear_buf) {
        cerr << "Error: malloc returned NULL\n";
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ret = EVP_DecryptInit(ctx, CIPHER, session_key, IV);
    if(ret != 1){
        cerr << "Error: EVP_DecryptInit returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(clear_buf);
        return 0;
    }
    ret = EVP_DecryptUpdate(ctx, clear_buf, &outlen, enc_buf, enc_size);
    if(ret != 1){
        cerr << "Error: EVP_DecryptUpdate returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(clear_buf);
        return 0;
    }
    clearlen = outlen;
    ret = EVP_DecryptFinal(ctx, clear_buf + clearlen, &outlen);
    if(ret != 1){
        cerr << "Error: EVP_DecryptFinal returned " << ret << "\n";
        EVP_CIPHER_CTX_free(ctx);
        free(clear_buf);
        return 0;
    }
    clearlen += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

/*              DIGITAL SIGNATURES      */
int apply_signature(unsigned char* clear_buf, unsigned short clear_size, unsigned char*& sgnt_buf, unsigned int &sgnt_size, EVP_PKEY* privkey){
    int ret;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        return 0;
    }

    sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(privkey));
    if(!sgnt_buf) {
        cerr << "Error: malloc returned NULL (signature too big?)\n";
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    ret = EVP_SignInit(md_ctx, MAC_TYPE);
    if(ret == 0){
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        free(sgnt_buf);
        return 0;
    }

    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
    if(ret == 0){
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        free(sgnt_buf);
        return 0;
    }


    ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, privkey);
    if(ret == 0){
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        EVP_MD_CTX_free(md_ctx);
        free(sgnt_buf);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}

int verify_signature(unsigned char* signed_buf,  unsigned short signed_size, unsigned char* clear_buf, unsigned short clear_size, EVP_PKEY* peer_pubkey){
    int ret;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        cerr << "Error: EVP_MD_CTX_new returned NULL"<<endl;
        return -1;
    }

    ret = EVP_VerifyInit(md_ctx, MAC_TYPE);
    if(ret == 0){
        cerr << "Error: EVP_VerifyInit returned " << ret << endl;
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
    if(ret == 0){
        cerr << "Error: EVP_VerifyUpdate returned " << ret << endl;
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    ret = EVP_VerifyFinal(md_ctx, signed_buf, signed_size, peer_pubkey);
    if(ret == -1){
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)"<<endl;
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    else if(ret == 0){//INVALID SIGNATURE
        cerr << "Error: Invalid signature!"<<endl;
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);

    return ret;
}






/*              CERTIFICATES            */

//reads a certificate from file
X509* read_certificate(string certificate_name){
    FILE* certificate_file = fopen(certificate_name.c_str(), "r");
    if(!certificate_file){
        cerr << "Error: cannot open file '" << certificate_name << "' (missing?)"<<endl;
        return NULL;
    }

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);
    fclose(certificate_file);
    if(!certificate){
        cerr << "Error: PEM_read_X509 returned NULL\n";
        return NULL;
    }

    return certificate;
}

//verifies authenticity of a certificates, given a CA certificate and relative crl
int verify_certificate(X509* cert_to_verify,const string& ca_cert_file_name, const string& crl_file_name){
    int ret;

    //load CA certificate
    FILE* ca_cert_file = fopen(ca_cert_file_name.c_str(), "r");
    if(!ca_cert_file){
        cerr << "Error: cannot open file '" << ca_cert_file_name << "' (missing?)\n";
        return -1;
    }
    X509* ca_certificate = PEM_read_X509(ca_cert_file, NULL, NULL, NULL);
    fclose(ca_cert_file);
    if(!ca_certificate){
        cerr << "Error: PEM_read_X509 returned NULL\n";
        return -1;
    }

    //load CRL
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    if(!crl_file){
        cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n";
        X509_free(ca_certificate);
        return -1;
    }
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){
        cerr << "Error: PEM_read_X509_CRL returned NULL\n";
        X509_free(ca_certificate);
        return -1;
    }

    X509_STORE* store = X509_STORE_new();
    if(!store) {
        cerr << "Error: X509_STORE_new returned NULL\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        return -1;
    }
    ret = X509_STORE_add_cert(store, ca_certificate);
    if(ret != 1) {
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) {
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) {
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" ;
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    //verification
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) {
        cerr << "Error: X509_STORE_CTX_new returned NULL\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert_to_verify, NULL);
    if(ret != 1) {
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        X509_STORE_CTX_free(certvfy_ctx);
        return -1;
    }

    ret = X509_verify_cert(certvfy_ctx);
    if(ret == 0) {
        cerr << "Error: peer certificate not verified " << ret << "\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        X509_STORE_CTX_free(certvfy_ctx);
        return -1;
    }
    else if(ret < 0) {
        cerr << "Error: X509_verify_cert returned " << ret << "\n";
        X509_free(ca_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        X509_STORE_CTX_free(certvfy_ctx);
        return -1;
    }

    X509_free(ca_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);

    return 1;
}
int encode_certificate (X509* to_serialize, unsigned char* &buffer, unsigned short& buf_size){
    int ret;
    unsigned char* tmp_buf;
    BIO* mem_bio = BIO_new(BIO_s_mem());
    if(!mem_bio){
        cerr<<"Error on instantiate BIO element\n";
        return 0;
    }

    ret = PEM_write_bio_X509(mem_bio,to_serialize);
    if(ret == 0){
        cerr<<"Error on PEM_write_bio_X509\n";
        BIO_free(mem_bio);
        return 0;
    }

    tmp_buf = NULL;
    buf_size = BIO_get_mem_data(mem_bio, &tmp_buf);
    buffer = (unsigned char*)malloc(buf_size);
    if(!buffer){
        BIO_free(mem_bio);
        cerr<<"Error on instantiate result buffer\n";
        return 0;
    }
    //copia dal buffer interno al BIO ad un buffer esterno
    memcpy(buffer,tmp_buf,buf_size);

    BIO_free(mem_bio);

    return 1;
}

X509* decode_certificate (unsigned char* to_deserialize, unsigned short buffer_len){
    int ret;
    X509* cert;
    BIO* mem_bio = BIO_new(BIO_s_mem());
    if(!mem_bio){
        cerr<<"Error on instantiate BIO element\n";
        return NULL;
    }

    ret = BIO_write(mem_bio, to_deserialize, buffer_len);
    if(ret != (int)buffer_len){
        cerr<<"Error on BIO_write\n";
        BIO_free(mem_bio);
        return NULL;
    }

    cert = PEM_read_bio_X509(mem_bio, NULL, NULL, NULL);
    if(!cert){
        cerr<<"Error on PEM_read_bio_X509\n";
        BIO_free(mem_bio);
        return NULL;
    }

    BIO_free(mem_bio);
    return cert;
}



/*                  HMAC                        */

unsigned int prepare_buffer_for_hmac(unsigned char*& buffer_mac,unsigned int& buffer_mac_len, unsigned char** inputs, unsigned int* input_lengths, unsigned int inputs_number){
    unsigned int total_input_len=0;
    for(unsigned int i=0; i<inputs_number; ++i){
        total_input_len += input_lengths[i];
    }
    buffer_mac_len = total_input_len;
    buffer_mac = (unsigned char*) malloc(buffer_mac_len);
    if(!buffer_mac){
        cerr << "Cannot allocate buffer for hmac\n";
        return 0;
    }
    unsigned int total_buffered=0;
    for(unsigned int i=0; i<inputs_number; ++i){
        if(input_lengths[i]>0) {
            memcpy(buffer_mac + total_buffered, inputs[i], input_lengths[i]);
            total_buffered += input_lengths[i];
        }
    }
    return total_buffered;
}


int compute_hmac(unsigned char* payload, unsigned int payload_len, unsigned char*& hmac_digest,unsigned char* hmac_key){
    HMAC_CTX* hmac_ctx;
    int ret;
    unsigned int outlen;

    hmac_ctx = HMAC_CTX_new();
    if(!hmac_ctx){
        cerr << "Error: HMAC_CTX_new returned NULL"<<endl;
        return 0;
    }

    hmac_digest = (unsigned char*) malloc(DIGEST_LEN);
    if(!hmac_digest) {
        cerr << "Error: malloc returned NULL\n";
        HMAC_CTX_free(hmac_ctx);
        return 0;
    }

    ret = HMAC_Init_ex(hmac_ctx,hmac_key,HMAC_KEY_LEN,MAC_TYPE,NULL);
    if(ret != 1){
        cerr << "Error: HMAC_Init returned " << ret << "\n";
        HMAC_CTX_free(hmac_ctx);
        free(hmac_digest);
        return 0;
    }

    ret= HMAC_Update(hmac_ctx, payload, payload_len);
    if(ret != 1){
        cerr << "Error: HMAC_Update returned " << ret << "\n";
        HMAC_CTX_free(hmac_ctx);
        free(hmac_digest);
        return 0;
    }

    ret = HMAC_Final(hmac_ctx, hmac_digest, &outlen);
    if(ret != 1){
        cerr << "Error: HMAC_Final returned " << ret << "\n";
        HMAC_CTX_free(hmac_ctx);
        free(hmac_digest);
        return 0;
    }
    if(outlen != DIGEST_LEN){
        cerr << "Error: HMAC_Final returned unexpected digest length\n";
        HMAC_CTX_free(hmac_ctx);
        free(hmac_digest);
        return 0;
    }

    HMAC_CTX_free(hmac_ctx);

    return 1;
}

int verify_hmac(message* m, unsigned int counter, unsigned char* hmac_key){
    int ret;

    unsigned char payload_len_bytes[PAYLOAD_LENGTH_LEN];
    unsigned char counter_bytes[sizeof(unsigned int)];
    for (int i=0; i<PAYLOAD_LENGTH_LEN; i++)
        payload_len_bytes[i]=(unsigned char)(m->header.payload_length>>((PAYLOAD_LENGTH_LEN-1-i)*8));
    for (unsigned int i=0; i<sizeof(unsigned int); i++)
        counter_bytes[i]=(unsigned char)(counter>>((sizeof(unsigned int)-1-i)*8));

    unsigned int input_lengths[] = {IV_LENGTH, OPCODE_LENGTH, PAYLOAD_LENGTH_LEN, m->header.payload_length, sizeof(unsigned int)};
    unsigned char* inputs[] = {m->header.initialization_vector, &m->header.opcode, payload_len_bytes, m->payload, counter_bytes};
    unsigned int inputs_number=5; //iv, opcode, payload_length, payload, counter
    unsigned char* buffer_mac;
    unsigned int buffer_mac_len;

    if (prepare_buffer_for_hmac(buffer_mac, buffer_mac_len, inputs, input_lengths, inputs_number) != FIXED_HEADER_LENGTH + m->header.payload_length + sizeof(unsigned int)){
        cerr<<"Impossible to create buffer for hmac: Message build aborted";
        return -1;
    }
    unsigned char* computed_digest;
    ret = compute_hmac(buffer_mac, buffer_mac_len, computed_digest, hmac_key);
    if(ret != 1){
        cerr<<"Impossible to compute hmac: Message build aborted";
        if (computed_digest)
            free(computed_digest);
        return ret;
    }

    ret = CRYPTO_memcmp(computed_digest, m->hmac, DIGEST_LEN);

    free(computed_digest);
    if (ret != 0) { //Wrong digests
        cerr << "The message results to be not authenticated\n";
        return 0;
    }
    return 1;
}