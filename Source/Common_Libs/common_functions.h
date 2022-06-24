//
// Created by mirco on 18/06/2022.
//

#ifndef SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H
#define SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H

#endif //SECURE_CLOUD_STORAGE_COMMON_FUNCTIONS_H
#include "struct_message.h"
using namespace std;
/*          SECURE CODING           */
bool check_username(const std::string& username);
bool check_file_name(const std::string& file_name);
bool command_ok(const std::string& command);


/*          MESSAGE EXCHANGE        */
message* build_message(unsigned char* iv, unsigned char opcode, unsigned int payload_length, unsigned char* payload, bool hmac, unsigned char* hmac_key=NULL, unsigned int counter=0);
int send_msg(int socket_id, message* msg, bool hmac, std::string identity);
int recv_msg(int socket_id, message *msg, bool hmac, std::string identity);
bool get_payload_fields(const unsigned char* total_payload, payload_field* fields[], unsigned short num_fields);
unsigned long get_file_size(const string &filename, bool &file_found);
unsigned char *read_chunk(const string &filename, unsigned int sent_size, int max_read);
bool delete_file(const string &filename);
bool write_file(unsigned char *file_chunk, unsigned int chunk_len, const string &filename);


/*          CRYPTO FUNCTIONS        */
int generate_random_iv(unsigned char* &iv, const int iv_length);
unsigned short generate_dh_secret(EVP_PKEY* &my_dhkey);
int generate_dh_session_key(EVP_PKEY* my_dhkey,EVP_PKEY* peer_pubkey,unsigned char* &session_key, unsigned short key_len, unsigned char* &kmac, unsigned short kmac_len);
bool read_pubkey(EVP_PKEY* &pubkey, string file_name);
bool read_privkey(EVP_PKEY* &privkey, string privkey_file_name);
EVP_PKEY* extract_dh_pubkey(EVP_PKEY* my_dhkey);

int encode_EVP_PKEY (EVP_PKEY* to_encode, unsigned char* &buffer, unsigned short& buf_size);
EVP_PKEY* decode_EVP_PKEY (unsigned char* to_decode, unsigned short buffer_len);

int symm_encrypt(unsigned char* clear_buf, unsigned int clear_size, unsigned char* session_key, unsigned char* IV, unsigned char*& enc_buf, unsigned int& cipherlen);
int symm_decrypt(unsigned char* enc_buf, unsigned int enc_size, unsigned char* session_key, unsigned char* IV, unsigned char*& clear_buf, unsigned int& clearlen);

int apply_signature(unsigned char* clear_buf, unsigned short clear_size, unsigned char*& sgnt_buf, unsigned int &sgnt_size, EVP_PKEY* privkey);
int verify_signature(unsigned char* signed_buf,  unsigned short signed_size, unsigned char* clear_buf, unsigned short clear_size, EVP_PKEY* peer_pubkey);

X509* read_certificate(string certificate_name);
int verify_certificate(X509* cert_to_verify,const string& ca_cert_file_name, const string& crl_file_name);
int encode_certificate (X509* to_serialize, unsigned char* &buffer, unsigned short& buf_size);
X509* decode_certificate (unsigned char* to_deserialize, unsigned short buffer_len);

unsigned int prepare_buffer_for_hmac(unsigned char*& buffer_mac,unsigned int& buffer_mac_len, unsigned char** inputs, unsigned int* input_lengths, unsigned int inputs_number);
int compute_hmac(unsigned char* payload, unsigned int payload_len, unsigned char*& hmac_digest,unsigned char* hmac_key);
int verify_hmac(message* m, unsigned int counter, unsigned char* hmac_key);