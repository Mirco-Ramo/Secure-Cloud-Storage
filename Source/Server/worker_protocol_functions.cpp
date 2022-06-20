//
// Created by Francesco del Turco, Mirco Ramo
//

#include "worker.h"

bool Worker::establish_session() {
    int ret;
    message* m1 = new message();
    EVP_PKEY* peer_dh_pubkey;
    ret = recv_msg(this->socket_id, m1, false, this->identity);
    if(ret<=0)
        return false;
    peer_dh_pubkey = decode_EVP_PKEY(m1->payload,m1->header.payload_length);
    BIO_dump_fp (stdout, (const char*)peer_dh_pubkey, m1->header.payload_length);
    return true;
}



