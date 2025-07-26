#ifndef RSA_EXCHANGE_H
#define RSA_EXCHANGE_H

#include "../common/common.h"
#include "../crypto_utils/crypto_utils.h"
#include "../aes/aes.h"
//#include "socket_utils.h"

extern const char* ECU_PRIVKEY_PATH;
extern EVP_PKEY* ecu_privkey;


std::string serialize_rsa_request(int id, int nonce, EVP_PKEY* ecu_private_key, EVP_PKEY* hsm_public_key);
void parse_rsa_response(
    std::string& json_str,
    EVP_PKEY* ecu_private_key,
    EVP_PKEY* hsm_public_key,
    unsigned char* aes_key_enc,
    time_t& nonce
);

#endif

// RSA_EXCHANGE AUTH
/*

// extern const char* ECU_PUBKEY_PATH;
// extern const char* HSM_CERT_PATH;
// extern EVP_PKEY* ecu_pubkey;
// extern EVP_PKEY* hsm_pubkey;
*/
