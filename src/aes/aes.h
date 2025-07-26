#ifndef AES_H
#define AES_H

#include "../common/common.h"
#include "../crypto_utils/crypto_utils.h"
//#include "socket_utils.h"

#define IV_LEN 12
#define TAG_LEN 16
#define AAD_LEN 8
#define MAX_PLAINTEXT_LEN 16384

struct AesEncryptedMessage {
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[MAX_PLAINTEXT_LEN];
    int ciphertext_len;
    char aad[AAD_LEN];
};


AesEncryptedMessage encrypt_message_aes(const unsigned char* plaintext, size_t plaintext_len, unsigned char *aes_hsm_key, bool is_aes_128 = false);
std::string serialize_aes_message(const AesEncryptedMessage& msg, int sender_id, int receiver_id, int type);
unsigned char* decrypt_message_aes(const rapidjson::Document& message, size_t& out_len, unsigned char *aes_hsm_key, bool is_aes_128 = false);

#endif 
