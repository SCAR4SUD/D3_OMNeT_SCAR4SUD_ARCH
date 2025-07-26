#include "aes.h"

std::string receive_message(int port) {
    return "test";
}

unsigned char* decrypt_message_aes(const rapidjson::Document& message, size_t& out_len, unsigned char *aes_hsm_key, bool is_aes_128) {
    if (!message.HasMember("iv") ||
        !message.HasMember("ciphertext") ||
        !message.HasMember("tag") ||
        !message.HasMember("aad"))
    {
        handle_errors("Campi AES mancanti nel JSON");
    }

    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[16384];
    unsigned char aad[AAD_LEN];

    size_t ciphertext_len = base64_decode(                                   //Decode da base64 a binario
    message["ciphertext"].GetString(), ciphertext, sizeof(ciphertext));
    base64_decode(message["iv"].GetString(), iv, IV_LEN);
    base64_decode(message["tag"].GetString(), tag, TAG_LEN);
    base64_decode(message["aad"].GetString(), aad, AAD_LEN);

    static unsigned char plaintext[16384];
    int len = 0;
    int plaintext_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();             // Creazione contesto
    if (!ctx) {
        handle_errors("allocazione EVP_CIPHER_CTX");
        return nullptr;
    }

    if(is_aes_128 == true) {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1){     // Accede al contesto, usa aes_gcm256
            handle_errors("init decifratura");
            return nullptr;
        }
    }else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1){     // Accede al contesto, usa aes_gcm256
            handle_errors("init decifratura");
            return nullptr;
        }
    }


    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_hsm_key, iv) != 1) {                  // Inserisce nel contesto iv e key
        handle_errors("init chiave/iv");
        return nullptr;
    }

    if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, AAD_LEN) != 1) {                         // Inserisce AAD
        handle_errors("AAD decifratura");
        return nullptr;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {            // Decrypt
        EVP_CIPHER_CTX_free(ctx);
        handle_errors("decifratura contenuto");
        return nullptr;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {           // Carica tag
        handle_errors("set tag");
        return nullptr;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {               // Finalizza decrypt verificando tag
        handle_errors("verifica tag (err="+std::to_string(ret)+")");
        return nullptr;
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    out_len = plaintext_len;
    return plaintext;
}
