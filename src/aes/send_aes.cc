#include "aes.h"

AesEncryptedMessage encrypt_message_aes(const unsigned char* plaintext, size_t plaintext_len, unsigned char *aes_hsm_key, bool is_aes_128) {
    if (plaintext_len > MAX_PLAINTEXT_LEN)
        handle_errors("plaintext troppo lungo");

    AesEncryptedMessage msg{};
    if (RAND_bytes(msg.iv, IV_LEN) != 1)
        handle_errors("generazione IV");

    memset(msg.aad, 0, AAD_LEN);
    // msg.aad[ECUID_LEN - 1] = '\0';

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors("allocazione EVP_CIPHER_CTX");
    int len;

    if(is_aes_128) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
            handle_errors("init AES GCM 128");
    }else {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            handle_errors("init AES GCM 256");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_hsm_key, msg.iv) != 1)
        handle_errors("init chiave e IV");

    if (EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(msg.aad), AAD_LEN) != 1)
        handle_errors("AAD");

    if (EVP_EncryptUpdate(ctx, msg.ciphertext, &len, plaintext, plaintext_len) != 1)
        handle_errors("cifratura");

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, msg.ciphertext + len, &len) != 1) 
        handle_errors("finale cifratura");

    ciphertext_len += len;
    msg.ciphertext_len = ciphertext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, msg.tag) != 1)
        handle_errors("estrazione tag");

    EVP_CIPHER_CTX_free(ctx);
    return msg;
}

 std::string serialize_aes_message(const AesEncryptedMessage& msg, int sender_id, int receiver_id, int type) {

    std::string iv_b64  = base64_encode(msg.iv, IV_LEN);
    std::string ct_b64  = base64_encode(msg.ciphertext, msg.ciphertext_len);
    std::string tag_b64 = base64_encode(msg.tag, TAG_LEN);
    std::string aad_b64 = base64_encode(reinterpret_cast<const unsigned char*>(msg.aad), ECUID_LEN);

    rapidjson::Document doc;
    doc.SetObject();
    auto& alloc = doc.GetAllocator();

    doc.AddMember("sender_id", sender_id, alloc);
    doc.AddMember("receiver_id", receiver_id, alloc);
    doc.AddMember("type", type, alloc);
    doc.AddMember("iv", rapidjson::Value().SetString(iv_b64.c_str(), alloc), alloc);
    doc.AddMember("ciphertext", rapidjson::Value().SetString(ct_b64.c_str(), alloc), alloc);
    doc.AddMember("tag", rapidjson::Value().SetString(tag_b64.c_str(), alloc), alloc);
    doc.AddMember("aad", rapidjson::Value().SetString(aad_b64.c_str(), alloc), alloc);

    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    doc.Accept(writer);
    return buf.GetString();
}

