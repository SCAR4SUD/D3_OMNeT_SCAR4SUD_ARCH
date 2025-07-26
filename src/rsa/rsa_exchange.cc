#include "rsa_exchange.h"

std::string serialize_rsa_request(int id, int nonce, EVP_PKEY* ecu_private_key, EVP_PKEY* hsm_public_key) {
    rapidjson::Document doc;
    doc.SetObject();
    auto& alloc = doc.GetAllocator();

    std::string to_sign = std::to_string(id) + std::to_string(nonce);
    size_t signature_len = 0;
    unsigned char *signature = rsa_sign_evp((const unsigned char*)to_sign.c_str(), to_sign.length(), ecu_private_key, &signature_len);
    std::string signature_b64 = base64_encode(signature, signature_len);

    doc.AddMember("id", id, alloc);
    doc.AddMember("nonce", nonce, alloc);
    doc.AddMember("signature", rapidjson::Value().SetString(signature_b64.c_str(), signature_b64.length()), alloc);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    std::string request = buffer.GetString();

    rapidjson::Document message;
    message.SetObject();
    auto& message_alloc = message.GetAllocator();

    unsigned char aes_rand_key[128];
    RAND_bytes(aes_rand_key, 128);

    AesEncryptedMessage aes_msg = encrypt_message_aes((unsigned char *)request.c_str(), request.length(), aes_rand_key, true);
    std::string ciphertext_b64 = base64_encode((unsigned char*)aes_msg.ciphertext, aes_msg.ciphertext_len);
    std::string iv_str = base64_encode((unsigned char*)aes_msg.iv, IV_LEN);
    std::string tag_str = base64_encode((unsigned char*)aes_msg.tag, TAG_LEN);
    std::string aad_str = base64_encode((unsigned char*)aes_msg.aad, AAD_LEN);

    unsigned char enc_key[256];
    size_t enc_key_len{0};
    rsa_encrypt_evp(hsm_public_key, aes_rand_key, 128, enc_key, &enc_key_len);
    std::string enc_key_b64 = base64_encode(enc_key, enc_key_len);

    std::string message_to_sign = aad_str + iv_str + ciphertext_b64 + tag_str + enc_key_b64;
    size_t message_signature_len = 0;
    unsigned char *message_signature = rsa_sign_evp(
        (const unsigned char*)message_to_sign.c_str(),
        message_to_sign.length(),
        ecu_private_key,
        &message_signature_len
    );
    std::string message_signature_b64 = base64_encode(message_signature, message_signature_len);

    message.AddMember("type", RSA_REQUEST, message_alloc);
    message.AddMember("id", id, message_alloc);
    message.AddMember(
        "aad",
        rapidjson::Value().SetString(aad_str.c_str(), aad_str.length()),
        message_alloc
    );
    message.AddMember(
        "iv",
        rapidjson::Value().SetString(iv_str.c_str(), iv_str.length()),
        message_alloc
    );
    message.AddMember(
        "ciphertext",
        rapidjson::Value().SetString(ciphertext_b64.c_str(), ciphertext_b64.length()),
        message_alloc
    );
    message.AddMember(
        "tag",
        rapidjson::Value().SetString(tag_str.c_str(), tag_str.length()),
        message_alloc
    );
    message.AddMember(
        "enc_key",
        rapidjson::Value().SetString(enc_key_b64.c_str(), enc_key_b64.length()),
        message_alloc
    );
    message.AddMember(
        "signature",
        rapidjson::Value().SetString(message_signature_b64.c_str(), message_signature_b64.length()),
        message_alloc
    );

    rapidjson::StringBuffer message_buffer;
    rapidjson::Writer<rapidjson::StringBuffer> message_writer(message_buffer);
    message.Accept(message_writer);

    return message_buffer.GetString();
}

void parse_rsa_response(
    std::string& json_str,
    EVP_PKEY* ecu_private_key,
    EVP_PKEY* hsm_public_key,
    unsigned char* aes_key,
    time_t& nonce
) {
    rapidjson::Document doc;
    if (doc.Parse(json_str.c_str()).HasParseError()) {
        handle_errors("Error parsing JSON in parse_rsa_response");
        return;
    }

    if (
            !doc.HasMember("aad")           || !doc["aad"].IsString()           ||
            !doc.HasMember("iv")            || !doc["iv"].IsString()            ||
            !doc.HasMember("ciphertext")    || !doc["ciphertext"].IsString()    ||
            !doc.HasMember("tag")           || !doc["tag"].IsString()           ||
            !doc.HasMember("key")           || !doc["key"].IsString()
    ) {
        handle_errors("missing camps");
        return;
    }

    std::string to_verify;
    to_verify.append(doc["aad"].GetString());
    to_verify.append(doc["iv"].GetString());
    to_verify.append(doc["ciphertext"].GetString());
    to_verify.append(doc["tag"].GetString());
    to_verify.append(doc["key"].GetString());

    std::string enc_key_b64 = doc["key"].GetString();

    unsigned char key_enc[256];
    size_t key_enc_len = base64_decode(enc_key_b64, key_enc, 256);

    unsigned char key[16];
    size_t key_len{0};
    rsa_decrypt_evp(ecu_private_key, key_enc, key_enc_len, key, &key_len);

    size_t plain_len = 0;
    unsigned char* plaintext = decrypt_message_aes(doc, plain_len, key, true);

    std::string response_json((char *)plaintext, plain_len);
    rapidjson::Document response;
    if (response.Parse(response_json.c_str()).HasParseError()) {
        handle_errors("Error parsing JSON in parse_rsa_response");
        return;
    }

    std::string session_key_b64 = response["key"].GetString();


    if(base64_decode(session_key_b64, aes_key, AES_KEY_ENC_MAXLEN) != 32) {
        std::cerr << "[INFO] received session key of wrong length" << std::endl;
        return;
    }

    nonce = response["nonce"].GetInt();
}



