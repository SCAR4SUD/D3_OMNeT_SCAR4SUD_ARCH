#include "rsa.h"

#include <iostream>
#include <chrono>

#include "../rapidjson/document.h"
#include "../rapidjson/stringbuffer.h"
#include "../rapidjson/writer.h"
#include "../rapidjson/error/en.h"

#include "../cryptoki.h"
#include "../sca.h"

std::string rsa_response(rapidjson::Document& message, sca::Session& session) {
    using namespace rapidjson;

    /* extracting response */

    if (!message.HasMember("id") || !message["id"].IsInt())
        std::cerr << "Errore parsing JSON (rsa_response)" << std::endl;

    CK_OBJECT_HANDLE hsm_private_key{0};
    CK_ULONG private_key_count{0};
    session.findKey(0, &hsm_private_key, &private_key_count);
    if(private_key_count == 0)
        std::cerr << "[HSM] HSM has no private key in its storage" << std::endl;

    CK_OBJECT_HANDLE ecu_public_key{0};
    CK_ULONG public_key_count{0};
    session.findKey(message["id"].GetInt(), &ecu_public_key, &public_key_count);
    if(public_key_count == 0)
        std::cerr << "[HSM] ECU-" << message["id"].GetInt() << " has no public key in the HSM" << std::endl;

    std::string enc_key_b64 = message["enc_key"].GetString();
    unsigned char enc_key[256];
    size_t enc_key_len = sca::base64_decode(enc_key_b64, enc_key, 256);

    unsigned char *key = nullptr;
    CK_ULONG key_len{0};
    if(!session.decryptRsa(hsm_private_key, enc_key, 256, key, &key_len)) {
        std::cerr << "[HSM] RSA_REQUEST from ECU-" << message["id"].GetInt() << ": aes key decryption failed." << std::endl;
        return "{\"type\":\"FAILED\"}";
    }

    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[16384];
    unsigned char aad[AAD_SIZE];

    sca::base64_decode(message["iv"].GetString(), iv, IV_LEN);
    sca::base64_decode(message["tag"].GetString(), tag, TAG_LEN);
    CK_ULONG ciphertext_len = sca::base64_decode(message["ciphertext"].GetString(), ciphertext, sizeof(ciphertext));
    sca::base64_decode(message["aad"].GetString(), aad, AAD_SIZE);

    CK_ULONG encrypted_data_len = IV_LEN + ciphertext_len + TAG_LEN;
    CK_BYTE_PTR encrypted_data = new CK_BYTE[encrypted_data_len];
    memcpy(encrypted_data, iv, IV_LEN);
    memcpy(encrypted_data + IV_LEN, ciphertext, ciphertext_len);
    memcpy(encrypted_data + IV_LEN + ciphertext_len, tag, TAG_LEN);

    session.createAesKey("ECU"+std::to_string(message["id"].GetInt())+"REQ", key, key_len/8);
    CK_OBJECT_HANDLE ecu_aes_128_key{0};
    CK_ULONG ecu_aes_128_key_count{0};
    if(!session.findKey("ECU"+std::to_string(message["id"].GetInt())+"REQ", &ecu_aes_128_key, &ecu_aes_128_key_count))
        std::cerr << "[HSM] failed to refind insetred AES one-use key" << std::endl;

    CK_BYTE_PTR decrypted_data;
    CK_ULONG decrypted_data_len;
    if(!session.decryptAesGCM(
        ecu_aes_128_key,
        encrypted_data,
        encrypted_data_len,
        std::string((char *)aad, ECUID_LEN),
        decrypted_data,
        &decrypted_data_len
    )) {
       std::cerr << "\033[1;31m[HSM] failed to decrypt request\033[0m" << std::endl;
       session.destroyObject(ecu_aes_128_key);
       return "{\"type\":\"FAILED\"}";
    }

    if(!session.destroyObject(ecu_aes_128_key)) {
        std::cerr << "[HSM] failed to delete temporary AES key" << std::endl;
    }


    std::string message_signature_b64 = message["signature"].GetString();
    CK_BYTE message_signature[256];
    size_t message_signature_len = sca::base64_decode(message_signature_b64, message_signature, 2048, "message_signature_b64 (rsa_response)");

    std::string message_to_verify;
    message_to_verify.append(message["aad"].GetString());
    message_to_verify.append(message["iv"].GetString());
    message_to_verify.append(message["ciphertext"].GetString());
    message_to_verify.append(message["tag"].GetString());
    message_to_verify.append(message["enc_key"].GetString());
    bool isMessageVerified = session.verifyRsa(
        ecu_public_key,
        (unsigned char *)message_to_verify.c_str(),
        message_to_verify.length(),
        message_signature,
        message_signature_len
    );
    if(!isMessageVerified) {
        std::cerr << "[HSM] RSA_REQUEST from ECU-" << message["id"].GetInt() << " was rejected. Message signature verification failed." << std::endl;
        return "{\"type\":\"FAILED\"}";
    }
    /* processing request */

    rapidjson::Document doc;
    if (doc.Parse((const char *)decrypted_data).HasParseError())
        std::cerr << "\033[1;31m[HSM] failed to parse decrypted RSA_REQUEST\033[0m" << std::endl;


    std::string signature_b64 = doc["signature"].GetString();
    CK_BYTE signature[256];
    size_t signature_len = sca::base64_decode(signature_b64, signature, 2048, "signature_b64 (rsa_response)");

    int nonce_to_resend = doc["nonce"].GetInt();
    std::string data_to_verify = std::to_string(doc["id"].GetInt()) + std::to_string(doc["nonce"].GetInt());
    bool isVerified = session.verifyRsa(
        ecu_public_key,
        (unsigned char *)data_to_verify.c_str(),
        data_to_verify.length(),
        signature,
        signature_len
    );
    if(!isVerified) {
        std::cerr << "[HSM] RSA_REQUEST from ECU-" << doc["id"].GetInt() << " was rejected. Request signature verification failed." << std::endl;
        return "{\"type\":\"FAILED\"}";
    }

    CK_ULONG id = doc["id"].GetInt();

    std::string label = "ECU" + std::to_string(doc["id"].GetInt());

    CK_OBJECT_HANDLE hsm_ecu_key = {0};
    CK_ULONG count = {0};
    session.findKey(label, &hsm_ecu_key, &count);
    if(count != 0) {
        session.destroyObject(hsm_ecu_key);
        //std::cerr << "[INFO] Session key with this label present -> destroy..." << std::endl;
    }
    if(!session.createSessionKey(label, &hsm_ecu_key))
        std::cerr << "failed to create key" << label << std::endl;
    
    CK_BYTE_PTR session_key{nullptr};
    CK_ULONG session_key_len{0};
    if(!session.getKeyValue(hsm_ecu_key, session_key, &session_key_len)) {
        std::cerr << "[HSM] RSA_REQUEST from ECU-" << doc["id"].GetInt() << " was rejected. Failed to extract session key value from HSM." << std::endl;
        return "{\"type\":\"FAILED\"}";
    }
    std::string session_key_b64 = sca::base64_encode(
        (const unsigned char*)session_key,
        session_key_len
    );

    CK_BYTE_PTR response_signature;
    CK_ULONG response_signature_len;

    std::time_t local_timestamp = std::time(0);
    if(
        !session.sign(
            hsm_private_key,
            (CK_BYTE_PTR)session_key_b64.c_str(),
            session_key_b64.length(),
            response_signature,
            &response_signature_len
        )
    ) {
        std::cerr << "[HSM] failed to sign key to be sent" << std::endl;
        return "{\"type\":\"FAILED\"}";
    }

    std::string response_signature_b64 = sca::base64_encode(response_signature, response_signature_len);

    rapidjson::Document return_json;
    return_json.SetObject();
    auto& alloc = return_json.GetAllocator();

    return_json.AddMember("type", HSM_RSA_RESPONSE, alloc);
    return_json.AddMember("id", id, alloc);
    return_json.AddMember("nonce", nonce_to_resend, alloc);
    return_json.AddMember(
        "key",
        rapidjson::Value().SetString(
            session_key_b64.c_str(),
            session_key_b64.length()
        ),
        alloc
    );
    return_json.AddMember(
        "signature",
        rapidjson::Value().SetString(
            response_signature_b64.c_str(),
            response_signature_b64.length()
        ),
        alloc
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    return_json.Accept(writer);

    std::string rsa_response = buffer.GetString();

    CK_OBJECT_HANDLE hsm_aes_128_key{0};
    CK_ULONG hsm_aes_128_key_count{0};
    if(session.findKey("ECU"+std::to_string(message["id"].GetInt())+"RES", &hsm_aes_128_key, &hsm_aes_128_key_count)) {
        std::cerr << "destrying objects: (" << hsm_aes_128_key << ")" << std::endl;
        session.destroyObject(hsm_aes_128_key);
        return "{\"type\":\"FAILED\"}";
    }

    if(!session.createAesKey("ECU"+std::to_string(message["id"].GetInt())+"RES", 16))
        std::cerr << "[HSM] failed to insert AES one-use key" << std::endl;
    if(!session.findKey("ECU"+std::to_string(message["id"].GetInt())+"RES", &hsm_aes_128_key, &hsm_aes_128_key_count))
        std::cerr << "[HSM] failed to refind inserted AES one-use key" << std::endl;


    CK_BYTE_PTR iv_res{nullptr};
    CK_ULONG iv_res_len{0};
    CK_BYTE_PTR tag_res{nullptr};
    CK_ULONG tag_res_len{0};
    CK_BYTE_PTR aad_res{nullptr};
    CK_ULONG aad_res_len{0};
    CK_BYTE_PTR ciphertext_res{nullptr};
    CK_ULONG ciphertext_res_len{0};

    session.encryptAesGCMParam(
        hsm_aes_128_key,
        (CK_BYTE_PTR)rsa_response.c_str(),
        rsa_response.length(),
        ciphertext_res,
        &ciphertext_res_len,
        aad_res,
        &aad_res_len,
        tag_res,
        &tag_res_len,
        iv_res,
        &iv_res_len
    );

    std::string ciphertext_str = sca::base64_encode(ciphertext_res, ciphertext_res_len);
    std::string iv_str = sca::base64_encode(iv_res, iv_res_len);
    std::string tag_str = sca::base64_encode(tag_res, tag_res_len);
    std::string aad_str = sca::base64_encode(aad_res, aad_res_len);

    CK_BYTE_PTR hsm_aes_key_value_enc{nullptr};
    CK_ULONG hsm_aes_key_value_enc_len{0};

    if(!session.wrapSessionKey(
        ecu_public_key,
        hsm_aes_128_key,
        hsm_aes_key_value_enc,
        &hsm_aes_key_value_enc_len
    )) {
        std::cerr << "\033[1;31m[HSM] failed to encrypt response key\033[0m" << std::endl;
        return "{\"type\":\"FAILED\"}";
    }

    if(!session.destroyObject(hsm_aes_128_key)) {
        std::cerr << "[HSM] failed to delete temporary AES key" << std::endl;
    }

    std::cout << "[HSM] hsm_aes_key_value_enc_len: " << hsm_aes_key_value_enc_len << std::endl;

    std::string hsm_aes_key_value_enc_b64 = sca::base64_encode(hsm_aes_key_value_enc, hsm_aes_key_value_enc_len);

    std::string response_message_to_sign = aad_str + iv_str + ciphertext_str + tag_str + hsm_aes_key_value_enc_b64;

    CK_BYTE_PTR response_message_signature{NULL_PTR};
    CK_ULONG response_message_signature_len{0};
    if(!session.sign(
        hsm_private_key,
        (CK_BYTE_PTR)response_message_to_sign.c_str(),
        response_message_to_sign.length(),
        response_message_signature,
        &response_message_signature_len
    )) {
        std::cerr << "[HSM] failed to sign RSA_RESPONSE" << std::endl;
        return "{\"type\":\"FAILED\"}";
    }

    std::string response_message_signature_str = sca::base64_encode(response_message_signature, response_message_signature_len);

    rapidjson::Document response_json;
    response_json.SetObject();
    auto& response_alloc = response_json.GetAllocator();

    response_json.AddMember(
        "type",
        HSM_RSA_RESPONSE,
        response_alloc
    );
    response_json.AddMember(
        "aad",
        rapidjson::Value().SetString(aad_str.c_str(), aad_str.length()),
        response_alloc
    );
    response_json.AddMember(
        "iv",
        rapidjson::Value().SetString(iv_str.c_str(), iv_str.length()),
        response_alloc
    );
    response_json.AddMember(
        "ciphertext",
        rapidjson::Value().SetString(ciphertext_str.c_str(), ciphertext_str.length()),
        response_alloc
    );
    response_json.AddMember(
        "tag",
        rapidjson::Value().SetString(tag_str.c_str(), tag_str.length()),
        response_alloc
    );
    response_json.AddMember(
        "key",
        rapidjson::Value().SetString(
            hsm_aes_key_value_enc_b64.c_str(),
            hsm_aes_key_value_enc_b64.length()
        ),
        response_alloc
    );
    response_json.AddMember(
        "signature",
        rapidjson::Value().SetString(
            response_message_signature_str.c_str(),
            response_message_signature_str.length()
        ),
        response_alloc
    );

    rapidjson::StringBuffer response_buffer;
    rapidjson::Writer<rapidjson::StringBuffer> response_writer(response_buffer);
    response_json.Accept(response_writer);

    return response_buffer.GetString();
}
