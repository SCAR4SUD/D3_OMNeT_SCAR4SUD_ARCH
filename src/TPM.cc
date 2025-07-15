#include "TPM.h"

#include "crypto_utils/crypto_utils.h"
#include <fstream>
#include <string>
#include <cstring>

TPM::TPM(int id) {
    std::string path = "tpm_storage/ecu" + std::to_string(id) + "/ecu" + std::to_string(id) +"_private.pem";
    init_keys(path.c_str(), ecu_priv_key);
    path = "tpm_storage/ecu" + std::to_string(id) + "/hsm_public.pem";
    init_public_keys(path.c_str(), hsm_pub_key);

    if(ecu_priv_key == nullptr)
        std::cout << "[Error] private key has not been retrieved" << std::endl;
    if(hsm_pub_key == nullptr)
        std::cout << "[Error] public key has not been retrieved" << std::endl;

    if(id >= 7) {
        std::fstream file_public(
            "tpm_storage/ecu" + std::to_string(id) + "/self_aes256.pem",
            std::ios::in
        );

        std::string self_key_b64;
        std::getline(file_public, self_key_b64);

        std::cout << "self_key_b64: " << self_key_b64 << std::endl;

        base64_decode(self_key_b64, aes_self_key, AES_KEY_LEN);
    }
}

EVP_PKEY* TPM::getPrivateKey()
{
    return ecu_priv_key;
}

EVP_PKEY* TPM::getPublicKey(std::string key_label)
{
    if(key_label == "hsm")
        return hsm_pub_key;
    else
        return nullptr;
}

unsigned char* TPM::getSessionKeyHandle(unsigned int key_id)
{
    if(key_id >= MAX_ECU_NUM)
        return nullptr;
    if(key_id == 0)
        return aes_hsm_key;
    return aes_ecu_session_keys[key_id];
}

TPM::~TPM() {
}

