#ifndef SRC_TPM_H_
#define SRC_TPM_H_

#include "common/common.h"

class TPM {
private:
    EVP_PKEY* ecu_priv_key{nullptr};
    EVP_PKEY* hsm_pub_key{nullptr};
    unsigned char aes_hsm_key[AES_KEY_LEN];
    unsigned char aes_ecu_session_keys[MAX_ECU_NUM][AES_KEY_LEN];

    unsigned char aes_self_key[AES_KEY_LEN];

public:
    TPM(int id);
    virtual ~TPM();
    EVP_PKEY* getPrivateKey();
    EVP_PKEY* getPublicKey(std::string key_label);
    unsigned char *getSelfKey() { return aes_self_key; }
    unsigned char *getSessionKeyHandle(unsigned int key_id);
};

#endif /* SRC_TPM_H_ */
