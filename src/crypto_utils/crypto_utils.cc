#include "crypto_utils.h"

const char* ECU_PRIVKEY_PATH = "keys/ecu_private.pem";
EVP_PKEY* ecu_privkey = nullptr;

void random_nonce(unsigned char* nonce, size_t len) {
    if (RAND_bytes(nonce, len) != 1) handle_errors("generating nonce failed");
}

void init_keys(const char* path, EVP_PKEY*& ecu_priv_key) {
    FILE* f_priv = fopen(path, "r");
    if (!f_priv) handle_errors("opening private key");
    ecu_priv_key = PEM_read_PrivateKey(f_priv, nullptr, nullptr, nullptr);
    fclose(f_priv);
    if (!ecu_priv_key) handle_errors("reading private key");
}

void init_public_keys(const char* path, EVP_PKEY*& ecu_publ_key) {
    FILE* f_publ = fopen(path, "r");
    if (!f_publ) handle_errors("opening public key");
    ecu_publ_key = PEM_read_PUBKEY(f_publ, nullptr, nullptr, nullptr);
    fclose(f_publ);
    if (!ecu_publ_key) handle_errors("reading public keys");
}

int rsa_encrypt_evp(EVP_PKEY* pubkey, const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext, size_t* ciphertext_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    if (!ctx) handle_errors("allocating EVP_PKEY_CTX");

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        handle_errors("encrypt_init");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        handle_errors("padding");

    if (EVP_PKEY_encrypt(ctx, nullptr, ciphertext_len, plaintext, plaintext_len) <= 0)
        handle_errors("encrypt (len)");

    if (EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) <= 0)
        handle_errors("encrypt (data)");

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int rsa_decrypt_evp(EVP_PKEY* privkey, const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext, size_t* plaintext_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    if (!ctx) handle_errors("allocating EVP_PKEY_CTX (decrypt)");

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handle_errors("decrypt_init");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        handle_errors("padding decrypt");

    if (EVP_PKEY_decrypt(ctx, nullptr, plaintext_len, ciphertext, ciphertext_len) <= 0)
        handle_errors("decrypt (len)");

    int res = EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);
    if (res <= 0) {
        handle_errors("decrypt (data)");
        return res;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

unsigned char* rsa_sign_evp (
    const unsigned char* data,
    size_t data_len,
    EVP_PKEY* private_key_evp,
    size_t* signature_len
) {
    const EVP_MD* md_algorithm = EVP_sha256();
    int rsa_padding_mode = RSA_PKCS1_PADDING;

    unsigned char* signature = NULL;
    EVP_MD_CTX* md_ctx = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    size_t temp_sig_len = 0;

    if (private_key_evp == NULL) {
        std::cerr << "Error: EVP_PKEY private key is NULL." << std::endl;
        goto cleanup;
    }
    if (md_algorithm == NULL) {
        std::cerr << "Error: Message digest algorithm is NULL." << std::endl;
        goto cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        std::cerr << "Error: Failed to create EVP_MD_CTX for hashing." << std::endl;
        goto cleanup;
    }

    if (EVP_DigestInit_ex(md_ctx, md_algorithm, NULL) != 1) {
        std::cerr << "Error: EVP_DigestInit_ex failed." << std::endl;
        goto cleanup;
    }

    if (EVP_DigestUpdate(md_ctx, data, data_len) != 1) {
        std::cerr << "Error: EVP_DigestUpdate failed." << std::endl;
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed." << std::endl;
        goto cleanup;
    }

    pkey_ctx = EVP_PKEY_CTX_new(private_key_evp, NULL);
    if (pkey_ctx == NULL) {
        std::cerr << "Error: Failed to create EVP_PKEY_CTX for signing." << std::endl;
        goto cleanup;
    }

    if (EVP_PKEY_sign_init(pkey_ctx) != 1) {
        std::cerr << "Error: EVP_PKEY_sign_init failed." << std::endl;
        goto cleanup;
    }

    if (EVP_PKEY_id(private_key_evp) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, rsa_padding_mode) != 1) {
            std::cerr << "Error: Failed to set RSA padding mode." << std::endl;
            goto cleanup;
        }
        if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, md_algorithm) != 1) {
            std::cerr << "Error: Failed to set signature message digest." << std::endl;
            goto cleanup;
        }
    }

    if (EVP_PKEY_sign(pkey_ctx, NULL, &temp_sig_len, digest, digest_len) != 1) {
        std::cerr << "Error: EVP_PKEY_sign (size determination) failed." << std::endl;
        goto cleanup;
    }

    signature = (unsigned char*)OPENSSL_malloc(temp_sig_len);
    if (signature == NULL) {
        std::cerr << "Error: Failed to allocate memory for signature." << std::endl;
        goto cleanup;
    }

    // Perform the actual signing
    if (EVP_PKEY_sign(pkey_ctx, signature, &temp_sig_len, digest, digest_len) != 1) {
        std::cerr << "Error: EVP_PKEY_sign failed." << std::endl;
        OPENSSL_free(signature); // Free on failure
        signature = NULL;
        goto cleanup;
    }

    *signature_len = temp_sig_len; // Set the actual signature length

cleanup:
    // Clean up allocated OpenSSL objects
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);

    return signature; // Return the dynamically allocated signature (or NULL on failure)
}

bool check_signature(unsigned char* plain_data, size_t plain_data_len, unsigned char *signature, size_t signature_len, EVP_PKEY* public_key)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create MD context" << std::endl;
        //EVP_PKEY_free(public_key);
        return false;
    }

    bool result = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha512(), nullptr, public_key) == 1) {
        // Update with data
        if (EVP_DigestVerifyUpdate(ctx, plain_data, plain_data_len) == 1) {
            // Verify signature
            int verifyResult = EVP_DigestVerifyFinal(ctx, signature, signature_len);
            if (verifyResult == 1) {
                result = true;  // Valid signature
            } else if (verifyResult == 0) {
                result = false; // Invalid signature
            } else {
                std::cerr << "Signature verification error" << std::endl;
                ERR_print_errors_fp(stderr);
            }
        } else {
            std::cerr << "Failed to update digest" << std::endl;
        }
    } else {
        std::cerr << "Failed to initialize digest verification" << std::endl;
    }

    // Cleanup
    EVP_MD_CTX_free(ctx);
    //EVP_PKEY_free(public_key);

    return result;
}

std::string base64_encode(const unsigned char* input, size_t len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, len);
    BIO_flush(b64);
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(b64, &buffer_ptr);
    std::string encoded(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(b64);
    return encoded;
}

size_t base64_decode(const std::string& input, unsigned char* output, size_t max_len) {
    BIO* bio = BIO_new_mem_buf(input.c_str(), input.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_len = BIO_read(bio, output, max_len);
    BIO_free_all(bio);
    if (decoded_len <= 0) {
        handle_errors("Error while encoding in Base64");
    }
    if (static_cast<size_t>(decoded_len) > max_len) {
        handle_errors("Base 64 decoding, buffer too small");
    }
    return static_cast<size_t>(decoded_len);
}

