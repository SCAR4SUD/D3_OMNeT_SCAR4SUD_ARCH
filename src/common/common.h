#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <cstring>
#include <fstream>
#include <cstdio>
#include <iostream>
#include "../include/rapidjson/document.h"
#include "../include/rapidjson/stringbuffer.h"
#include "../include/rapidjson/writer.h"
#include "../include/rapidjson/error/en.h"
#include <openssl/err.h>
#include "../def.h"

#define ECUID_LEN 8
#define AES_KEY_LEN 32
#define MAX_ECU_NUM 128



//extern unsigned char aes_hsm_key[AES_KEY_LEN];


enum MessageType : unsigned char {
    AES_COMMUNICATION = 0
};

void handle_errors(const std::string& context);  


#endif
