#ifndef SCAR_DEF_H
#define SCAR_DEF_H

#include <string>

enum stateData{
    PERSONAL_DATA,
    USER_PREFERENCES,
    TEMPORAL_DATA,
    VEHICLE_PREFERENCES,
    UNCATEGORIZED
};

inline std::string stateToString(stateData currentState){
    switch(currentState){
    case stateData::PERSONAL_DATA: return "PERSONAL_DATA";
    case stateData::USER_PREFERENCES: return "USER_PREFERENCES";
    case stateData::TEMPORAL_DATA: return "TEMPORAL_DATA";
    case stateData::VEHICLE_PREFERENCES: return "VEHICLE_PREFERENCES";
    case stateData::UNCATEGORIZED: return "UNCATEGORIZED";
    default: return "ERROR_UNKNOWN";
    }
}

#define HSM_TOPOLOGICAL_ID              0
#define INFOTAINMENT_ID                 4

#define ECU_INIT_RSA_SIGNAL             301
#define ECU_INIT_CLOCK_SYNC             302
#define ECU_SEND_DATA_SIGNAL            303

#define RSA_REQUEST                     0
#define RSA_RESPONSE                    1

#define NS_REQUEST                      2
#define NS_RESPONSE_SENDER              3
#define NS_RESPONSE_RECEIVER            4
#define NS_CHALLENGE_REQUEST            5
#define NS_CHALLENGE_RESPONSE           6
#define NS_AUTH_REQUEST                 5
#define NS_AUTH_RESPONSE                6
#define CLOCK_SYNC_REQUEST              7
#define CLOCK_SYNC_RESPONSE             8

#define REQUEST_STORAGE                 9
#define REQUEST_STORAGE_DATA            10
#define STORAGE_RETRIEVE_DATA           11
#define STORAGE_ACK                     12
#define STORAGE_NACK                    13
#define STORAGE_DOWN                    14
#define STORAGE_RETRIEVE_DATA_ERROR     15
#define STORAFE_DELETE_DATA_ERROR       16

//Ping Gateway<->Storage
#define PING_MSG                        100
#define PONG_MSG                        101
#define CLEAN_UP_EVENT                  102

#define BUFFER_SIZE                     8192
#define EPSILON_SECONDS                 15

#define GATEWAY_ROUTE_UPDATE            201
#define GATEWAY_ROUTE_UPDATE_INTERNAL   202
#define STORAGE_ECU_DOWN                203

#define STORAGE_ERROR                   600

#define STORAGE_WRITE                   601
#define STORAGE_EDIT                    602
#define STORAGE_DELETE                  603

#define STORAGE_DELETE_USER             604

#define STORAGE_DATA_ACCESS             605
#define STORAGE_DATA_ACCESS_PORTABLE    606

#define STORAGE_DATA_EXPORT_23          607


#define PUBLIC_DATA                     0
#define PRIVATE_DATA                    1
typedef int PrivacyLevel;

#define UNSPECIFIED_STORE               -1

#define INFOTAINMENT_ECU                4
#define PRIMARY_STORAGE                 7
#define SECONDARY_STORAGE               8

#endif

