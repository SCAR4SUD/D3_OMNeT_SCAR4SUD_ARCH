#ifndef SCAR_DEF_H
#define SCAR_DEF_H

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

#define REQUEST_STORAGE                 9 //Richiesta di storage
#define REQUEST_STORAGE_DATA            10 //Richiesta di dati
#define STORAGE_RETRIEVE_DATA           11 //Ritorno dei dati
#define STORAGE_ACK                     12
#define STORAGE_NACK                    13

//Ping Gateway<->Storage
#define PING_MSG                        100
#define PONG_MSG                        101
#define CLEAN_UP_EVENT                  102

#define BUFFER_SIZE                     8192
#define EPSILON_SECONDS                 15

#define GATEWAY_ROUTE_UPDATE            201
#define GATEWAY_ROUTE_UPDATE_INTERNAL   202


#define PRIVATE_DATA                    1
#define PUBLIC_DATA                     0
typedef int PrivacyLevel;

#endif

