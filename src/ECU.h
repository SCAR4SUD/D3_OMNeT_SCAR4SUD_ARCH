#ifndef __PROGETTO_ECU_H_
#define __PROGETTO_ECU_H_

#include "def.h"
#include <omnetpp.h>
#include <chrono>
#include <tuple>
#include <unordered_map>
#include "Packet_m.h"
#include "common/common.h"

#include "TPM.h"
#include "clock/Clock.h"

using namespace omnetpp;

// structure that makes it possible to index the map used to store used nonces
struct TupleHash {
    template <class T1, class T2>
    std::size_t operator()(const std::tuple<T1, T2>& t) const {
        auto h1 = std::hash<T1>{}(std::get<0>(t));
        auto h2 = std::hash<T2>{}(std::get<1>(t));

        return h1 ^ (h2 << 1); // Simple XOR and shift for combination
    }
};

/* class describing the ECU network nodes */
class ECU : public cSimpleModule
{
protected:
    int id;                                 // the ECU id
    int numECUs;                            // number of ECUs on the network
    Packet *HSMCommunicationInit;           // when to begin key exchange process with HSM
    Packet *ClockSyncSignal;                // self message to synchronize internal clock
    Packet *SendDataSignal;                 // testing signal, on its arrival it sends data to demonstrate storing functionality
    Packet *RetriveDataSignal;
    bool isUp = true;                       // is the ECU functioning? used to simulate storage device failure.

    unsigned int id_active_storage;         // variable holding the 'preferred' data storage ECU id

    TPM *tpm_access = nullptr;              // reference to the simulated TPM chip
    Clock hw_clock;                         // simulated internal hardware clock

    bool hsm_connection_active = false;     // set to true when a common session key is agreed with the HSM
    bool *isECUAuth;                        // set to true when a common session key is agreed with another ECU and
                                            // they have been reciprocally authenticated
    std::time_t *timestamp_challenge;       // where timestamp(nonces) to check for ns challenge

    void sendHsmRsaRequest();               // function for sending session key request to HSM via RSA encryption
    bool setHsmSessionKey(Packet *pkg);     // function for parsing and verifying response to session key request

    void sendEcuSessionRequest(int dst);    // function for sending session key request to another ECU via ns with HSM
    bool handleEcuSessionKey(Packet *pkg);  // function for parsing response to sendEcuSessionRequest
                                            // and sending ns 'ticket' to other ECU
    bool handleEcuTicket(Packet *pkg);      // function for parsing session key 'ticket' sent by other ECU

    void sendChallenge(int other_ecu_id);   // function for sending ns challenge to other ECU
    void acceptChallenge(Packet *pkg);      // function for parsing ns challenge and sending response to
    bool checkChallenge(Packet *pkg);       // function for parsing and verifying that the challenge has been completed

    void sendClockSyncRequest();            // function for clock synchronization sent to the time server (Gateway)
    void handleClockSync(Packet *pkg);      // function for handling the response from the time server (Gateway)

    void sendEncPacket(Packet *pkg, int id, int type);          // function encapsulating the process of sending a
                                                                // message trough the ECU-ECU encrypted channel
    void receiveEncPacket(Packet *pkg, int other_ecu_id);       // function encapsulating the process of receiving a
                                                                // message trough the ECU-ECU encrypted channel

    void sendDataToStorage(Packet *pkg, PrivacyLevel privacyData, stateData data_state);
    void sendRequestToStorage();

    std::string get_current_timestamp_iso8601();                // function for getting the timestamp in the ISO format

    inline std::string stateToString(stateData currentState){
        switch(currentState){
        case stateData::DATI_ANAGRAFICI: return "DATI_ANAGRAFICI";
        case stateData::PREFERENZE_UTENTE: return "PREFERENZE_UTENTE";
        case stateData::DATO_TEMPORALE: return "DATO_TEMPORALE";
        case stateData::PREFERENZE_AUTOVETTURA: return "PREFERENZE_AUTOVETTURA";
        case stateData::NON_CATEGORIZZATO: return "NON_CATEGORIZZATO";
        default: return "ERROR_SCONOSCIUTO";
        }
    }
    void setStorageStatusDown(int id);      // sets the status of a storage device as down

    std::string *timestamp_b64;
    std::time_t timestamp_hsm;
    std::unordered_map<std::tuple<std::time_t, int>, bool, TupleHash> used_nonces_rsa;  // structure holding used rsa messages nonces
    std::unordered_map<std::tuple<std::time_t, int>, bool, TupleHash> used_nonces_ns;   // structure holding used ns messages nonces

    /* initialization processing functions */
    virtual void initialize() override;
    virtual void additional_initialize() {};                // used to add behavior on specialized ECU classes

    /* event processing functions */
    virtual void handleMessage(cMessage *msg) override;
    virtual void additional_handleMessage(cMessage *msg);   // used to add behavior on specialized ECU classes

    /* used for cleaning at the end of the simulation */
    virtual void finish() override;
};

#endif
