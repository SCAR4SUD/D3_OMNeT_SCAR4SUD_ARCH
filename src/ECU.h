#ifndef __PROGETTO_ECU_H_
#define __PROGETTO_ECU_H_

#include "def.h"
#include <omnetpp.h>
#include <chrono>
#include "Packet_m.h"
#include "common/common.h"

#include "TPM.h"
#include "clock/Clock.h"

using namespace omnetpp;

class ECU : public cSimpleModule
{
protected:
    int id;                         // ECU id
    int numECUs;                    // numero totale di ECU
    Packet *HSMCommunicationInit;   // timer per inviare il prossimo messaggio
    Packet *ClockSyncSignal;
    bool isUp = true;

    TPM *tpm_access = nullptr;
    Clock hw_clock;

    enum stateData{
        DATI_ANAGRAFICI,
        PREFERENZE_UTENTE,
        DATO_TEMPORALE,
        PREFERENZE_AUTOVETTURA,
        NON_CATEGORIZZATO
    };

    stateData stateOfData;

    bool hsm_connection_active = false;
    bool *isECUAuth;
    std::time_t *timestamp_challenge;

    void sendHsmRsaRequest();
    bool setHsmSessionKey(Packet *pkg);

    bool handleEcuSessionKey(Packet *pkg);
    void sendEcuSessionRequest(int dst);
    bool handleEcuTicket(Packet *pkg);

    void sendEcuAuthenticartion();
    void sendClockSyncRequest();

    void sendEncPacket(Packet *pkg, int id, int type);
    void receiveEncPacket(Packet *pkg, int other_ecu_id);

    void sendChallenge(int other_ecu_id);
    void acceptChallenge(Packet *pkg);
    bool checkChallenge(Packet *pkg);

    void sendDataToStorage(Packet *pkg, PrivacyLevel privacyData);
    void retrieveDataFromStorage(Packet *pkg, PrivacyLevel privacyData);
    //Funzione per ottenere il timestampo iso
    std::string get_current_timestamp_iso8601();
    //funzione di supporto enum
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

    void handleClockSync(Packet *pkg);

    void sendEncrypted(Packet *pkg, const unsigned char *key);

    std::string *timestamp_b64;

    virtual void initialize() override;
    virtual void additional_initialize() {};

    virtual void handleMessage(cMessage *msg) override;
    virtual void additional_handleMessage(cMessage *msg);
    virtual void finish() override;
};

#endif
