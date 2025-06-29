#ifndef __PROGETTO_STORAGE_H_
#define __PROGETTO_STORAGE_H_

#include <string>
#include <omnetpp.h>
#include "ECU.h"
#include <fstream>
#include <map>
#include <string>
#include "Packet_m.h"
#include <filesystem>
#include "aes/aes.h"
#include "crypto_utils/crypto_utils.h"
#include "def.h"
using namespace omnetpp;

class Storage : public ECU
{
  protected:
    //Id ECU
    int id;
    int real_id;
    //Funzioni sovrascritte lasciando quelle originali non toccate
    virtual void additional_initialize() override;
    virtual void additional_handleMessage(cMessage *msg) override;

    //funzioni per le funzionalità dello storage
    void storeData(Packet *package);
    void pingWithGateway(Packet *package);
    Packet *readDataFile(Packet *package);
    void cleanupLogFile(int ecuId, const std::string& type);
    void initFailureState();

    virtual void finish() override;


  private:
    //map per i file txt
    std::map<int, std::fstream> privateFileStreams;
    std::map<int, std::fstream> publicFileStreams;

    simtime_t checkInterval;    // Intervallo di tempo tra i controlli
    simtime_t dataLifetime;     // Durata massima di un dato prima che scada
    Packet *cleanupEvent = nullptr; // Messaggio per l'autoprogrammazione
    Packet *failureEvent = nullptr; // Messaggio per l'autoprogrammazione


    int numEcu;
};

#endif
