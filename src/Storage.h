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
    int numECUs;

    virtual void additional_initialize() override;
    virtual void additional_handleMessage(cMessage *msg) override;

    void storeData(Packet *package);
    void pingWithGateway(Packet *package);

    Packet *readDataFile(Packet *package);
    void cleanupLogFile(int ecuId, const std::string& type);
    void initFailureState();

    virtual void finish() override;


  private:
    //map per i file txt
    std::map<int, std::string> privateFilePath;
    std::map<int, std::string> publicFilePath;

    simtime_t checkInterval;
    simtime_t dataLifetime;
    Packet *cleanupEvent = nullptr;
    Packet *failureEvent = nullptr;


};

#endif
