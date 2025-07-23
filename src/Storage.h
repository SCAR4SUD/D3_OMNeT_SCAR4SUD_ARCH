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

struct RetentionPolicy
{
    std::time_t min_retention_s; // tempo minimo di conservazione in secondi
    std::time_t max_retention_s; // tempo massimo di conservazione in secondi
};

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
    Packet *exportDataUser(Packet *packet);

    void deleteData(int ecuId, int source_id, const int& type, const std::string& name,  bool ignore_min_retention = false);
    Packet* deleteUserData(Packet *packet);

    void cleanUpFile(int ecuId, const std::string& type);
    void initFailureState();
    void initialize_retention_policies();

    virtual void finish() override;


  private:
    //map per i file txt
    std::map<int, std::string> privateFilePath;
    std::map<int, std::string> publicFilePath;
    std::map<stateData, RetentionPolicy> data_retention_policies;

    simtime_t checkInterval;
    unsigned int dataLifetime;
    Packet *cleanupEvent = nullptr;
    Packet *failureEvent = nullptr;


};

#endif
