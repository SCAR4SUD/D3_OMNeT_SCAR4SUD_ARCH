#ifndef __PROGETTO_HSM_H_
#define __PROGETTO_HSM_H_

#include <omnetpp.h>
#include <string>
#include "Communication_m.h"
#include "Packet_m.h"
#include "include/rapidjson/document.h"
#include "include/sca.h"


using namespace omnetpp;

class HSM : public cSimpleModule
{
private:
    void sendRequestToHSM(Packet *pkg, int response_type, const char* ret_pkg_name);
    std::string clock_response(rapidjson::Document& doc, sca::Session& session, int id);
    std::string route_response(rapidjson::Document& doc, sca::Session& session);

    sca::HSM *hsm = sca::HSM::get();
    sca::Slot *slot = hsm->getSlot(0);
    sca::Session session = sca::Session();
    int numECUs;

    bool *sessionKeyWith;

protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;

};


#endif
