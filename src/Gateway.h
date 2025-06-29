#ifndef __PROGETTO_GATEWAY_H_
#define __PROGETTO_GATEWAY_H_

#include <omnetpp.h>
#include <fstream>
#include <map>
#include "common/common.h"
#include "Communication_m.h"   // contiene Request, KeyRequest, KeyResponse
#include "Request_m.h"
#include "Packet_m.h"
#include <tuple>
#include <unordered_map>
using namespace omnetpp;

struct TupleHash {
    template <class T1, class T2>
    std::size_t operator()(const std::tuple<T1, T2>& t) const {
        auto h1 = std::hash<T1>{}(std::get<0>(t));
        auto h2 = std::hash<T2>{}(std::get<1>(t));

        return h1 ^ (h2 << 1); // Simple XOR and shift for combination
    }
};

class Gateway : public cSimpleModule
{
private:
    int numECUs;
    bool isStorageActive;
    std::unordered_map<std::tuple<int, int>, bool, TupleHash> approved_routes;


protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    void checkStorage(cMessage *msg, Packet *pkg);
    void checkPong(cMessage *msg, Packet *pkg);

    bool loadFilterRules();
    void updateRule(Packet *pkg);

    virtual void finish() override;
};

#endif
