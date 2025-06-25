#include "Gateway.h"
#include "Packet_m.h"
#include "def.h"

#include "common/common.h"

#define CLOCK_INTERVAL 5

Define_Module(Gateway);

void Gateway::initialize()
{
    numECUs = par("numECUs");
}

void Gateway::handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;
    int type = pkg->getType();
    switch(type) {
        case RSA_REQUEST: {
            send(msg, "toHsm");
            }break;
        case RSA_RESPONSE: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case NS_REQUEST: {
            send(msg, "toHsm");
            }break;
        case NS_RESPONSE_SENDER: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case NS_RESPONSE_RECEIVER: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case CLOCK_SYNC_REQUEST: {
            send(msg, "toHsm");
            }break;
        case CLOCK_SYNC_RESPONSE: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        default: {
            if(pkg->getDstId() != 0) {
                send(msg, "ecuOut", pkg->getDstId()-1);
            }else {
                send(msg, "toHsm");
            }
            }break;
    }
}

void Gateway::finish()
{

    // Chiudo il file di log
    if (logFile.is_open()) {
        logFile.close();
        EV << "[Gateway] Chiuso events.log\n";
    }
}
