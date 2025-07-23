#include "Gateway.h"
#include "Packet_m.h"
#include "def.h"
#include <tuple>

#include "common/common.h"

#define CLOCK_INTERVAL 5
#define GATEWAY_STORAGE_SELF_PONG -2

Define_Module(Gateway);

void Gateway::initialize()
{
    numECUs = par("numECUs");
    isStorageActive = true;
    loadFilterRules();

    pending_ping = new bool[numECUs];
    memset(pending_ping, false, numECUs);

    self = new Packet("SELF_PONG_CHECK");

    ping_reminder = new Packet("PERIODIC_PING");
    ping_reminder->setSrcId(-2);
    ping_reminder->setDstId(-2);
    // scheduleAt(simTime()+5, ping_reminder);
}

bool Gateway::loadFilterRules()
{
    std::string path = "storage/hsm/whitelist.rules";
    std::ifstream whitelist_file(path);
    if (!whitelist_file.is_open()) {
        std::cerr << "[ERROR] Infotainment: failed to retrieve whitelist file" << std::endl;
        return false;
    }

    rapidjson::Document doc;

    int line_count = 0;
    std::string line;
    while(getline(whitelist_file, line)) {
        if (
            doc.Parse(line.c_str()).HasParseError() ||
            !doc.HasMember("from")                  || !doc["from"].IsInt()         ||
            !doc.HasMember("to")                    || !doc["to"].IsInt()           ||
            !doc.HasMember("route")                 || !doc["route"].IsBool()

        ) {
            std::cerr << "[ERROR] Gateway: rule at line " << ++line_count << " has not been parsed correctly" << std::endl;
            continue;
        }

        approved_routes[{doc["from"].GetInt(), doc["to"].GetInt()}] = doc["route"].GetBool();
    }




    whitelist_file.close();
    return true;
}

void Gateway::handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;

    EV << "\033[36m[Gateway] packet \"" << pkg->getName() << "\"(" << pkg->getType() << "):\t\t" \
            << pkg->getSrcId() << " -> " << pkg->getDstId() << "\033[0m" << std::endl;

    if(approved_routes[{pkg->getSrcId(), pkg->getDstId()}] != true) {
        EV << "[Gateway] blocked message: \"" << pkg->getName() <<"\" with source: " << pkg->getSrcId() << " and destination: " \
            << ((pkg->getDstId() == -1) ? "Gateway" : std::to_string(pkg->getDstId())) << std::endl;
        delete msg;
        return;
    }

    if(pkg == ping_reminder) {
        sendStoragePing(7);
        sendStoragePing(8);
        scheduleAt(simTime()+5, ping_reminder);
        return;
    }

    if(pkg->getDstId() == 7 || pkg->getDstId() == 8) {
        sendStoragePing(pkg->getDstId());
    }

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
        case REQUEST_STORAGE: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case REQUEST_STORAGE_DATA: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case STORAGE_RETRIEVE_DATA: {
            send(msg, "ecuOut", pkg->getDstId()-1);
            }break;
        case PONG_MSG: {
            // std::cout << "[Gateway] cheking pong message" << std::endl;
            if(pkg->getDstId() != GATEWAY_STORAGE_SELF_PONG)
                pending_ping[pkg->getSrcId()-1] = false;
                checkStoragePong(pkg->getSrcId());
            }break;
        case GATEWAY_ROUTE_UPDATE: {
            send(msg, "toHsm", pkg->getDstId()-1);
            }break;
        case GATEWAY_ROUTE_UPDATE_INTERNAL: {
            updateRule(pkg);
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

void Gateway::sendStoragePing(int dst_id) {
    Packet *ping = new Packet("GATEWAY_PING");

    ping->setDstId(dst_id);     // destination set but not logically used for forwarding
    ping->setSrcId(-1);         // message not sent from a node
    ping->setData(nullptr);     // the ping packet has no payload
    ping->setType(PING_MSG);    // type of ping message is PING_MSG

    send(ping, "ecuOut", dst_id-1);
    pending_ping[dst_id-1] = true;

    self->setType(PONG_MSG);
    self->setSrcId(dst_id);
    self->setDstId(GATEWAY_STORAGE_SELF_PONG);
    scheduleAt(simTime() + 1, self->dup());

    return;
}

void Gateway::checkStoragePong(int src_id){
    if(pending_ping[src_id-1] == false) {
        EV << "[Gateway] received store (ECU " << src_id << ") pong" << std::endl;
        return;
    }

    EV << "[Gateway] a storage device has failed" << std::endl;
    sendBroadcastStorageDownSignal(src_id);

    return;
}

void Gateway::sendBroadcastStorageDownSignal(int storage_id) {
    EV << "[Gateway] sending broadcast down signal" << std::endl;
    Packet *broadcast_message = new Packet("STORAGE_DOWN_SIGNAL");

    broadcast_message->setSrcId(-1);
    broadcast_message->setType(STORAGE_DOWN);
    broadcast_message->setData(std::to_string(storage_id).c_str());

    for(int i = 0; i < numECUs; ++i ) {

        Packet *to_send = broadcast_message->dup();
        to_send->setDstId(i+1);
        EV << "\033[36m[Gateway] packet \"" << to_send->getName() << "\"(" << to_send->getType() << "):\t\t" \
                    << to_send->getSrcId() << " -> " << to_send->getDstId() << "\033[0m" << std::endl;

        send(to_send, "ecuOut", i);
    }
}

void Gateway::updateRule(Packet *pkg)
{
    rapidjson::Document doc;

    std::string line = pkg->getData();


    if (
        doc.Parse(line.c_str()).HasParseError() ||
        !doc.HasMember("from")                  || !doc["from"].IsInt()         ||
        !doc.HasMember("to")                    || !doc["to"].IsInt()           ||
        !doc.HasMember("route")                 || !doc["route"].IsBool()

    ) {
        std::cerr << "[ERROR] Gateway: updated rule has not been parsed correctly" << std::endl;
        return;
    }

    approved_routes[{doc["from"].GetInt(), doc["to"].GetInt()}] = doc["route"].GetBool();
}

void Gateway::finish()
{

}
