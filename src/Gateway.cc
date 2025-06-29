#include "Gateway.h"
#include "Packet_m.h"
#include "def.h"
#include <tuple>

#include "common/common.h"

#define CLOCK_INTERVAL 5

Define_Module(Gateway);

void Gateway::initialize()
{
    numECUs = par("numECUs");
    isStorageActive = true;
    loadFilterRules();

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
        // std::cout << "from: " << doc["from"].GetInt() << "\t\tto: " << doc["to"].GetInt() << std::endl;

        approved_routes[{doc["from"].GetInt(), doc["to"].GetInt()}] = doc["route"].GetBool();
    }




    whitelist_file.close();
    return true;
}

void Gateway::handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;
    if(approved_routes[{pkg->getSrcId(), pkg->getDstId()}] != true) {
        std::cout << "TYPE: " << pkg->getType();
        std::cout << "\tBLOCKED: " << pkg->getSrcId() << ", " << pkg->getDstId() << std::endl;
        delete msg;
        return;
    }
/*
    cGate *store_gate = gate("ecuOut", 6)->getNextGate();
    if(pkg->getDstId() == 7) {
        Packet *pkt_dup = pkg->dup();
        pkt_dup->setDstId(8);
        // EV << "[INFO] Storage 1 is unreachable" << std::endl;
        scheduleAt(simTime(), pkt_dup);
        if(!store_gate->isConnected())
            delete msg;
    }*/
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
            checkPong(msg, pkg);
            }break;
        case GATEWAY_ROUTE_UPDATE: {
            send(msg, "toHsm", pkg->getDstId()-1);
            std::cout << "GATEWAY_ROUTE_UPDATE" << std::endl;
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
void Gateway::checkStorage(cMessage *msg, Packet *pkg){
    if(1){
        cMessage *dup_msg = msg->dup();
        Packet *pkg_dup = (Packet *) msg;
        pkg_dup->setDstId(pkg->getDstId()+1);
        scheduleAt(simTime(), dup_msg);
        send(msg, "ecuOut", pkg->getDstId()-1);
        send(dup_msg, "ecuOut", pkg_dup->getDstId()-1);
    }else{
        pkg->setDstId(8);
        send(msg, "ecuOut", pkg->getDstId()-1);
    }
}
void Gateway::checkPong(cMessage *msg, Packet *pkg){
    std::string value = "true";
    if(pkg->getData() == value){
        pkg->setType(PING_MSG);
        send(msg, "ecuOut", pkg->getDstId()-1);
    } else {
        isStorageActive = false;
        pkg->setDstId(8);
        send(msg, "ecuOut", pkg->getDstId()-1);
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
    std::cout << "from: " << doc["from"].GetInt() << "\t\tto: " << doc["to"].GetInt() << std::endl;

    approved_routes[{doc["from"].GetInt(), doc["to"].GetInt()}] = doc["route"].GetBool();
}

void Gateway::finish()
{

}
