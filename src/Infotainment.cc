#include "Infotainment.h"
#include "Communication_m.h"
#include "Packet_m.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <openssl/rand.h>
#include <ctime>
#include <fstream>

#include "def.h"
#include "rsa/rsa_exchange.h"
#include "ns/ns_exchange.h"
#include "aes/aes.h"
#include "crypto_utils/crypto_utils.h"

Define_Module(Infotainment);

void Infotainment::additional_initialize()
{
    loadFilterRules();

    std::string email = "mario.rossi@provider.com";
    std::string password = "secure_password";
    std::string hashed_password = hash_password(password);


    // pre-installed user for testing gdpr compliance
    user_data_store[{email, hashed_password}] = 1001;

    gdpr_test = new Packet("SELF_GDPR_REQUEST_TEST");
    gdpr_test->setData("15");
}

bool Infotainment::loadFilterRules()
{
    std::string path = "storage/ecu" + std::to_string(id) + "/whitelist.rules";
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
            doc.Parse(line.c_str()).HasParseError()     ||
            !doc.HasMember("uri")                       || !doc["uri"].IsString()       ||
            !doc.HasMember("action")                    || !doc["action"].IsString()

        ) {
            std::cerr << "[ERROR] Infotainment: rule at line " << ++line_count << " has not been parsed correctly" << std::endl;
            continue;
        }

        rules[doc["uri"].GetString()] = doc["action"].GetString();
    }


    whitelist_file.close();
    return true;
}

void Infotainment::additional_handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;


    static bool once = true;
    if(hsm_connection_active && once) {
        sendNewRoutingRule(5, 0, false);
        sendNewRoutingRule(6, 0, false);
        once = false;
    }

    if(pkg == SendDataSignal) {
        initialize_sample_data();
        scheduleAt(simTime()+5, gdpr_test);
    }


    if(pkg == gdpr_test) {
        test_gdpr_requests(pkg);
    }


    int type = pkg->getType();
    switch(type) {
        case RSA_RESPONSE:{
            sendEcuSessionRequest(7);
            sendEcuSessionRequest(8);
            }break;
        case NS_CHALLENGE_REQUEST:{
            static bool once = true;
            if(once) {
                once = false;
                scheduleAt(simTime()+3.0, SendDataSignal);
            }
            }break;
        case STORAGE_DOWN:{
            EV << "[Infotainment] request to storage was lost. Resending the request" << std::endl;
            int req_num = std::atoi(gdpr_test->getData());
            std::string data_to_set = std::to_string(req_num-1);
            gdpr_test->setData(data_to_set.c_str());
            }break;
        case STORAGE_DATA_EXPORT_23: {
            receiveEncPacket(pkg, id_active_storage);
            std::ofstream file_export = std::ofstream("storage/ecu" + std::to_string(id) + "/" + pending_email + ".txt", std::ios::out);
            file_export << pkg->getData() << std::endl;
            }break;
        default:
            break;
    }
}

void Infotainment::test_gdpr_requests(Packet *pkg) {
    int gdpr_right_req = std::atoi(pkg->getData());

    std::string email = "mario.rossi@provider.com";
    std::string password = "secure_password";
    std::string hashed_password = hash_password(password);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "email",
        rapidjson::Value().SetString(email.c_str(), email.length()),
        alloc
    );
    store_request.AddMember(
        "hash_password",
        rapidjson::Value().SetString(hashed_password.c_str(), hashed_password.length()),
        alloc
    );
    store_request.AddMember(
        "privacy_level",
        rapidjson::Value().SetString(hashed_password.c_str(), hashed_password.length()),
        alloc
    );
    if(gdpr_right_req == 18) {
        store_request.AddMember(
            "value",
            rapidjson::Value().SetString("true", strlen("true")),
            alloc
        );
        store_request.AddMember(
            "reason",
            rapidjson::Value().SetString("reason_for_change", strlen("reason_for_change")),
            alloc
        );
    }
    if(gdpr_right_req == 21 || gdpr_right_req == 22) {
        store_request.AddMember(
            "value",
            rapidjson::Value().SetString("false", strlen("false")),
            alloc
        );
        store_request.AddMember(
            "reason",
            rapidjson::Value().SetString("reason_for_change", strlen("reason_for_change")),
            alloc
        );
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);


    EV << "\x1b[34m[Infotainment] GDPR right to exercise: " << gdpr_right_req << "\x1b[0m" << std::endl;

    GDPR_request_handler(gdpr_right_req, buffer.GetString());

    gdpr_right_req++;
    if(gdpr_right_req == 19) gdpr_right_req++;

    pkg->setData(std::to_string(gdpr_right_req).c_str());
    if(gdpr_right_req > 23) return;
    if(gdpr_right_req == 17) scheduleAt(simTime()+4, pkg);
    else scheduleAt(simTime()+2, pkg);
}

void Infotainment::sendNewRoutingRule(int src, int dst, bool isAccepted)
{
    Packet *pkg = new Packet("GATEWAY_ROUTE_UPDATE");

    std::string rule =  "{\"from\":" +
                        std::to_string(src) +
                        ", \"to\":" +
                        std::to_string(dst) +
                        ", \"route\":" +
                        ((isAccepted) ? "true" : "false") +
                        "}";

    pkg->setSrcId(id);
    pkg->setDstId(HSM_TOPOLOGICAL_ID);
    pkg->setType(GATEWAY_ROUTE_UPDATE);
    pkg->setData(rule.c_str());
    sendEncPacket(pkg, HSM_TOPOLOGICAL_ID, GATEWAY_ROUTE_UPDATE);
}

std::string createTaggedData(std::string value, stateData state, std::string insetion_time) {
    rapidjson::Document doc;
    doc.SetObject();
    auto& alloc = doc.GetAllocator();

    doc.AddMember(
        "value",
        rapidjson::Value().SetString(value.c_str(), value.length()),
        alloc
    );
    doc.AddMember(
        "tag",
        state,
        alloc
    );
    doc.AddMember(
        "insetion_time",
        rapidjson::Value().SetString(insetion_time.c_str(), insetion_time.length()),
        alloc
    );


    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    return buffer.GetString();
}

std::string Infotainment::hash_password(const std::string& password) {
    size_t hashed_val = std::hash<std::string>{}(password + HASH_SALT);
    return std::to_string(hashed_val); // Converti l'hash in stringa per usarlo come chiave
}

void Infotainment::GDPR_request_handler(int gdpr_rigth_req, std::string params_json) {
    rapidjson::Document params;
    // std::cout << "GDPR_request_handler parameters: " << params_json << std::endl;
    if (params.Parse(params_json.c_str()).HasParseError()) {
        handle_errors("invalid json formatted request sent to Infotainment");
        return;
    }


    std::string email = params["email"].GetString();
    std::string hashed_password = params["hash_password"].GetString();

    int user_id = user_data_store[{email, hashed_password}];

    switch(gdpr_rigth_req) {
        case 15: {              // 15. Right of access by the data subject
            handle_article_15_access(user_id);
        }break;
        case 16: {              // 16. Right to rectification
            Packet *pkg = new Packet("DATA_STORE");
            pkg->setSrcId(id);
            pkg->setDstId(id_active_storage);
            pkg->setType(REQUEST_STORAGE);
            std::string data_to_send = createTaggedData("Via dell'anticorso 2, Milano", PERSONAL_DATA, get_current_timestamp_iso8601());
            pkg->setData(data_to_send.c_str());
            handle_article_16_rectification(pkg, email, hashed_password);
        }break;
        case 17: {              // 17. Right to erasure
            handle_article_17_erasure_with_check(email, hashed_password);
        }break;
        case 18: {              // 18. Right to restriction of processing
            Packet *pkg = new Packet("DATA_STORE");
            pkg->setSrcId(id);
            pkg->setDstId(id_active_storage);
            pkg->setType(REQUEST_STORAGE);
            std::string value = params["value"].GetString();
            std::string data_to_send = createTaggedData(value + "," + params["reason"].GetString(), PERSONAL_DATA, get_current_timestamp_iso8601());
            pkg->setData(data_to_send.c_str());
            handle_article_18_restriction(pkg, email, hashed_password);
        }break;
        case 20: {              // 20. Right to data portability
            handle_article_20_portability(user_id);
        }break;
        case 21: {              // 21. Right to object
            Packet *pkg = new Packet("DATA_STORE");
            pkg->setSrcId(id);
            pkg->setDstId(id_active_storage);
            pkg->setType(REQUEST_STORAGE);
            std::string value = params["value"].GetString();
            std::string data_to_send = createTaggedData(value + "," + params["reason"].GetString(), PERSONAL_DATA, get_current_timestamp_iso8601());
            pkg->setData(data_to_send.c_str());
            handle_article_21_objection(pkg, email, hashed_password);
        }break;
        case 22: {              // 22. Automated individual decision-making, including profiling
            Packet *pkg = new Packet("DATA_STORE");
            pkg->setSrcId(id);
            pkg->setDstId(id_active_storage);
            pkg->setType(REQUEST_STORAGE);
            std::string data_to_send = createTaggedData("false", PERSONAL_DATA, get_current_timestamp_iso8601());
            pkg->setData(data_to_send.c_str());
            handle_article_22_automated_decision(pkg, email, hashed_password);
        }break;
        case 23: {
            handle_article_23_data_export(user_id, email);
        }break;
    }

    return;
}

void Infotainment::handle_article_15_access(int user_id) {
    requestAccessToData(user_id);
}

void Infotainment::handle_article_16_rectification(Packet* pkg, std::string email, std::string hashed_password) {
    sendDataToStorage(pkg, user_data_store[{email, hashed_password}], "address", STORAGE_EDIT, PRIVATE_DATA, PERSONAL_DATA);
}

void Infotainment::handle_article_17_erasure_with_check(std::string email, std::string hashed_password) {
    deleteUserData(user_data_store[{email, hashed_password}]);
}

void Infotainment::handle_article_18_restriction(Packet* pkg, std::string email, std::string hashed_password) {
    sendDataToStorage(pkg, user_data_store[{email, hashed_password}], "restriction", STORAGE_EDIT, PRIVATE_DATA, PERSONAL_DATA);
}

void Infotainment::handle_article_20_portability(int user_id) {
    requestAccessToData(user_id, STORAGE_DATA_ACCESS_PORTABLE);
}

void Infotainment::handle_article_21_objection(Packet* pkg, std::string email, std::string hashed_password) {
    sendDataToStorage(pkg, user_data_store[{email, hashed_password}], "marketing_cosent", STORAGE_EDIT, PRIVATE_DATA, PERSONAL_DATA);
}

void Infotainment::handle_article_22_automated_decision(Packet* pkg, std::string email, std::string hashed_password) {
    sendDataToStorage(pkg, user_data_store[{email, hashed_password}], "automated_decision", STORAGE_EDIT, PRIVATE_DATA, PERSONAL_DATA);
}

void Infotainment::handle_article_23_data_export(int user_id, std::string email) {
    pending_email = email;
    requestAccessToData(user_id, STORAGE_DATA_EXPORT_23);
}

void Infotainment::initialize_sample_data() {
    std::string timestamp = get_current_timestamp_iso8601();

    std::string email = "mario.rossi@provider.com";
    std::string password = "secure_password";
    std::string hashed_password = hash_password(password);

    Packet *pkg_1 = new Packet("DATA_STORE");
    pkg_1->setSrcId(id);
    pkg_1->setDstId(id_active_storage);
    pkg_1->setType(REQUEST_STORAGE);
    std::string data_to_send = createTaggedData("Via del corso 1, Roma", PERSONAL_DATA, timestamp);
    pkg_1->setData(data_to_send.c_str());
    sendDataToStorage(pkg_1, user_data_store[{email, hashed_password}], "address", STORAGE_WRITE, PRIVATE_DATA, PERSONAL_DATA);

    Packet *pkg_2 = new Packet("DATA_STORE");
    pkg_2->setSrcId(id);
    pkg_2->setDstId(id_active_storage);
    pkg_2->setType(REQUEST_STORAGE);
    data_to_send = createTaggedData("true", USER_PREFERENCES, timestamp);
    pkg_2->setData(data_to_send.c_str());
    sendDataToStorage(pkg_2, user_data_store[{email, hashed_password}], "automated_decision", STORAGE_WRITE, PRIVATE_DATA, USER_PREFERENCES);

    Packet *pkg_3 = new Packet("DATA_STORE");
    pkg_3->setSrcId(id);
    pkg_3->setDstId(id_active_storage);
    pkg_3->setType(REQUEST_STORAGE);
    data_to_send = createTaggedData("true", USER_PREFERENCES, timestamp);
    pkg_3->setData(data_to_send.c_str());
    sendDataToStorage(pkg_3, user_data_store[{email, hashed_password}], "marketing_cosent", STORAGE_WRITE, PRIVATE_DATA, USER_PREFERENCES);

    Packet *pkg_4 = new Packet("DATA_STORE");
    pkg_4->setSrcId(id);
    pkg_4->setDstId(id_active_storage);
    pkg_4->setType(REQUEST_STORAGE);
    data_to_send = createTaggedData("false", USER_PREFERENCES, timestamp);
    pkg_4->setData(data_to_send.c_str());
    sendDataToStorage(pkg_4, user_data_store[{email, hashed_password}], "restriction", STORAGE_WRITE, PRIVATE_DATA, USER_PREFERENCES);
}

bool Infotainment::webAccess(std::string uri)
{
    if(rules[uri] == "ACCEPT") {
        EV << "Infotainment: requested resouces at " << uri << " can be requested" << std::endl;
    } else if(rules[uri] == "ALERT") {
        EV << "Infotainment: requested resouces at " << uri << " can be requested but alert is being sent" << std::endl;
    } else {
        EV << "Infotainment: requested resouces at " << uri << " cannot requested. request has been dropped" << std::endl;
        return false;
    }
    return true;
}
