#include "HSM.h"
#include "def.h"
#include "Packet_m.h"

#include <chrono>
#include <cstring>

#include "include/rapidjson/document.h"
#include "include/rapidjson/stringbuffer.h"
#include "include/rapidjson/writer.h"
#include "include/rapidjson/error/en.h"

#include "include/rsa_handling/rsa.h"
#include "include/ns_handling/ns.h"
#include "include/sca.h"

#define PORT 9000
#define LOCALHOST "127.0.0.1"

Define_Module(HSM);

void HSM::initialize()
{
    numECUs = par("numECUs");
    sessionKeyWith = new bool[numECUs];
    memset(sessionKeyWith, 0, sizeof(bool)*numECUs);
}

void HSM::handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;
    switch(pkg->getType()) {
    case RSA_REQUEST: {
        sendRequestToHSM(pkg, HSM_RSA_RESPONSE, "hsm_rsa_res");
        }break;
    case NS_REQUEST: {
        sendRequestToHSM(pkg, HSM_NS_RESPONSE_SENDER, "hsm_ecu_key_res");
        }break;
    case CLOCK_SYNC_REQUEST: {
        sendRequestToHSM(pkg, CLOCK_SYNC_RESPONSE, "SYNC_CLOCK_RESPONSE");
        }break;
    default: {
        }break;
    }
}

void HSM::sendRequestToHSM(Packet *pkg, int response_type, const char* ret_pkg_name) {
    session.beginReadWrite(slot->getID());
    session.loginUser("12345");

    std::string json_request = pkg->getData();

    rapidjson::Document doc;
    if (doc.Parse(json_request.c_str()).HasParseError())
        std::cerr << "Errore parsing JSON" << std::endl;
    if (!doc.HasMember("type") || !doc["type"].IsInt())
        std::cerr << "Errore parsing JSON" << std::endl;

    std::string json_response;
    switch(doc["type"].GetInt()) {
        case HSM_RSA_REQUEST: {
            json_response = rsa_response(doc, session);
            sessionKeyWith[doc["id"].GetInt()-1] = true;
            } break;
        case HSM_NS_REQUEST: {
            json_response = ns_response(doc, session);
            } break;
        case CLOCK_SYNC_REQUEST: {
            json_response = clock_response(doc, session, doc["id"].GetInt());
            }break;
        default: {
            } break;
    }

    Packet *res = new Packet(ret_pkg_name);

    res->setType(response_type);
    res->setDstId(pkg->getSrcId());
    res->setSrcId(HSM_TOPOLOGICAL_ID);
    res->setData(json_response.c_str());

    send(res, "toGateway");
    session.logout();
    session.end();
}

std::string HSM::clock_response(rapidjson::Document& doc, sca::Session& session, int id)
{
    using namespace rapidjson;

    CK_OBJECT_HANDLE ecu_hsm_key{0};
    CK_ULONG ecu_hsm_key_count{0};
    session.findKey("ECU"+std::to_string(id), &ecu_hsm_key, &ecu_hsm_key_count);

    rapidjson::Document clock_sync_to_ecu;
    clock_sync_to_ecu.SetObject();
    auto& alloc = clock_sync_to_ecu.GetAllocator();

    clock_sync_to_ecu.AddMember("timestamp", std::time(0), alloc);

    rapidjson::StringBuffer buffer_clock_sync_to_ecu;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer_clock_sync_to_ecu);
    clock_sync_to_ecu.Accept(writer);

    std::string clock_sync_to_ecu_str = buffer_clock_sync_to_ecu.GetString();

    CK_BYTE_PTR iv{nullptr};
    CK_ULONG iv_len{0};
    CK_BYTE_PTR tag{nullptr};
    CK_ULONG tag_len{0};
    CK_BYTE_PTR aad{nullptr};
    CK_ULONG aad_len{0};
    memset(aad, 0, aad_len);

    CK_BYTE_PTR ciphertext{nullptr};
    CK_ULONG ciphertext_len{0};

    session.encryptAesGCMParam(
        ecu_hsm_key,
        (CK_BYTE_PTR)clock_sync_to_ecu_str.c_str(),
        clock_sync_to_ecu_str.length(),
        ciphertext,
        &ciphertext_len,
        aad,
        &aad_len,
        tag,
        &tag_len,
        iv,
        &iv_len
    );

    std::string ciphertext_b64 = sca::base64_encode(ciphertext, ciphertext_len);

    rapidjson::Document aes_message;
    aes_message.SetObject();
    auto& alloc_aes = aes_message.GetAllocator();

    std::string iv_str = sca::base64_encode(iv, iv_len);
    std::string tag_str = sca::base64_encode(tag, tag_len);
    std::string aad_str = sca::base64_encode(aad, aad_len);

    aes_message.AddMember(
        "type",
        CLOCK_SYNC_RESPONSE,
        alloc_aes
    );
    aes_message.AddMember(
        "aad",
        rapidjson::Value().SetString(aad_str.c_str(), aad_str.length()),
        alloc_aes
    );
    aes_message.AddMember(
        "iv",
        rapidjson::Value().SetString(iv_str.c_str(), iv_str.length()),
        alloc_aes
    );
    aes_message.AddMember(
        "ciphertext",
        rapidjson::Value().SetString(ciphertext_b64.c_str(), ciphertext_b64.length()),
        alloc_aes
    );
    aes_message.AddMember(
        "tag",
        rapidjson::Value().SetString(tag_str.c_str(), tag_str.length()),
        alloc_aes
    );

    rapidjson::StringBuffer buffer_aes_message;
    rapidjson::Writer<rapidjson::StringBuffer> aes_writer(buffer_aes_message);
    aes_message.Accept(aes_writer);

    std::string aes_message_str = buffer_aes_message.GetString();

    return aes_message_str;
}

void HSM::finish() {

}
