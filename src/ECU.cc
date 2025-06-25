#include "ECU.h"
#include "Communication_m.h"
#include "Packet_m.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <openssl/rand.h>
#include <ctime>

#include "def.h"
#include "rsa/rsa_exchange.h"
#include "ns/ns_exchange.h"
#include "aes/aes.h"
#include "crypto_utils/crypto_utils.h"
#include "TPM.h"

Define_Module(ECU);
void ECU::initialize()
{
    id = par("id");
    numECUs = par("numECUs");

    tpm_access = new TPM(id);
    timestamp_b64 = new std::string[numECUs];

    isECUAuth = new bool[numECUs];
    ::memset(isECUAuth, 0, sizeof(bool) * numECUs);

    timestamp_challenge = new std::time_t[numECUs];
    ::memset(timestamp_challenge, 0, sizeof(std::time_t) * numECUs);

    HSMCommunicationInit = new Packet("HSM");
    HSMCommunicationInit->setType(ECU_INIT_RSA_SIGNAL);
    scheduleAt(0, HSMCommunicationInit);

    additional_initialize();
}

void ECU::handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;

    int type = pkg->getType();
    switch(type) {
        case ECU_INIT_RSA_SIGNAL: {
            sendHsmRsaRequest();
            }break;
        case RSA_RESPONSE: {
            setHsmSessionKey(pkg);
            if(id == 1) {
                sendEcuSessionRequest(7);
            }
            }break;
        case NS_RESPONSE_SENDER: {
            handleEcuSessionKey(pkg);
            }break;
        case NS_RESPONSE_RECEIVER: {
            handleEcuTicket(pkg);
            sendChallenge(pkg->getSrcId());
            }break;
        case CLOCK_SYNC_RESPONSE: {
            handleClockSync(pkg);
            delete pkg;
            }break;
        case NS_CHALLENGE_REQUEST: {
            acceptChallenge(pkg);
            }break;
        case NS_CHALLENGE_RESPONSE: {
            checkChallenge(pkg);
            sendClockSyncRequest();
            }break;
        default: {
            additional_handleMessage(msg);
            }break;
    }
}

void ECU::additional_handleMessage(cMessage *msg)
{
    Packet *pkg = (Packet *) msg;

    int type = pkg->getType();
    switch(type) {
        default:
            break;
    }
}

void ECU::sendHsmRsaRequest() {
    Packet *req = new Packet("hsm_rsa_req");

    req->setType(RSA_REQUEST);
    req->setDstId(HSM_TOPOLOGICAL_ID);
    req->setSrcId(id);
    std::string json_formatted_request = serialize_rsa_request(id);
    const char *data = json_formatted_request.c_str();
    req->setData(data);

    send(req, "out");
}

bool ECU::setHsmSessionKey(Packet *res) {
    std::string json_response(res->getData());

    unsigned char aes_key_enc[AES_KEY_ENC_MAXLEN];
    //std::cout << "json_response: " << json_response << std::endl;
    parse_rsa_response(json_response, aes_key_enc);

    size_t aes_key_len = AES_KEY_LEN;
    rsa_decrypt_evp(tpm_access->getPrivateKey(), aes_key_enc, AES_KEY_ENC_MAXLEN, tpm_access->getSessionKeyHandle(0), &aes_key_len);
    //std::cout << "rsa_decrypt_evp: " << ret << std::endl;
    //std::cout << "aes_key_len: " << aes_key_len << std::endl;

    if (aes_key_len != AES_KEY_LEN) {
        EV << "[Error] Chiave ricevuta con lunghezza errata" << std::endl;
        EV << "with key len: " << aes_key_len << std::endl;
    }

    return true;
}

void ECU::sendEcuSessionRequest(int dst) {
    std::string timestamp = std::to_string(hw_clock.time_since_epoch());
    timestamp_b64[dst-1] = base64_encode((const unsigned char*)timestamp.c_str(), timestamp.length());

    std::string ns_request = serialize_ns_session_request(
            id,
            dst,
            timestamp_b64[dst-1]
    );

    Packet *req = new Packet("hsm_ecu_key_req");

    req->setType(NS_REQUEST);
    req->setSrcId(id);
    req->setDstId(HSM_TOPOLOGICAL_ID);
    //const char *data = json_request.c_str();
    const char *data = ns_request.c_str();
    req->setData(data);

    // std::cout << "json_request: " << json_request << std::endl;

    send(req, "out");
}

bool ECU::handleEcuSessionKey(Packet *pkg) {
    const std::string& receivedData = pkg->getData();

    std::string nonce_b64;
    std::string ns_session_key_b64;
    std::string ticket_b64;
    int receiver_id;

    parse_ns_response_aes(
            receivedData,
            nonce_b64,
            ns_session_key_b64,
            ticket_b64,
            receiver_id,
            tpm_access->getSessionKeyHandle(0)
    );

    if(timestamp_b64[receiver_id-1] != nonce_b64)
        return false;
    base64_decode(ns_session_key_b64, tpm_access->getSessionKeyHandle(receiver_id), AES_KEY_LEN);

    unsigned char* ticket_msg_arr[4096];
    size_t ticket_len = base64_decode(ticket_b64, (unsigned char*)ticket_msg_arr, sizeof(ticket_msg_arr));
    std::string ticket((const char*)ticket_msg_arr, ticket_len);

    Packet *msg = new Packet("ecu_ticket");
    msg->setType(NS_RESPONSE_RECEIVER);
    msg->setSrcId(id);
    msg->setDstId(receiver_id);
    msg->setData(ticket.c_str());

    send(msg, "out");

    return true;
}

bool ECU::handleEcuTicket(Packet *pkg)
{
    const std::string receivedData = pkg->getData();
    int sender_id;
    std::string ns_session_key_b64;

    ns_receive_ticket(receivedData, sender_id, ns_session_key_b64, tpm_access->getSessionKeyHandle(0));

    base64_decode(ns_session_key_b64, (unsigned char*)tpm_access->getSessionKeyHandle(sender_id), AES_KEY_LEN);

    return true;
}

void ECU::sendEncPacket(Packet *pkg, int other_ecu_id, int type)
{
    std::string data = pkg->getData();
    AesEncryptedMessage aes_msg = encrypt_message_aes((unsigned char*)data.c_str(), data.length(), tpm_access->getSessionKeyHandle(other_ecu_id));

    rapidjson::Document aes_message;
    aes_message.SetObject();
    auto& alloc_aes = aes_message.GetAllocator();

    std::string ciphertext_b64 = base64_encode((unsigned char*)aes_msg.ciphertext, aes_msg.ciphertext_len);
    std::string iv_str = base64_encode((unsigned char*)aes_msg.iv, IV_LEN);
    std::string tag_str = base64_encode((unsigned char*)aes_msg.tag, TAG_LEN);
    std::string aad_str = base64_encode((unsigned char*)aes_msg.aad, AAD_LEN);

    aes_message.AddMember(
        "type",
        type,
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

    pkg->setData(aes_message_str.c_str());
    send(pkg, "out");
}

void ECU::receiveEncPacket(Packet *pkg, int other_ecu_id)
{
    std::string enc_message = pkg->getData();
    rapidjson::Document doc;
    if (doc.Parse(enc_message.c_str()).HasParseError())
        handle_errors("JSON non valido");

    unsigned long plain_len{0};
    const unsigned char* plaintext = decrypt_message_aes(doc, plain_len, tpm_access->getSessionKeyHandle(other_ecu_id));    // Decrypt ticket
    std::string dec_msg((const char*)plaintext, plain_len);

    pkg->setData(dec_msg.c_str());
}

void ECU::sendChallenge(int other_ecu_id)
{
    Packet *pkg = new Packet("NS_CHALLENGE_REQUEST");
    pkg->setSrcId(id);
    pkg->setDstId(other_ecu_id);
    pkg->setType(NS_CHALLENGE_REQUEST);

    rapidjson::Document message;
    message.SetObject();
    auto& alloc = message.GetAllocator();

    std::time_t timestamp = hw_clock.time_since_epoch();
    timestamp_challenge[other_ecu_id-1] = timestamp;

    message.AddMember(
        "type",
        NS_CHALLENGE_REQUEST,
        alloc
    );
    message.AddMember(
        "nonce",
        timestamp,
        alloc
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    message.Accept(writer);

    std::string message_str = buffer.GetString();

    pkg->setData(message_str.c_str());

    sendEncPacket(pkg, other_ecu_id, NS_CHALLENGE_REQUEST);
}

void ECU::acceptChallenge(Packet *pkg)
{
    receiveEncPacket(pkg, pkg->getSrcId());

    std::string message = pkg->getData();
    rapidjson::Document doc;
    if (doc.Parse(message.c_str()).HasParseError())
        handle_errors("JSON non valido");

    doc["type"].SetInt(NS_CHALLENGE_RESPONSE);
    doc["nonce"].SetInt(
        doc["nonce"].GetInt() - 1
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    Packet *ret = new Packet("NS_CHALLENGE_RESPONSE");

    ret->setType(NS_CHALLENGE_RESPONSE);
    ret->setSrcId(id);
    ret->setDstId(pkg->getSrcId());
    ret->setData(buffer.GetString());

    sendEncPacket(ret, pkg->getSrcId(), NS_CHALLENGE_RESPONSE);
}

bool ECU::checkChallenge(Packet *pkg)
{
    receiveEncPacket(pkg, pkg->getSrcId());

    std::string message = pkg->getData();
    rapidjson::Document doc;
    if (doc.Parse(message.c_str()).HasParseError())
        handle_errors("JSON non valido");

    std::time_t received_nonce = doc["nonce"].GetInt() + 1;

    if(received_nonce != timestamp_challenge[pkg->getSrcId()-1]) {
        isECUAuth[pkg->getSrcId()-1] = false;
        return false;
    }

    isECUAuth[pkg->getSrcId()-1] = true;
    return true;
}


void ECU::sendClockSyncRequest()
{
    rapidjson::Document doc;
    rapidjson::StringBuffer buffer;

    doc.SetObject();
    auto& alloc = doc.GetAllocator();

    doc.AddMember("type", CLOCK_SYNC_REQUEST, alloc);
    doc.AddMember("id", id, alloc);
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);

    Packet *sync_clock_event = new Packet("SYNC_CLOCK_REQUEST");

    sync_clock_event->setType(CLOCK_SYNC_REQUEST);
    sync_clock_event->setSrcId(id);
    sync_clock_event->setDstId(HSM_TOPOLOGICAL_ID);
    sync_clock_event->setData(buffer.GetString());

    send(sync_clock_event, "out");
}

void ECU::handleClockSync(Packet *pkg)
{
    std::string enc_message = pkg->getData();
    rapidjson::Document doc;
    if (doc.Parse(enc_message.c_str()).HasParseError())
        handle_errors("JSON non valido");

    unsigned long plain_len{0};
    const unsigned char* plaintext = decrypt_message_aes(doc, plain_len, tpm_access->getSessionKeyHandle(HSM_TOPOLOGICAL_ID));    // Decrypt ticket
    std::string dec_str((const char *)plaintext, plain_len);

    rapidjson::Document message_doc;
    if (message_doc.Parse(dec_str.c_str()).HasParseError())
        std::cerr << "Error while parsing json (ECU::handleClockSync)" << std::endl;

    if (!message_doc.HasMember("timestamp") || !message_doc["timestamp"].IsInt())
        std::cerr << "Sync Message lacks time member (ECU::handleClockSync)" << std::endl;

    std::time_t trusted_timestamp = message_doc["timestamp"].GetInt();
    hw_clock.update_drift_correction(trusted_timestamp);
}

void ECU::finish()
{
    delete tpm_access;
    cancelAndDelete(HSMCommunicationInit);
}
