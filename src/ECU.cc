#include "ECU.h"
#include "Communication_m.h"
#include "Packet_m.h"

#include <string>
#include <cstdio>
#include <cstring>
#include <openssl/rand.h>
#include <ctime>
#include <iomanip>

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
    id_active_storage = par("storage1_id");

    tpm_access = new TPM(id);
    timestamp_b64 = new std::string[numECUs];

    isECUAuth = new bool[numECUs];
    ::memset(isECUAuth, 0, sizeof(bool) * numECUs);

    timestamp_challenge = new std::time_t[numECUs];
    ::memset(timestamp_challenge, 0, sizeof(std::time_t) * numECUs);

    HSMCommunicationInit = new Packet("SELF_HSMCommunicationInit");
    HSMCommunicationInit->setType(ECU_INIT_RSA_SIGNAL);
    scheduleAt(simTime(), HSMCommunicationInit);

    ClockSyncSignal = new Packet("SELF_ClockSyncSignal");
    ClockSyncSignal->setType(ECU_INIT_CLOCK_SYNC);
    scheduleAt(simTime()+10.0, ClockSyncSignal);

    SendDataSignal = new Packet("SELF_SendDataSignal");
    SendDataSignal->setType(ECU_SEND_DATA_SIGNAL);
    //scheduleAt(simTime()+10.0, SendDataSignal);

    RetriveDataSignal = new Packet("SELF_RetriveDataSignal");
    RetriveDataSignal->setType(ECU_SEND_DATA_SIGNAL);

    additional_initialize();
}

void ECU::handleMessage(cMessage *msg)
{
    if(!isUp) {
        //delete msg;
        EV << "[info] id: " << id << " is not receiving packets" << std::endl;
        return;
    }
    Packet *pkg = (Packet *) msg;

    int type = pkg->getType();
    switch(type) {
        case ECU_INIT_RSA_SIGNAL: {
            sendHsmRsaRequest();
            return;
            }break;
        case ECU_INIT_CLOCK_SYNC: {
            sendClockSyncRequest();
            scheduleAt(simTime()+5.0, ClockSyncSignal);
            return;
            }break;
        case RSA_RESPONSE: {
            setHsmSessionKey(pkg);
            //sendClockSyncRequest();
            if(id == 4) {
                sendEcuSessionRequest(7);
                sendEcuSessionRequest(8);
            }
            }break;
        case NS_RESPONSE_SENDER: {
            if(!handleEcuSessionKey(pkg))
                std::cerr << "failed to set session key" << std::endl;
            }break;
        case NS_RESPONSE_RECEIVER: {
            handleEcuTicket(pkg);
            sendChallenge(pkg->getSrcId());
            }break;
        case CLOCK_SYNC_RESPONSE: {
            handleClockSync(pkg);
            }break;
        case NS_CHALLENGE_REQUEST: {
            static bool once = true;
            acceptChallenge(pkg);
            if(id == 4 && once) {
                once = false;
                scheduleAt(simTime()+3.0, SendDataSignal);
            }
            }break;
        case NS_CHALLENGE_RESPONSE: {
            checkChallenge(pkg);
            }break;
        case STORAGE_RETRIEVE_DATA: {
            receiveEncPacket(pkg, id_active_storage);
            EV << "[ECU-" << id <<"] data retrived from storage: \n" << pkg->getData() << std::endl;
            }break;
        case STORAGE_DOWN: {
            if(std::stoi(pkg->getData()) == 7)
                id_active_storage = 8;
            else
                id_active_storage = 7;
            EV << "[ECU-" << id <<"] received info that a storage device is down, changing active storage option" << std::endl;
            }break;
        case STORAGE_ERROR: {
            receiveEncPacket(pkg, id_active_storage);
            EV << "[ECU-" << id <<"] received the following error: \n" << pkg->getData() << std::endl;
            }break;
        default: {
            }break;
    }
    /*
    if(pkg == SendDataSignal) {
        // std::cout << "sending storage data..." << std::endl;
        Packet *pkg_to_send = new Packet("DATA_STORE");
        pkg_to_send->setSrcId(id);
        pkg_to_send->setDstId(id_active_storage);
        pkg_to_send->setType(REQUEST_STORAGE);
        std::string data_to_send = "{\"height\":15}";
        pkg_to_send->setData(data_to_send.c_str());
        sendDataToStorage(pkg_to_send, "SEATING_HEIGHT", STORAGE_WRITE, PRIVATE_DATA, USER_PREFERENCES);
        scheduleAt(simTime()+8, RetriveDataSignal);
    }
    */
    /*
    if(pkg == RetriveDataSignal) {
        sendRequestToStorage(PRIVATE_DATA, "SEATING_HEIGHT", id);
    }
    */
    additional_handleMessage(msg);
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
    EV << "[ECU-" << id << "] is sending RSA session key request to the HSM" << std::endl;
    Packet *req = new Packet("hsm_rsa_req");

    req->setType(RSA_REQUEST);
    req->setDstId(HSM_TOPOLOGICAL_ID);
    req->setSrcId(id);

    timestamp_hsm = hw_clock.time_since_epoch();
    std::string json_formatted_request = serialize_rsa_request(
        id,
        timestamp_hsm,
        tpm_access->getPrivateKey(),
        tpm_access->getPublicKey("hsm")
    );
    const char *data = json_formatted_request.c_str();
    req->setData(data);

    send(req, "out");
}

bool ECU::setHsmSessionKey(Packet *res) {
    std::string json_response = res->getData();

    unsigned char aes_key[AES_KEY_ENC_MAXLEN];
    std::time_t retrived_timestamp = 0;

    parse_rsa_response(
        json_response,
        tpm_access->getPrivateKey(),
        tpm_access->getPublicKey("hsm"),
        aes_key,
        retrived_timestamp
    );

    size_t aes_key_len = AES_KEY_LEN;
    memcpy(tpm_access->getSessionKeyHandle(0), aes_key, AES_KEY_ENC_MAXLEN);


    if(timestamp_hsm != retrived_timestamp) {
        std::cerr << "[ECU-" << id << "] timestamp of response is invalid" << std::endl;
        return false;
    }

    if (aes_key_len != AES_KEY_LEN) {
        EV << "[Error] key length is not right" << std::endl;
        EV << "with key len: " << aes_key_len << std::endl;
        return false;
    }

    EV << "[ECU-" << id << "] received session key from the HSM" << std::endl;
    hsm_connection_active = true;
    return true;
}

void ECU::sendEcuSessionRequest(int dst) {
    EV << "[ECU-" << id << "] is sending Needham–Schroeder request to HSM to get session key with ECU-" << dst << std::endl;
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
    const char *data = ns_request.c_str();
    req->setData(data);

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

    EV << "[ECU-" << id << "] received Needham–Schroeder session key with ECU-" << receiver_id << std::endl;
    EV << "[ECU-" << id << "] is sending ticket to ECU-" << receiver_id << std::endl;

    return true;
}

bool ECU::handleEcuTicket(Packet *pkg)
{
    const std::string receivedData = pkg->getData();
    int sender_id;
    std::string ns_session_key_b64;
    std::string nonce_signature_b64;
    std::time_t nonce;

    ns_receive_ticket(receivedData, sender_id, ns_session_key_b64, nonce, nonce_signature_b64, tpm_access->getSessionKeyHandle(0));
    unsigned char nonce_signature[2048];
    size_t nonce_signature_len = base64_decode(nonce_signature_b64, nonce_signature, 2048);

    if(used_nonces_ns[{nonce, sender_id}] == true) {
        EV << "[ECU-" << id << "] received invalid session key with ECU-" << sender_id << "; DROPPING" << std::endl;
        return false;
    }else {
        used_nonces_ns[{nonce, sender_id}] = true;
    }
    if(!check_signature((unsigned char *)&nonce, sizeof(std::time_t), nonce_signature, nonce_signature_len, tpm_access->getPublicKey("hsm"))) {
        EV << "[ECU-" << id << "] received invalid session key with ECU-" << sender_id << "; DROPPING" << std::endl;
        return false;
    }
    base64_decode(ns_session_key_b64, (unsigned char*)tpm_access->getSessionKeyHandle(sender_id), AES_KEY_LEN);

    EV << "[ECU-" << id << "] received session key with ECU-" << sender_id << std::endl;
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
        "id",
        id,
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
    unsigned char* plaintext = decrypt_message_aes(doc, plain_len, tpm_access->getSessionKeyHandle(other_ecu_id));    // Decrypt ticket
    if(plaintext == nullptr) {
        //std::cerr << "receiveEncPacket failed" << std::endl;
        EV << "[ECU-" << id << "] received a packet that it failed to decrytp" << std::endl;
        pkg->setData("");
    }
    std::string dec_msg((const char*)plaintext, plain_len);

    pkg->setData(dec_msg.c_str());
}

void ECU::sendChallenge(int other_ecu_id)
{
    EV << "[ECU-" << id << "] is sending challenge to ECU-" << other_ecu_id << std::endl;
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

    EV << "[ECU-" << id << "] is sending challenge response to ECU-" << pkg->getSrcId() << std::endl;
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
        EV << "[ECU-" << id << "] verified failed challenge from ECU-" << pkg->getSrcId() << std::endl;
        return false;
    }

    isECUAuth[pkg->getSrcId()-1] = true;
    EV << "[ECU-" << id << "] verified successful challenge from ECU-" << pkg->getSrcId() << std::endl;
    return true;
}


void ECU::sendClockSyncRequest()
{
    EV << "[ECU-" << id << "] sent clock synchronization request to the HMS" << std::endl;
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
    EV << "[ECU-" << id << "] received clock synchronization response from HSM" << std::endl;
    EV << "[ECU-" << id << "] synchronized its internal clock" << std::endl;
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
    if((hw_clock.time_since_epoch() - trusted_timestamp) < (std::time_t)EPSILON_SECONDS) {
        hw_clock.update_drift_correction(trusted_timestamp);
    }
}

void ECU::sendDataToStorage(Packet *logPacket, int user_id, std::string record_name, int request_type, PrivacyLevel privacy_level, stateData data_state, int affected_id){
    std::string value = logPacket->getData();
    std::string date = get_current_timestamp_iso8601();
    logPacket->setSrcId(id);
    logPacket->setDstId(id_active_storage);
    logPacket->setType(REQUEST_STORAGE);

    rapidjson::Document store_message;
    store_message.SetObject();
    auto& store_alloc = store_message.GetAllocator();

    if(affected_id == UNSPECIFIED_STORE)
        affected_id = id;

    store_message.AddMember(
        "store_id",
        affected_id,
        store_alloc
    );
    store_message.AddMember(
        "user_id",
        user_id,
        store_alloc
    );
    store_message.AddMember(
        "type",
        request_type,
        store_alloc
    );
    store_message.AddMember(
        "name",
        rapidjson::Value().SetString(record_name.c_str(), record_name.length()),
        store_alloc
    );
    store_message.AddMember(
        "value",
        rapidjson::Value().SetString(value.c_str(), value.length()),
        store_alloc
    );
    store_message.AddMember(
        "tag",
        data_state,
        store_alloc
    );
    store_message.AddMember(
        "privacy_level",
        privacy_level,
        store_alloc
    );
    store_message.AddMember(
        "date",
        rapidjson::Value().SetString(date.c_str(), date.length()),
        store_alloc
    );

    rapidjson::StringBuffer buffer_aes_message;
    rapidjson::Writer<rapidjson::StringBuffer> aes_writer(buffer_aes_message);
    store_message.Accept(aes_writer);

    std::string data_to_send = buffer_aes_message.GetString();
    logPacket->setData(data_to_send.c_str());

    EV << "[ECU-" << id << "] sending data to be stored with level "
       << (privacy_level == PUBLIC_DATA ? "PUBLIC" : "PRIVATE")
       << ": " << logPacket->getData() << "\n";

    Packet* redundant_logPacket = logPacket->dup();
    redundant_logPacket->setDstId(8);
    // std::cout << "logPacket->getData(): " << logPacket->getData() << std::endl;
    if(id_active_storage == 7) sendEncPacket(logPacket, 7, REQUEST_STORAGE);
    sendEncPacket(redundant_logPacket, 8, REQUEST_STORAGE);

}

std::string ECU::get_current_timestamp_iso8601()
{
    time_t now_c = hw_clock.time_since_epoch();
    std::stringstream ss;
    ss << std::put_time(localtime(&now_c), "%Y-%m-%dT%H:%M:%SZ"); // iso 8601 format
    return ss.str();
}

void ECU::sendEditToStorage(
    PrivacyLevel privacy_level,
    std::string record_name,
    int user_id,
    int resource_id
){
    Packet *packet = new Packet("EDIT_TO_STORAGE");
    packet->setDstId(id_active_storage);
    packet->setSrcId(id);
    packet->setType(REQUEST_STORAGE_DATA);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "type",
        STORAGE_EDIT,
        alloc
    );
    store_request.AddMember(
        "privacy_level",
        privacy_level,
        alloc
    );
    store_request.AddMember(
        "name",
        rapidjson::Value().SetString(record_name.c_str(), record_name.length()),
        alloc
    );
    store_request.AddMember(
        "user_id",
        user_id,
        alloc
    );
    store_request.AddMember(
        "id",
        resource_id,
        alloc
    );


    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);

    packet->setData(buffer.GetString());

    sendEncPacket(packet, id_active_storage, REQUEST_STORAGE_DATA);
}


void ECU::requestAccessToData(
    int user_id,
    int type
) {
    Packet *packet = new Packet("REQUEST_TO_STORAGE");
    packet->setDstId(id_active_storage);
    packet->setSrcId(id);
    packet->setType(STORAGE_DATA_ACCESS);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "type",
        type,
        alloc
    );
    store_request.AddMember(
        "user_id",
        user_id,
        alloc
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);

    packet->setData(buffer.GetString());

    sendEncPacket(packet, id_active_storage, STORAGE_DATA_ACCESS);
}

void ECU::requestAccessToDataPortable(
    int user_id
) {
    Packet *packet = new Packet("REQUEST_TO_STORAGE");
    packet->setDstId(id_active_storage);
    packet->setSrcId(id);
    packet->setType(STORAGE_DATA_ACCESS);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "type",
        STORAGE_DATA_ACCESS_PORTABLE,
        alloc
    );
    store_request.AddMember(
        "user_id",
        user_id,
        alloc
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);

    packet->setData(buffer.GetString());

    sendEncPacket(packet, id_active_storage, STORAGE_DATA_ACCESS);
}

void ECU::deleteData(
    PrivacyLevel privacy_level,
    std::string record_name,
    int user_id,
    int resource_id
) {
    Packet *packet = new Packet("EDIT_TO_STORAGE");
    packet->setDstId(id_active_storage);
    packet->setSrcId(id);
    packet->setType(REQUEST_STORAGE_DATA);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "type",
        STORAGE_DELETE,
        alloc
    );
    store_request.AddMember(
        "name",
        rapidjson::Value().SetString(record_name.c_str(), record_name.length()),
        alloc
    );
    store_request.AddMember(
        "user_id",
        user_id,
        alloc
    );
    store_request.AddMember(
        "id",
        resource_id,
        alloc
    );


    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);

    packet->setData(buffer.GetString());

    sendEncPacket(packet, id_active_storage, REQUEST_STORAGE_DATA);
}

void ECU::deleteUserData(
    int user_id
) {
    Packet *packet = new Packet("EDIT_TO_STORAGE");
    packet->setDstId(id_active_storage);
    packet->setSrcId(id);
    packet->setType(STORAGE_DELETE_USER);

    rapidjson::Document store_request;
    store_request.SetObject();
    auto& alloc = store_request.GetAllocator();

    store_request.AddMember(
        "type",
        STORAGE_DELETE_USER,
        alloc
    );
    store_request.AddMember(
        "user_id",
        user_id,
        alloc
    );

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    store_request.Accept(writer);

    packet->setData(buffer.GetString());

    sendEncPacket(packet, id_active_storage, STORAGE_DELETE_USER);
}

void ECU::finish()
{
    delete tpm_access;
    cancelAndDelete(HSMCommunicationInit);
}
