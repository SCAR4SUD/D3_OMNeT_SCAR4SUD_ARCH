#include "def.h"
#include "Storage.h"

namespace fs = std::filesystem;

Define_Module(Storage);
#define INIT_FAILURE_STATE 500

void Storage::additional_initialize()
{
    id = par("id");
    numECUs = par("numECUs");
    std::string storageBasePath = ("storage/ecu" + std::to_string(id));

    //Initialize clean up.
    int checkInterval_t = par("checkInterval");
    int dataLifeTime_t = par("dataLifeTime");
    checkInterval = SimTime(checkInterval_t, SIMTIME_S);
    dataLifetime = SimTime(dataLifeTime_t, SIMTIME_S);

    EV_INFO << "[Storage] Periodic clean up configured. Clean up every: " << checkInterval
            << ", Data lifetime: " << dataLifetime << endl;

    if(id == 7) {
        failureEvent = new Packet("failureEvent");
        failureEvent->setType(INIT_FAILURE_STATE);
        scheduleAt(simTime() + 9, failureEvent);
    }

    cleanupEvent = new Packet("periodicCleanup");
    cleanupEvent->setType(CLEAN_UP_EVENT);
    // scheduleAt(simTime() + checkInterval, cleanupEvent);

    //Initialize file
    try {

        fs::create_directory(storageBasePath);

    } catch (const fs::filesystem_error& e) {
        throw cRuntimeError("Error while creating directory '%s': %s",
                            storageBasePath.c_str(), e.what());
    }


    for (int i = 1; i <= numECUs; ++i) {
        std::string ecuDirPath = storageBasePath + ("/ecu" + std::to_string(i));

        try {
            fs::create_directory(ecuDirPath);
        } catch (const fs::filesystem_error& e) {
            throw cRuntimeError("Error while creating directory for ECU %d ('%s'): %s",
                                i, ecuDirPath.c_str(), e.what());
        }

        publicFilePath[i] = ecuDirPath +  "/public.txt";
        privateFilePath[i] = ecuDirPath +  "/private.txt";

        std::fstream file_public(publicFilePath[i], std::ios::app);
        std::fstream file_private(privateFilePath[i], std::ios::app);

        if(!file_public.is_open()) file_public.open(publicFilePath[i], std::ios::out);
        if(!file_private.is_open()) file_private.open(privateFilePath[i], std::ios::out);

        file_public.close();
        file_private.close();
    }
}

void Storage::additional_handleMessage(cMessage *msg)
{
    if(msg == failureEvent) {
        initFailureState();
        return;
    }

    // cleanup self message
    // clean event and scheduling of next cleanup event
    if (msg == cleanupEvent) {
        EV_INFO << "[Storage] Clean event at time: " << simTime() << endl;

        simtime_t expirationThreshold = simTime() - dataLifetime;

        for (int i = 1; i <= numECUs; ++i) {
            cleanupLogFile(i, "Public");
            cleanupLogFile(i, "Private");
        }

        scheduleAt(simTime() + checkInterval, cleanupEvent);
        return;
    }

    Packet *packet = dynamic_cast<Packet *>(msg);
    if (!packet) {
        ECU::handleMessage(msg);
        return;
    }

    int type = packet->getType();
        switch(type) {
            case REQUEST_STORAGE: {
                if (tpm_access->getSessionKeyHandle(HSM_TOPOLOGICAL_ID) == nullptr) {
                    EV_WARN << "[Storage (ECU " << id << ")] no session key with source of packet";
                    return;
                }
                storeData(packet);
                }break;
            case REQUEST_STORAGE_DATA:{
                EV << "[Storage (ECU" << id << ")] received a data read request" << std::endl;
                packet = readDataFile(packet);
                sendEncPacket(packet, packet->getDstId(), packet->getType());
                }break;
            case PING_MSG:{
                pingWithGateway(packet);
                }break;
            default: {

                }break;
        }
}

void Storage::pingWithGateway(Packet *package){
    EV << "[Storage (ECU " << id << ")] Received Ping. Sending pong.\n";
    Packet *response = new Packet("GATEWAY_PONG");
    response->setType(PONG_MSG);
    response->setSrcId(id);
    response->setDstId(-1);             // number indicating that the destination is not a node.
    response->setData(nullptr);         // the PONG message has no payload
    send(response, "out");
}

void Storage::storeData(Packet *packet){
    int sourceId = packet->getSrcId();
    PrivacyLevel privacy = 1; //packet->getPrivacyLevel();

    receiveEncPacket(packet, sourceId);
    std::string payload = packet->getData();

    std::cout << "[Storage] Received from ECU " << sourceId << " with payload: '" << payload << "'\n";

    AesEncryptedMessage aes_msg = encrypt_message_aes(
        (unsigned char*)payload.c_str(),
        payload.length(),
        tpm_access->getSelfKey()
    );

    std::string aad_b64 = base64_encode((const unsigned char*)aes_msg.aad, AAD_LEN);
    std::string iv_b64 = base64_encode(aes_msg.iv, IV_LEN);
    std::string tag_b64 = base64_encode(aes_msg.tag, TAG_LEN);
    std::string ciphertext_b64 = base64_encode(aes_msg.ciphertext, aes_msg.ciphertext_len);

    // std::string storable_data = iv_b64 + ":" + tag_b64 + ":" + ciphertext_b64;
    std::string storable_data = "{\"time\":\"" + get_current_timestamp_iso8601() +
                                "\", \"aad\":\"" + aad_b64 +
                                "\", \"iv\":\"" + iv_b64 +
                                "\", \"ciphertext\":\"" + ciphertext_b64 +
                                "\", \"tag\":\"" + tag_b64 + "\"}";

    std::fstream targetStream;
    if (privacy == PUBLIC_DATA) {
        targetStream.open(publicFilePath[sourceId], std::ios::out | std::ios::app);
    } else if (privacy == PRIVATE_DATA) {
        targetStream.open(privateFilePath[sourceId], std::ios::out | std::ios::app);
    }

    if (targetStream.is_open()) {
        targetStream << storable_data << std::endl;
    } else {
        EV_WARN << "[Storage] Ricevuto messaggio da ECU " << sourceId
                << ", ma non è stato trovato un file di log corrispondente. Messaggio ignorato.\n";
    }

}

Packet *Storage::readDataFile(Packet *packet) {
    if (!packet) {
        EV_WARN << "[Storage] Received null packet. Request dropped." << std::endl;
        return nullptr;
    }

    int sourceId = packet->getSrcId();

    PrivacyLevel privacy = PRIVATE_DATA;
    std::string lineContent;
    std::string allFileContent;
    std::fstream requested_file_stream;

    EV << "here - Attempting to read data for sourceId: " << sourceId << std::endl;


    int stream_id = -1;
    if (privacy == PUBLIC_DATA) {
        requested_file_stream.open(publicFilePath[sourceId], std::ios::in);
        /*if (it != publicFileStreams.end()) {
             stream_id = sourceId;
        }*/
    } else if (privacy == PRIVATE_DATA) {
        requested_file_stream.open(privateFilePath[sourceId], std::ios::in);
        /*if (it != privateFileStreams.end()) {
            stream_id = sourceId;
        }*/
    } else {
        EV_WARN << "[Storage] Invalid privacy level for sourceId: " << sourceId << ". Request dropped." << std::endl;
        packet->setSrcId(id);
        packet->setDstId(sourceId);
        packet->setData(""); // No data read
        packet->setType(STORAGE_RETRIEVE_DATA_ERROR);
        return packet;
    }

    if (requested_file_stream.is_open()) {
        requested_file_stream.clear();
        requested_file_stream.seekg(0, std::ios::beg);

        while (std::getline(requested_file_stream, lineContent)) {
            EV << "data read from storage: " << lineContent << std::endl;

            rapidjson::Document doc;
            if (doc.Parse(lineContent.c_str()).HasParseError())
                handle_errors("[Store] invalid JSON");

            size_t decrypted_record_size = 0;
            unsigned char *decrypted_record = decrypt_message_aes(doc, decrypted_record_size, tpm_access->getSelfKey());
            std::string decrypted_line((char *)decrypted_record, decrypted_record_size);


            allFileContent += decrypted_line;
        }
    } else {
        EV_WARN << "[Storage] Received request from ECU. " << sourceId
                << " corresponding file stream could not be found or opened. Request dropped." << std::endl;
        // Set packet data to empty message if no stream/data
        packet->setSrcId(id);
        packet->setDstId(sourceId);
        packet->setData(""); // No data read
        packet->setType(STORAGE_RETRIEVE_DATA_ERROR);
        return packet;
    }

    packet->setSrcId(id);
    packet->setDstId(sourceId);
    packet->setData(allFileContent.c_str());
    packet->setType(STORAGE_RETRIEVE_DATA);

    return packet;
}

void Storage::cleanupLogFile(int ecuId, const std::string& type) {
    fs::path storageBasePath = ("storage/ecu" + std::to_string(id));
    fs::path ecuDirPath = storageBasePath / ("ecu" + std::to_string(ecuId));
    fs::path filePath;
    std::fstream* fileStream = nullptr;

    if (type == "Public") {
        filePath = ecuDirPath / "public_log.txt";
    } else if (type == "Private") {
        filePath = ecuDirPath / "private_log.txt";
    } else {
        return;
    }

    if (fileStream->is_open()) {
        fileStream->close();
    }


    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        EV_ERROR << "[Storage] cannot open " << filePath << " during clenaup." << std::endl;

        fileStream->open(filePath, std::ios_base::app);
        return;
    }

    std::string line;
    std::vector<std::string> validLines;
    simtime_t expirationThreshold = simTime() - dataLifetime;

    while (std::getline(inFile, line)) {
        size_t separatorPos = line.find(" | ");
        if (separatorPos == std::string::npos) {
            validLines.push_back(line);
            continue;
        }

        std::string timeStr = line.substr(0, separatorPos);
        try {
            simtime_t entryTime = SimTime::parse(timeStr.c_str());
            if (entryTime >= expirationThreshold) {
                validLines.push_back(line);
            } else {
                EV_DETAIL << "[Storage] expired record deleted from " << filePath << ": " << line << std::endl;
            }
        } catch (const cException& e) {
            EV_WARN << "[Storage] cannot parse date in: '" << line << "'. the record will not be deleted." << std::endl;
            validLines.push_back(line);
        }
    }
    inFile.close();

    std::ofstream outFile(filePath, std::ios::trunc);
    if (!outFile.is_open()) {
        EV_ERROR << "[Storage] cannot open " << filePath << " for reading" << std::endl;

        fileStream->open(filePath, std::ios_base::app);
        return;
    }

    for (const auto& validLine : validLines) {
        outFile << validLine << std::endl;
    }
    outFile.close();

    fileStream->open(filePath, std::ios_base::app);
    if (!fileStream->is_open()) {
         throw cRuntimeError("Failure: cannot open data stream from %s", filePath.c_str());
    }

    if(validLines.size() > 0) {
        EV_INFO << "[Storage] cleanup start: " << filePath << std::endl;
        EV_INFO << "[Storage] Cleanup of " << filePath << " complete. Valid lines: " << validLines.size() << std::endl;
    }
}

void Storage::initFailureState()
{
    isUp = false;
    getDisplayString().setTagArg("i", 1, "red");
    getDisplayString().setTagArg("t", 0, "FAILED");
    getDisplayString().setTagArg("t", 2, "red");
    static cGate *gateIn = nullptr;
    static cGate *gateOut = nullptr;
    gateIn = gate("in");
    gateOut = gate("out");
    gateIn->disconnect();
    gateOut->disconnect();
}

void Storage::finish()
{

    EV << "[Storage] Simulazione terminata. Chiudo tutti i file di log." << std::endl;

    cancelAndDelete(cleanupEvent);

    ECU::finish();
}
