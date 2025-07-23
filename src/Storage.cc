#include "def.h"
#include "Storage.h"
#include <cstring>

namespace fs = std::filesystem;

Define_Module(Storage);

#define INIT_FAILURE_STATE 500


void Storage::initialize_retention_policies()
{
    data_retention_policies[PERSONAL_DATA] = {(10 * 31536000LL), (15 * 31536000LL)};
    data_retention_policies[USER_PREFERENCES] = {(30 * 86400LL), (2 * 31536000LL)};
    data_retention_policies[TEMPORAL_DATA]= {(1 * 31536000LL), (5 * 31536000LL)};
    data_retention_policies[VEHICLE_PREFERENCES] = {(90 * 86400LL), (3 * 31536000LL)};
    data_retention_policies[UNCATEGORIZED] = {(0), (10 * 31536000LL)}; // default for tag less data
}

void Storage::additional_initialize()
{
    id = par("id");
    numECUs = par("numECUs");
    std::string storageBasePath = ("storage/ecu" + std::to_string(id));

    //Initialize clean up.
    int checkInterval_t = par("checkInterval");
    int dataLifeTime_t = par("dataLifeTime");
    checkInterval = SimTime(checkInterval_t, SIMTIME_S);
    dataLifetime = dataLifeTime_t;

    EV_INFO << "[Storage] Periodic clean up configured. Clean up every: " << checkInterval
            << ", Data lifetime: " << dataLifetime << endl;

    if(id == 7) {
        failureEvent = new Packet("failureEvent");
        failureEvent->setType(INIT_FAILURE_STATE);
        scheduleAt(simTime() + 12, failureEvent);
    }

    cleanupEvent = new Packet("periodicCleanup");
    cleanupEvent->setType(CLEAN_UP_EVENT);
    scheduleAt(simTime() + checkInterval, cleanupEvent);

    //Initialize file
    try {

        fs::create_directory(storageBasePath);

    } catch (const fs::filesystem_error& e) {
        throw cRuntimeError("Error while creating directory '%s': %s",
                            storageBasePath.c_str(), e.what());
    }


    int trunc = par("clean_files");
    std::ios_base::openmode open_mode;
    if(trunc != 0)
        open_mode = std::ios::trunc;
    else
        open_mode = std::ios::app;


    for (int i = 1; i <= numECUs; ++i) {
        std::string ecuDirPath = storageBasePath + ("/ecu" + std::to_string(i));

        try {
            fs::create_directory(ecuDirPath);
        } catch (const fs::filesystem_error& e) {
            throw cRuntimeError("Error while creating directory for ECU %d ('%s'): %s",
                                i, ecuDirPath.c_str(), e.what());
        }

        publicFilePath[i] = ecuDirPath +  "/public_log.txt";
        privateFilePath[i] = ecuDirPath +  "/private_log.txt";

        std::fstream file_public(publicFilePath[i], open_mode);
        std::fstream file_private(privateFilePath[i], open_mode);

        if(!file_public.is_open()) file_public.open(publicFilePath[i], std::ios::out);
        if(!file_private.is_open()) file_private.open(privateFilePath[i], std::ios::out);

        file_public.close();
        file_private.close();
    }
    initialize_retention_policies();
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
        // EV_INFO << "[Storage] Clean event at time: " << simTime() << endl;

        // simtime_t expirationThreshold = simTime() - dataLifetime;

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
                EV << "[Storage (ECU-" << id << ")] received a data read request" << std::endl;
                packet = readDataFile(packet);
                sendEncPacket(packet, packet->getDstId(), packet->getType());
                }break;
            case STORAGE_DATA_ACCESS:{
                EV << "[Storage (ECU-" << id << ")] received a data access request" << std::endl;
                packet = exportDataUser(packet);
                sendEncPacket(packet, packet->getDstId(), packet->getType());
                }break;
            case STORAGE_DELETE_USER:{
                //if(!canDeleteUserData()) packet->setData("{\"error\":\"could not delete user data: minimum retention time has not elapsed\"}");
                packet = deleteUserData(packet);
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
    EV << "[Storage (ECU-" << id << ")] Received Ping. Sending pong.\n";
    Packet *response = new Packet("GATEWAY_PONG");
    response->setType(PONG_MSG);
    response->setSrcId(id);
    response->setDstId(-1);             // number indicating that the destination is not a node.
    response->setData(nullptr);         // the PONG message has no payload
    send(response, "out");
}

void Storage::storeData(Packet *packet){
    int sourceId = packet->getSrcId();

    receiveEncPacket(packet, sourceId);
    std::string payload = packet->getData();

    std::cout << "[Storage] Received from ECU " << sourceId << " with payload: '" << payload << "'\n";

    rapidjson::Document doc;
    if (doc.Parse(payload.c_str()).HasParseError())
        handle_errors("[Store] received invalid JSON to store");

    int store_id = doc["store_id"].GetInt();
    int user_id = doc["user_id"].GetInt();
    int type = doc["type"].GetInt();
    PrivacyLevel privacy = doc["privacy_level"].GetInt();
    std::string record_name = doc["name"].GetString();
    stateData state_data = (stateData)doc["tag"].GetInt();


    switch(type) {
        case STORAGE_WRITE:{
            // nothing
            EV << "[Storage] writing the following data to storage: " << payload << std::endl;
            }break;
        case STORAGE_DELETE:{
            deleteData(store_id, sourceId, privacy, record_name);
            return;
            }break;
        case STORAGE_EDIT:{
            deleteData(store_id, sourceId, privacy, record_name, true);
            EV << "[Storage] editing the following data to storage: " << payload << std::endl;
            }break;

    }


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
                                "\", \"user_id\":" + std::to_string(user_id) +
                                  ", \"record_name\":\"" + record_name +
                                "\", \"aad\":\"" + aad_b64 +
                                "\", \"iv\":\"" + iv_b64 +
                                "\", \"ciphertext\":\"" + ciphertext_b64 +
                                "\", \"tag\":\"" + tag_b64 +
                                "\", \"data_tag\":" + std::to_string((int)state_data) + "}";

    std::fstream targetStream;
    if (privacy == PUBLIC_DATA) {
        targetStream.open(publicFilePath[store_id], std::ios::out | std::ios::app);
    } else if (privacy == PRIVATE_DATA) {
        targetStream.open(privateFilePath[store_id], std::ios::out | std::ios::app);
    }

    if (targetStream.is_open()) {
        targetStream << storable_data << std::endl;
    } else {
        EV_WARN << "[Storage] request from ECU-" << sourceId
                << ", Corresponding storage not found. Dropping request\n";
    }

}

Packet *Storage::readDataFile(Packet *packet) {
    if (!packet) {
        EV_WARN << "[Storage] Received null packet. Request dropped." << std::endl;
        return nullptr;
    }

    receiveEncPacket(packet, packet->getSrcId());
    if(strlen(packet->getData()) <= 0) {
        std::cerr << "[Storage] Request decryption failed. Request dropped" << std::endl;
        return nullptr;
    }

    int sourceId = packet->getSrcId();
    std::string json_request = packet->getData();

    EV << "[STORAGE] request: " << json_request << std::endl;

    rapidjson::Document request_doc;
    if (request_doc.Parse(json_request.c_str()).HasParseError()) {
        handle_errors("invalid json formatted request sent to storage");
        packet->setData("");
    }

    PrivacyLevel privacy = request_doc["privacy_level"].GetInt();
    int user_id = request_doc["user_id"].GetInt();
    std::string record_name = request_doc["name"].GetString();
    int data_id = request_doc["id"].GetInt();

    std::string lineContent;
    std::string allFileContent;
    std::fstream requested_file_stream;

    EV << "here - Attempting to read data for sourceId: " << data_id << std::endl;

    int stream_id = -1;
    if (privacy == PUBLIC_DATA) {
        requested_file_stream.open(publicFilePath[data_id], std::ios::in);
        /*if (it != publicFileStreams.end()) {
             stream_id = sourceId;
        }*/
    } else if (privacy == PRIVATE_DATA) {
        requested_file_stream.open(privateFilePath[data_id], std::ios::in);
        /*if (it != privateFileStreams.end()) {
            stream_id = sourceId;
        }*/
    } else {
        EV_WARN << "[Storage] Invalid privacy level for id: " << data_id << ". Request dropped." << std::endl;
        packet->setSrcId(id);
        packet->setDstId(sourceId);
        packet->setData(""); // No data read
        packet->setType(STORAGE_RETRIEVE_DATA_ERROR);
        return packet;
    }

    rapidjson::Document line_json;
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

            if (line_json.Parse(decrypted_line.c_str()).HasParseError())
                continue;

            if(!line_json.HasMember("name") || !line_json["name"].IsString())
                continue;

            std::string requested_name = request_doc["name"].GetString();
            if(requested_name.compare(line_json["name"].GetString()) != 0)
                continue;

            if(user_id != line_json["user_id"].GetInt())
                continue;

            allFileContent += decrypted_line + "\n";
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

Packet* Storage::exportDataUser(Packet *packet) {
    EV << "[Storage] exportDataUser requested" << std::endl;
    if (!packet) {
        EV_WARN << "[Storage] Received null packet. Request dropped." << std::endl;
        return nullptr;
    }

    receiveEncPacket(packet, packet->getSrcId());
    if(strlen(packet->getData()) <= 0) {
        std::cerr << "[Storage] Request decryption failed. Request dropped" << std::endl;
        return nullptr;
    }

    int sourceId = packet->getSrcId();
    std::string json_request = packet->getData();

    rapidjson::Document request_doc;
    if (request_doc.Parse(json_request.c_str()).HasParseError()) {
        handle_errors("invalid json formatted request sent to storage");
        return nullptr;
    }

    int type = request_doc["type"].GetInt();
    int user_id = request_doc["user_id"].GetInt();

    std::string lineContent;
    std::string allFileContent;
    std::ifstream requested_file_stream;

    bool isPublic = true;
    for(size_t i = 1; i <= (numECUs); ++i) {
        isPublic = true;
        for(size_t j = 0; j < 2; ++j) {

            if(isPublic)
                requested_file_stream.open(publicFilePath[i]);
            else
                requested_file_stream.open(privateFilePath[i]);

            // std::cout << "[Storage] privateFilePath: " << privateFilePath[i] << std::endl;

            rapidjson::Document line_json;
            if (requested_file_stream.is_open()) {
                requested_file_stream.clear();
                requested_file_stream.seekg(0, std::ios::beg);

                while (std::getline(requested_file_stream, lineContent)) {
                    // std::cout << "data read from storage: " << lineContent << std::endl;

                    rapidjson::Document doc;
                    if (doc.Parse(lineContent.c_str()).HasParseError())
                        handle_errors("[Store] invalid JSON");

                    size_t decrypted_record_size = 0;
                    unsigned char *decrypted_record = decrypt_message_aes(doc, decrypted_record_size, tpm_access->getSelfKey());
                    std::string decrypted_line((char *)decrypted_record, decrypted_record_size);

                    if (line_json.Parse(decrypted_line.c_str()).HasParseError())
                        continue;

                    if(user_id != line_json["user_id"].GetInt())
                        continue;

                    if(type == STORAGE_DATA_ACCESS_PORTABLE) {
                        rapidjson::Document fix_line;
                        if (fix_line.Parse(decrypted_line.c_str()).HasParseError()) {
                            handle_errors("invalid json formatted request sent to storage");
                        }

                        fix_line.EraseMember("store_id");
                        fix_line.EraseMember("user_id");
                        fix_line.EraseMember("type");
                        fix_line.EraseMember("tag");
                        fix_line.EraseMember("privacy_level");
                        fix_line.EraseMember("date");


                        rapidjson::StringBuffer buffer;
                        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                        fix_line.Accept(writer);

                        decrypted_line = buffer.GetString();
                    }


                    allFileContent += decrypted_line + "\n";
                }
            } else {
                std::cerr << "[Storage] Received request from ECU: " << sourceId
                        << ". corresponding file stream (" << i << ") could not be found or opened. Request dropped." << std::endl;
                /*
                packet->setSrcId(id);
                packet->setDstId(sourceId);
                packet->setData(""); // No data read
                packet->setType(STORAGE_RETRIEVE_DATA_ERROR);
                return packet;
                */
            }
            isPublic = false;
            requested_file_stream.close();
        }
    }

    EV << "[Storage] retrived info: \n" << allFileContent << std::endl;

    packet->setSrcId(id);
    packet->setDstId(sourceId);
    packet->setData(allFileContent.c_str());
    packet->setType(STORAGE_RETRIEVE_DATA);
    if(type == STORAGE_DATA_EXPORT_23) packet->setType(STORAGE_DATA_EXPORT_23);

    return packet;

}

void Storage::cleanupLogFile(int ecuId, const std::string& type) {
    std::string storageBasePath = ("storage/ecu" + std::to_string(id));
    std::string ecuDirPath = storageBasePath + ("/ecu" + std::to_string(ecuId));
    fs::path filePath;
    std::ofstream* fileStream = new std::ofstream;

    if (type == "Public") {
        filePath = ecuDirPath + "/public_log.txt";
        fileStream->open(filePath, std::ios_base::app);
    } else if (type == "Private") {
        filePath = ecuDirPath + "/private_log.txt";
        fileStream->open(filePath, std::ios_base::app);
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
    std::time_t expirationThreshold; // = hw_clock.time_since_epoch() - dataLifetime;

    // EV << "[Storage (ECU-" << id << ")] clean up" << std::endl;

    while (std::getline(inFile, line)) {
        // std::cout << "\t\tline: " << line << std::endl;
        rapidjson::Document doc;
        if (doc.Parse(line.c_str()).HasParseError())
            handle_errors("invalid json in internal store");

        expirationThreshold = hw_clock.time_since_epoch() - data_retention_policies[(stateData)doc["data_tag"].GetInt()].max_retention_s;

        std::string timeStr = doc["time"].GetString();
        try {
            std::tm entryTime {0};

            std::istringstream ss_in(timeStr);
            ss_in >> std::get_time(&entryTime, "%Y-%m-%d %H:%M:%S");
            std::time_t entry_timestamp = std::mktime(&entryTime);

            if (entry_timestamp >= expirationThreshold) {
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

void Storage::deleteData(int ecuId, int source_id, const int& type, const std::string& name,  bool ignore_min_retention) {
    std::string storageBasePath = ("storage/ecu" + std::to_string(id));
    std::string ecuDirPath = storageBasePath + ("/ecu" + std::to_string(ecuId));
    fs::path filePath;
    std::ofstream* fileStream = new std::ofstream;

    if (type == PUBLIC_DATA) {
        filePath = ecuDirPath + "/public_log.txt";
        fileStream->open(filePath, std::ios_base::app);
    } else if (type == PRIVATE_DATA) {
        filePath = ecuDirPath + "/private_log.txt";
        fileStream->open(filePath, std::ios_base::app);
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
    std::time_t minRetentionThreshold; // = hw_clock.time_since_epoch() - dataLifetime;

    // EV << "[Storage (ECU-" << id << ")] clean up" << std::endl;

    while (std::getline(inFile, line)) {
        // std::cout << "\t\tline: " << line << std::endl;
        rapidjson::Document doc;
        if (doc.Parse(line.c_str()).HasParseError())
            handle_errors("invalid json in internal store");

        std::string timeStr = doc["time"].GetString();
        std::string record_name = doc["record_name"].GetString();
        try {
            std::tm entryTime {0};

            std::istringstream ss_in(timeStr);
            ss_in >> std::get_time(&entryTime, "%Y-%m-%d %H:%M:%S");
            std::time_t entry_timestamp = std::mktime(&entryTime);

            minRetentionThreshold = entry_timestamp + data_retention_policies[(stateData)doc["data_tag"].GetInt()].min_retention_s;

            if (record_name == name && ((hw_clock.time_since_epoch() >= minRetentionThreshold) || ignore_min_retention)) {
                // delete it
            } else {
                validLines.push_back(line);
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

Packet* Storage::deleteUserData(Packet *packet) {
    // EV << "[Storage] exportDataUser requested" << std::endl;
    if (!packet) {
        EV_WARN << "[Storage] Received null packet. Request dropped." << std::endl;
        return nullptr;
    }

    receiveEncPacket(packet, packet->getSrcId());
    if(strlen(packet->getData()) <= 0) {
        std::cerr << "[Storage] Request decryption failed. Request dropped" << std::endl;
        return nullptr;
    }

    int sourceId = packet->getSrcId();
    std::string json_request = packet->getData();

    rapidjson::Document request_doc;
    if (request_doc.Parse(json_request.c_str()).HasParseError()) {
        handle_errors("invalid json formatted request sent to storage");
        return nullptr;
    }

    int type = request_doc["type"].GetInt();
    int user_id = request_doc["user_id"].GetInt();

    std::string lineContent;
    std::string allFileContent;
    std::ifstream requested_file_stream;

    std::time_t minRetentionThreshold;
    bool canDelete = true;

    bool isPublic = true;
    for(size_t i = 1; i <= (numECUs); ++i) {
        isPublic = true;
        for(size_t j = 0; j < 2; ++j) {

            if(isPublic)
                requested_file_stream.open(publicFilePath[i]);
            else
                requested_file_stream.open(privateFilePath[i]);

            // std::cout << "[Storage] privateFilePath: " << privateFilePath[i] << std::endl;

            rapidjson::Document line_json;
            if (requested_file_stream.is_open()) {
                requested_file_stream.clear();
                requested_file_stream.seekg(0, std::ios::beg);

                while (std::getline(requested_file_stream, lineContent)) {
                    // std::cout << "data read from storage: " << lineContent << std::endl;

                    rapidjson::Document doc;
                    if (doc.Parse(lineContent.c_str()).HasParseError())
                        handle_errors("[Store] invalid JSON");

                    size_t decrypted_record_size = 0;
                    unsigned char *decrypted_record = decrypt_message_aes(doc, decrypted_record_size, tpm_access->getSelfKey());
                    std::string decrypted_line((char *)decrypted_record, decrypted_record_size);

                    if (line_json.Parse(decrypted_line.c_str()).HasParseError())
                        continue;

                    int record_user_id = doc["user_id"].GetInt();
                    std::string timeStr = doc["time"].GetString();
                    std::tm entryTime {0};

                    std::istringstream ss_in(timeStr);
                    ss_in >> std::get_time(&entryTime, "%Y-%m-%d %H:%M:%S");
                    std::time_t entry_timestamp = std::mktime(&entryTime);

                    minRetentionThreshold = entry_timestamp + data_retention_policies[(stateData)line_json["data_tag"].GetInt()].min_retention_s;

                    if((hw_clock.time_since_epoch() < minRetentionThreshold) && (user_id == record_user_id))
                        canDelete = false;

                    if(user_id != line_json["user_id"].GetInt())
                        continue;

                    allFileContent += decrypted_line + "\n";
                }
            } else {
                std::cerr << "[Storage] Received request from ECU: " << sourceId
                        << ". corresponding file stream (" << i << ") could not be found or opened. Request dropped." << std::endl;
            }
            isPublic = false;
            requested_file_stream.close();
        }
    }

    if(!canDelete) {
        packet->setData("{\"error\":\"could not delete user data: minimum retention time has not elapsed\"}");
        packet->setType(STORAGE_ERROR);
    }

    std::string delete_path = "";

    isPublic = true;
    for(size_t i = 1; i <= (numECUs); ++i) {
        isPublic = true;
        for(size_t j = 0; j < 2; ++j) {
            if(isPublic)
                delete_path = publicFilePath[i];
            else
                delete_path = privateFilePath[i];

            requested_file_stream.open(publicFilePath[i]);


            std::string line;
            std::vector<std::string> validLines;

            while (std::getline(requested_file_stream, line)) {
                // std::cout << "\t\tline: " << line << std::endl;
                rapidjson::Document doc;
                if (doc.Parse(line.c_str()).HasParseError())
                    handle_errors("invalid json in internal store");

                std::string timeStr = doc["time"].GetString();
                int record_user_id = doc["user_id"].GetInt();
                try {


                    if (record_user_id == user_id) {
                        // delete it
                    } else {
                        validLines.push_back(line);
                    }
                } catch (const cException& e) {
                    EV_WARN << "[Storage] cannot parse date in: '" << line << "'. the record will not be deleted." << std::endl;
                    validLines.push_back(line);
                }
            }
            requested_file_stream.close();

            std::ofstream outFile(delete_path, std::ios::trunc);
            if (!outFile.is_open()) {
                EV_ERROR << "[Storage] cannot open " << delete_path << " for reading" << std::endl;
                return packet;
            }

            for (const auto& validLine : validLines) {
                outFile << validLine << std::endl;
            }
            outFile.close();

        }
    }

    packet->setData("");

    return packet;
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
    cancelAndDelete(cleanupEvent);

    ECU::finish();
}
