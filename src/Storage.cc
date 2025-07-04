#include "def.h"
#include "Storage.h"

namespace fs = std::filesystem;

Define_Module(Storage);
#define INIT_FAILURE_STATE 500

void Storage::additional_initialize()
{
    numEcu = par("numECUs");
    fs::path storageBasePath = "storage";

    //Initialize pulizia.
    int checkInterval_t = par("checkInterval");
    int dataLifeTime_t = par("dataLifeTime");
    checkInterval = SimTime(checkInterval_t, SIMTIME_S);
    dataLifetime = SimTime(dataLifeTime_t, SIMTIME_S);

    EV_INFO << "[Storage] Pulizia periodica configurata. Controllo ogni: " << checkInterval
            << ", Durata dati: " << dataLifetime << endl;

    if(id == 7) {
        failureEvent = new Packet("failureEvent");
        failureEvent->setType(INIT_FAILURE_STATE);
        scheduleAt(simTime() + SimTime(static_cast<double>(12), SIMTIME_MS), failureEvent);
    }

    cleanupEvent = new Packet("periodicCleanup");
    cleanupEvent->setType(CLEAN_UP_EVENT);
    scheduleAt(simTime() + checkInterval, cleanupEvent);

    //Initialize file
    try {

        fs::create_directory(storageBasePath);
        EV << "[Storage] Directory di base per i log: '" << storageBasePath << "' assicurata.\n";

    } catch (const fs::filesystem_error& e) {
        throw cRuntimeError("Errore nella creazione della directory di base '%s': %s",
                            storageBasePath.c_str(), e.what());
    }


    // Creiamo le directory per ogni ECU
    for (int i = 1; i <= numEcu; ++i) {

        fs::path ecuDirPath = storageBasePath / ("ecu" + std::to_string(i));

        try {

            fs::create_directory(ecuDirPath);

        } catch (const fs::filesystem_error& e) {
            throw cRuntimeError("Errore nella creazione della directory per ECU %d ('%s'): %s",
                                i, ecuDirPath.c_str(), e.what());
        }


        // Percorso completo per il file PUBLIC
        fs::path publicFilePath = ecuDirPath / "public_log.txt";
        publicFileStreams[i].open(publicFilePath, std::ios_base::app);
        if (!publicFileStreams[i].is_open()) {
            throw cRuntimeError("Impossibile aprire il file di log pubblico: %s", publicFilePath.c_str());
        }
        EV << "[Storage] File di log pubblico creato: " << publicFilePath << "\n";

        // Percorso completo per il file PRIVATE
        fs::path privateFilePath = ecuDirPath / "private_log.txt";
        privateFileStreams[i].open(privateFilePath, std::ios_base::app);
        if (!privateFileStreams[i].is_open()) {
            throw cRuntimeError("Impossibile aprire il file di log privato: %s", privateFilePath.c_str());
        }
        EV << "[Storage] File di log privato creato: " << privateFilePath << "\n";
    }
}

void Storage::additional_handleMessage(cMessage *msg)
{
    if(msg == failureEvent) {
        initFailureState();
        return;
    }

    //Self messagge pulizia
    if (msg == cleanupEvent) {
        EV_INFO << "[Storage] Evento di pulizia attivato al tempo: " << simTime() << endl;

        // Calcoliamo la soglia di scadenza
        simtime_t expirationThreshold = simTime() - dataLifetime;

        // Eseguiamo la pulizia per ogni ECU
        for (int i = 1; i <= numEcu; ++i) {
            cleanupLogFile(i, "Public");
            cleanupLogFile(i, "Private");
        }

        // Riprogrammiamo per la prossima volta
        scheduleAt(simTime() + checkInterval, cleanupEvent);
        return;
    }

    Packet *packet = dynamic_cast<Packet *>(msg);
    if (!packet) {
        ECU::handleMessage(msg);
        EV_ERROR << "[Storage] Errore: ricevuto un messaggio che non è di tipo Packet. Messaggio ignorato.\n";
        //delete msg;
        return;
    }

    int type = packet->getType();
        switch(type) {
            case REQUEST_STORAGE: {
                if (tpm_access->getSessionKeyHandle(HSM_TOPOLOGICAL_ID) == nullptr) {
                    EV_WARN << "[Storage " << id << "] Non ho ancora una chiave di sessione con l'HSM. Messaggio scartato";
                    return;
                }
                    storeData(packet);
                }break;
            case REQUEST_STORAGE_DATA:{
                packet = readDataFile(packet);
                send(packet, "toGateway");
            }break;
            case PING_MSG:{
                pingWithGateway(packet);
            }break;
            default: {

                }break;
        }
}

void Storage::pingWithGateway(Packet *package){

    if (package->getType() == PING_MSG) {
        EV << "[Storage " << getIndex() << "] Ricevuto Ping. Invio risposta.\n";
        Packet *response = new Packet();
        response->setType(PONG_MSG);
        response->setSrcId(getIndex());
        response->setDstId(package->getSrcId());
        response->setData("true");
        send(response, "toGateway");

        return;
    }
}

void Storage::storeData(Packet *packet){
    int sourceId = packet->getSrcId();
    std::string payload = packet->getData();
    PrivacyLevel privacy = 1; //packet->getPrivacyLevel();

    EV << "[Storage] Ricevuto messaggio da ECU " << sourceId << " con payload: '" << payload << "'\n";

    //Ricezione packet
    receiveEncPacket(packet, sourceId);

    //Cifratura payaload
    AesEncryptedMessage aes_msg = encrypt_message_aes(
        (unsigned char*)payload.c_str(),
        payload.length(),
        tpm_access->getSessionKeyHandle(HSM_TOPOLOGICAL_ID)
    );
        //Serializzazione

        std::string iv_b64 = base64_encode(aes_msg.iv, IV_LEN);
        std::string tag_b64 = base64_encode(aes_msg.tag, TAG_LEN);
        std::string ciphertext_b64 = base64_encode(aes_msg.ciphertext, aes_msg.ciphertext_len);

        std::string storable_data = iv_b64 + ":" + tag_b64 + ":" + ciphertext_b64;

    std::fstream *targetStream = nullptr;
    //Cerca il relativo file Publico o Privato
    if (privacy == PUBLIC_DATA) {
        auto it = publicFileStreams.find(sourceId);
        if (it != publicFileStreams.end()) {
            targetStream = &(it->second);
        }
    } else if (privacy == PRIVATE_DATA) {
        auto it = privateFileStreams.find(sourceId);
        if (it != privateFileStreams.end()) {
            targetStream = &(it->second);
        }
    }

    if (targetStream && targetStream->is_open()) {
        *targetStream << simTime() << " | " << storable_data << std::endl;
    } else {
        EV_WARN << "[Storage] Ricevuto messaggio da ECU " << sourceId
                << ", ma non è stato trovato un file di log corrispondente. Messaggio ignorato.\n";
    }

    free(aes_msg.ciphertext);
}

Packet *Storage::readDataFile(Packet *packet){
    int sourceId = packet->getSrcId();
    PrivacyLevel privacy = 1;//packet->getPrivacyLevel();
    std::string readFile = nullptr;

    std::fstream *ReadStream = nullptr;
    if (privacy == PUBLIC_DATA) {
        auto it = publicFileStreams.find(sourceId);
        if (it != publicFileStreams.end()) {
            ReadStream = &(it->second);
        }
    } else if (privacy == PRIVATE_DATA) {
        auto it = privateFileStreams.find(sourceId);
        if (it != privateFileStreams.end()) {
            ReadStream = &(it->second);
        }
    }

    if (ReadStream && ReadStream->is_open()) {
       while(std::getline(*ReadStream, readFile));
    } else {
        EV_WARN << "[Storage] Ricevuto messaggio da ECU " << sourceId
                << ", ma non è stato trovato un file di log corrispondente. Messaggio ignorato.\n";
    }

   packet->setSrcId(id);
   packet->setDstId(sourceId);
   packet->setData(readFile.c_str());
   packet->setType(STORAGE_RETRIEVE_DATA);

   return packet;
}
//Funzione clean
void Storage::cleanupLogFile(int ecuId, const std::string& type) {
    fs::path storageBasePath = "storage";
    fs::path ecuDirPath = storageBasePath / ("ecu" + std::to_string(ecuId));
    fs::path filePath;
    std::fstream* fileStream = nullptr;

    if (type == "Public") {
        filePath = ecuDirPath / "public_log.txt";
        fileStream = &publicFileStreams.at(ecuId);
    } else if (type == "Private") {
        filePath = ecuDirPath / "private_log.txt";
        fileStream = &privateFileStreams.at(ecuId);
    } else {
        return;
    }

    EV_INFO << "[Storage] Inizio pulizia file: " << filePath << endl;

    if (fileStream->is_open()) {
        fileStream->close();
    }

    // Apriamo per leggere e filtrare le righe
    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        EV_ERROR << "[Storage] Impossibile riaprire " << filePath << " per la lettura durante la pulizia.";

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
                EV_DETAIL << "[Storage] Dato scaduto eliminato da " << filePath << ": " << line;
            }
        } catch (const cException& e) {
            EV_WARN << "[Storage] Impossibile parsare la data nella riga: '" << line << "'. La riga sarà conservata.";
            validLines.push_back(line);
        }
    }
    inFile.close();

    //Riscriviamo il file con solo le righe valide
    std::ofstream outFile(filePath, std::ios::trunc); // Cancella il contenuto
    if (!outFile.is_open()) {
        EV_ERROR << "[Storage] Impossibile aprire " << filePath << " in scrittura per la pulizia!";

        fileStream->open(filePath, std::ios_base::app);
        return;
    }

    for (const auto& validLine : validLines) {
        outFile << validLine << std::endl;
    }
    outFile.close();

    //Riapriamo lo stream originale in modalità append per la mappa
    fileStream->open(filePath, std::ios_base::app);
    if (!fileStream->is_open()) {
         throw cRuntimeError("Fallimento critico: impossibile ripristinare lo stream del log per %s", filePath.c_str());
    }

    EV_INFO << "[Storage] Pulizia file " << filePath << " completata. Righe valide: " << validLines.size() << std::endl;
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

    EV << "[Storage] Simulazione terminata. Chiudo tutti i file di log.\n";

    cancelAndDelete(cleanupEvent);

    for (auto& pair : publicFileStreams) {
        if (pair.second.is_open()) {
            pair.second.close();
        }
    }
    for (auto& pair : privateFileStreams) {
        if (pair.second.is_open()) {
            pair.second.close();
        }
    }
    ECU::finish();
}
