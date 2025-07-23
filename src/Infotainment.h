#ifndef __PROGETTO_INFOTAINMENT_H_
#define __PROGETTO_INFOTAINMENT_H_

#include "ECU.h"

#include <omnetpp.h>
#include "Packet_m.h"
#include "common/common.h"
#include <unordered_map>

const std::string HASH_SALT = "YourSuperSecretHardcodedSalt_GDPR_12345!";

using namespace omnetpp;

class Infotainment : public ECU
{
private:
    std::unordered_map<std::string, std::string> rules;
    std::unordered_map<std::tuple<std::string, std::string>, int, TupleHash> user_data_store; // passowrd_hash and email mapped to id

    Packet *gdpr_test = nullptr;
    std::string pending_email = "";

protected:
    bool loadFilterRules();
    bool webAccess(std::string uri);
    void sendNewRoutingRule(int src, int dst, bool isAccepted);

    void GDPR_request_handler(int gdpr_rigth_req, std::string params_json);
    void test_gdpr_requests(Packet *pkg);

    void additional_initialize() override;
    void additional_handleMessage(cMessage *msg) override;

    void handle_article_15_access(int user_id);
    void handle_article_16_rectification(Packet* pkg, std::string email, std::string hashed_password);
    void handle_article_17_erasure_with_check(std::string email, std::string hashed_password);
    void handle_article_18_restriction(Packet* pkg, std::string email, std::string hashed_password);
    void handle_article_20_portability(int user_id);
    void handle_article_21_objection(Packet* pkg, std::string email, std::string hashed_password);
    void handle_article_22_automated_decision(Packet* pkg, std::string email, std::string hashed_password);
    void handle_article_23_data_export(int user_id, std::string email);


    void initialize_sample_data();
    std::string hash_password(const std::string& password);
};

#endif
