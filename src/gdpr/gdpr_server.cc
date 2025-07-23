#include "../include/rapidjson/document.h"
#include "../include/rapidjson/stringbuffer.h"
#include "../include/rapidjson/writer.h"
#include "../include/rapidjson/error/en.h"

#include "../clock/Clock.h"
/*


std::string sget_current_timestamp_iso8601(Clock& hw_clock) {
    time_t now_c = hw_clock.time_since_epoch();
    std::stringstream ss;
    ss << std::put_time(localtime(&now_c), "%Y-%m-%dT%H:%M:%SZ"); // iso 8601 format
    return ss.str();
}

const string HASH_SALT = "YourSuperSecretHardcodedSalt_GDPR_12345!";

std::string hash_password(const string& password) {
    size_t hashed_val = std::hash<std::string>{}(password + HASH_SALT);
    return std::to_string(hashed_val);
}

std::string createTaggedData(std::string& value, const string& tag, std::string& insetion_time)
{
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
        rapidjson::Value().SetString(tag.c_str(), tag.length()),
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


void initialize_sample_data(Clock& hw_clock)
{
    // Esempio con password al posto di user_id
    std::string clear_password_user1 = "passwordUtente123";
    std::string hashed_password_user1 = hash_password(clear_password_user1); // Hash della password

    rapidjson::Document doc_1;
    doc_1.SetObject();
    auto& alloc_1 = doc_1.GetAllocator();

    doc_1.AddMember(name, value, allocator)

    doc.AddMember(
        "email",
        rapidjson::Value().SetString(value.c_str(), value.length()),
        alloc
    );

    std::string timestamp = get_current_timestamp_iso8601(hw_clock);


    Json::Value user1_data;
    user1_data["email"] = createTaggedData("mario.rossi@example.com", "DATI_ANAGRAFICI", timestamp);
    user1_data["nome"] = createTaggedData("Mario Rossi", "DATI_ANAGRAFICI", timestamp);
    user1_data["indirizzo"] = createTaggedData("Via del corso 1, Roma", "DATI_ANAGRAFICI", timestamp);
    user1_data["data_registrazione"] =  createTaggedData("2023-01-15", "DATO_TEMPORALE", timestamp);
    user1_data["consenso_marketing"] = createTaggedData(true, "preferenze utente", timestamp);
    Json::Value preferenze_sedile_auto_user1;
    preferenze_sedile_auto_user1["posizione_orizzontale"] = 10;
    preferenze_sedile_auto_user1["inclinazione_schienale"] = 30;
    user1_data["preferenze_sedile_auto"] = createTaggedData(preferenze_sedile_auto_user1, "PREFERENZE_AUTOVETTURA", timestamp);

    std::string clear_password_user2 = "secretPass456";
    std::string hashed_password_user2 = hash_password(clear_password_user2); // Hash della password

    rapidjson::Document doc_2;
    doc_2.SetObject();
    auto& alloc_2 = doc_2.GetAllocator();

    Json::Value user2_data;
    user2_data["email"] = createTaggedData("anna.verdi@example.com", "DATI_ANAGRAFICI", timestamp);
    user2_data["nome"] = createTaggedData("Anna Verdi", "DATI_ANAGRAFICI", timestamp);
    user2_data["indirizzo"] = createTaggedData("Corso Vittorio Emanuele 100, Milano", "DATI_ANAGRAFICI", timestamp);
    user2_data["data_registrazione"] = createTaggedData("2024-03-20", "DATO_TEMPORALE", timestamp);
    user2_data["consenso_marketing"] = createTaggedData(false, "preferenze utente", timestamp);
    Json::Value preferenze_sedile_auto_user2;
    preferenze_sedile_auto_user2["posizione_orizzontale"] = 15;
    preferenze_sedile_auto_user2["inclinazione_schienale"] = 25;
    user2_data["preferenze_sedile_auto"] = createTaggedData(preferenze_sedile_auto_user2, "PREFERENZE_AUTOVETTURA", timestamp);
    user_data_store[hashed_password_user2] = user2_data; // Usa l'hash come chiave
}
*/
