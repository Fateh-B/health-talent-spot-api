#include "crow_all.h"
#include "json.hpp"
#include <cstdint>
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <map>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_document;
using json = nlohmann::json;


int main() {
    std::map<std::string, std::string> env;
    std::ifstream file(".env");
    std::string line;
    while (std::getline(file, line)) {
        auto pos = line.find('=');
        if (pos != std::string::npos) {
            env[line.substr(0, pos)] = line.substr(pos + 1);
        }
    }

    mongocxx::instance instance;

    crow::SimpleApp app;

    CROW_ROUTE(app, "/api/db-test")([env](){
        mongocxx::uri uri(env.at("MONGODB_URI"));
        mongocxx::client client(uri);

        auto db = client["User"];
        auto collection = db["user"];
        auto document = collection.find_one({});

        auto username = document->view()["username"];
        return std::string(username.get_string().value);
    });

    CROW_ROUTE(app, "/api/joboffers")([env](){
        mongocxx::uri uri(env.at("MONGODB_URI"));
        mongocxx::client client(uri);
        
        auto db = client["health_talent_spot"];
        auto collection = db["joboffers"];
        
        json jobs = json::array();

        for (auto&& doc : collection.find({})) {
            json job;
            job["title"] = std::string(doc["title"].get_string().value);
            job["sector"] = std::string(doc["sector"].get_string().value);
            job["specialty"] = std::string(doc["specialty"].get_string().value);
            job["location"] = std::string(doc["location"].get_string().value);
            job["contractType"] = std::string(doc["contractType"].get_string().value);
            job["salary"] = doc["salary"].get_int32().value;
            job["experience"] = std::string(doc["experience"].get_string().value);
            job["genderPreference"] = std::string(doc["genderPreference"].get_string().value);
            job["description"] = std::string(doc["description"].get_string().value);
            job["requiredSkills"] = std::string(doc["requiredSkills"].get_string().value);
            job["recruiterId"] = std::string(doc["recruiterId"].get_string().value);
            // job["postedDate"] = doc["postedDate"].get_date().value.to_string();
            job["postedDate"] = "Récemment";
            job["applicants"] = doc["applicants"].get_int32().value;
            // job["rating"] = doc["rating"].get_double().value;
            job["rating"] = 4.5;
            jobs.push_back(job);
        }
        return crow::response(jobs.dump());
    });

    app.port(3000).run();
}
