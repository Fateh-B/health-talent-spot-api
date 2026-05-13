#include "crow_all.h"

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/health")([](){
        crow::response response(R"({"status":"ok"})");
        response.set_header("Content-Type", "application/json");
        return response;
    });

    app.port(8081).run();
}
