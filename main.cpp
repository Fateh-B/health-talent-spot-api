#include "crow_all.h"

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/health")([](){
        return "hello from C++ api";
    });

    app.port(8081).run();
}
