#include "lib/cpp-httplib/httplib.h"

int main(void) {
    using namespace httplib;

    Server svr;

    svr.Get(R"(/auth/([^/]+))", [](const Request &req, Response &res) {
        res.set_content("username", "text/plain");
    });

    svr.Get("/verify", [&](const Request &req, Response &res) {
        res.set_content("verify", "text/plain");
    });

    svr.Get("/README.txt", [](const Request &req, Response &res) {
        res.set_content("readMe", "text/plain");
    });

    svr.listen("localhost", 8080);
}
