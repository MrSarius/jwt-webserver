#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <string>
#include <iostream>


int main(void) {
    using namespace httplib;

    Server svr;
    const std::string pubKey = "-----BEGIN PUBLIC KEY-----\n"
                               "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAc+95gTomCPtOtnF2pZA/P31O9Jij6nbr\n"
                               "1ndI7hHsep/cBcxJWyle0vepFi5qdrnMYnMN+18eayuhMOjTZAgcuQIDAQAB\n"
                               "-----END PUBLIC KEY-----";

    const std::string priKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                               "MIIBOQIBAAJAc+95gTomCPtOtnF2pZA/P31O9Jij6nbr1ndI7hHsep/cBcxJWyle\n"
                               "0vepFi5qdrnMYnMN+18eayuhMOjTZAgcuQIDAQABAkBSidGVYRKnHlOhrBHuOU3u\n"
                               "I4ZMuUcpq9SncXEonPYhLia3gbhXWPKCHMYaL+zeHP8o6uBUSwFGEz/IQ7SExfIB\n"
                               "AiEA2IQhAOuNgGRkl8E6F52s7XRGPZTBYgSLhtFhf7vcPWECIQCJE9KAwcVnfBY1\n"
                               "3kPlvQv2yYMziimxpBW9RuVgRhaGWQIgQrBf4gKrsPI7Marok8GTNAhuYiVhcyln\n"
                               "OH1hhJB+g8ECIFKf5x+DLQj+i6i2q7h75g1AU9wqKI2R+SSY6kPIm2UpAiEA05et\n"
                               "x16bseIO9P+g+x7yljWsceZ+/+pw4pQnyRJTT30=\n"
                               "-----END RSA PRIVATE KEY-----";

    svr.Get(R"(/auth/([^/]+))", [&](const Request &req, Response &res) {
        auto token = jwt::create()
                .set_issuer("auth0")
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{86400}) //86400s -> 24h
                .sign(jwt::algorithm::rs256{pubKey, priKey});

        res.set_header("Set-Cookie", "token=" + token + "; HttpOnly; Path=/");
        res.set_content(token, "text/plain");
    });

    svr.Get("/verify", [&](const Request &req, Response &res) {
        try {
            std::string token = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE2MzgwNTUyMTYsImlhdCI6MTYznzk2ODgxNiwiaXNzIjoiYXV0aDAifQ.NHfxsZwDJMVfIDbCm88RIOE13o5EMjCqOdfW3BhfDup40H0xoZejgiBD_4RMPHj4XYX4SQJ8BHqcSFttcLb-BQ";
            auto decoded = jwt::decode(token);
            for (auto &e: decoded.get_payload_claims())
                std::cout << e.first << " = " << e.second << std::endl;

            auto verifier = jwt::verify()
                    .allow_algorithm(jwt::algorithm::rs256{pubKey, priKey})
                    .with_issuer("auth0");
            verifier.verify(decoded);
        } catch (const std::exception &e) {
            res.set_content("invalid", "text/plain");
        }
        res.set_content("valid", "text/plain");
    });

    svr.Get("/README.txt", [](const Request &req, Response &res) {
        res.set_content("readMe", "text/plain");
    });

    svr.set_exception_handler([](const auto &req, auto &res, std::exception &e) {
        res.status = 500;
        auto fmt = "<h1>Error 500</h1><p>%s</p>";
        char buf[256];
        snprintf(buf, sizeof(buf), fmt, e.what());
        res.set_content(buf, "text/html");
    });

    svr.listen("localhost", 8080);
}
