#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <string>
#include <exception>
#include <filesystem>

std::string getTokenFromCookies(std::string cookies) {
    size_t pos{};
    size_t index{};
    std::string cookie;
    std::string delim{"; "};

    while (true) {
        pos = cookies.find(delim);

        if (pos == std::string::npos) {
            index = cookies.length();
        } else {
            index = pos;
        }
        cookie = cookies.substr(0, index);
        if (cookie.find("token=") == 0) {
            return cookies.substr(6);
        }
        if (pos == std::string::npos) {
            return "";
        }
        cookies.erase(0, pos + delim.length());
    }
}


int main() {
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
        std::string username = req.path.substr(req.path.find("/auth/") + 6, req.path.size());
        auto token = jwt::create()
                .set_issuer("auth0")
                .set_type("JWT")
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{86400}) //86400s -> 24h
                .set_subject(username)
                .sign(jwt::algorithm::rs256{"", priKey, "", ""});

        res.set_header("Set-Cookie", "token=" + token + "; HttpOnly; Path=/");
        res.set_content(pubKey, "text/plain");
    });

    svr.Get("/verify", [&](const Request &req, Response &res) {

        if (!req.has_header("Cookie")) {
            res.status = 400;
            res.set_content("No token sent with cookies", "text/plain");
            return;
        }

        std::string token{getTokenFromCookies(req.get_header_value("Cookie"))};

        if (token.empty()) {
            res.status = 400;
            res.set_content("No token sent with cookies", "text/plain");
            return;
        }
        try {
            auto verifier = jwt::verify()
                    .allow_algorithm(jwt::algorithm::rs256{pubKey, "", "", ""})
                    .with_issuer("auth0");
            auto decoded = jwt::decode(token);
            verifier.verify(decoded);
            std::string username = decoded.get_payload_claim("sub").as_string();
            res.set_content(username, "text/plain");
        } catch (const std::exception &e) {
            res.status = 400;
            res.set_content("JWT token was not valid", "text/plain");
            return;
        }
    });

    svr.Get("/stats", [](const Request &req, Response &res) {
        res.set_content("Not Yet Implemented", "text/plain");
    });

    svr.set_mount_point("/", "../static");
    svr.set_file_extension_and_mimetype_mapping("txt", "text/plain");

    svr.set_exception_handler([](const auto &req, auto &res, std::exception &e) {
        res.status = 500;
        res.set_content("Internal Error", "text/plain");
    });

    svr.listen("localhost", 8080);
}
