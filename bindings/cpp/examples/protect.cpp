// Protect a (pretend) server's requests with the universal adapter.
//
//     cmake -S bindings/cpp -B target/cpp && cmake --build target/cpp
//     target/cpp/protect

#include <iostream>
#include <string>

#include "mini_waf.hpp"

// Your server's request and response types.
struct Request {
    std::string method;
    std::string target;
    std::string peer;
    std::string user_agent;
};

struct Response {
    int status = 200;
};

int main() {
    using namespace mini_waf;

    // 1. Build the WAF once, at startup.
    auto waf = create_mini_waf(
        WafConfig()
            .presets({WafPresetName::Default})
            .level(ProtectionLevel::Balanced)
            .rules({
                WafRule("allow-health",
                        FieldCondition(WafField::Path()).equals("/health"),
                        WafAction::Allow)
                    .priority(1),
            }));

    // 2. Describe your server's request / response types once.
    auto adapter = create_adapter(
        CustomAdapterHandlers<Request, Response>("example")
            .get_method([](const Request& req) { return req.method; })
            .get_url([](const Request& req) { return req.target; })
            .get_ip([](const Request& req) { return req.peer; })
            .get_headers([](const Request& req) {
                return HeaderMap{{"user-agent", req.user_agent}};
            })
            .get_raw_body([](const Request&) { return RawBody(); })
            .set_response_header(
                [](Response&, std::string_view, std::string_view) {})
            .drop([](const Request&, Response& res, std::uint16_t status,
                     std::string_view) { res.status = status; }));

    // 3. Evaluate every request.
    for (const Request& request : {
             Request{"GET", "/health", "198.51.100.4", "curl/8.0"},
             Request{"GET", "/search?q=1'%20UNION%20SELECT%201", "198.51.100.4",
                     "Mozilla/5.0"},
             Request{"GET", "/", "198.51.100.4", "sqlmap/1.7"},
         }) {
        Response response;
        auto result = waf.protect(adapter, request, response);
        std::cout << request.target << " -> " << response.status << " "
                  << (result.matched_rule ? result.matched_rule->id() : "")
                  << "\n";
    }
}
