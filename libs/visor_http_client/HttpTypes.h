#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace visor::http {

struct HttpTimings {
    uint64_t total_us{0};
    uint64_t dns_us{0};
    uint64_t connect_us{0};
    uint64_t tls_us{0};
    uint64_t ttfb_us{0};
};
struct HttpRequest {
    std::string url;
    std::string method{"GET"};
    uint64_t timeout_ms{0};
    bool follow_redirects{true};
    bool verify_tls{true};
    std::string body;                   // request body bytes (empty => no body)
    std::vector<std::string> headers;   // extra request headers, each "Key: Value"
    bool capture_response{false};       // when true, capture the response body
};
struct HttpResult {
    bool transport_ok{false};
    long curl_code{0};
    long status_code{0};
    HttpTimings timings;
    std::string response_body;          // populated only when HttpRequest.capture_response
    std::string content_type;           // raw response Content-Type header when transport_ok (compare case-insensitively)
    std::string error_msg;              // human-readable curl error detail when !transport_ok
};
}
