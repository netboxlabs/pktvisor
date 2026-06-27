#pragma once
#include <cstdint>
#include <string>

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
};
struct HttpResult {
    bool transport_ok{false};
    long curl_code{0};
    long status_code{0};
    HttpTimings timings;
};
}
