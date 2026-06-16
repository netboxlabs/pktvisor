#include <catch2/catch_test_macros.hpp>

#include <iostream>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <uvw/dns.h>
#include <uvw/tcp.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include "httpssession.h"

void connect_tcp_events(std::shared_ptr<uvw::tcp_handle> tcp_handle, std::shared_ptr<TCPSession> tcp_session)
{
    /** SOCKET CALLBACKS **/

    // SOCKET: local socket was closed, cleanup resources and possibly restart another connection
    tcp_handle->on<uvw::close_event>([](uvw::close_event &, uvw::tcp_handle &handle) {
        std::cerr << "close_event" << std::endl;
        handle.stop();
    });

    // SOCKET: socket error
    tcp_handle->on<uvw::error_event>([](uvw::error_event &event, uvw::tcp_handle &handle) {
        std::cerr << "error_event: " << handle.sock().ip << ":" << handle.sock().port << " - " << event.what() << std::endl;
        handle.close();
    });

    // INCOMING: remote peer closed connection, EOF
    tcp_handle->on<uvw::end_event>([tcp_session](uvw::end_event &, uvw::tcp_handle &) {
        std::cerr << "end_event" << std::endl;
        tcp_session->on_end_event();
    });

    // OUTGOING: we've finished writing all our data and are shutting down
    tcp_handle->on<uvw::shutdown_event>([tcp_session](uvw::shutdown_event &, uvw::tcp_handle &) {
        std::cerr << "shutdown_event" << std::endl;
        tcp_session->on_shutdown_event();
    });

    // INCOMING: remote peer sends data, pass to session
    tcp_handle->on<uvw::data_event>([tcp_session](uvw::data_event &event, uvw::tcp_handle &) {
        std::cerr << "data_event" << std::endl;
        tcp_session->receive_data(event.data.get(), event.length);
    });

    // OUTGOING: write operation has finished
    tcp_handle->on<uvw::write_event>([](uvw::write_event &, uvw::tcp_handle &) {
        std::cerr << "WriteEvent" << std::endl;
    });

    // SOCKET: on connect
    tcp_handle->on<uvw::connect_event>([tcp_session](uvw::connect_event &, uvw::tcp_handle &handle) {
        std::cerr << "ConnectEvent" << std::endl;
        // start reading from incoming stream, fires data_event when receiving
        handle.read();
        tcp_session->on_connect_event();

    });
}

TEST_CASE("HTTP Client", "[http]")
{
    auto loop = uvw::loop::get_default();

    auto family = AF_INET;

    auto svr = std::make_unique<httplib::SSLServer>(
        "/tmp/cacert.pem",
        "/tmp/cakey.pem");
    if (!svr->is_valid()) {
        std::cerr << "could not create test server" << std::endl;
        return;
    }
    auto svr_port = svr->bind_to_any_port("127.0.0.1");
    if (svr_port <= 0) {
        std::cerr << "could not bind test server" << std::endl;
        return;
    } else {
        std::cerr << "tls test server started on 127.0.0.1:" << svr_port << std::endl;
    }

    auto svr_thread = std::make_unique<std::thread>([&svr] {
       svr->listen_after_bind();
    });

    std::vector<Target> target_list;
    std::vector<std::string> raw_target_list;
    raw_target_list.emplace_back("https://127.0.0.1:" + std::to_string(svr_port));
    auto request = loop->resource<uvw::get_addr_info_req>();
    for (const auto &i : raw_target_list) {
        uvw::socket_address addr;
        struct http_parser_url parsed = {};
        std::string url = i;
        if (url.rfind("https://", 0) != 0) {
            url.insert(0, "https://");
        }
        int ret = http_parser_parse_url(url.c_str(), strlen(url.c_str()), 0, &parsed);
        if (ret != 0) {
            std::cerr << "could not parse url: " << url << std::endl;
        }
        std::string authority(&url[parsed.field_data[UF_HOST].off], parsed.field_data[UF_HOST].len);
        std::string port;
        if (parsed.field_data[UF_PORT].len) {
            port = std::string(&url[parsed.field_data[UF_PORT].off], parsed.field_data[UF_PORT].len);
        }

        auto target_resolved = request->addr_info_sync(authority, port);
        if (!target_resolved.first) {
            std::cerr << "unable to resolve target address: " << authority << std::endl;
            if (i == "file") {
                std::cerr << "(did you mean to include --targets?)" << std::endl;
            }
        }
        addrinfo *node{target_resolved.second.get()};
        while (node && node->ai_family != family) {
            node = node->ai_next;
        }
        if (!node) {
            std::cerr << "name did not resolve to valid IP address for this inet family: " << i
                      << std::endl;
            continue;
        }

        if (family == AF_INET) {
            char buffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in *>(node->ai_addr)->sin_addr, buffer, INET_ADDRSTRLEN);
            addr.ip = buffer;
        } else if (family == AF_INET6) {
            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6 *>(node->ai_addr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
            addr.ip = buffer;
        }
        target_list.push_back({&parsed, addr.ip, url, port});
    }

    if (!target_list.size()) {
        std::cerr << "no targets resolved" << std::endl;
        return;
    }

    // ---

    std::shared_ptr<TCPSession> tcp_session;
    auto tcp_handle = loop->resource<uvw::tcp_handle>(family);

    auto malformed_data = [tcp_handle]() {
        std::cerr << "malformed_data or handshake error" << std::endl;
        tcp_handle->close();
    };
    auto got_dns_message = []([[maybe_unused]] std::unique_ptr<const char[]> data,
                               [[maybe_unused]] size_t size) {
        std::cerr << "got_dns_message" << std::endl;
        // process_wire(data.get(), size);
    };
    auto connection_ready = [tcp_session]() {
        /** SEND DATA **/
        std::cerr << "connection_ready" << std::endl;
        // tcp_session->write(std::move(std::get<0>(qt)), std::get<1>(qt));
    };

    tcp_session = std::make_shared<HTTPSSession>(tcp_handle,
        malformed_data,
        got_dns_message,
        connection_ready,
        malformed_data,
        target_list[0],
        HTTPMethod::GET);
    connect_tcp_events(tcp_handle, tcp_session);
    if (!tcp_session->setup()) {
        std::cerr << "setup failed" << std::endl;
    }
    std::cerr << "connecting to " << target_list[0].address << ":" << target_list[0].port << std::endl;
    tcp_handle->connect(target_list[0].address, std::stoul(target_list[0].port));

    // ----
    CHECK(loop->run() == 0);
    loop = nullptr;
    svr->stop();
    svr_thread->join();

}
