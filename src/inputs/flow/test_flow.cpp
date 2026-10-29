#include "FlowInputStream.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/catch_test_visor.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <uvw/loop.h>
#include <uvw/udp.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#include <cstring>
#include <mutex>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/UdpLayer.h>
#include <vector>

using namespace visor::input::flow;

TEST_CASE("sflow pcap file", "[flow][sflow][file]")
{

    FlowInputStream stream{"sflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/ecmp.pcap");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "flow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/ecmp.pcap");
}

TEST_CASE("netflow pcap file", "[flow][netflow][file]")
{

    FlowInputStream stream{"netflow-test"};
    stream.config_set("pcap_file", "tests/fixtures/nf9.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    CHECK(stream.schema_key() == "flow");
    CHECK(stream.consumer_count() == 0);

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
    CHECK(j["module"]["config"]["pcap_file"] == "tests/fixtures/nf9.pcap");
}

TEST_CASE("sflow udp socket", "[sflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6343;

    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("bind", bind);
    stream.config_set("port", port);

    CHECK_NOTHROW(stream.start());

    auto loop = uvw::loop::get_default();
    auto client = loop->resource<uvw::udp_handle>();
    client->on<uvw::send_event>([](const uvw::send_event &, uvw::udp_handle &handle) {
        handle.close();
    });
    auto dataSend = std::unique_ptr<char[]>(new char[2]{'b', 'c'});
    client->send(uvw::socket_address{bind, static_cast<unsigned int>(port)}, dataSend.get(), 2);
    client->send(bind, port, nullptr, 0);

    uv_sleep(100);

    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 1);
}

TEST_CASE("netflow udp socket", "[netflow][udp]")
{

    std::string bind = "127.0.0.1";
    uint64_t port = 6344;

    FlowInputStream stream{"netflow-test"};
    stream.config_set("flow_type", "netflow");
    stream.config_set("bind", bind);
    stream.config_set("port", port);

    CHECK_NOTHROW(stream.start());

    auto loop = uvw::loop::get_default();
    auto client = loop->resource<uvw::udp_handle>();
    client->on<uvw::send_event>([](const uvw::send_event &, uvw::udp_handle &handle) {
        handle.close();
    });
    auto dataSend = std::unique_ptr<char[]>(new char[2]{'b', 'c'});
    client->send(uvw::socket_address{bind, static_cast<unsigned int>(port)}, dataSend.get(), 2);
    client->send(bind, port, nullptr, 0);

    uv_sleep(100);

    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 1);
}

TEST_CASE("sflow udp socket without bind", "[flow][sflow][udp]")
{
    FlowInputStream stream{"sflow-test"};
    stream.config_set("flow_type", "sflow");

    CHECK_THROWS_WITH(stream.start(), "flow config must specify port and bind");
}

TEST_CASE("flow udp socket on a port in use fails to start", "[flow][udp]")
{
    std::string bind = "127.0.0.1";
    uint64_t port = 6345;

    FlowInputStream first{"flow-first"};
    first.config_set("flow_type", "sflow");
    first.config_set("bind", bind);
    first.config_set("port", port);
    REQUIRE_NOTHROW(first.start());

    // the second listener must fail rather than run on a socket that never gets the port's datagrams
    FlowInputStream second{"flow-second"};
    second.config_set("flow_type", "netflow");
    second.config_set("bind", bind);
    second.config_set("port", port);
    CHECK_THROWS_WITH(second.start(), Catch::Matchers::StartsWith("unable to bind flow UDP server on 127.0.0.1:6345: ") && Catch::Matchers::ContainsSubstring("address already in use"));
    CHECK_FALSE(second.running());
    CHECK_NOTHROW(second.stop());

    CHECK(first.running());
    CHECK_NOTHROW(first.stop());
}

TEST_CASE("flow udp socket on an IPv6 address", "[flow][udp][ipv6]")
{
    uint64_t port = 6347;

    FlowInputStream stream{"flow-ipv6"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("bind", "::1");
    stream.config_set("port", port);

    std::mutex samples_mutex;
    std::vector<SFLAddress> sources;
    auto proxy = static_cast<FlowInputEventProxy *>(stream.add_event_proxy(visor::Configurable()));
    proxy->sflow_signal.connect([&](const SFSample &sample, std::size_t) {
        std::lock_guard lock(samples_mutex);
        sources.push_back(sample.sourceIP);
    });
    REQUIRE_NOTHROW(stream.start());

    // a valid sFlow datagram, from ::1 to [::1]:6347: the listener only gets it if it is bound there
    auto reader = std::unique_ptr<pcpp::IFileReaderDevice>(pcpp::IFileReaderDevice::getReader("tests/fixtures/sflow_keyed.pcap"));
    REQUIRE(reader->open());
    pcpp::RawPacket raw;
    REQUIRE(reader->getNextPacket(raw));
    pcpp::Packet packet(&raw);
    auto udp = packet.getLayerOfType<pcpp::UdpLayer>();
    REQUIRE(udp);
    sockaddr_in6 to{};
    REQUIRE(uv_ip6_addr("::1", static_cast<int>(port), &to) == 0);
    auto client = uvw::loop::get_default()->resource<uvw::udp_handle>();
    auto len = static_cast<unsigned int>(udp->getLayerPayloadSize());
    CHECK(client->try_send(reinterpret_cast<const sockaddr &>(to), reinterpret_cast<char *>(udp->getLayerPayload()), len) == static_cast<int>(len));
    client->close();

    uv_sleep(100);
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);

    // the sample carries the IPv6 sender
    std::lock_guard lock(samples_mutex);
    REQUIRE(sources.size() == 1);
    CHECK(sources[0].type == SFLADDRESSTYPE_IP_V6);
    in6_addr loopback{};
    REQUIRE(uv_inet_pton(AF_INET6, "::1", &loopback) == 0);
    CHECK(std::memcmp(&sources[0].address.ip_v6.addr, &loopback, 16) == 0);
}

TEST_CASE("flow udp socket bind must be an address", "[flow][udp]")
{
    FlowInputStream stream{"flow-hostname"};
    stream.config_set("flow_type", "sflow");
    stream.config_set("bind", "localhost");
    stream.config_set("port", static_cast<uint64_t>(6348));

    CHECK_THROWS_WITH(stream.start(), "flow bind \"localhost\" is not an IPv4 or IPv6 address");
    CHECK_FALSE(stream.running());
}

TEST_CASE("flow udp socket port must be 1-65535", "[flow][udp]")
{
    for (uint64_t port : {uint64_t{0}, uint64_t{70000}}) {
        FlowInputStream stream{"flow-port"};
        stream.config_set("flow_type", "sflow");
        stream.config_set("bind", "127.0.0.1");
        stream.config_set("port", port);

        CHECK_THROWS_WITH(stream.start(), fmt::format("flow port {} is out of range 1-65535", port));
        CHECK_FALSE(stream.running());
    }
}

TEST_CASE("netflow v9 with options flowset does not cause packet errors", "[flow][netflow][options-flowset]")
{
    // Fixture carries two datagrams: one with a real data flowset alongside
    // an options flowset (options template id 256) that pktvisor now
    // parses and recognizes, and one that is a pure template refresh with
    // zero data flowsets. Neither should be counted as a parse error.
    FlowInputStream stream{"netflow-options-test"};
    stream.config_set("pcap_file", "tests/fixtures/nf9_options.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
}

TEST_CASE("ipfix with options set does not cause packet errors", "[flow][netflow][options-flowset]")
{
    FlowInputStream stream{"ipfix-options-test"};
    stream.config_set("pcap_file", "tests/fixtures/ipfix_options.pcap");
    stream.config_set("flow_type", "netflow");

    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());

    nlohmann::json j;
    stream.info_json(j);
    CHECK(j["flow"]["packet_errors"] == 0);
}
