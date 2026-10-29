#include "DnstapInputStream.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/catch_test_visor.hpp>

using namespace visor::input::dnstap;
using namespace std::chrono;

// bidirectional: READY with dnstap content-type
static uint8_t bi_frame_1_len42[] = {
    0x00, 0x00, 0x00, 0x00, // escape: expect control frame
    0x00, 0x00, 0x00, 0x22, // control frame length 0x22 == 34 bytes
    // control frame 34 bytes. READY and content type
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x70, 0x72, 0x6f, 0x74,
    0x6f, 0x62, 0x75, 0x66, 0x3a, 0x64, 0x6e, 0x73, 0x74, 0x61, 0x70, 0x2e, 0x44, 0x6e, 0x73, 0x74,
    0x61, 0x70};

static uint8_t bi_frame_2_len12[] = {
    0x00, 0x00, 0x00, 0x00, // escape
    0x00, 0x00, 0x00, 0x04, // length 4 bytes
    0x00, 0x00, 0x00, 0x02  // START
};

static uint8_t bi_frame_2_ready_len12[] = {
    0x00, 0x00, 0x00, 0x00, // escape
    0x00, 0x00, 0x00, 0x04, // length 4 bytes
    0x00, 0x00, 0x00, 0x01  // ACCEPT
};

static uint8_t bi_frame_3_len400[] = {
    0x00, 0x00, 0x00, 0x45, 0x72, 0x41, 0x08, 0x05, 0x10, 0x01, 0x18, 0x01, 0x22, 0x04, 0x7f, 0x00, 0x00,
    0x01, 0x30, 0xb4, 0xce, 0x03, 0x40, 0xb0, 0xdf, 0xed, 0x8d, 0x06, 0x4d, 0x98, 0xdb, 0xee, 0x01,
    0x52, 0x24, 0x88, 0x61, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x66,
    0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x59, 0x72, 0x55, 0x08, 0x07,
    0x10, 0x01, 0x18, 0x01, 0x22, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x2a, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x08, 0x08, 0x08, 0x08, 0x30, 0xb4, 0xce, 0x03,
    0x38, 0x35, 0x40, 0xb0, 0xdf, 0xed, 0x8d, 0x06, 0x4d, 0xd8, 0xd0, 0xf5, 0x01, 0x52, 0x24, 0x88,
    0x61, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x66, 0x6f, 0x6f, 0x03,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x7b, 0x72, 0x77, 0x08, 0x08, 0x10, 0x01, 0x18,
    0x01, 0x22, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x2a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xff, 0x08, 0x08, 0x08, 0x08, 0x30, 0xb4, 0xce, 0x03, 0x38, 0x35, 0x40,
    0xb0, 0xdf, 0xed, 0x8d, 0x06, 0x4d, 0xd8, 0xd0, 0xf5, 0x01, 0x60, 0xb0, 0xdf, 0xed, 0x8d, 0x06,
    0x6d, 0xf8, 0xa2, 0xc2, 0x06, 0x72, 0x3b, 0x88, 0x61, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x03, 0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x03, 0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x04, 0x22, 0xce, 0x27, 0x99, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x67, 0x72, 0x63, 0x08, 0x06, 0x10, 0x01, 0x18, 0x01,
    0x22, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0xb4, 0xce, 0x03, 0x40, 0xb0, 0xdf, 0xed, 0x8d, 0x06,
    0x4d, 0x98, 0xdb, 0xee, 0x01, 0x60, 0xb0, 0xdf, 0xed, 0x8d, 0x06, 0x6d, 0x18, 0x6e, 0xc3, 0x06,
    0x72, 0x3b, 0x88, 0x61, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03, 0x66,
    0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0x66, 0x6f, 0x6f, 0x03,
    0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x22, 0xce,
    0x27, 0x99, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x01};

struct MockClient {
    std::unique_ptr<char[]> data;
    unsigned int len;
    void write(std::unique_ptr<char[]> d, unsigned int l)
    {
        data = std::move(d);
        len = l;
    }
};

TEST_CASE("bi-directional frame stream process", "[dnstap][frmstrm]")
{
    bool data_frame_parsed{false};
    int df_count{0};
    auto on_data_frame = [&data_frame_parsed, &df_count](const void *data, std::size_t len_data) {
        data_frame_parsed = true;
        df_count++;
        ::dnstap::Dnstap d;
        CHECK(d.ParseFromArray(data, len_data) == true);
        CHECK(d.has_type() == true);
        CHECK(d.type() == ::dnstap::Dnstap_Type_MESSAGE);
        CHECK(d.has_message() == true);
    };

    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, on_data_frame);
#ifdef _WIN32
    CHECK_THROWS_WITH(session.receive_socket_data(bi_frame_1_len42, 42), "Dnstap not supported on Windows OS");
    return;
#endif
    CHECK_NOTHROW(session.receive_socket_data(bi_frame_1_len42, 42));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Ready);
    CHECK(session.is_bidir() == true);
    CHECK(std::memcmp(client->data.get(), bi_frame_2_ready_len12, 12) == 0);

    CHECK_NOTHROW(session.receive_socket_data(bi_frame_2_len12, 12));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Running);

    CHECK_NOTHROW(session.receive_socket_data(bi_frame_3_len400, 400));
    CHECK(data_frame_parsed == true);
    CHECK(df_count == 4);
}

TEST_CASE("dnstap file", "[dnstap][file]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");

    stream.start();
    stream.stop();
}

TEST_CASE("dnstap tcp socket", "[dnstap][tcp]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("tcp", "127.0.0.1:5353");
    stream.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24", "2001:db8::/48"});

    stream.start();
    stream.stop();
}

TEST_CASE("dnstap unix socket", "[dnstap][unix]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", "/tmp/dnstap-test.sock");

    stream.start();
    stream.stop();
}

TEST_CASE("dnstap tcp socket on a port in use fails to start", "[dnstap][tcp]")
{
    DnstapInputStream first{"dnstap-first"};
    first.config_set("tcp", "127.0.0.1:5354");
    REQUIRE_NOTHROW(first.start());

    // the second server must fail rather than run without listening on the port
    DnstapInputStream second{"dnstap-second"};
    second.config_set("tcp", "127.0.0.1:5354");
    CHECK_THROWS_WITH(second.start(), Catch::Matchers::ContainsSubstring("dnstap server on 127.0.0.1:5354: address already in use"));
    CHECK_FALSE(second.running());
    CHECK_NOTHROW(second.stop());

    CHECK(first.running());
    CHECK_NOTHROW(first.stop());
}

TEST_CASE("dnstap unix socket that cannot be bound fails to start", "[dnstap][unix]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", "/nonexistent-pktvisor-dir/dnstap-test.sock");

    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::StartsWith("unable to bind dnstap server on /nonexistent-pktvisor-dir/dnstap-test.sock: "));
    CHECK_FALSE(stream.running());
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("dnstap file filter by valid subnet", "[dnstap][file][filter][!mayfail]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    uint64_t count_callbacks = 0;
    visor::Config filter;
    filter.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24"});
    auto stream_proxy = stream.add_event_proxy(filter);
    DnstapInputEventProxy *callback = static_cast<DnstapInputEventProxy *>(stream_proxy);

    callback->dnstap_signal.connect([&]([[maybe_unused]] const ::dnstap::Dnstap &d, [[maybe_unused]] size_t size) {
        ++count_callbacks;
        return;
    });

    stream.start();
    std::this_thread::sleep_for(200ms);
    stream.stop();

    CHECK(count_callbacks == 153);
}

TEST_CASE("dnstap file filter by invalid subnet", "[dnstap][file][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("dnstap_file", "inputs/dnstap/tests/fixtures/fixture.dnstap");
    uint64_t count_callbacks = 0;
    visor::Config filter;
    filter.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.12/32"});
    auto stream_proxy = stream.add_event_proxy(filter);
    DnstapInputEventProxy *callback = static_cast<DnstapInputEventProxy *>(stream_proxy);

    callback->dnstap_signal.connect([&]([[maybe_unused]] const ::dnstap::Dnstap &d, [[maybe_unused]] size_t size) {
        ++count_callbacks;
        return;
    });

    stream.start();
    stream.stop();

    CHECK(count_callbacks == 0);
}

TEST_CASE("dnstap invalid filters", "[dnstap][tcp][filter]")
{
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("tcp", "127.0.0.1:5353");
    visor::Config filter;
    SECTION("invalid ipv4 cidr")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/24/12ac"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid CIDR: 192.168.0.0/24/12ac");
    }

    SECTION("ipv4 cidr over max value")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.0.0/64"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid CIDR: 192.168.0.0/64");
    }

    SECTION("invalid ipv4 ip")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"192.168.AE.0/24"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid IPv4 address: 192.168.AE.0");
    }

    SECTION("invalid ipv6 cidr")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"2001:db8::/48/12ac"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid CIDR: 2001:db8::/48/12ac");
    }

    SECTION("ipv6 cidr over max value")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"2001:db8::/256"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid CIDR: 2001:db8::/256");
    }

    SECTION("invalid ipv6 ip")
    {
        filter.config_set<visor::Configurable::StringList>("only_hosts", {"fe80:2030:31:24/12"});
        REQUIRE_THROWS_WITH(stream.add_event_proxy(filter), "invalid IPv6 address: fe80:2030:31:24");
    }
}
