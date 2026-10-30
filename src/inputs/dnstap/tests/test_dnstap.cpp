#include "DnstapInputStream.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <catch2/catch_test_visor.hpp>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

using namespace visor::input::dnstap;
using namespace std::chrono;

#ifndef _WIN32
namespace {
int dnstap_clients(const DnstapInputStream &stream)
{
    nlohmann::json j;
    stream.info_json(j);
    return j["dnstap"].is_object() ? j["dnstap"].value("clients", -1) : -1;
}

// the server accepts and drops clients on its own loop thread, so give it up to 2 s to settle
int wait_for_clients(const DnstapInputStream &stream, int want)
{
    int clients = dnstap_clients(stream);
    for (int i = 0; i < 200 && clients != want; ++i) {
        std::this_thread::sleep_for(10ms);
        clients = dnstap_clients(stream);
    }
    return clients;
}

int connect_tcp(uint16_t port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (fd >= 0 && ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

sockaddr_un unix_address(const std::string &path)
{
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    return addr;
}

int connect_unix(const std::string &path)
{
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    auto addr = unix_address(path);
    if (fd >= 0 && ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::basic_string<uint8_t> control_frame(fstrm_control_type type, const std::vector<std::string> &content_types)
{
    control_ptr c{fstrm_control_init()};
    REQUIRE(fstrm_control_set_type(c.get(), type) == fstrm_res_success);
    for (const auto &content_type : content_types) {
        REQUIRE(fstrm_control_add_field_content_type(c.get(), reinterpret_cast<const uint8_t *>(content_type.data()), content_type.size()) == fstrm_res_success);
    }
    uint8_t frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
    size_t len = sizeof(frame);
    REQUIRE(fstrm_control_encode(c.get(), frame, &len, FSTRM_CONTROL_FLAG_WITH_HEADER) == fstrm_res_success);
    return {frame, len};
}
}
#endif

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

static uint8_t bi_frame_accept_len42[] = {
    0x00, 0x00, 0x00, 0x00, // escape: expect control frame
    0x00, 0x00, 0x00, 0x22, // control frame length 0x22 == 34 bytes
    // control frame 34 bytes. ACCEPT and content type
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x70, 0x72, 0x6f, 0x74,
    0x6f, 0x62, 0x75, 0x66, 0x3a, 0x64, 0x6e, 0x73, 0x74, 0x61, 0x70, 0x2e, 0x44, 0x6e, 0x73, 0x74,
    0x61, 0x70};

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
    int writes{0};
    int write_rc{0};
    int write(std::unique_ptr<char[]> d, unsigned int l)
    {
        data = std::move(d);
        len = l;
        writes++;
        return write_rc;
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
    REQUIRE(client->len == 42);
    CHECK(std::memcmp(client->data.get(), bi_frame_accept_len42, 42) == 0);

    CHECK_NOTHROW(session.receive_socket_data(bi_frame_2_len12, 12));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Running);

    CHECK_NOTHROW(session.receive_socket_data(bi_frame_3_len400, 400));
    CHECK(data_frame_parsed == true);
    CHECK(df_count == 4);
}

TEST_CASE("bi-directional frame stream split across reads at every byte", "[dnstap][frmstrm]")
{
#ifdef _WIN32
    return;
#endif
    // a socket read can end anywhere, including inside a frame's length or a control frame
    std::basic_string<uint8_t> stream;
    stream.append(bi_frame_1_len42, sizeof(bi_frame_1_len42));
    stream.append(bi_frame_2_len12, sizeof(bi_frame_2_len12));
    stream.append(bi_frame_3_len400, sizeof(bi_frame_3_len400));

    int df_count{0};
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [&df_count](const void *, std::size_t) { df_count++; });
    for (auto byte : stream) {
        REQUIRE_NOTHROW(session.receive_socket_data(&byte, 1));
    }
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Running);
    REQUIRE(client->len == 42);
    CHECK(std::memcmp(client->data.get(), bi_frame_accept_len42, 42) == 0);
    CHECK(df_count == 4);
}

TEST_CASE("bi-directional frame stream split into two reads anywhere", "[dnstap][frmstrm]")
{
#ifdef _WIN32
    return;
#endif
    // whole frames and part of the next in one read: the part waits for the rest in the next read
    std::basic_string<uint8_t> stream;
    stream.append(bi_frame_1_len42, sizeof(bi_frame_1_len42));
    stream.append(bi_frame_2_len12, sizeof(bi_frame_2_len12));
    stream.append(bi_frame_3_len400, sizeof(bi_frame_3_len400));

    for (std::size_t split = 0; split <= stream.size(); ++split) {
        CAPTURE(split);
        std::vector<std::basic_string<uint8_t>> frames;
        auto client = std::make_shared<MockClient>();
        FrameSessionData<MockClient> session(client, CONTENT_TYPE, [&frames](const void *data, std::size_t len) {
            frames.emplace_back(static_cast<const uint8_t *>(data), len);
        });
        REQUIRE_NOTHROW(session.receive_socket_data(stream.data(), split));
        REQUIRE_NOTHROW(session.receive_socket_data(stream.data() + split, stream.size() - split));
        CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Running);
        CHECK(client->writes == 1);
        // the four data frames of bi_frame_3_len400, each as it was sent
        REQUIRE(frames.size() == 4);
        std::size_t offset = sizeof(bi_frame_1_len42) + sizeof(bi_frame_2_len12);
        for (const auto &frame : frames) {
            REQUIRE(frame.size() + 4 <= stream.size() - offset);
            CHECK(frame == stream.substr(offset + 4, frame.size()));
            offset += 4 + frame.size();
        }
        CHECK(offset == stream.size());
    }
}

// unidirectional: START with dnstap content-type
static uint8_t uni_frame_start_len42[] = {
    0x00, 0x00, 0x00, 0x00, // escape: expect control frame
    0x00, 0x00, 0x00, 0x22, // control frame length 0x22 == 34 bytes
    // control frame 34 bytes. START and content type
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x16, 0x70, 0x72, 0x6f, 0x74,
    0x6f, 0x62, 0x75, 0x66, 0x3a, 0x64, 0x6e, 0x73, 0x74, 0x61, 0x70, 0x2e, 0x44, 0x6e, 0x73, 0x74,
    0x61, 0x70};

TEST_CASE("uni-directional frame stream starts in memory a bi-directional session used", "[dnstap][frmstrm]")
{
#ifdef _WIN32
    return;
#endif
    // a freed session's memory is reused for the next client, so a new session must not inherit its fields
    using Session = FrameSessionData<MockClient>;
    alignas(Session) unsigned char storage[sizeof(Session)];
    std::memset(storage, 0x01, sizeof(storage));
    auto client = std::make_shared<MockClient>();
    auto session = new (storage) Session(client, CONTENT_TYPE, [](const void *, std::size_t) {});

    CHECK_NOTHROW(session->receive_socket_data(uni_frame_start_len42, 42));
    CHECK(session->is_bidir() == false);
    CHECK(session->state() == Session::FrameState::Running);
    session->~Session();
}

#ifndef _WIN32
static uint8_t frame_stop_len12[] = {
    0x00, 0x00, 0x00, 0x00, // escape
    0x00, 0x00, 0x00, 0x04, // length 4 bytes
    0x00, 0x00, 0x00, 0x03  // STOP
};

static uint8_t frame_finish_len12[] = {
    0x00, 0x00, 0x00, 0x00, // escape
    0x00, 0x00, 0x00, 0x04, // length 4 bytes
    0x00, 0x00, 0x00, 0x05  // FINISH
};

TEST_CASE("bi-directional frame stream accepts the dnstap content type a READY offers", "[dnstap][frmstrm]")
{
    // some writers close the connection unless ACCEPT names their content type
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});
    std::basic_string<uint8_t> ready;

    SECTION("among other content types")
    {
        ready = control_frame(FSTRM_CONTROL_READY, {"protobuf:example.Other", CONTENT_TYPE});
    }
    SECTION("no content type at all")
    {
        ready = control_frame(FSTRM_CONTROL_READY, {});
    }

    CHECK_NOTHROW(session.receive_socket_data(ready.data(), ready.size()));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Ready);
    REQUIRE(client->writes == 1);
    REQUIRE(client->len == 42);
    CHECK(std::memcmp(client->data.get(), bi_frame_accept_len42, 42) == 0);
}

TEST_CASE("bi-directional frame stream refuses a READY without the dnstap content type", "[dnstap][frmstrm]")
{
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});
    auto ready = control_frame(FSTRM_CONTROL_READY, {"protobuf:example.Other"});

    CHECK_THROWS_WITH(session.receive_socket_data(ready.data(), ready.size()), "content type mismatch");
    CHECK(client->writes == 0);
}

TEST_CASE("bi-directional frame stream answers STOP with FINISH", "[dnstap][frmstrm]")
{
    // the writer sends STOP and waits for FINISH before it closes the connection
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});
    REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_1_len42, 42));
    REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_2_len12, 12));
    REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_3_len400, 400));
    REQUIRE(client->writes == 1);

    CHECK_NOTHROW(session.receive_socket_data(frame_stop_len12, 12));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Finishing);
    CHECK(client->writes == 2);
    CHECK(client->len == 12);
    CHECK(std::memcmp(client->data.get(), frame_finish_len12, 12) == 0);
}

TEST_CASE("uni-directional frame stream ends on STOP without a reply", "[dnstap][frmstrm]")
{
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});
    REQUIRE_NOTHROW(session.receive_socket_data(uni_frame_start_len42, 42));

    CHECK_NOTHROW(session.receive_socket_data(frame_stop_len12, 12));
    CHECK(session.state() == FrameSessionData<MockClient>::FrameState::Finishing);
    CHECK(client->writes == 0);
}

TEST_CASE("frame stream refuses frames after STOP", "[dnstap][frmstrm]")
{
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});
    REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_1_len42, 42));
    REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_2_len12, 12));
    REQUIRE_NOTHROW(session.receive_socket_data(frame_stop_len12, 12));

    SECTION("a data frame")
    {
        CHECK_THROWS_WITH(session.receive_socket_data(bi_frame_3_len400, 400), "received a frame after STOP, aborting");
    }
    SECTION("a second STOP")
    {
        CHECK_THROWS_WITH(session.receive_socket_data(frame_stop_len12, 12), "received a frame after STOP, aborting");
    }
    SECTION("an ACCEPT")
    {
        CHECK_THROWS_WITH(session.receive_socket_data(bi_frame_2_ready_len12, 12), "received a frame after STOP, aborting");
    }
    SECTION("a FINISH")
    {
        CHECK_THROWS_WITH(session.receive_socket_data(frame_finish_len12, 12), "received a frame after STOP, aborting");
    }
}

TEST_CASE("frame stream reports control frames it cannot send", "[dnstap][frmstrm]")
{
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});

    SECTION("ACCEPT")
    {
        client->write_rc = UV_EPIPE;
        CHECK_THROWS_WITH(session.receive_socket_data(bi_frame_1_len42, 42), std::string("unable to send ACCEPT: ") + uv_strerror(UV_EPIPE));
    }
    SECTION("FINISH")
    {
        REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_1_len42, 42));
        REQUIRE_NOTHROW(session.receive_socket_data(bi_frame_2_len12, 12));
        client->write_rc = UV_EPIPE;
        CHECK_THROWS_WITH(session.receive_socket_data(frame_stop_len12, 12), std::string("unable to send FINISH: ") + uv_strerror(UV_EPIPE));
    }
}

TEST_CASE("frame stream refuses control frames out of order or of another content type", "[dnstap][frmstrm]")
{
    auto client = std::make_shared<MockClient>();
    FrameSessionData<MockClient> session(client, CONTENT_TYPE, [](const void *, std::size_t) {});

    SECTION("START twice")
    {
        REQUIRE_NOTHROW(session.receive_socket_data(uni_frame_start_len42, 42));
        CHECK_THROWS_WITH(session.receive_socket_data(uni_frame_start_len42, 42), "received START frame out of order, aborting");
    }
    SECTION("READY after START")
    {
        REQUIRE_NOTHROW(session.receive_socket_data(uni_frame_start_len42, 42));
        CHECK_THROWS_WITH(session.receive_socket_data(bi_frame_1_len42, 42), "received READY frame but already started, aborting");
    }
    SECTION("another content type")
    {
        auto start = control_frame(FSTRM_CONTROL_START, {"protobuf:example.Other"});
        CHECK_THROWS_WITH(session.receive_socket_data(start.data(), start.size()), "content type mismatch");
    }
}
#endif

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

#ifndef _WIN32
TEST_CASE("dnstap tcp server reports its connected clients", "[dnstap][tcp]")
{
    DnstapInputStream stream{"dnstap-clients"};
    stream.config_set("tcp", "127.0.0.1:15355");
    REQUIRE_NOTHROW(stream.start());
    CHECK(dnstap_clients(stream) == 0);

    // CHECK rather than REQUIRE while the server runs, so a failure still reaches stop()
    int fd = connect_tcp(15355);
    CHECK(fd >= 0);
    CHECK(wait_for_clients(stream, 1) == 1);

    ::close(fd);
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("dnstap tcp clients that disconnect are released", "[dnstap][tcp]")
{
    DnstapInputStream stream{"dnstap-disconnects"};
    stream.config_set("tcp", "127.0.0.1:15356");
    REQUIRE_NOTHROW(stream.start());

    // CHECK rather than REQUIRE while the server runs, so a failure still reaches stop()
    int staying = connect_tcp(15356);
    CHECK(staying >= 0);
    CHECK(wait_for_clients(stream, 1) == 1);
    // each client is dropped by the server once it disconnects, while the one that stays is kept
    for (int i = 0; i < 3; ++i) {
        int fd = connect_tcp(15356);
        CHECK(fd >= 0);
        CHECK(wait_for_clients(stream, 2) == 2);
        ::close(fd);
        CHECK(wait_for_clients(stream, 1) == 1);
    }

    ::close(staying);
    CHECK(wait_for_clients(stream, 0) == 0);
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("dnstap tcp server lets a bi-directional fstrm writer close", "[dnstap][tcp]")
{
    DnstapInputStream stream{"dnstap-stop"};
    stream.config_set("tcp", "127.0.0.1:15357");
    REQUIRE_NOTHROW(stream.start());

    // libfstrm's socket writers are bi-directional: closing sends STOP, then blocks reading until FINISH arrives or the connection closes
    auto writer_session = std::async(std::launch::async, [] {
        auto wopt = fstrm_writer_options_init();
        fstrm_writer_options_add_content_type(wopt, CONTENT_TYPE.data(), CONTENT_TYPE.size());
        auto topt = fstrm_tcp_writer_options_init();
        fstrm_tcp_writer_options_set_socket_address(topt, "127.0.0.1");
        fstrm_tcp_writer_options_set_socket_port(topt, "15357");
        auto writer = fstrm_tcp_writer_init(topt, wopt);
        fstrm_tcp_writer_options_destroy(&topt);
        fstrm_writer_options_destroy(&wopt);

        auto res = fstrm_writer_open(writer);
        if (res == fstrm_res_success) {
            // the first data frame of bi_frame_3_len400: a 0x45 byte dnstap message after its length
            res = fstrm_writer_write(writer, bi_frame_3_len400 + 4, 0x45);
        }
        if (res == fstrm_res_success) {
            res = fstrm_writer_close(writer);
        }
        fstrm_writer_destroy(&writer);
        return res;
    });

    // CHECK rather than REQUIRE while the server runs: stopping it closes the connection, which releases a writer still waiting
    CHECK(writer_session.wait_for(2s) == std::future_status::ready);
    // the writer closes the connection once FINISH arrives, and the server then releases the client
    CHECK(wait_for_clients(stream, 0) == 0);
    CHECK_NOTHROW(stream.stop());
    CHECK(writer_session.get() == fstrm_res_success);
}

TEST_CASE("dnstap unix server lets libfstrm's I/O thread shut down", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-stop.sock";
    std::error_code ec;
    std::filesystem::remove(path, ec);
    DnstapInputStream stream{"dnstap-stop-unix"};
    stream.config_set("socket", path);
    REQUIRE_NOTHROW(stream.start());

    auto wopt = fstrm_writer_options_init();
    fstrm_writer_options_add_content_type(wopt, CONTENT_TYPE.data(), CONTENT_TYPE.size());
    auto uwopt = fstrm_unix_writer_options_init();
    fstrm_unix_writer_options_set_socket_path(uwopt, path.c_str());
    auto writer = fstrm_unix_writer_init(uwopt, wopt);
    fstrm_unix_writer_options_destroy(&uwopt);
    fstrm_writer_options_destroy(&wopt);

    // CHECK rather than REQUIRE while the server runs: stopping it closes the connection, which releases a thread still waiting
    // the I/O thread opens the writer as it starts
    auto iothr = fstrm_iothr_init(nullptr, &writer);
    // static data, so there is nothing to free
    CHECK(fstrm_iothr_submit(iothr, fstrm_iothr_get_input_queue(iothr), bi_frame_3_len400 + 4, 0x45, nullptr, nullptr) == fstrm_res_success);
    CHECK(wait_for_clients(stream, 1) == 1);

    // fstrm_iothr_destroy() joins the thread once it has closed the writer, which waits for FINISH. The thread can miss
    // the shutdown signal and sleep out its 1 s flush timeout first, hence the longer wait
    auto destroyed = std::async(std::launch::async, [&iothr] { fstrm_iothr_destroy(&iothr); });
    CHECK(destroyed.wait_for(5s) == std::future_status::ready);
    CHECK(wait_for_clients(stream, 0) == 0);
    CHECK_NOTHROW(stream.stop());
    destroyed.get();
    std::filesystem::remove(path, ec);
}

TEST_CASE("dnstap unix socket another server listens on is refused", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-in-use.sock";
    DnstapInputStream first{"dnstap-first"};
    first.config_set("socket", path);
    REQUIRE_NOTHROW(first.start());
    struct stat before{};
    CHECK(::stat(path.c_str(), &before) == 0);

    // the second server must fail rather than remove the first one's socket and take its clients
    DnstapInputStream second{"dnstap-second"};
    second.config_set("socket", path);
    CHECK_THROWS_WITH(second.start(), "unable to bind dnstap server on " + path + ": address already in use");
    CHECK_FALSE(second.running());
    CHECK_NOTHROW(second.stop());

    // the path is still the first server's socket, and a client on it reaches that server
    struct stat after{};
    CHECK(::stat(path.c_str(), &after) == 0);
    CHECK(after.st_ino == before.st_ino);
    int fd = connect_unix(path);
    CHECK(fd >= 0);
    ::close(fd);
    CHECK_NOTHROW(first.stop());
}

TEST_CASE("dnstap unix socket path that is not a socket is refused", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-not-a-socket.sock";
    {
        std::ofstream file(path, std::ios::trunc);
        file << "not a socket";
    }
    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);

    CHECK_THROWS_WITH(stream.start(), "unable to bind dnstap server on " + path + ": the path exists and is not a socket");
    CHECK_FALSE(stream.running());
    CHECK_NOTHROW(stream.stop());
    // the file is left alone
    std::ifstream file(path);
    std::string content;
    std::getline(file, content);
    CHECK(content == "not a socket");
    std::filesystem::remove(path);
}

TEST_CASE("dnstap unix socket left by a server that stopped is replaced", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-stale.sock";
    std::filesystem::remove(path);
    // a socket bound and closed without removing its file, as a server that crashed leaves it
    int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    auto addr = unix_address(path);
    REQUIRE(::bind(stale, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    ::close(stale);
    REQUIRE(std::filesystem::is_socket(path));

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    REQUIRE_NOTHROW(stream.start());
    int fd = connect_unix(path);
    CHECK(fd >= 0);
    CHECK(wait_for_clients(stream, 1) == 1);
    ::close(fd);
    CHECK_NOTHROW(stream.stop());
}

TEST_CASE("dnstap unix socket path as long as a socket address holds is replaced when stale", "[dnstap][unix]")
{
    // libuv binds a name that fills sun_path without a terminating NUL
    sockaddr_un addr{};
    std::string path = "/tmp/";
    path.append(sizeof(addr.sun_path) - path.size(), 'd');
    std::filesystem::remove(path);
    int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.data(), path.size());
    REQUIRE(::bind(stale, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    ::close(stale);
    REQUIRE(std::filesystem::is_socket(path));

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());
    std::filesystem::remove(path);
}

TEST_CASE("dnstap unix socket a datagram server listens on is refused", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-datagram.sock";
    std::error_code ec;
    std::filesystem::remove(path, ec);
    // a live socket of another type refuses a stream connect with EPROTOTYPE, and a stale one would refuse it outright
    int live = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    auto addr = unix_address(path);
    REQUIRE(::bind(live, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    CHECK_THROWS_WITH(stream.start(), "unable to bind dnstap server on " + path + ": address already in use");
    CHECK_FALSE(stream.running());
    CHECK_NOTHROW(stream.stop());
    CHECK(std::filesystem::is_socket(path));
    ::close(live);
    std::filesystem::remove(path, ec);
}

TEST_CASE("dnstap unix socket left by a datagram server that stopped is replaced", "[dnstap][unix]")
{
    const std::string path = "/tmp/dnstap-test-stale-datagram.sock";
    std::error_code ec;
    std::filesystem::remove(path, ec);
    int stale = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    auto addr = unix_address(path);
    REQUIRE(::bind(stale, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    ::close(stale);

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    CHECK_NOTHROW(stream.start());
    CHECK_NOTHROW(stream.stop());
    std::filesystem::remove(path, ec);
}

TEST_CASE("dnstap unix socket that cannot be checked for a server is reported and kept", "[dnstap][unix]")
{
    if (::geteuid() == 0) {
        SKIP("root can connect to the socket regardless of its permissions");
    }
    const std::string path = "/tmp/dnstap-test-no-access.sock";
    std::error_code ec;
    std::filesystem::remove(path, ec);
    int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    auto addr = unix_address(path);
    REQUIRE(::bind(stale, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    ::close(stale);
    // without write permission on the socket nobody but root can connect, so whether a server is there is unknown
    std::filesystem::permissions(path, std::filesystem::perms::none);

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::StartsWith("unable to bind dnstap server on " + path + ": unable to tell whether a server listens on the socket there: "));
    CHECK_FALSE(stream.running());
    CHECK_NOTHROW(stream.stop());
    CHECK(std::filesystem::is_socket(path));
    std::filesystem::remove(path, ec);
}

TEST_CASE("dnstap unix socket left behind that cannot be removed is reported", "[dnstap][unix]")
{
    if (::geteuid() == 0) {
        SKIP("root can remove the socket regardless of the directory's permissions");
    }
    const std::string dir = "/tmp/dnstap-test-read-only";
    const std::string path = dir + "/stale.sock";
    std::error_code ec;
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, ec);
    std::filesystem::remove_all(dir, ec);
    REQUIRE(std::filesystem::create_directory(dir));
    int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    auto addr = unix_address(path);
    REQUIRE(::bind(stale, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    ::close(stale);
    std::filesystem::permissions(dir, std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec);

    DnstapInputStream stream{"dnstap-test"};
    stream.config_set("socket", path);
    CHECK_THROWS_WITH(stream.start(), Catch::Matchers::StartsWith("unable to bind dnstap server on " + path + ": unable to remove the stale socket there: "));
    CHECK_FALSE(stream.running());
    CHECK_NOTHROW(stream.stop());

    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, ec);
    std::filesystem::remove_all(dir, ec);
}
#endif

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
