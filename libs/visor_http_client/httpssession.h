#pragma once

#include <unordered_map>
#include <vector>

using ssize_t = std::make_signed_t<size_t>; //Windows fix required
#include <nghttp2/nghttp2.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "base64.h"
#include "tcpsession.h"
#include "url_parser.h"

struct Target {
    http_parser_url *parsed;
    std::string address;
    std::string uri;
    std::string port;
};

enum class HTTPMethod {
    POST,
    GET,
};

struct http2_stream_data {
    http2_stream_data(std::string _scheme, std::string _authority, std::string _path, int32_t _id, std::string _data)
        : scheme(_scheme)
        , authority(_authority)
        , path(_path)
        , id(_id)
        , data(_data)
    {
    }

    std::string scheme;
    std::string authority;
    std::string path;
    int32_t id;
    std::string data;
};

enum STATE_HTTP2 {
    WAIT_SETTINGS,
    SENDING_DATA
};

class HTTPSSession : public TCPSession
{
public:
    using log_send_cb = std::function<void(int32_t id)>;
    using handshake_error_cb = std::function<void()>;

    HTTPSSession(std::shared_ptr<uvw::tcp_handle> handle,
        TCPSession::malformed_data_cb malformed_data_handler,
        TCPSession::got_dns_msg_cb got_dns_msg_handler,
        TCPSession::connection_ready_cb connection_ready_handler,
        handshake_error_cb handshake_error_handler,
        Target target,
        HTTPMethod method);

    ~HTTPSSession() override;

    virtual bool setup() override;

    virtual void on_connect_event() override;

    void send_tls(void *data, size_t len);

    void init_nghttp2();

    void send_settings();

    void receive_response(const char data[], size_t len);

    int session_send();

    int session_receive();

    void close() override;

    void receive_data(const char data[], size_t len) override;

    void write(std::unique_ptr<char[]> data, size_t len) override;

    void process_receive(const uint8_t *data, size_t len);

    std::unique_ptr<http2_stream_data> create_http2_stream_data(std::unique_ptr<char[]> data, size_t len);

    void add_stream(http2_stream_data *stream_data);

    void remove_stream(http2_stream_data *stream_data);

    void settings_received();

    std::unordered_map<int32_t, std::vector<uint8_t>> _recv_chunks;

protected:
    void destroy_stream();

    void destroy_session();

    void do_handshake();

private:
    STATE_HTTP2 http2_state;
    malformed_data_cb _malformed_data;
    got_dns_msg_cb _got_dns_msg;
    std::shared_ptr<uvw::tcp_handle> _handle;
    enum class LinkState {
        HANDSHAKE,
        DATA,
        CLOSE
    } _tls_state;
    handshake_error_cb _handshake_error;
    Target _target;
    HTTPMethod _method;

    nghttp2_session *_current_session;
//    std::string _pull_buffer;

    SSL *_ssl_session;
    SSL_CTX *_ssl_context;
    BIO *_read_bio;
    BIO *_write_bio;
    void flush_read_bio();
};
