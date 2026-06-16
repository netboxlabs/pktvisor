#include <algorithm>
#include <cstring>
#include <iostream>
#include <uvw/tcp.h>

#include "httpssession.h"

HTTPSSession::HTTPSSession(std::shared_ptr<uvw::tcp_handle> handle,
    TCPSession::malformed_data_cb malformed_data_handler,
    TCPSession::got_dns_msg_cb got_dns_msg_handler,
    TCPSession::connection_ready_cb connection_ready_handler,
    handshake_error_cb handshake_error_handler,
    Target target,
    HTTPMethod method)
    : TCPSession(handle, malformed_data_handler, got_dns_msg_handler, connection_ready_handler)
    , http2_state{STATE_HTTP2::WAIT_SETTINGS}
    , _malformed_data{malformed_data_handler}
    , _got_dns_msg{got_dns_msg_handler}
    , _handle{handle}
    , _tls_state{LinkState::HANDSHAKE}
    , _handshake_error{handshake_error_handler}
    , _target{std::move(target)}
    , _method{method}
    , _current_session{nullptr}
{
}

HTTPSSession::~HTTPSSession()
{
    destroy_session();
}

std::unique_ptr<http2_stream_data> HTTPSSession::create_http2_stream_data(std::unique_ptr<char[]> data, size_t len)
{
    std::string uri = _target.uri;
    struct http_parser_url *u = _target.parsed;
    std::string scheme(&uri[u->field_data[UF_SCHEMA].off], u->field_data[UF_SCHEMA].len);
    std::string authority(&uri[u->field_data[UF_HOST].off], u->field_data[UF_HOST].len);
    std::string path(&uri[u->field_data[UF_PATH].off], u->field_data[UF_PATH].len);
    int32_t stream_id = -1;
    if (_method == HTTPMethod::GET) {
        path.append("?dns=");
        path.append(data.get(), len);
    }
    std::string streamData(data.get(), len);
    auto root = std::make_unique<http2_stream_data>(scheme, authority, path, stream_id, streamData);
    return root;
}
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

static ssize_t ng2_send_callback([[maybe_unused]] nghttp2_session *session, const uint8_t *data,
    size_t length, [[maybe_unused]] int flags, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    class_session->send_tls((void *)data, length);
    return (ssize_t)length;
}

void HTTPSSession::destroy_session()
{
    // Free the SSL session
    if (_ssl_session) {
        SSL_free(_ssl_session);
        _ssl_session = nullptr;
    }
    // Free the SSL context
    if (_ssl_context) {
        SSL_CTX_free(_ssl_context);
        _ssl_context = nullptr;
    }
    // Clean up nghttp2 session
    nghttp2_session_del(_current_session);
}

void HTTPSSession::process_receive(const uint8_t *data, size_t len)
{
    auto buf = std::make_unique<char[]>(len);
    memcpy(buf.get(), (const char *)data, len);
    _got_dns_msg(std::move(buf), len);
}

static int ng2_on_data_chunk_recv_callback(nghttp2_session *session, [[maybe_unused]] uint8_t flags,
    int32_t stream_id, const uint8_t *data,
    size_t len, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    auto req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!req) {
        std::cerr << "No stream data on data chunk" << std::endl;
        return 0;
    }
    auto existing = class_session->_recv_chunks.find(stream_id);
    if (existing != class_session->_recv_chunks.end()) {
        class_session->_recv_chunks[stream_id].insert(class_session->_recv_chunks[stream_id].end(), data, data + len);
    } else {
        class_session->_recv_chunks[stream_id] = std::vector<uint8_t>(data, data + len);
    }
    return 0;
}

static int ng2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id, [[maybe_unused]] uint32_t error_code,
    [[maybe_unused]] void *user_data)
{
    auto stream_data = static_cast<http2_stream_data *>(nghttp2_session_get_stream_user_data(session, stream_id));
    if (!stream_data) {
        std::cerr << "No stream data on stream close" << std::endl;
        return 0;
    }
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    return 0;
}

int ng2_on_frame_recv_callback([[maybe_unused]] nghttp2_session *session,
    const nghttp2_frame *frame, void *user_data)
{
    auto class_session = static_cast<HTTPSSession *>(user_data);
    switch (frame->hd.type) {
    case NGHTTP2_SETTINGS:
        class_session->settings_received();
        break;
    case NGHTTP2_DATA:
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            auto data = class_session->_recv_chunks[frame->data.hd.stream_id];
            class_session->process_receive(data.data(), data.size());
        }
    }
    return 0;
}

void HTTPSSession::init_nghttp2()
{
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, ng2_send_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, ng2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, ng2_on_stream_close_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, ng2_on_frame_recv_callback);
    nghttp2_session_client_new(&_current_session, callbacks, this);
    nghttp2_session_callbacks_del(callbacks);
}
#define WHERE_INFO(ssl, w, flag, msg) { \
    if(w & flag) { \
      printf("\t"); \
      printf(msg); \
      printf(" - %s ", SSL_state_string(ssl)); \
      printf(" - %s ", SSL_state_string_long(ssl)); \
      printf("\n"); \
    }\
 }

// INFO CALLBACK
void dummy_ssl_info_callback(const SSL* ssl, int where, int ret) {
    if(ret == 0) {
        printf("dummy_ssl_info_callback, error occured.\n");
        return;
    }
    WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
    WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
    WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
    WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
    WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}
void dummy_ssl_msg_callback(
    int writep
    ,int version
    ,int contentType
    ,const void* buf
    ,size_t len
    ,SSL* ssl
    ,void *arg
)
{
    printf("\tMessage callback with length: %zu\n", len);
}

bool HTTPSSession::setup()
{
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL_CTX object as a framework for TLS/SSL enabled functions
    _ssl_context = SSL_CTX_new(TLS_client_method());
    if (!_ssl_context) {
        std::cerr << "OpenSSL failed to create SSL_CTX object." << std::endl;
        return false;
    }

    // Load the system's default certificates for verification purposes
    if (!SSL_CTX_set_default_verify_paths(_ssl_context)) {
        std::cerr << "OpenSSL failed to set default verify paths." << std::endl;
        return false;
    }

    const unsigned char alpn_protos[] = {2, 'h', '2'}; // 2 is the length of 'h2'
    if (SSL_CTX_set_alpn_protos(_ssl_context, alpn_protos, sizeof(alpn_protos))) {
        std::cerr << "OpenSSL failed to set ALPN." << std::endl;
        return false;
    }

    // Create SSL session
    _ssl_session = SSL_new(_ssl_context);
    if (!_ssl_session) {
        std::cerr << "OpenSSL failed to create SSL session." << std::endl;
        return false;
    }
    SSL_CTX_set_info_callback(_ssl_context, dummy_ssl_info_callback);
    SSL_CTX_set_msg_callback(_ssl_context, dummy_ssl_msg_callback);
    _read_bio = BIO_new(BIO_s_mem());
    _write_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(_ssl_session, _read_bio, _write_bio);
    SSL_set_connect_state(_ssl_session);
    return true;
}
void HTTPSSession::send_settings()
{
    nghttp2_settings_entry settings[1] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, (1U << 31) - 1}};
    int val;
    val = nghttp2_submit_settings(_current_session, NGHTTP2_FLAG_NONE, settings, ARRLEN(settings));
    if (val != 0) {
        std::cerr << "Could not submit SETTINGS frame: " << nghttp2_strerror(val) << std::endl;
    }
}

void HTTPSSession::settings_received()
{
    if (http2_state == STATE_HTTP2::WAIT_SETTINGS) {
        TCPSession::on_connect_event();
        http2_state = STATE_HTTP2::SENDING_DATA;
    }
}

void HTTPSSession::receive_response(const char data[], size_t len)
{
    ssize_t stream_id = nghttp2_session_mem_recv(_current_session, (const uint8_t *)data, len);
    if (stream_id < 0) {
        std::cerr << "Could not get HTTP2 request: " << nghttp2_strerror(stream_id);
        close();
        return;
    }
}

int HTTPSSession::session_send()
{
    int rv;
    rv = nghttp2_session_send(_current_session);
    if (rv != 0) {
        std::cerr << "HTTP2 fatal error: " << nghttp2_strerror(rv);
        return -1;
    }
    return 0;
}

void HTTPSSession::on_connect_event()
{
    _current_session = {};
    do_handshake();
}

void HTTPSSession::close()
{
    _tls_state = LinkState::CLOSE;
    // Shutdown the SSL/TLS session gracefully
    SSL_shutdown(_ssl_session);
    // Free up the SSL session
    SSL_free(_ssl_session);
    _ssl_session = nullptr;
    TCPSession::close();
}

static ssize_t post_data(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, [[maybe_unused]] nghttp2_data_source *source, [[maybe_unused]] void *user_data)
{
    auto stream_data = static_cast<http2_stream_data *>(nghttp2_session_get_stream_user_data(session, stream_id));
    size_t nread = std::min(stream_data->data.size(), length);
    memcpy(buf, stream_data->data.c_str(), nread);
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return nread;
}

#define HDR_S(NAME, VALUE)                                                         \
    {                                                                              \
        (uint8_t *)NAME, (uint8_t *)VALUE.c_str(), sizeof(NAME) - 1, VALUE.size(), \
            NGHTTP2_NV_FLAG_NONE                                                   \
    }

void HTTPSSession::write(std::unique_ptr<char[]> data, size_t len)
{
    int32_t stream_id;
    auto stream_data = create_http2_stream_data(std::move(data), len);
    nghttp2_data_provider provider = {};

    std::string method = _method == HTTPMethod::GET ? "GET" : "POST";
    std::string content = "application/dns-message";
    std::vector<nghttp2_nv> hdrs{
        HDR_S(":method", method),
        HDR_S(":scheme", stream_data->scheme),
        HDR_S(":authority", stream_data->authority),
        HDR_S(":path", stream_data->path),
        HDR_S("accept", content)};
    if (_method == HTTPMethod::POST) {
        hdrs.push_back(HDR_S("content-type", content));
        hdrs.push_back(HDR_S("content-length", std::to_string(len)));
        provider.read_callback = post_data;
    }

    stream_id = nghttp2_submit_request(_current_session, NULL, hdrs.data(), hdrs.size(), &provider, stream_data.get());
    if (stream_id < 0) {
        std::cerr << "Could not submit HTTP request: " << nghttp2_strerror(stream_id);
    }

    stream_data->id = stream_id;

    if (session_send() != 0) {
        std::cerr << "HTTP2 failed to send" << std::endl;
    }
}
void HTTPSSession::flush_read_bio() {
    char buf[1024*16];
    int bytes_read = 0;
    while((bytes_read = BIO_read(_write_bio, buf, sizeof(buf))) > 0) {
        std::cerr << "flush_read_bio: " << buf << std::endl;
        // WRITE TO STREAM
        _handle->write(buf, bytes_read);
    }
}
void HTTPSSession::receive_data(const char data[], size_t _len)
{
    std::cerr << "receive_data: " << data << std::endl;
    int written = BIO_write(_read_bio, data, _len);
//    _pull_buffer.append(data, _len);
    switch (_tls_state) {
    case LinkState::HANDSHAKE:
        do_handshake();
        break;
    case LinkState::DATA:
        char buf[16384];
        for (;;) {
            int len = SSL_read(_ssl_session, buf, sizeof(buf));
            if (len > 0) {
                receive_response(buf, len);
            } else {
                int error = SSL_get_error(_ssl_session, len);
                if (error == SSL_ERROR_WANT_READ) {
                    // OpenSSL wants to read more data. Check if we don't have any data left to read.
//                    if (_pull_buffer.empty()) {
//                        break;
//                    }
                    continue;
                } else if (error == SSL_ERROR_WANT_WRITE) {
                    // OpenSSL wants to write data (e.g., for renegotiation). Continue processing.
                    continue;
                } else {
                    // Some other error occurred. Handle as necessary.
                    std::cerr << "OpenSSL error while reading data: " << ERR_reason_error_string(error) << std::endl;
                    break;
                }
            }
        }
        break;
    case LinkState::CLOSE:
        break;
    }
}

void HTTPSSession::send_tls(void *data, size_t len)
{
    int sent = SSL_write(_ssl_session, data, len);
    if (sent <= 0) {
        int error = SSL_get_error(_ssl_session, sent);
        std::cerr << "OpenSSL error while sending data: " << ERR_reason_error_string(error) << std::endl;
    }
}

void HTTPSSession::do_handshake()
{
    int err = SSL_connect(_ssl_session); // client-side
    if (err == 1) {                      // Successful handshake
//        const unsigned char *alpn = NULL;
//        unsigned int alpnlen = 0;
//        SSL_get0_alpn_selected(_ssl_session, &alpn, &alpnlen);
//        if (!alpn || alpnlen != 2 || memcmp(alpn, "h2", 2) != 0) {
//            std::cerr << "Cannot get ALPN or ALPN is not 'h2'." << std::endl;
//            close();
//            return;
//        }
        init_nghttp2();
        send_settings();
        if (session_send() != 0) {
            std::cerr << "Cannot submit settings frame" << std::endl;
        }
        _tls_state = LinkState::DATA;
    } else {
        int error = SSL_get_error(_ssl_session, err);
        if (error == SSL_ERROR_SSL) {
            std::cerr << "Handshake failed: SSL error" << std::endl;
            ERR_print_errors_fp(stderr);
            _handshake_error();
        } else if (error == SSL_ERROR_SYSCALL) {
            std::cerr << "Handshake failed: syscall error" << std::endl;
            ERR_print_errors_fp(stderr);
            _handshake_error();
        } else if (error == SSL_ERROR_WANT_READ) {
            std::cout << "Handshake needs READ" << std::endl;
            flush_read_bio();
        } else if (error == SSL_ERROR_WANT_WRITE) {
            std::cout << "Handshake needs WRITE" << std::endl;
        } else {
            std::cerr << "Unknown handshake error." << std::endl;
        }
    }
}