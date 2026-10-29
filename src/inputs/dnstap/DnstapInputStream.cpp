/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "DnstapInputStream.h"
#include "DnstapException.h"
#include "ThreadName.h"
#include <filesystem>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <uvw/async.h>
#include <uvw/loop.h>
#include <uvw/pipe.h>
#include <uvw/stream.h>
#include <uvw/tcp.h>
#include <uvw/timer.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace visor::input::dnstap {

#ifndef _WIN32
namespace {
// connects to the Unix socket at path: 0 when a server is there, ECONNREFUSED when its server is gone and left the
// file behind, ENOENT when the file went away since it was found, or the errno that leaves it unknown. macOS also
// refuses when a live server's backlog is full, where Linux returns EAGAIN
int probe_unix_socket(const std::string &path)
{
    sockaddr_un addr{};
    // libuv binds a name that fills sun_path without a terminating NUL, so that length is probed too
    if (path.size() > sizeof(addr.sun_path)) {
        return ENAMETOOLONG;
    }
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return errno;
    }
    // non-blocking, so a live server with a full backlog cannot stall the start
    if (::fcntl(fd, F_SETFL, O_NONBLOCK) != 0) {
        int err = errno;
        ::close(fd);
        return err;
    }
    int result = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 ? 0 : errno;
    ::close(fd);
    // a full backlog, or a live socket of another type, which refuses a stream connect with EPROTOTYPE
    return (result == EAGAIN || result == EINPROGRESS || result == EPROTOTYPE) ? 0 : result;
}
}
#endif

DnstapInputStream::DnstapInputStream(const std::string &name)
    : visor::InputStream(name)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;
    _logger = spdlog::get("visor");
    assert(_logger);
}

void DnstapInputStream::_read_frame_stream_file()
{
    assert(config_exists("dnstap_file"));

#ifndef _WIN32
    // Setup file reader options
    auto fileOptions = fstrm_file_options_init();
    fstrm_file_options_set_file_path(fileOptions, config_get<std::string>("dnstap_file").c_str());

    // Initialize file reader
    auto reader = fstrm_file_reader_init(fileOptions, nullptr);
    if (!reader) {
        throw DnstapException("fstrm_file_reader_init() failed");
    }
    auto result = fstrm_reader_open(reader);
    if (result != fstrm_res_success) {
        throw DnstapException("fstrm_reader_open() failed");
    }

    // Cleanup
    fstrm_file_options_destroy(&fileOptions);

    // Loop over data frames
    for (;;) {
        const uint8_t *data;
        size_t len_data;

        result = fstrm_reader_read(reader, &data, &len_data);
        if (result == fstrm_res_success) {
            // Data frame ready, parse protobuf
            ::dnstap::Dnstap d;
            if (!d.ParseFromArray(data, len_data)) {
                _logger->warn("Dnstap::ParseFromArray fail, skipping frame of size {}", len_data);
                continue;
            }
            if (!d.has_type() || d.type() != ::dnstap::Dnstap_Type_MESSAGE || !d.has_message()) {
                _logger->warn("dnstap data is wrong type or has no message, skipping frame of size {}", len_data);
                continue;
            }

            // Emit signal to handlers
            if (!_filtering(d)) {
                std::shared_lock lock(_input_mutex);
                for (auto &proxy : _event_proxies) {
                    static_cast<DnstapInputEventProxy *>(proxy.get())->dnstap_cb(d, len_data);
                }
            }
        } else if (result == fstrm_res_stop) {
            // Normal end of data stream
            break;
        } else {
            // Abnormal end
            _logger->warn("fstrm_reader_read() data stream ended abnormally: {}", static_cast<int>(result));
            break;
        }
    }

    fstrm_reader_destroy(&reader);
#endif
}

void DnstapInputStream::start()
{

    if (_running) {
        return;
    }

    validate_configs(_config_defs);

    if (config_exists("dnstap_file")) {
        // read from dnstap file. this is a special case from a command line utility
        _running = true;
        _read_frame_stream_file();
        return;
    } else if (config_exists("socket")) {
        _create_frame_stream_unix_socket();
    } else if (config_exists("tcp")) {
        _create_frame_stream_tcp_socket();
    } else {
        throw DnstapException("config must specify one of: socket, dnstap_file");
    }

    _running = true;
}

void DnstapInputStream::_create_frame_stream_tcp_socket()
{
    assert(config_exists("tcp"));

    // split address and port
    auto tcp_config = config_get<std::string>("tcp");
    if (tcp_config.find(':') == std::string::npos) {
        throw DnstapException("invalid tcp address specification, use HOST:PORT");
    }

    std::string host;
    unsigned int port;
    try {
        host = tcp_config.substr(0, tcp_config.find(':'));
        port = std::stoul(tcp_config.substr(tcp_config.find(':') + 1, std::string::npos));
    } catch (std::exception &err) {
        throw DnstapException("unable to parse tcp address specification, use HOST:PORT");
    }

    // main io loop, run in its own thread
    _io_loop = uvw::loop::create();
    if (!_io_loop) {
        throw DnstapException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::async_handle>();
    if (!_async_h) {
        throw DnstapException("unable to initialize AsyncHandle");
    }
    _async_h->on<uvw::async_event>([this](const auto &, auto &handle) {
        // Stop and close the handles, then stop the loop so uv_run() returns.
        // Also close any connected clients so no active handles remain when the
        // loop is closed (otherwise uv_loop_close returns EBUSY and leaks). This
        // runs on the loop thread, so closing the handles here is safe.
        // Do NOT close the loop here: uv_loop_close() while uv_run() is still on
        // the stack frees structures that uv__io_poll keeps using, crashing with
        // SIGSEGV/SIGBUS. The loop is closed in the io thread after run() returns.
        _timer->stop();
        _timer->close();
        _tcp_server_h->stop();
        _tcp_server_h->close();
        for (auto &session : _tcp_sessions) {
            if (session.second) {
                session.second->close_handle();
            }
        }
        _io_loop->stop();
        handle.close();
    });
    _async_h->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    _timer = _io_loop->resource<uvw::timer_handle>();
    if (!_timer) {
        throw DnstapException("unable to initialize TimerHandle");
    }
    _timer->on<uvw::timer_event>([this](const auto &, auto &) {
        timespec stamp;
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            static_cast<DnstapInputEventProxy *>(proxy.get())->heartbeat_cb(stamp);
        }
    });
    _timer->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] TimerEvent error: {}", _name, err.what());
        handle.close();
    });

    // setup server socket
    _tcp_server_h = _io_loop->resource<uvw::tcp_handle>();
    if (!_tcp_server_h) {
        throw DnstapException("unable to initialize server pipe_handle");
    }

    // only reached from the loop thread, where a throw would terminate the process
    _tcp_server_h->on<uvw::error_event>([this](const auto &err, auto &) {
        _logger->error("[{}] socket error: {}", _name, err.what());
    });

    // listen_event happens on client connection
    _tcp_server_h->on<uvw::listen_event>([this](const uvw::listen_event &, uvw::tcp_handle &) {
        // on the loop thread, so failures are logged: a throw here would terminate the process
        auto client = _io_loop->resource<uvw::tcp_handle>();
        if (!client) {
            _logger->error("[{}]: unable to initialize connected client TCPHandle", _name);
            return;
        }

        auto on_data_frame = [this](const void *data, std::size_t len_data) {
            // Data frame ready, parse protobuf
            ::dnstap::Dnstap d;
            if (!d.ParseFromArray(data, len_data)) {
                _logger->warn("Dnstap::ParseFromArray fail, skipping frame of size {}", len_data);
                return;
            }
            if (!d.has_type() || d.type() != ::dnstap::Dnstap_Type_MESSAGE || !d.has_message()) {
                _logger->warn("dnstap data is wrong type or has no message, skipping frame of size {}", len_data);
                return;
            }

            // Emit signal to handlers
            if (!_filtering(d)) {
                std::shared_lock lock(_input_mutex);
                for (auto &proxy : _event_proxies) {
                    static_cast<DnstapInputEventProxy *>(proxy.get())->dnstap_cb(d, len_data);
                }
            }
        };

        client->on<uvw::error_event>([this](const uvw::error_event &err, uvw::tcp_handle &c_sock) {
            _logger->error("[{}]: dnstap client socket error: {}", _name, err.what());
            c_sock.stop();
            c_sock.close();
        });

        // client sent data
        client->on<uvw::data_event>([this](const uvw::data_event &data, uvw::tcp_handle &c_sock) {
            assert(_tcp_sessions[&c_sock]);
            try {
                _tcp_sessions[&c_sock]->receive_socket_data(reinterpret_cast<uint8_t *>(data.data.get()), data.length);
            } catch (DnstapException &err) {
                _logger->error("[{}] dnstap client read error: {}", _name, err.what());
                c_sock.stop();
                c_sock.close();
            }
        });
        // client was closed
        client->on<uvw::close_event>([this](const uvw::close_event &, uvw::tcp_handle &c_sock) {
            _logger->info("[{}]: dnstap client disconnected", _name);
            _tcp_sessions.erase(&c_sock);
            _clients = _tcp_sessions.size();
        });
        // client read EOF
        client->on<uvw::end_event>([this](const uvw::end_event &, uvw::tcp_handle &c_sock) {
            _logger->info("[{}]: dnstap client EOF {}", _name, c_sock.peer().ip);
            c_sock.stop();
            c_sock.close();
        });

        if (auto rc = _tcp_server_h->accept(*client); rc < 0) {
            _logger->error("[{}]: unable to accept dnstap client: {}", _name, uv_strerror(rc));
            client->close();
            return;
        }
        _logger->info("[{}]: dnstap client connected {}", _name, client->peer().ip);
        _tcp_sessions[client.get()] = std::make_unique<FrameSessionData<uvw::tcp_handle>>(client, CONTENT_TYPE, on_data_frame);
        _clients = _tcp_sessions.size();
        if (auto rc = client->read(); rc < 0) {
            _logger->error("[{}]: unable to read from dnstap client: {}", _name, uv_strerror(rc));
            client->close();
        }
    });

    _logger->info("[{}]: opening dnstap server on {}", _name, config_get<std::string>("tcp"));
    // uvw returns these errors rather than emitting them: a port another server holds must fail the start
    if (auto rc = _tcp_server_h->bind(host, port); rc < 0) {
        _close_unstarted_loop();
        throw DnstapException(fmt::format("unable to bind dnstap server on {}: {}", config_get<std::string>("tcp"), uv_strerror(rc)));
    }
    if (auto rc = _tcp_server_h->listen(); rc < 0) {
        _close_unstarted_loop();
        throw DnstapException(fmt::format("unable to listen with dnstap server on {}: {}", config_get<std::string>("tcp"), uv_strerror(rc)));
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _timer->start(uvw::timer_handle::time{1000}, uvw::timer_handle::time{HEARTBEAT_INTERVAL * 1000});
        thread::change_self_name(schema_key(), name());
        _io_loop->run();
        // run() has returned and every handle is closed; safe to close the loop.
        _io_loop->close();
    });
}
void DnstapInputStream::_create_frame_stream_unix_socket()
{
    assert(config_exists("socket"));

    // main io loop, run in its own thread
    _io_loop = uvw::loop::create();
    if (!_io_loop) {
        throw DnstapException("unable to create io loop");
    }
    // AsyncHandle lets us stop the loop from its own thread
    _async_h = _io_loop->resource<uvw::async_handle>();
    if (!_async_h) {
        throw DnstapException("unable to initialize AsyncHandle");
    }
    _async_h->on<uvw::async_event>([this](const auto &, auto &handle) {
        // Stop and close the handles, then stop the loop so uv_run() returns.
        // Also close any connected clients so no active handles remain when the
        // loop is closed (otherwise uv_loop_close returns EBUSY and leaks). This
        // runs on the loop thread, so closing the handles here is safe.
        // Do NOT close the loop here: uv_loop_close() while uv_run() is still on
        // the stack frees structures that uv__io_poll keeps using, crashing with
        // SIGSEGV/SIGBUS. The loop is closed in the io thread after run() returns.
        _timer->stop();
        _timer->close();
        _unix_server_h->stop();
        _unix_server_h->close();
        for (auto &session : _unix_sessions) {
            if (session.second) {
                session.second->close_handle();
            }
        }
        _io_loop->stop();
        handle.close();
    });
    _async_h->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] AsyncEvent error: {}", _name, err.what());
        handle.close();
    });

    _timer = _io_loop->resource<uvw::timer_handle>();
    if (!_timer) {
        throw DnstapException("unable to initialize TimerHandle");
    }
    _timer->on<uvw::timer_event>([this](const auto &, auto &) {
        timespec stamp;
        // use now()
        std::timespec_get(&stamp, TIME_UTC);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            static_cast<DnstapInputEventProxy *>(proxy.get())->heartbeat_cb(stamp);
        }
    });
    _timer->on<uvw::error_event>([this](const auto &err, auto &handle) {
        _logger->error("[{}] TimerEvent error: {}", _name, err.what());
        handle.close();
    });

    // setup server socket
    _unix_server_h = _io_loop->resource<uvw::pipe_handle>();
    if (!_unix_server_h) {
        throw DnstapException("unable to initialize server pipe_handle");
    }

    // only reached from the loop thread, where a throw would terminate the process
    _unix_server_h->on<uvw::error_event>([this](const auto &err, auto &) {
        _logger->error("[{}] socket error: {}", _name, err.what());
    });

    // listen_event happens on client connection
    _unix_server_h->on<uvw::listen_event>([this](const uvw::listen_event &, uvw::pipe_handle &) {
        // on the loop thread, so failures are logged: a throw here would terminate the process
        auto client = _io_loop->resource<uvw::pipe_handle>();
        if (!client) {
            _logger->error("[{}]: unable to initialize connected client pipe_handle", _name);
            return;
        }

        auto on_data_frame = [this](const void *data, std::size_t len_data) {
            // Data frame ready, parse protobuf
            ::dnstap::Dnstap d;
            if (!d.ParseFromArray(data, len_data)) {
                _logger->warn("Dnstap::ParseFromArray fail, skipping frame of size {}", len_data);
                return;
            }
            if (!d.has_type() || d.type() != ::dnstap::Dnstap_Type_MESSAGE || !d.has_message()) {
                _logger->warn("dnstap data is wrong type or has no message, skipping frame of size {}", len_data);
                return;
            }
            // Emit signal to handlers
            if (!_filtering(d)) {
                std::shared_lock lock(_input_mutex);
                for (auto &proxy : _event_proxies) {
                    static_cast<DnstapInputEventProxy *>(proxy.get())->dnstap_cb(d, len_data);
                }
            }
        };

        client->on<uvw::error_event>([this](const uvw::error_event &err, uvw::pipe_handle &c_sock) {
            _logger->error("[{}]: dnstap client socket error: {}", _name, err.what());
            c_sock.stop();
            c_sock.close();
        });

        // client sent data
        client->on<uvw::data_event>([this](const uvw::data_event &data, uvw::pipe_handle &c_sock) {
            assert(_unix_sessions[&c_sock]);
            try {
                _unix_sessions[&c_sock]->receive_socket_data(reinterpret_cast<uint8_t *>(data.data.get()), data.length);
            } catch (DnstapException &err) {
                _logger->error("[{}] dnstap client read error: {}", _name, err.what());
                c_sock.stop();
                c_sock.close();
            }
        });
        // client was closed
        client->on<uvw::close_event>([this](const uvw::close_event &, uvw::pipe_handle &c_sock) {
            _logger->info("[{}]: dnstap client disconnected", _name);
            _unix_sessions.erase(&c_sock);
            _clients = _unix_sessions.size();
        });
        // client read EOF
        client->on<uvw::end_event>([this](const uvw::end_event &, uvw::pipe_handle &c_sock) {
            _logger->info("[{}]: dnstap client EOF {}", _name, c_sock.sock());
            c_sock.stop();
            c_sock.close();
        });

        if (auto rc = _unix_server_h->accept(*client); rc < 0) {
            _logger->error("[{}]: unable to accept dnstap client: {}", _name, uv_strerror(rc));
            client->close();
            return;
        }
        _logger->info("[{}]: dnstap client connected {}", _name, client->sock());
        _unix_sessions[client.get()] = std::make_unique<FrameSessionData<uvw::pipe_handle>>(client, CONTENT_TYPE, on_data_frame);
        _clients = _unix_sessions.size();
        if (auto rc = client->read(); rc < 0) {
            _logger->error("[{}]: unable to read from dnstap client: {}", _name, uv_strerror(rc));
            client->close();
        }
    });

#ifdef _WIN32
    // attempt to remove socket if it exists, ignore errors
    std::filesystem::remove(config_get<std::string>("socket"));
#else
    // a socket file is replaced only when nothing listens on it: removing a live server's socket would take its
    // clients, and anything else at the path is not ours to delete. A live server's socket fails the bind below
    const auto socket_path = config_get<std::string>("socket");
    std::error_code ec;
    if (auto status = std::filesystem::symlink_status(socket_path, ec); !ec && std::filesystem::exists(status)) {
        if (!std::filesystem::is_socket(status)) {
            _close_unstarted_loop();
            throw DnstapException(fmt::format("unable to bind dnstap server on {}: the path exists and is not a socket", socket_path));
        }
        if (auto probe = probe_unix_socket(socket_path); probe == ECONNREFUSED) {
            if (!std::filesystem::remove(socket_path, ec) && ec) {
                _close_unstarted_loop();
                throw DnstapException(fmt::format("unable to bind dnstap server on {}: unable to remove the stale socket there: {}", socket_path, ec.message()));
            }
        } else if (probe != 0 && probe != ENOENT) {
            _close_unstarted_loop();
            throw DnstapException(fmt::format("unable to bind dnstap server on {}: unable to tell whether a server listens on the socket there: {}",
                socket_path, std::error_code(probe, std::generic_category()).message()));
        }
    }
#endif

    _logger->info("[{}]: opening dnstap server on {}", _name, config_get<std::string>("socket"));
    // uvw returns these errors rather than emitting them: a socket that cannot be bound must fail the start
    if (auto rc = _unix_server_h->bind(config_get<std::string>("socket")); rc < 0) {
        _close_unstarted_loop();
        throw DnstapException(fmt::format("unable to bind dnstap server on {}: {}", config_get<std::string>("socket"), uv_strerror(rc)));
    }
    if (auto rc = _unix_server_h->listen(); rc < 0) {
        _close_unstarted_loop();
        throw DnstapException(fmt::format("unable to listen with dnstap server on {}: {}", config_get<std::string>("socket"), uv_strerror(rc)));
    }

    // spawn the loop
    _io_thread = std::make_unique<std::thread>([this] {
        _timer->start(uvw::timer_handle::time{1000}, uvw::timer_handle::time{HEARTBEAT_INTERVAL * 1000});
        thread::change_self_name(schema_key(), name());
        _io_loop->run();
        // run() has returned and every handle is closed; safe to close the loop.
        _io_loop->close();
    });
}

void DnstapInputStream::_close_unstarted_loop()
{
    // the loop never ran: close its handles, let one pass of the loop finish the closes, then close the loop
    _timer->close();
    if (_tcp_server_h) {
        _tcp_server_h->close();
    }
    if (_unix_server_h) {
        _unix_server_h->close();
    }
    _async_h->close();
    _io_loop->run(uvw::loop::run_mode::NOWAIT);
    if (auto rc = _io_loop->close(); rc != 0) {
        _logger->warn("[{}] unable to close io loop: {}", _name, uv_strerror(rc));
    }
    _tcp_server_h.reset();
    _unix_server_h.reset();
    _timer.reset();
    _async_h.reset();
    _io_loop.reset();
}

void DnstapInputStream::stop()
{
    if (!_running) {
        return;
    }

    if (_async_h && _io_thread) {
        // we have to use AsyncHandle to stop the loop from the same thread the loop is running in
        _async_h->send();
        // waits for _io_loop->run() to return
        if (_io_thread->joinable()) {
            _io_thread->join();
        }
    }

    _running = false;
}

void DnstapInputStream::info_json(json &j) const
{
    common_info_json(j);
    j[schema_key()]["clients"] = _clients.load();
}

std::unique_ptr<InputEventProxy> DnstapInputStream::create_event_proxy(const Configurable &filter)
{
    return std::make_unique<DnstapInputEventProxy>(_name, filter);
}
}
