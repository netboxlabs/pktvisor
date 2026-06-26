#pragma once

#include "DnstapException.h"
#include <functional>
#include <memory>

namespace visor::input::dnstap {

template <typename C>
class FrameSessionData
{
public:
    using on_data_frame_cb_t = std::function<void(const void *data, std::size_t size)>;

    enum class FrameState {
        New,
        Ready,
        Running,
        Finishing
    };

private:
    std::shared_ptr<C> _client_h;
    std::string _content_type;
    using binary = std::basic_string<uint8_t>;
    binary _buffer;
    bool _is_bidir{false};

    on_data_frame_cb_t _on_data_frame_cb;

    FrameState _state{FrameState::New};

public:
    FrameSessionData(
        std::shared_ptr<C> client,
        const std::string &content_type,
        on_data_frame_cb_t on_data_frame)
        : _client_h{client}
        , _content_type{content_type}
        , _on_data_frame_cb{std::move(on_data_frame)}
    {
    }

    void receive_socket_data(const uint8_t[], std::size_t)
    {
        throw DnstapException("Dnstap not supported on Windows OS");
    }

    // Close the underlying client handle during shutdown, so the loop has no
    // active client handles left when it is closed (otherwise uv_loop_close
    // returns UV_EBUSY and the handles leak). Must be called on the loop thread.
    void close_handle()
    {
        if (_client_h && !_client_h->closing()) {
            _client_h->close();
        }
    }

    const FrameState &state() const
    {
        return _state;
    }

    bool is_bidir() const
    {
        return _is_bidir;
    }
};

}