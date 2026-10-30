/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include "DnstapException.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <fstrm/fstrm.h>
#include <functional>
#include <memory>
#include <uv.h>

namespace visor::input::dnstap {

struct ControlDeleter {
    void operator()(fstrm_control *c) const
    {
        fstrm_control_destroy(&c);
    }
};
using control_ptr = std::unique_ptr<fstrm_control, ControlDeleter>;

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

    bool _decode_control_frame(const void *control_frame, size_t len_control_frame);
    void _check_content_type(const fstrm_control *c) const;
    void _send_control_frame(fstrm_control_type type, const char *name, bool with_content_type = false);
    bool _try_yield_frame();

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

    void receive_socket_data(const uint8_t data[], std::size_t data_len);

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

template <typename C>
bool FrameSessionData<C>::_decode_control_frame(const void *control_frame, size_t len_control_frame)
{
    fstrm_res res;
    fstrm_control_type c_type;
    uint32_t flags = 0;
    // destroyed on every return and throw below
    control_ptr c{fstrm_control_init()};
    res = fstrm_control_decode(c.get(), control_frame, len_control_frame, flags);
    if (res != fstrm_res_success) {
        return false;
    }
    res = fstrm_control_get_type(c.get(), &c_type);
    if (res != fstrm_res_success) {
        return false;
    }

    switch (c_type) {
        // uni-directional
    case FSTRM_CONTROL_START: {
        if ((!_is_bidir && _state != FrameState::New) || (_is_bidir && _state != FrameState::Ready)) {
            throw DnstapException("received START frame out of order, aborting");
        }
        _check_content_type(c.get());
        _state = FrameState::Running;
        break;
    }
        // bi-directional
    case FSTRM_CONTROL_READY: {
        if (_state != FrameState::New) {
            throw DnstapException("received READY frame but already started, aborting");
        }
        // READY lists the content types the writer can send
        _check_content_type(c.get());
        _state = FrameState::Ready;
        _is_bidir = true;
        // some writers close the connection unless ACCEPT names their content type
        _send_control_frame(FSTRM_CONTROL_ACCEPT, "ACCEPT", true);
        break;
    }
    case FSTRM_CONTROL_STOP: {
        // STOP ends the stream: _try_yield_frame refuses any frame after it
        _state = FrameState::Finishing;
        // bi-directional: the writer waits for FINISH before it closes the connection
        if (_is_bidir) {
            _send_control_frame(FSTRM_CONTROL_FINISH, "FINISH");
        }
        break;
    }
    case FSTRM_CONTROL_ACCEPT:
    case FSTRM_CONTROL_FINISH:
        break;
    }

    return true;
}

template <typename C>
void FrameSessionData<C>::_check_content_type(const fstrm_control *c) const
{
    // a frame without a content type matches any, as in libfstrm's reader
    if (fstrm_control_match_field_content_type(c, reinterpret_cast<const uint8_t *>(_content_type.data()), _content_type.size()) != fstrm_res_success) {
        throw DnstapException("content type mismatch");
    }
}

template <typename C>
void FrameSessionData<C>::_send_control_frame(fstrm_control_type type, const char *name, bool with_content_type)
{
    control_ptr c{fstrm_control_init()};
    if (fstrm_control_set_type(c.get(), type) != fstrm_res_success) {
        throw DnstapException(std::string("unable to send ") + name + ": fstrm_control_set_type");
    }
    if (with_content_type && fstrm_control_add_field_content_type(c.get(), reinterpret_cast<const uint8_t *>(_content_type.data()), _content_type.size()) != fstrm_res_success) {
        throw DnstapException(std::string("unable to send ") + name + ": fstrm_control_add_field_content_type");
    }
    auto control_frame_data = std::make_unique<char[]>(FSTRM_CONTROL_FRAME_LENGTH_MAX);
    size_t length_control_frame = FSTRM_CONTROL_FRAME_LENGTH_MAX;
    if (fstrm_control_encode(c.get(), control_frame_data.get(), &length_control_frame, FSTRM_CONTROL_FLAG_WITH_HEADER) != fstrm_res_success) {
        throw DnstapException(std::string("unable to send ") + name + ": fstrm_control_encode");
    }
    if (auto rc = _client_h->write(std::move(control_frame_data), length_control_frame); rc < 0) {
        throw DnstapException(std::string("unable to send ") + name + ": " + uv_strerror(rc));
    }
}

template <typename C>
void FrameSessionData<C>::receive_socket_data(const uint8_t data[], std::size_t data_len)
{
    _buffer.append(data, data_len);
    while (_try_yield_frame()) { }
}
template <typename C>
bool FrameSessionData<C>::_try_yield_frame()
{

    std::uint32_t frame_len{0};

    // a socket read can end anywhere in a frame, so a partial length or frame waits for more data
    if (_buffer.size() < sizeof(frame_len)) {
        return false;
    }

    if (_state == FrameState::Finishing) {
        throw DnstapException("received a frame after STOP, aborting");
    }

    std::memcpy(&frame_len, _buffer.data(), sizeof(frame_len));
    frame_len = ntohl(frame_len);

    if (frame_len != 0) {
        // this is a data frame and we have the length
        if (_state != FrameState::Running) {
            // we got a data frame but we never saw a START control frame, abort
            throw DnstapException("data frame without a START control frame");
        }

        // ensure we never allocate more than max
        if (frame_len > FSTRM_READER_MAX_FRAME_SIZE_DEFAULT) {
            throw DnstapException("data frame too large");
        }

        if (_buffer.size() >= sizeof(frame_len) + frame_len) {
            _on_data_frame_cb(_buffer.data() + sizeof(frame_len), frame_len);
            _buffer.erase(0, sizeof(frame_len) + frame_len);
        } else {
            // need more data
            return false;
        }
    } else {
        // this is a control frame: escape code, length, then the frame. Nothing is consumed until all of it is here
        // note this happens infrequently

        // get control frame length
        std::uint32_t ctrl_len{0};

        if (_buffer.size() < sizeof(frame_len) + sizeof(ctrl_len)) {
            // need more data
            return false;
        }

        std::memcpy(&ctrl_len, _buffer.data() + sizeof(frame_len), sizeof(ctrl_len));
        ctrl_len = ntohl(ctrl_len);

        // ensure we never allocate more than max
        if (ctrl_len > FSTRM_CONTROL_FRAME_LENGTH_MAX) {
            throw DnstapException("control frame too large");
        }

        if (_buffer.size() >= sizeof(frame_len) + sizeof(ctrl_len) + ctrl_len) {
            if (!_decode_control_frame(_buffer.data() + sizeof(frame_len) + sizeof(ctrl_len), ctrl_len)) {
                throw DnstapException("unable to parse control frame");
            }
            _buffer.erase(0, sizeof(frame_len) + sizeof(ctrl_len) + ctrl_len);
        } else {
            // need more data
            return false;
        }
    }
    // parsed ok. if we have more data, try to parse another frame.
    return _buffer.size();
}

}