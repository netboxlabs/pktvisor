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
    bool _is_bidir;

    on_data_frame_cb_t _on_data_frame_cb;

    FrameState _state{FrameState::New};

    bool _decode_control_frame(const void *control_frame, size_t len_control_frame);
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
    struct fstrm_control *c;
    uint32_t flags = 0;
    c = fstrm_control_init();
    res = fstrm_control_decode(c, control_frame, len_control_frame, flags);
    if (res != fstrm_res_success) {
        fstrm_control_destroy(&c);
        return false;
    }
    res = fstrm_control_get_type(c, &c_type);
    if (res != fstrm_res_success) {
        fstrm_control_destroy(&c);
        return false;
    }

    switch (c_type) {
        // uni-directional
    case FSTRM_CONTROL_START: {
        if ((!_is_bidir && _state != FrameState::New) || (_is_bidir && _state != FrameState::Ready)) {
            throw DnstapException("received START frame out of order, aborting");
        } else {
            _state = FrameState::Running;
        }
        break;
    }
        // bi-directional
    case FSTRM_CONTROL_READY: {
        if (_state != FrameState::New) {
            throw DnstapException("received READY frame but already started, aborting");
        } else {
            _state = FrameState::Ready;
            _is_bidir = true;
            // bi-directional: got READY, send ACCEPT
            fstrm_res res;
            struct fstrm_control *c;
            auto control_frame_data = std::make_unique<char[]>(FSTRM_CONTROL_FRAME_LENGTH_MAX);
            size_t length_control_frame = FSTRM_CONTROL_FRAME_LENGTH_MAX;
            c = fstrm_control_init();
            res = fstrm_control_set_type(c, FSTRM_CONTROL_ACCEPT);
            if (res != fstrm_res_success) {
                throw DnstapException("unable to send ACCEPT: fstrm_control_set_type");
            }
            // Serialize the control frame.
            res = fstrm_control_encode(c, control_frame_data.get(), &length_control_frame, FSTRM_CONTROL_FLAG_WITH_HEADER);
            if (res != fstrm_res_success) {
                throw DnstapException("unable to send ACCEPT: fstrm_control_encode");
            }
            fstrm_control_destroy(&c);
            // don't write to client in unit tests
            _client_h->write(std::move(control_frame_data), length_control_frame);
        }
        break;
    }
    case FSTRM_CONTROL_ACCEPT:
    case FSTRM_CONTROL_STOP:
    case FSTRM_CONTROL_FINISH:
        break;
    }

    size_t n_content_type;
    res = fstrm_control_get_num_field_content_type(c, &n_content_type);
    if (res != fstrm_res_success) {
        fstrm_control_destroy(&c);
        return false;
    }
    const uint8_t *content_type;
    size_t len_content_type;
    for (size_t idx = 0; idx < n_content_type; idx++) {
        res = fstrm_control_get_field_content_type(c, idx,
            &content_type, &len_content_type);
        if (res != fstrm_res_success) {
            throw DnstapException("unable to parse content type");
        }
        if (len_content_type != _content_type.size() || std::memcmp(content_type, _content_type.data(), len_content_type) != 0) {
            throw DnstapException("content type mismatch");
        }
    }
    fstrm_control_destroy(&c);
    return true;
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

    if (_buffer.size() < sizeof(frame_len)) {
        throw DnstapException("invalid data: header length");
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
        // this is a control frame
        // note this happens infrequently

        _buffer.erase(0, sizeof(frame_len)); // erase escape code

        // get control frame length
        std::uint32_t ctrl_len{0};

        if (_buffer.size() < sizeof(ctrl_len)) {
            throw DnstapException("invalid data: control frame length");
        }

        std::memcpy(&ctrl_len, _buffer.data(), sizeof(ctrl_len));
        ctrl_len = ntohl(ctrl_len);

        // ensure we never allocate more than max
        if (ctrl_len > FSTRM_CONTROL_FRAME_LENGTH_MAX) {
            throw DnstapException("control frame too large");
        }

        if (_buffer.size() >= sizeof(ctrl_len) + ctrl_len) {
            if (!_decode_control_frame(_buffer.data() + sizeof(ctrl_len), ctrl_len)) {
                throw DnstapException("unable to parse control frame");
            }
            _buffer.erase(0, sizeof(ctrl_len) + ctrl_len);
        } else {
            // need more data
            return false;
        }
    }
    // parsed ok. if we have more data, try to parse another frame.
    return _buffer.size();
}

}