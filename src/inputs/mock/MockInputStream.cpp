/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "MockInputStream.h"

namespace visor::input::mock {

MockInputStream::MockInputStream(const std::string &name)
    : visor::InputStream(name)
{
    _logger = spdlog::get("visor");
    assert(_logger);
    _logger->info("mock input created");
}
MockInputStream::~MockInputStream()
{
    _logger->info("mock input destroyed");
}

void MockInputStream::start()
{

    if (_running) {
        return;
    }

    _logger->info("mock input start()");

    // for unit testing purposes
    if (config_exists("except_on_start")) {
        throw std::runtime_error("mock error on start");
    }
    if (config_exists("except_on_start_logic")) {
        throw std::logic_error("mock logic error on start");
    }

    static timer timer_thread{500ms};
    std::srand(std::time(nullptr));
    _mock_work = timer_thread.set_interval(1s, [this] {
        auto i = std::rand();
        _logger->info("mock input sends random int signal: {}", i);
        std::shared_lock lock(_input_mutex);
        for (auto &proxy : _event_proxies) {
            static_cast<MockInputEventProxy *>(proxy.get())->random_int_cb(i);
        }
    });

    _running = true;
}

void MockInputStream::stop()
{
    if (!_running) {
        return;
    }

    _logger->info("mock input stop()");

    _mock_work->cancel();

    _running = false;
}

void MockInputStream::info_json(json &j) const
{
    common_info_json(j);
}

std::unique_ptr<InputEventProxy> MockInputStream::create_event_proxy(const Configurable &filter)
{
    return std::make_unique<MockInputEventProxy>(_name, filter);
}

}
