/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdexcept>
#include <string>

namespace visor::input::flow {

class FlowException : public std::runtime_error
{
public:
    FlowException(const char *msg)
        : std::runtime_error(msg)
    {
    }

    FlowException(std::string msg)
        : std::runtime_error(msg)
    {
    }
};

}