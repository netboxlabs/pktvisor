/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "AbstractPlugin.h"
#include "CorradeCompat.h"
#include <fmt/format.h>
#include <regex>

namespace visor {

void AbstractPlugin::check_schema(json obj, SchemaMap &required, SchemaMap &optional)
{
    for (const auto &[key, value] : required) {
        if (!obj.contains(key)) {
            throw SchemaException(fmt::format("{}: required field is missing: {}", plugin(), key));
        }
        if (!std::regex_match(obj[key].get<std::string>(), std::regex(value))) {
            throw SchemaException(fmt::format("{}: required field fails input validation: {} requires {}", plugin(), key, value));
        }
    }
    for (const auto &[key, value] : optional) {
        if (obj.contains(key) && !std::regex_match(obj[key].get<std::string>(), std::regex(value))) {
            throw SchemaException(fmt::format("{}: optional field fails input validation: {} requires {}", plugin(), key, value));
        }
    }
}

}