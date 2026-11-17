/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "PolicyAttributes.h"
#include "Policies.h"
#include <fmt/format.h>

namespace visor {

LabelMap parse_attributes(const YAML::Node &node, const std::string &where)
{
    if (!node.IsMap()) {
        throw PolicyException(fmt::format("attributes of {} is not a map", where));
    }
    LabelMap attrs;
    for (const auto &kv : node) {
        if (!kv.first.IsScalar()) {
            throw PolicyException(fmt::format("attributes of {} has a key that is not a scalar", where));
        }
        const auto key = kv.first.Scalar();
        if (!kv.second.IsScalar()) {
            throw PolicyException(fmt::format("attribute '{}' of {} must be a scalar value", key, where));
        }
        const auto &value = kv.second.Scalar();
        if (value.empty()) {
            throw PolicyException(fmt::format("attribute '{}' of {} must not be empty", key, where));
        }
        attrs[key] = value;
    }
    return attrs;
}

std::string prometheus_label_name(const std::string &key)
{
    std::string name(key);
    for (auto &c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            c = '_';
        }
    }
    return name;
}

}
