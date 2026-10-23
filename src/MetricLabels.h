/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
#pragma once

#include <map>
#include <string>
#include <string_view>

namespace visor {

using LabelMap = std::map<std::string, std::string>;

// OTLP, Prometheus and JSON all require label values to be UTF-8, but values
// taken from packets, such as DNS names, can hold any byte. utf8_label_value
// returns a valid value unchanged and writes each byte that is not part of a
// well-formed UTF-8 sequence as \DDD, the decimal escape of DNS presentation
// format, so one such value cannot make a whole export or scrape fail.
bool is_utf8(std::string_view value);
std::string utf8_label_value(std::string_view value);

// Process-global static labels (e.g. instance). Storage defined in Metrics.cpp.
LabelMap &prometheus_static_labels_mutable();
inline const LabelMap &prometheus_static_labels() { return prometheus_static_labels_mutable(); }

}
