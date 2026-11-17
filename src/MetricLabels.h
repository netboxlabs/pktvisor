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
// writes each byte that is not part of a well-formed UTF-8 sequence as \DDD,
// the decimal escape of DNS presentation format, so one such value cannot make
// a whole export or scrape fail. A backslash followed by three digits becomes
// \092, so two different values never render the same. Any other value is
// returned unchanged; label_value_needs_escape tells the two cases apart.
bool is_utf8(std::string_view value);
bool label_value_needs_escape(std::string_view value);
std::string utf8_label_value(std::string_view value);

// The Prometheus label name of a label key: every character outside [A-Za-z0-9_] becomes _, one _ per
// code point (the bytes after the first of a UTF-8 sequence write nothing), as the OTLP to Prometheus
// translators do. append_prometheus_label_name writes it onto `out` without a temporary string.
inline void append_prometheus_label_name(std::string &out, std::string_view key)
{
    for (unsigned char c : key) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
            out.push_back(static_cast<char>(c));
        } else if ((c & 0xC0) != 0x80) {
            out.push_back('_');
        }
    }
}

inline std::string prometheus_label_name(std::string_view key)
{
    std::string name;
    name.reserve(key.size());
    append_prometheus_label_name(name, key);
    return name;
}

// Process-global static labels (e.g. instance). Storage defined in Metrics.cpp.
LabelMap &prometheus_static_labels_mutable();
inline const LabelMap &prometheus_static_labels() { return prometheus_static_labels_mutable(); }

}
